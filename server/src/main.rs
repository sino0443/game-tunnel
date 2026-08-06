use anyhow::{Context, Result};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use game_tunnel_shared::config::ServerConfig;
use game_tunnel_shared::protocol::{self, Frame, Message, TunnelProtocol};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch, RwLock};
use tokio_rustls::rustls;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

static STREAM_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
const MAX_CONNECTIONS: usize = 200;
const CLIENT_IDLE_TIMEOUT_SECS: u64 = 120;
/// UDP sessions are cleaned up after this period of inactivity.
/// 300 s (5 minutes) gives games with long loading phases (Satisfactory,
/// ARK, Valheim) enough time to finish loading a map without the tunnel
/// server dropping the session mid-load.  Bedrock and other fast games
/// are unaffected — their stale sessions just linger a bit longer.
const UDP_SESSION_TIMEOUT_SECS: u64 = 300;
/// Socket send/receive buffer size for game connections.
/// 256 KB is large enough for most game update bursts while keeping
/// per-connection overhead low.
const SOCKET_BUF_SIZE: usize = 256 * 1024;
/// Send/receive buffer size for tunnel UDP sockets. Each UDP socket here
/// multiplexes *every* player on that tunnel port, so it needs a much
/// bigger cushion than a single TCP connection's buffer to avoid kernel-side
/// packet drops during bursts (movement updates, chunk data, etc.).
const UDP_SOCKET_BUF_SIZE: usize = 4 * 1024 * 1024;
/// Pre-auth cache entries expire after 10 seconds.
/// The client must connect within this window after the manager sends the
/// pre-auth notification, otherwise the connection will be rejected.
const PRE_AUTH_TTL_SECS: u64 = 10;

/// In-memory pre-auth cache: maps client UUID → timestamp of when the
/// manager granted the pre-authorization.
type PreAuthCache = Arc<RwLock<HashMap<String, Instant>>>;

// ── Connection tracking ───────────────────────────────────────────────────────

/// Per-connection record kept in the global registry.
struct ConnRecord {
    db_id: u32,
    tunnel_id: u32,
    peer_ip: String,
    bytes_in: Arc<AtomicU64>,
    bytes_out: Arc<AtomicU64>,
    /// Computed once per second by `update_connection_rates`.
    bytes_in_per_sec: Arc<AtomicU64>,
    /// Computed once per second by `update_connection_rates`.
    bytes_out_per_sec: Arc<AtomicU64>,
    connected_at: Instant,
    /// Sending `true` here terminates the TCP player-stream task immediately.
    /// For UDP sessions the signal is best-effort — the registry entry is
    /// removed on `DELETE /api/connections/{stream_id}` regardless.
    kill_tx: watch::Sender<bool>,
}

/// Process-wide map of `stream_id → ConnRecord`.
type ConnRegistry = Arc<RwLock<HashMap<u64, ConnRecord>>>;

/// Combined state for the management HTTP server.
/// All three management routes share this single state.
#[derive(Clone)]
struct MgmtState {
    pre_auth_cache: PreAuthCache,
    registry: ConnRegistry,
    mgmt_secret: Arc<String>,
}

/// Requires a valid `X-Mgmt-Secret` header matching `state.mgmt_secret`.
/// This management API lets a caller list/kick player connections and grant
/// tunnel pre-auth for any client UUID, so it must not be reachable without
/// this shared secret even when bound to a private network.
async fn mgmt_auth_middleware(
    axum::extract::State(state): axum::extract::State<MgmtState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let expected = state.mgmt_secret.as_bytes();
    let provided = req
        .headers()
        .get("X-Mgmt-Secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .as_bytes();
    let valid = !expected.is_empty()
        && expected.len() == provided.len()
        && expected.iter().zip(provided.iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
    if valid {
        next.run(req).await
    } else {
        (StatusCode::UNAUTHORIZED, "invalid or missing X-Mgmt-Secret").into_response()
    }
}

/// JSON payload returned by `GET /api/connections`.
/// Field names and types match `ServerConnData` in the manager.
#[derive(Serialize)]
struct ConnectionInfo {
    stream_id: u64,
    db_id: u32,
    tunnel_id: u32,
    peer_ip: String,
    bytes_in: u64,
    bytes_out: u64,
    bytes_in_per_sec: u64,
    bytes_out_per_sec: u64,
    connected_secs: u64,
}

// ─────────────────────────────────────────────────────────────────────────────

struct ActiveTunnel {
    #[allow(dead_code)] tunnel_id: u32,
    #[allow(dead_code)] remote_port: u16,
    #[allow(dead_code)] protocol: TunnelProtocol,
    /// Database row id of this tunnel.  Carried in `OpenTunnel` by the client
    /// so new player connections can populate `ConnRecord.db_id` without a
    /// separate database lookup.
    db_id: u32,
    shutdown_tx: watch::Sender<bool>,
}

struct PlayerStream { tx: mpsc::Sender<Vec<u8>> }

struct UdpPeer {
    addr: std::net::SocketAddr,
    socket: Arc<UdpSocket>,
    /// Outbound byte counter; incremented in `handle_client` each time a
    /// `Frame::Data` is forwarded back to this UDP peer.
    bytes_out: Arc<AtomicU64>,
}

struct ServerState {
    tunnels: HashMap<u32, ActiveTunnel>,
    streams: HashMap<u64, PlayerStream>,
    udp_peers: HashMap<u64, UdpPeer>,
    stream_tunnel: HashMap<u64, u32>,
    public_bind_address: String,
}

fn load_tls_config(cert_path: &str, key_path: &str) -> Result<Arc<rustls::ServerConfig>> {
    let cert_file = File::open(cert_path).with_context(|| format!("failed to open cert: {}", cert_path))?;
    let key_file = File::open(key_path).with_context(|| format!("failed to open key: {}", key_path))?;
    let certs: Vec<rustls::pki_types::CertificateDer> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<std::result::Result<Vec<_>, _>>().context("parse certs")?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .context("read private key")?.context("no private key found")?;
    Ok(Arc::new(rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)?))
}

fn is_valid_game_port(port: u16) -> bool {
    // Explicitly allow HTTP (80) and HTTPS (443) so plain TCP tunnels can
    // carry web traffic without needing a dedicated proxy.
    if port == 80 || port == 443 { return true; }
    // Block other privileged ports and the server's own management ports.
    if port < 1024 { return false; }
    if port == 9000 || port == 9001 { return false; }
    true
}

fn apply_socket_options(stream: &TcpStream) {
    use std::time::Duration;
    let sock_ref = socket2::SockRef::from(stream);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(10))
        .with_interval(Duration::from_secs(5))
        .with_retries(3);
    if let Err(e) = sock_ref.set_tcp_keepalive(&keepalive) {
        warn!("Failed to set TCP keepalive: {:?}", e);
    }
    // Larger send/receive buffers improve throughput for game traffic bursts.
    if let Err(e) = sock_ref.set_send_buffer_size(SOCKET_BUF_SIZE) {
        warn!("Failed to set SO_SNDBUF: {:?}", e);
    }
    if let Err(e) = sock_ref.set_recv_buffer_size(SOCKET_BUF_SIZE) {
        warn!("Failed to set SO_RCVBUF: {:?}", e);
    }
}

// ── Management HTTP server ───────────────────────────────────────────────────

#[derive(Deserialize)]
struct PreAuthRequest {
    client_uuid: String,
}

/// Handler for `POST /api/manager/pre-auth`.
///
/// Called by the manager to notify the server that a client with the given
/// UUID is expected to connect within the next `PRE_AUTH_TTL_SECS` seconds.
async fn handle_pre_auth_request(
    State(state): State<MgmtState>,
    Json(req): Json<PreAuthRequest>,
) -> axum::http::StatusCode {
    let mut c = state.pre_auth_cache.write().await;
    c.insert(req.client_uuid.clone(), Instant::now());
    info!("Pre-auth stored for client UUID {} (TTL: {}s)", req.client_uuid, PRE_AUTH_TTL_SECS);
    axum::http::StatusCode::OK
}

/// Handler for `GET /api/connections`.
///
/// Returns all currently active player connections so the manager can
/// display them in the tunnel-connections UI.  The manager polls this
/// endpoint once per second from `refresh_stats`.
async fn handle_get_connections(State(state): State<MgmtState>) -> impl IntoResponse {
    let reg = state.registry.read().await;
    let conns: Vec<ConnectionInfo> = reg.iter().map(|(&stream_id, r)| ConnectionInfo {
        stream_id,
        db_id:             r.db_id,
        tunnel_id:         r.tunnel_id,
        peer_ip:           r.peer_ip.clone(),
        bytes_in:          r.bytes_in.load(Ordering::Relaxed),
        bytes_out:         r.bytes_out.load(Ordering::Relaxed),
        bytes_in_per_sec:  r.bytes_in_per_sec.load(Ordering::Relaxed),
        bytes_out_per_sec: r.bytes_out_per_sec.load(Ordering::Relaxed),
        connected_secs:    r.connected_at.elapsed().as_secs(),
    }).collect();
    Json(conns)
}

/// Handler for `DELETE /api/connections/{stream_id}`.
///
/// Forces a player off the server.  For TCP the stream task is signalled and
/// exits immediately.  For UDP the registry entry is removed; the underlying
/// socket session drains naturally via the stale-session timeout path.
async fn handle_disconnect_connection(
    State(state): State<MgmtState>,
    Path(stream_id): Path<u64>,
) -> impl IntoResponse {
    let mut reg = state.registry.write().await;
    match reg.remove(&stream_id) {
        Some(record) => {
            // Signal the TCP player-stream task to shut down.  Errors are
            // ignored because the connection may have already closed on its own.
            let _ = record.kill_tx.send(true);
            StatusCode::OK
        }
        None => StatusCode::NOT_FOUND,
    }
}

/// Starts the management HTTP server that the manager reaches for pre-auth
/// and connection-list requests.  Runs as a background task.
async fn start_mgmt_server(bind_addr: String, state: MgmtState) {
    let app = Router::new()
        .route("/api/manager/pre-auth",           post(handle_pre_auth_request))
        .route("/api/connections",                 get(handle_get_connections))
        .route("/api/connections/{stream_id}",     delete(handle_disconnect_connection))
        .layer(axum::middleware::from_fn_with_state(state.clone(), mgmt_auth_middleware))
        .with_state(state);

    info!("Server management API listening on {}", bind_addr);
    match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(listener) => {
            if let Err(e) = axum::serve(listener, app).await {
                error!("Management server error: {:?}", e);
            }
        }
        Err(e) => {
            error!("Failed to bind management API on {}: {:?}", bind_addr, e);
        }
    }
}

/// Background task: removes expired pre-auth entries every 5 seconds.
async fn cleanup_pre_auth_cache(cache: PreAuthCache) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
    loop {
        interval.tick().await;
        let mut c = cache.write().await;
        let before = c.len();
        c.retain(|_, ts| ts.elapsed().as_secs() < PRE_AUTH_TTL_SECS + 5);
        let removed = before - c.len();
        if removed > 0 {
            debug!("Pre-auth cache cleanup: removed {} expired entries", removed);
        }
    }
}

/// Background task: updates per-second bandwidth rates for all tracked connections.
///
/// Runs every second, computes the delta of `bytes_in`/`bytes_out` since the
/// previous tick, and stores the result in the `*_per_sec` atomics.  Using
/// separate atomic counters avoids taking a write lock on every received packet.
async fn update_connection_rates(registry: ConnRegistry) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
    // Previous snapshot: stream_id → (prev_bytes_in, prev_bytes_out)
    let mut prev: HashMap<u64, (u64, u64)> = HashMap::new();
    loop {
        interval.tick().await;
        let reg = registry.read().await;
        for (&sid, r) in reg.iter() {
            let cur_in  = r.bytes_in.load(Ordering::Relaxed);
            let cur_out = r.bytes_out.load(Ordering::Relaxed);
            let (p_in, p_out) = prev.entry(sid).or_insert((cur_in, cur_out));
            r.bytes_in_per_sec.store(cur_in.saturating_sub(*p_in),    Ordering::Relaxed);
            r.bytes_out_per_sec.store(cur_out.saturating_sub(*p_out), Ordering::Relaxed);
            *p_in  = cur_in;
            *p_out = cur_out;
        }
        // Purge entries for connections that have since closed.
        prev.retain(|sid, _| reg.contains_key(sid));
    }
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
    ).init();

    let config_path = std::env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("server.toml"));
    let config = ServerConfig::load(&config_path).with_context(|| format!("failed to load {:?}", config_path))?;
    if config.mgmt_secret.trim().is_empty() {
        anyhow::bail!("server.toml: `mgmt_secret` must be set to a non-empty shared secret");
    }

    info!("Loading TLS certificate from {}", config.tls_cert);
    let tls_acceptor = TlsAcceptor::from(load_tls_config(&config.tls_cert, &config.tls_key)?);

    // Shared pre-auth cache: populated by manager, consumed on client connect.
    let pre_auth_cache: PreAuthCache = Arc::new(RwLock::new(HashMap::new()));

    // Global connection registry: every active player stream registers here so
    // the management API can expose the list to the manager.
    let registry: ConnRegistry = Arc::new(RwLock::new(HashMap::new()));

    // Start management HTTP server so the manager can push pre-auth entries
    // and poll active connections.
    let mgmt_state = MgmtState {
        pre_auth_cache: Arc::clone(&pre_auth_cache),
        registry: Arc::clone(&registry),
        mgmt_secret: Arc::new(config.mgmt_secret.clone()),
    };
    let mgmt_addr = config.mgmt_bind_address.clone();
    tokio::spawn(start_mgmt_server(mgmt_addr, mgmt_state));

    // Periodically remove expired cache entries.
    let cleanup_cache = Arc::clone(&pre_auth_cache);
    tokio::spawn(cleanup_pre_auth_cache(cleanup_cache));

    // Periodically compute per-second bandwidth rates.
    let registry_rate = Arc::clone(&registry);
    tokio::spawn(update_connection_rates(registry_rate));

    info!("Starting game-tunnel server {} on {}", config.server_id, config.bind_address);
    let listener = TcpListener::bind(&config.bind_address).await
        .with_context(|| format!("failed to bind {}", config.bind_address))?;

    let public_bind = config.public_bind_address.clone().unwrap_or_else(|| "0.0.0.0".to_string());

    loop {
        let (tcp_stream, addr) = listener.accept().await?;
        tcp_stream.set_nodelay(true).ok();
        apply_socket_options(&tcp_stream);

        let conn_count = ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        if conn_count >= MAX_CONNECTIONS {
            ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
            warn!("Max connections reached, rejecting {}", addr);
            continue;
        }

        info!("Client connection from {} (TLS handshake...)", addr);
        let acceptor    = tls_acceptor.clone();
        let config      = config.clone();
        let public_bind = public_bind.clone();
        let cache       = Arc::clone(&pre_auth_cache);
        let reg         = Arc::clone(&registry);

        tokio::spawn(async move {
            match acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => {
                    info!("Client {} TLS handshake complete", addr);
                    if let Err(e) = handle_client(tls_stream, addr, &config, &public_bind, cache, reg).await {
                        let msg = e.to_string();
                        if msg.contains("close_notify") || msg.contains("peer closed") || msg.contains("idle timeout") {
                            // Expected disconnects – silent.
                        } else if msg.contains("malformed auth frame")
                            || msg.contains("expected Auth frame")
                            || msg.contains("authentication timeout")
                            || msg.contains("authentication failed")
                            || msg.contains("pre-auth expired")
                            || msg.contains("not pre-authorized")
                            || msg.contains("Auth payload")
                        {
                            // Auth rejections are expected (e.g. external scanners,
                            // expired pre-auth, wrong secret) – log as WARN, not ERROR.
                            warn!("Client {} auth rejected: {}", addr, msg);
                        } else {
                            error!("Client {} error: {:?}", addr, e);
                        }
                    }
                }
                Err(e) => {
                    let msg = e.to_string();
                    // These are all expected from external scanners / probes and
                    // produce nothing actionable — suppress or downgrade them.
                    let scanner_noise = msg.contains("InvalidContentType")
                        || msg.contains("close_notify")
                        || msg.contains("UnknownIssuer")
                        // TLS 1.2 probe against a TLS-1.3-only server.
                        || msg.contains("Tls12NotOffered")
                        || msg.contains("PeerIncompatible")
                        // Scanner drops the TCP connection immediately.
                        || msg.contains("Connection reset by peer")
                        || msg.contains("ConnectionReset")
                        || msg.contains("code: 104");
                    if !scanner_noise {
                        error!("TLS handshake failed for {}: {:?}", addr, e);
                    }
                }
            }
            ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
            info!("Client {} disconnected ({} active)", addr, ACTIVE_CONNECTIONS.load(Ordering::Relaxed));
        });
    }
}

async fn handle_client(
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    addr: SocketAddr,
    config: &ServerConfig,
    public_bind: &str,
    pre_auth_cache: PreAuthCache,
    registry: ConnRegistry,
) -> Result<()> {
    let (mut read_half, mut write_half) = tokio::io::split(stream);

    let frame = match tokio::time::timeout(tokio::time::Duration::from_secs(10), protocol::read_frame(&mut read_half)).await {
        Ok(Ok(f)) => f,
        Ok(Err(e)) => {
            // Malformed frame – inform the client before closing so it knows
            // why the connection was rejected (prevents silent EOF reconnect loops).
            let _ = protocol::write_control(
                &mut write_half,
                &Message::AuthFailed { reason: "malformed auth frame".into() },
            ).await;
            return Err(e.into());
        }
        Err(_) => { warn!("Auth timeout for {}", addr); anyhow::bail!("authentication timeout"); }
    };

    match frame {
        Frame::Control(Message::Auth { secret, client_uuid }) => {
            // 1. Constant-time secret check.
            let expected = config.secret.as_bytes();
            let provided = secret.as_bytes();
            let valid = expected.len() == provided.len()
                && expected.iter().zip(provided.iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
            if !valid {
                protocol::write_control(&mut write_half, &Message::AuthFailed { reason: "invalid secret".into() }).await?;
                warn!("Auth failed (bad secret) from {}", addr);
                anyhow::bail!("authentication failed");
            }

            // 2. If a UUID is provided, verify against the pre-auth cache.
            //    The manager must have sent a pre-auth notification (within the
            //    last PRE_AUTH_TTL_SECS seconds) for this UUID to be accepted.
            if let Some(ref uuid) = client_uuid {
                let mut cache = pre_auth_cache.write().await;
                match cache.get(uuid).cloned() {
                    Some(ts) if ts.elapsed().as_secs() < PRE_AUTH_TTL_SECS => {
                        // Valid — consume the entry (one-time use per connection).
                        cache.remove(uuid);
                        info!("Client {} authenticated with UUID {} (pre-auth valid)", addr, uuid);
                    }
                    Some(_) => {
                        cache.remove(uuid);
                        protocol::write_control(
                            &mut write_half,
                            &Message::AuthFailed { reason: "pre-auth expired".into() },
                        ).await?;
                        warn!("Client {} UUID {} pre-auth expired (>{}s)", addr, uuid, PRE_AUTH_TTL_SECS);
                        anyhow::bail!("pre-auth expired");
                    }
                    None => {
                        protocol::write_control(
                            &mut write_half,
                            &Message::AuthFailed { reason: "not pre-authorized by manager".into() },
                        ).await?;
                        warn!("Client {} UUID {} not in pre-auth cache", addr, uuid);
                        anyhow::bail!("not pre-authorized");
                    }
                }
            }

            protocol::write_control(&mut write_half, &Message::AuthOk).await?;
            info!("Client {} authenticated (server_id: {})", addr, config.server_id);
        }
        _ => {
            let _ = protocol::write_control(
                &mut write_half,
                &Message::AuthFailed { reason: "expected auth frame".into() },
            ).await;
            anyhow::bail!("expected Auth frame");
        }
    }

    let state = Arc::new(RwLock::new(ServerState {
        tunnels: HashMap::new(), streams: HashMap::new(), udp_peers: HashMap::new(),
        stream_tunnel: HashMap::new(), public_bind_address: public_bind.to_string(),
    }));

    let (write_tx, mut write_rx) = mpsc::channel::<Frame>(8192);
    let writer_task = tokio::spawn(async move {
        // NOTE: this used to batch several queued frames per flush to cut
        // down on syscalls under load. That change went out in the same
        // release as several other fixes and coincided with reports of
        // widespread player disconnects / stuck "ghost" connections in
        // production, so it's reverted here out of caution while it gets
        // investigated properly, back to the simple, previously-stable
        // one-frame-one-flush behavior.
        while let Some(frame) = write_rx.recv().await {
            let r = match &frame {
                Frame::Control(msg) => protocol::write_control(&mut write_half, msg).await,
                Frame::Data { stream_id, payload } => protocol::write_data(&mut write_half, *stream_id, payload).await,
                Frame::StreamClose { stream_id } => protocol::write_stream_close(&mut write_half, *stream_id).await,
            };
            if r.is_err() { break; }
        }
    });

    let state_clone    = Arc::clone(&state);
    let write_tx_clone = write_tx.clone();
    let registry_loop  = Arc::clone(&registry);
    let idle_timeout   = tokio::time::Duration::from_secs(CLIENT_IDLE_TIMEOUT_SECS);

    let result: Result<()> = async {
        loop {
            let frame = match tokio::time::timeout(idle_timeout, protocol::read_frame(&mut read_half)).await {
                Ok(Ok(f)) => f,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => { warn!("Client {} idle timeout", addr); anyhow::bail!("idle timeout"); }
            };
            match frame {
                Frame::Control(msg) => {
                    handle_control_message(msg, addr, &state_clone, &write_tx_clone, &registry_loop).await?;
                }
                Frame::Data { stream_id, payload } => {
                    let tcp_tx = { state_clone.read().await.streams.get(&stream_id).map(|s| s.tx.clone()) };
                    if let Some(tx) = tcp_tx {
                        if tx.send(payload).await.is_err() {
                            let _ = write_tx_clone.send(Frame::StreamClose { stream_id }).await;
                            let mut st = state_clone.write().await;
                            st.streams.remove(&stream_id); st.stream_tunnel.remove(&stream_id);
                        }
                    } else {
                        // UDP path: look up the peer, update outbound byte counter, forward.
                        let peer = {
                            state_clone.read().await.udp_peers.get(&stream_id)
                                .map(|p| (p.addr, Arc::clone(&p.socket), Arc::clone(&p.bytes_out)))
                        };
                        if let Some((peer_addr, socket, bytes_out)) = peer {
                            bytes_out.fetch_add(payload.len() as u64, Ordering::Relaxed);
                            let _ = socket.send_to(&payload, peer_addr).await;
                        }
                    }
                }
                Frame::StreamClose { stream_id } => {
                    {
                        let mut st = state_clone.write().await;
                        st.streams.remove(&stream_id);
                        st.udp_peers.remove(&stream_id);
                        st.stream_tunnel.remove(&stream_id);
                    }
                    // Remove from the global registry so the web UI no longer shows this
                    // connection as active.  For TCP streams handle_player_stream removes
                    // itself when it exits; for UDP there is no per-peer task, so this
                    // explicit removal is the only way to avoid a ~5-minute ghost window
                    // caused by the stale UDP session-cleanup delay.
                    registry_loop.write().await.remove(&stream_id);
                }
            }
        }
    }.await;

    { let mut st = state.write().await; for (_, t) in st.tunnels.drain() { let _ = t.shutdown_tx.send(true); } st.streams.clear(); }
    writer_task.abort();
    result
}

async fn handle_control_message(
    msg: Message, client_addr: SocketAddr,
    state: &Arc<RwLock<ServerState>>, write_tx: &mpsc::Sender<Frame>,
    registry: &ConnRegistry,
) -> Result<()> {
    match msg {
        Message::OpenTunnel { tunnel_id, remote_port, protocol, db_id } => {
            if !is_valid_game_port(remote_port) {
                warn!("Invalid port {} from {}", remote_port, client_addr);
                let _ = write_tx.send(Frame::Control(Message::CloseTunnel { tunnel_id })).await;
                return Ok(());
            }
            { let st = state.read().await; if st.tunnels.contains_key(&tunnel_id) { warn!("Duplicate tunnel_id {} rejected", tunnel_id); return Ok(()); } }

            info!("Opening tunnel {} on port {} ({:?})", tunnel_id, remote_port, protocol);
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let bind_addr = state.read().await.public_bind_address.clone();

            if protocol == TunnelProtocol::Tcp || protocol == TunnelProtocol::Both {
                let addr_str = format!("{}:{}", bind_addr, remote_port);
                let listener = match TcpListener::bind(&addr_str).await {
                    Ok(l) => l,
                    Err(e) => {
                        error!("Failed to bind port {}: {:?}", remote_port, e);
                        let _ = write_tx.send(Frame::Control(Message::CloseTunnel { tunnel_id })).await;
                        return Ok(());
                    }
                };
                info!("Listening on {} (TCP)", addr_str);
                let state_tcp    = Arc::clone(state);
                let write_tx_tcp = write_tx.clone();
                let registry_tcp = Arc::clone(registry);
                let mut shutdown = shutdown_rx.clone();
                tokio::spawn(async move {
                    loop { tokio::select! {
                        res = listener.accept() => { match res {
                            Ok((player_stream, peer)) => {
                                player_stream.set_nodelay(true).ok();
                                apply_socket_options(&player_stream);
                                let stream_id = STREAM_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
                                debug!("Player {} connected (stream {} TCP)", peer, stream_id);
                                let (player_tx, player_rx) = mpsc::channel::<Vec<u8>>(2048);
                                { let mut st = state_tcp.write().await; st.streams.insert(stream_id, PlayerStream { tx: player_tx }); st.stream_tunnel.insert(stream_id, tunnel_id); }
                                let _ = write_tx_tcp.send(Frame::Control(Message::NewConnection { tunnel_id, stream_id, is_udp: false, peer_addr: Some(peer) })).await;

                                // Register this connection in the global registry so the
                                // manager can see it via GET /api/connections.
                                let db_id_val = state_tcp.read().await.tunnels.get(&tunnel_id).map(|t| t.db_id).unwrap_or(0);
                                let bytes_in     = Arc::new(AtomicU64::new(0));
                                let bytes_out    = Arc::new(AtomicU64::new(0));
                                let bytes_in_ps  = Arc::new(AtomicU64::new(0));
                                let bytes_out_ps = Arc::new(AtomicU64::new(0));
                                let (kill_tx, kill_rx) = watch::channel(false);
                                registry_tcp.write().await.insert(stream_id, ConnRecord {
                                    db_id:             db_id_val,
                                    tunnel_id,
                                    peer_ip:           peer.ip().to_string(),
                                    bytes_in:          Arc::clone(&bytes_in),
                                    bytes_out:         Arc::clone(&bytes_out),
                                    bytes_in_per_sec:  Arc::clone(&bytes_in_ps),
                                    bytes_out_per_sec: Arc::clone(&bytes_out_ps),
                                    connected_at:      Instant::now(),
                                    kill_tx,
                                });

                                let wtx = write_tx_tcp.clone();
                                let st  = Arc::clone(&state_tcp);
                                let reg = Arc::clone(&registry_tcp);
                                tokio::spawn(async move {
                                    handle_player_stream(
                                        player_stream, stream_id, player_rx, wtx, st,
                                        bytes_in, bytes_out, kill_rx, reg,
                                    ).await;
                                });
                            }
                            Err(e) => { error!("Accept error: {:?}", e); }
                        }}
                        _ = shutdown.changed() => { info!("Shutting down port {} (TCP)", remote_port); break; }
                    }}
                });
            }

            if protocol == TunnelProtocol::Udp || protocol == TunnelProtocol::Both {
                let addr_str = format!("{}:{}", bind_addr, remote_port);
                let socket = match UdpSocket::bind(&addr_str).await {
                    Ok(s) => {
                        // Default kernel UDP buffers (often ~200 KB or less) are too
                        // small once one socket multiplexes many players' bursty
                        // traffic (Rust, ARK, Valheim, Minecraft Bedrock/RakNet, ...);
                        // packets get dropped by the kernel before our code ever
                        // sees them. Size generously — this is one socket shared by
                        // every player on this tunnel, not a per-player buffer.
                        let sock_ref = socket2::SockRef::from(&s);
                        if let Err(e) = sock_ref.set_recv_buffer_size(UDP_SOCKET_BUF_SIZE) {
                            warn!("Failed to set UDP SO_RCVBUF for port {}: {:?}", remote_port, e);
                        }
                        if let Err(e) = sock_ref.set_send_buffer_size(UDP_SOCKET_BUF_SIZE) {
                            warn!("Failed to set UDP SO_SNDBUF for port {}: {:?}", remote_port, e);
                        }
                        Arc::new(s)
                    }
                    Err(e) => {
                        error!("Failed to bind UDP port {}: {:?}", remote_port, e);
                        let _ = write_tx.send(Frame::Control(Message::CloseTunnel { tunnel_id })).await;
                        return Ok(());
                    }
                };
                info!("Listening on {} (UDP)", addr_str);
                let write_tx_udp = write_tx.clone();
                let state_udp    = Arc::clone(state);
                let registry_udp = Arc::clone(registry);
                let mut shutdown = shutdown_rx.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65535];
                    let mut peer_streams: HashMap<std::net::SocketAddr, u64> = HashMap::new();
                    let mut last_seen: HashMap<std::net::SocketAddr, std::time::Instant> = HashMap::new();
                    // Per-stream inbound byte counters (updated inline on each recv).
                    let mut peer_bytes_in:  HashMap<u64, Arc<AtomicU64>> = HashMap::new();
                    // Keep bytes_out arcs here so we can rebind the UdpPeer on NAT port-change.
                    let mut peer_bytes_out: HashMap<u64, Arc<AtomicU64>> = HashMap::new();
                    let mut cleanup_interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
                    loop { tokio::select! {
                        res = socket.recv_from(&mut buf) => { match res {
                            Ok((len, peer_addr)) => {
                                last_seen.insert(peer_addr, std::time::Instant::now());

                                // Stale-peer check: the client may have sent StreamClose (e.g.
                                // on its 120 s inactivity timeout) for an entry that is still in
                                // our local peer_streams map but whose udp_peers entry was
                                // removed by handle_client.  Detect this now so that a player
                                // who reconnects from the same IP:port is treated as a fresh
                                // connection rather than silently having their data dropped
                                // because it would be forwarded to an already-closed stream.
                                if let Some(&sid) = peer_streams.get(&peer_addr) {
                                    let still_active = {
                                        let st = state_udp.read().await;
                                        st.udp_peers.contains_key(&sid)
                                    };
                                    if !still_active {
                                        info!(
                                            "UDP: peer {} stream {} was closed by client — \
                                             evicting stale mapping, will re-register on next packet",
                                            peer_addr, sid
                                        );
                                        peer_streams.remove(&peer_addr);
                                        last_seen.remove(&peer_addr);
                                        peer_bytes_in.remove(&sid);
                                        peer_bytes_out.remove(&sid);
                                    }
                                }

                                let stream_id = if let Some(&sid) = peer_streams.get(&peer_addr) {
                                    sid
                                } else {
                                    // NAT-rebinding detection: same IP, different port.
                                    // Some routers/CGNAT reassign the UDP source port within
                                    // seconds. Instead of creating a new session (which would
                                    // break the in-progress game connection), we update the
                                    // existing session to use the new address — but ONLY when
                                    // there is exactly one existing session from that IP and it
                                    // was active recently. Multiple players can share a
                                    // single public IP (mobile CGNAT, shared/hotel/campus
                                    // networks), so a plain "same IP" match would silently merge
                                    // two different players into one stream and cross-deliver
                                    // their traffic. Requiring uniqueness + recency makes that
                                    // far less likely; anything ambiguous falls through to
                                    // "genuinely new connection" below instead.
                                    //
                                    // 60 s gives players enough time to alt-tab, pause the game,
                                    // or wait through a loading screen without their session being
                                    // dropped.  The original 5 s window was too short — any
                                    // player idle for more than 5 seconds after a NAT port change
                                    // was treated as a new connection, leaving their old session
                                    // as a ghost in the registry for up to 5 minutes.
                                    const REBIND_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
                                    let now = std::time::Instant::now();
                                    let mut matches = peer_streams.iter()
                                        .filter(|&(addr, _)| addr.ip() == peer_addr.ip())
                                        .filter(|&(addr, _)| {
                                            last_seen.get(addr)
                                                .map(|t| now.duration_since(*t) < REBIND_WINDOW)
                                                .unwrap_or(false)
                                        });
                                    let rebind = match (matches.next(), matches.next()) {
                                        (Some((&addr, &sid)), None) => Some((addr, sid)), // exactly one candidate
                                        _ => None, // none, or ambiguous (multiple players on this IP)
                                    };

                                    if let Some((old_addr, existing_sid)) = rebind {
                                        info!("UDP NAT rebind detected: {} → {} (stream {})",
                                              old_addr, peer_addr, existing_sid);
                                        peer_streams.remove(&old_addr);
                                        last_seen.remove(&old_addr);
                                        peer_streams.insert(peer_addr, existing_sid);
                                        last_seen.insert(peer_addr, std::time::Instant::now());
                                        // Update the stored peer address so responses go to new port.
                                        let existing_bytes_out = peer_bytes_out.get(&existing_sid)
                                            .cloned()
                                            .unwrap_or_else(|| Arc::new(AtomicU64::new(0)));
                                        {
                                            let mut st = state_udp.write().await;
                                            st.udp_peers.insert(existing_sid, UdpPeer {
                                                addr: peer_addr,
                                                socket: Arc::clone(&socket),
                                                bytes_out: existing_bytes_out,
                                            });
                                        }
                                        existing_sid
                                    } else {
                                        // Genuinely new player connection.
                                        let sid = STREAM_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
                                        peer_streams.insert(peer_addr, sid);
                                        let bytes_in     = Arc::new(AtomicU64::new(0));
                                        let bytes_out    = Arc::new(AtomicU64::new(0));
                                        let bytes_in_ps  = Arc::new(AtomicU64::new(0));
                                        let bytes_out_ps = Arc::new(AtomicU64::new(0));
                                        peer_bytes_in.insert(sid,  Arc::clone(&bytes_in));
                                        peer_bytes_out.insert(sid, Arc::clone(&bytes_out));
                                        let db_id_val = state_udp.read().await.tunnels.get(&tunnel_id).map(|t| t.db_id).unwrap_or(0);
                                        // kill_rx is not actively watched for UDP (no per-peer task);
                                        // the kill_tx is still stored so DELETE /api/connections/{sid}
                                        // can remove the registry entry cleanly.
                                        let (kill_tx, _kill_rx) = watch::channel(false);
                                        registry_udp.write().await.insert(sid, ConnRecord {
                                            db_id:             db_id_val,
                                            tunnel_id,
                                            peer_ip:           peer_addr.ip().to_string(),
                                            bytes_in:          Arc::clone(&bytes_in),
                                            bytes_out:         Arc::clone(&bytes_out),
                                            bytes_in_per_sec:  Arc::clone(&bytes_in_ps),
                                            bytes_out_per_sec: Arc::clone(&bytes_out_ps),
                                            connected_at:      Instant::now(),
                                            kill_tx,
                                        });
                                        {
                                            let mut st = state_udp.write().await;
                                            st.udp_peers.insert(sid, UdpPeer { addr: peer_addr, socket: Arc::clone(&socket), bytes_out });
                                            st.stream_tunnel.insert(sid, tunnel_id);
                                        }
                                        let _ = write_tx_udp.send(Frame::Control(Message::NewConnection { tunnel_id, stream_id: sid, is_udp: true, peer_addr: Some(peer_addr) })).await;
                                        sid
                                    }
                                };
                                // Accumulate inbound bytes for the rate-computation task.
                                if let Some(b) = peer_bytes_in.get(&stream_id) {
                                    b.fetch_add(len as u64, Ordering::Relaxed);
                                }
                                let _ = write_tx_udp.send(Frame::Data { stream_id, payload: buf[..len].to_vec() }).await;
                            }
                            Err(e) => { error!("UDP recv error: {:?}", e); break; }
                        }}
                        _ = cleanup_interval.tick() => {
                            let now = std::time::Instant::now();
                            let stale: Vec<std::net::SocketAddr> = last_seen.iter()
                                .filter(|(_, t)| now.duration_since(**t).as_secs() > UDP_SESSION_TIMEOUT_SECS)
                                .map(|(addr, _)| *addr)
                                .collect();
                            for addr in stale {
                                last_seen.remove(&addr);
                                if let Some(sid) = peer_streams.remove(&addr) {
                                    peer_bytes_in.remove(&sid);
                                    peer_bytes_out.remove(&sid);
                                    { let mut st = state_udp.write().await;
                                        st.udp_peers.remove(&sid);
                                        st.stream_tunnel.remove(&sid);
                                    }
                                    registry_udp.write().await.remove(&sid);
                                    let _ = write_tx_udp.send(Frame::StreamClose { stream_id: sid }).await;
                                    info!("UDP: stale session removed for {} (stream {})", addr, sid);
                                }
                            }
                        }
                        _ = shutdown.changed() => {
                            info!("Shutting down port {} (UDP)", remote_port);
                            // Clean up registry entries for any sessions still open on this tunnel.
                            let mut reg = registry_udp.write().await;
                            for sid in peer_streams.values() { reg.remove(sid); }
                            break;
                        }
                    }}
                });
            }

            { state.write().await.tunnels.insert(tunnel_id, ActiveTunnel { tunnel_id, remote_port, protocol, db_id, shutdown_tx }); }
            write_tx.send(Frame::Control(Message::TunnelOpened { tunnel_id })).await.context("send TunnelOpened")?;
        }
        Message::CloseTunnel { tunnel_id } => {
            info!("Closing tunnel {}", tunnel_id);
            let sids = {
                let mut st = state.write().await;
                if let Some(t) = st.tunnels.remove(&tunnel_id) { let _ = t.shutdown_tx.send(true); }
                let sids: Vec<u64> = st.stream_tunnel.iter().filter(|(_, &tid)| tid == tunnel_id).map(|(&sid, _)| sid).collect();
                for sid in &sids { st.streams.remove(sid); st.udp_peers.remove(sid); st.stream_tunnel.remove(sid); let _ = write_tx.send(Frame::StreamClose { stream_id: *sid }).await; }
                sids
            };
            if !sids.is_empty() {
                info!("Closed {} connections for tunnel {}", sids.len(), tunnel_id);
                // Purge registry entries for all streams belonging to this tunnel.
                // TCP streams will also self-remove when handle_player_stream exits,
                // so this is an eager cleanup that avoids a brief stale window.
                let mut reg = registry.write().await;
                for sid in &sids { reg.remove(sid); }
            }
        }
        Message::Ping => { let _ = write_tx.try_send(Frame::Control(Message::Pong)); }
        _ => { warn!("Unexpected control message from {}: {:?}", client_addr, msg); }
    }
    Ok(())
}

async fn handle_player_stream(
    player: TcpStream, stream_id: u64,
    mut from_tunnel: mpsc::Receiver<Vec<u8>>,
    to_tunnel: mpsc::Sender<Frame>,
    state: Arc<RwLock<ServerState>>,
    bytes_in: Arc<AtomicU64>,
    bytes_out: Arc<AtomicU64>,
    mut kill_rx: watch::Receiver<bool>,
    registry: ConnRegistry,
) {
    let (mut pr, mut pw) = player.into_split();
    let to_tunnel_r = to_tunnel.clone();
    let bytes_in_c  = Arc::clone(&bytes_in);
    let mut read_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match pr.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    bytes_in_c.fetch_add(n as u64, Ordering::Relaxed);
                    if to_tunnel_r.send(Frame::Data { stream_id, payload: buf[..n].to_vec() }).await.is_err() { break; }
                }
                Err(_) => break,
            }
        }
    });
    let bytes_out_c = Arc::clone(&bytes_out);
    let mut write_task = tokio::spawn(async move {
        while let Some(data) = from_tunnel.recv().await {
            bytes_out_c.fetch_add(data.len() as u64, Ordering::Relaxed);
            if pw.write_all(&data).await.is_err() { break; }
        }
    });
    tokio::select! {
        _ = &mut read_task  => {}
        _ = &mut write_task => {}
        _ = kill_rx.changed() => {
            // Forced disconnect via DELETE /api/connections/{stream_id}.
            read_task.abort();
            write_task.abort();
        }
    }
    // Abort whichever task is still running so both socket halves are
    // closed immediately.  Without this the "loser" task keeps its
    // OwnedReadHalf (pr) or OwnedWriteHalf (pw) alive, leaving the
    // player's TCP connection half-open.  The player's game client will
    // not detect the disconnect until it tries to write — which may not
    // happen for a long time on a quiet connection — so the player stays
    // on-screen in the game until the OS-level timeout fires.
    read_task.abort();
    write_task.abort();
    let _ = to_tunnel.send(Frame::StreamClose { stream_id }).await;
    let mut st = state.write().await;
    st.streams.remove(&stream_id);
    st.stream_tunnel.remove(&stream_id);
    // Remove from registry (no-op when the disconnect handler already did it).
    registry.write().await.remove(&stream_id);
}
