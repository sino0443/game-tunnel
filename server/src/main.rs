use anyhow::{Context, Result};
use axum::Router;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Json};
use axum::routing::{delete, get, post};
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
/// Pre-auth cache entries expire after 10 seconds.
/// The client must connect within this window after the manager sends the
/// pre-auth notification, otherwise the connection will be rejected.
const PRE_AUTH_TTL_SECS: u64 = 10;

/// In-memory pre-auth cache: maps client UUID → timestamp of when the
/// manager granted the pre-authorization.
type PreAuthCache = Arc<RwLock<HashMap<String, Instant>>>;

// ── Global connection registry ────────────────────────────────────────────────

/// Per-connection tracking record stored in the global registry.
///
/// Both the management HTTP server (reads / forced disconnect) and the
/// per-connection tasks (byte-count writes) hold Arc references here.
struct ConnRecord {
    db_id: u32,
    tunnel_id: u32,
    /// IP address of the connected player (no port).
    peer_ip: String,
    /// Cumulative bytes received from the player (player → tunnel).
    bytes_in: Arc<AtomicU64>,
    /// Cumulative bytes forwarded to the player (tunnel → player).
    bytes_out: Arc<AtomicU64>,
    /// Per-second receive rate; refreshed every second by a background task.
    bytes_in_per_sec: u64,
    /// Per-second send rate; refreshed every second by a background task.
    bytes_out_per_sec: u64,
    /// `bytes_in` snapshot from the previous rate-update interval.
    bytes_in_prev: u64,
    /// `bytes_out` snapshot from the previous rate-update interval.
    bytes_out_prev: u64,
    connected_at: Instant,
    /// Frame sender for the owning tunnel client – used to push a
    /// `StreamClose` frame on a forced disconnect.
    write_tx: mpsc::Sender<Frame>,
    /// Per-client `ServerState` reference – lets the delete handler clean up
    /// local stream maps without having to hold the registry lock.
    server_state: Arc<RwLock<ServerState>>,
}

/// Global map from `stream_id` → `ConnRecord`, shared between the management
/// HTTP server and all connection-handling tasks.
type GlobalRegistry = Arc<RwLock<HashMap<u64, ConnRecord>>>;

// ── Per-connection structs ────────────────────────────────────────────────────

struct ActiveTunnel {
    #[allow(dead_code)] tunnel_id: u32,
    #[allow(dead_code)] remote_port: u16,
    #[allow(dead_code)] protocol: TunnelProtocol,
    shutdown_tx: watch::Sender<bool>,
    /// Database id of the tunnel, carried from the `OpenTunnel` wire message.
    db_id: u32,
}

struct PlayerStream { tx: mpsc::Sender<Vec<u8>> }

struct UdpPeer {
    addr: std::net::SocketAddr,
    socket: Arc<UdpSocket>,
    /// Bytes forwarded from the tunnel to this UDP peer (tunnel → player).
    bytes_out: Arc<AtomicU64>,
}

struct ServerState {
    tunnels: HashMap<u32, ActiveTunnel>,
    streams: HashMap<u64, PlayerStream>,
    udp_peers: HashMap<u64, UdpPeer>,
    stream_tunnel: HashMap<u64, u32>,
    public_bind_address: String,
}

// ── Management HTTP server ────────────────────────────────────────────────────

#[derive(Deserialize)]
struct PreAuthRequest {
    client_uuid: String,
}

/// Shared state for all management API handlers.
#[derive(Clone)]
struct MgmtState {
    pre_auth_cache: PreAuthCache,
    registry: GlobalRegistry,
}

/// JSON shape returned by `GET /api/connections` (consumed by the manager).
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

/// `POST /api/manager/pre-auth`
///
/// Called by the manager to tell the server that a client with the given UUID
/// is expected to connect within the next `PRE_AUTH_TTL_SECS` seconds.
async fn handle_pre_auth_request(
    State(mgmt): State<MgmtState>,
    Json(req): Json<PreAuthRequest>,
) -> axum::http::StatusCode {
    let mut c = mgmt.pre_auth_cache.write().await;
    c.insert(req.client_uuid.clone(), Instant::now());
    info!("Pre-auth stored for client UUID {} (TTL: {}s)", req.client_uuid, PRE_AUTH_TTL_SECS);
    axum::http::StatusCode::OK
}

/// `GET /api/connections`
///
/// Returns a JSON array of all currently active player connections.
/// Consumed every second by the manager's `refresh_stats` loop.
async fn handle_get_connections(State(mgmt): State<MgmtState>) -> impl IntoResponse {
    let reg = mgmt.registry.read().await;
    let conns: Vec<ConnectionInfo> = reg
        .iter()
        .map(|(&stream_id, r)| ConnectionInfo {
            stream_id,
            db_id: r.db_id,
            tunnel_id: r.tunnel_id,
            peer_ip: r.peer_ip.clone(),
            bytes_in: r.bytes_in.load(Ordering::Relaxed),
            bytes_out: r.bytes_out.load(Ordering::Relaxed),
            bytes_in_per_sec: r.bytes_in_per_sec,
            bytes_out_per_sec: r.bytes_out_per_sec,
            connected_secs: r.connected_at.elapsed().as_secs(),
        })
        .collect();
    Json(conns)
}

/// `DELETE /api/connections/{stream_id}`
///
/// Force-closes a single player connection.  Called by the manager when the
/// operator requests a disconnect via the web UI.
async fn handle_delete_connection(
    State(mgmt): State<MgmtState>,
    Path(stream_id): Path<u64>,
) -> axum::http::StatusCode {
    // Read the needed data under a short-lived read lock, then release it
    // before acquiring any write locks to avoid potential deadlocks.
    let entry = {
        let reg = mgmt.registry.read().await;
        reg.get(&stream_id)
            .map(|r| (r.write_tx.clone(), Arc::clone(&r.server_state)))
    };

    let Some((write_tx, server_state)) = entry else {
        return axum::http::StatusCode::NOT_FOUND;
    };

    // Tell the tunnel client to close this stream.
    let _ = write_tx.send(Frame::StreamClose { stream_id }).await;

    // Remove from the per-client in-memory maps (acquire, use, release).
    {
        let mut st = server_state.write().await;
        st.streams.remove(&stream_id);
        st.udp_peers.remove(&stream_id);
        st.stream_tunnel.remove(&stream_id);
    }

    // Remove from the global registry (separate lock acquisition, no nesting).
    mgmt.registry.write().await.remove(&stream_id);

    info!("Force-disconnected stream {}", stream_id);
    axum::http::StatusCode::NO_CONTENT
}

/// Starts the management HTTP server in a background task.
async fn start_mgmt_server(bind_addr: String, state: MgmtState) {
    let app = Router::new()
        .route("/api/manager/pre-auth",       post(handle_pre_auth_request))
        .route("/api/connections",            get(handle_get_connections))
        .route("/api/connections/:stream_id", delete(handle_delete_connection))
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

/// Background task: refreshes per-second byte rates for all active connections.
///
/// Runs once per second; holds the registry write lock only briefly.
async fn update_connection_rates(registry: GlobalRegistry) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
    loop {
        interval.tick().await;
        let mut reg = registry.write().await;
        for record in reg.values_mut() {
            let cur_in  = record.bytes_in.load(Ordering::Relaxed);
            let cur_out = record.bytes_out.load(Ordering::Relaxed);
            record.bytes_in_per_sec  = cur_in.saturating_sub(record.bytes_in_prev);
            record.bytes_out_per_sec = cur_out.saturating_sub(record.bytes_out_prev);
            record.bytes_in_prev  = cur_in;
            record.bytes_out_prev = cur_out;
        }
    }
}

// ── TLS / socket helpers ──────────────────────────────────────────────────────

fn load_tls_config(cert_path: &str, key_path: &str) -> Result<Arc<rustls::ServerConfig>> {
    let cert_file = File::open(cert_path).with_context(|| format!("failed to open cert: {}", cert_path))?;
    let key_file  = File::open(key_path).with_context(|| format!("failed to open key: {}", key_path))?;
    let certs: Vec<rustls::pki_types::CertificateDer> =
        rustls_pemfile::certs(&mut BufReader::new(cert_file))
            .collect::<std::result::Result<Vec<_>, _>>().context("parse certs")?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .context("read private key")?.context("no private key found")?;
    Ok(Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?,
    ))
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
    if let Err(e) = sock_ref.set_send_buffer_size(SOCKET_BUF_SIZE) {
        warn!("Failed to set SO_SNDBUF: {:?}", e);
    }
    if let Err(e) = sock_ref.set_recv_buffer_size(SOCKET_BUF_SIZE) {
        warn!("Failed to set SO_RCVBUF: {:?}", e);
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
    ).init();

    let config_path = std::env::args().nth(1).map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("server.toml"));
    let config = ServerConfig::load(&config_path)
        .with_context(|| format!("failed to load {:?}", config_path))?;

    info!("Loading TLS certificate from {}", config.tls_cert);
    let tls_acceptor = TlsAcceptor::from(load_tls_config(&config.tls_cert, &config.tls_key)?);

    let pre_auth_cache: PreAuthCache  = Arc::new(RwLock::new(HashMap::new()));
    let global_registry: GlobalRegistry = Arc::new(RwLock::new(HashMap::new()));

    let mgmt_state = MgmtState {
        pre_auth_cache: Arc::clone(&pre_auth_cache),
        registry:       Arc::clone(&global_registry),
    };

    // Management HTTP server (pre-auth + connection API).
    tokio::spawn(start_mgmt_server(config.mgmt_bind_address.clone(), mgmt_state));

    // Housekeeping background tasks.
    tokio::spawn(cleanup_pre_auth_cache(Arc::clone(&pre_auth_cache)));
    tokio::spawn(update_connection_rates(Arc::clone(&global_registry)));

    info!("Starting game-tunnel server {} on {}", config.server_id, config.bind_address);
    let listener = TcpListener::bind(&config.bind_address).await
        .with_context(|| format!("failed to bind {}", config.bind_address))?;

    let public_bind = config.public_bind_address.clone()
        .unwrap_or_else(|| "0.0.0.0".to_string());

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
        let acceptor   = tls_acceptor.clone();
        let config     = config.clone();
        let public_bind = public_bind.clone();
        let cache      = Arc::clone(&pre_auth_cache);
        let registry   = Arc::clone(&global_registry);

        tokio::spawn(async move {
            match acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => {
                    info!("Client {} TLS handshake complete", addr);
                    if let Err(e) = handle_client(tls_stream, addr, &config, &public_bind, cache, registry).await {
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
                            warn!("Client {} auth rejected: {}", addr, msg);
                        } else {
                            error!("Client {} error: {:?}", addr, e);
                        }
                    }
                }
                Err(e) => {
                    let msg = e.to_string();
                    let scanner_noise = msg.contains("InvalidContentType")
                        || msg.contains("close_notify")
                        || msg.contains("UnknownIssuer")
                        || msg.contains("Tls12NotOffered")
                        || msg.contains("PeerIncompatible")
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
    registry: GlobalRegistry,
) -> Result<()> {
    let (mut read_half, mut write_half) = tokio::io::split(stream);

    let frame = match tokio::time::timeout(
        tokio::time::Duration::from_secs(10),
        protocol::read_frame(&mut read_half),
    ).await {
        Ok(Ok(f)) => f,
        Ok(Err(e)) => {
            // Inform the client before closing so it knows why.
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
            if let Some(ref uuid) = client_uuid {
                let mut cache = pre_auth_cache.write().await;
                match cache.get(uuid).cloned() {
                    Some(ts) if ts.elapsed().as_secs() < PRE_AUTH_TTL_SECS => {
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
        tunnels: HashMap::new(),
        streams: HashMap::new(),
        udp_peers: HashMap::new(),
        stream_tunnel: HashMap::new(),
        public_bind_address: public_bind.to_string(),
    }));

    let (write_tx, mut write_rx) = mpsc::channel::<Frame>(8192);
    let writer_task = tokio::spawn(async move {
        while let Some(frame) = write_rx.recv().await {
            let r = match &frame {
                Frame::Control(msg)              => protocol::write_control(&mut write_half, msg).await,
                Frame::Data { stream_id, payload } => protocol::write_data(&mut write_half, *stream_id, payload).await,
                Frame::StreamClose { stream_id } => protocol::write_stream_close(&mut write_half, *stream_id).await,
            };
            if r.is_err() { break; }
        }
    });

    let state_clone    = Arc::clone(&state);
    let write_tx_clone = write_tx.clone();
    let registry_clone = Arc::clone(&registry);
    let idle_timeout   = tokio::time::Duration::from_secs(CLIENT_IDLE_TIMEOUT_SECS);

    let result: Result<()> = async {
        loop {
            let frame = match tokio::time::timeout(idle_timeout, protocol::read_frame(&mut read_half)).await {
                Ok(Ok(f))  => f,
                Ok(Err(e)) => return Err(e.into()),
                Err(_)     => { warn!("Client {} idle timeout", addr); anyhow::bail!("idle timeout"); }
            };

            match frame {
                Frame::Control(msg) => {
                    handle_control_message(msg, addr, &state_clone, &write_tx_clone, &registry_clone).await?;
                }

                Frame::Data { stream_id, payload } => {
                    // Try TCP path first.
                    let tcp_tx = { state_clone.read().await.streams.get(&stream_id).map(|s| s.tx.clone()) };
                    if let Some(tx) = tcp_tx {
                        if tx.send(payload).await.is_err() {
                            let _ = write_tx_clone.send(Frame::StreamClose { stream_id }).await;
                            let mut st = state_clone.write().await;
                            st.streams.remove(&stream_id);
                            st.stream_tunnel.remove(&stream_id);
                        }
                    } else {
                        // UDP path: forward to the peer and track outbound bytes.
                        let peer = {
                            state_clone.read().await.udp_peers.get(&stream_id)
                                .map(|p| (p.addr, Arc::clone(&p.socket), Arc::clone(&p.bytes_out)))
                        };
                        if let Some((peer_addr, socket, bytes_out)) = peer {
                            let n = payload.len() as u64;
                            let _ = socket.send_to(&payload, peer_addr).await;
                            bytes_out.fetch_add(n, Ordering::Relaxed);
                        }
                    }
                }

                Frame::StreamClose { stream_id } => {
                    // Release state lock before acquiring registry lock to
                    // prevent lock-order inversion with handle_delete_connection.
                    {
                        let mut st = state_clone.write().await;
                        st.streams.remove(&stream_id);
                        st.udp_peers.remove(&stream_id);
                        st.stream_tunnel.remove(&stream_id);
                    }
                    registry_clone.write().await.remove(&stream_id);
                }
            }
        }
    }.await;

    // Tear-down: shut down all tunnel listeners and clear stream maps.
    // Collect stream IDs first, then clean maps, then update registry —
    // never hold both the state lock and the registry lock simultaneously.
    let stream_ids: Vec<u64> = {
        let mut st = state.write().await;
        let ids: Vec<u64> = st.streams.keys().chain(st.udp_peers.keys()).copied().collect();
        for (_, t) in st.tunnels.drain() { let _ = t.shutdown_tx.send(true); }
        st.streams.clear();
        st.udp_peers.clear();
        st.stream_tunnel.clear();
        ids
    };
    {
        let mut reg = registry.write().await;
        for sid in stream_ids { reg.remove(&sid); }
    }

    writer_task.abort();
    result
}

async fn handle_control_message(
    msg: Message,
    client_addr: SocketAddr,
    state: &Arc<RwLock<ServerState>>,
    write_tx: &mpsc::Sender<Frame>,
    registry: &GlobalRegistry,
) -> Result<()> {
    match msg {
        Message::OpenTunnel { tunnel_id, remote_port, protocol, db_id } => {
            if !is_valid_game_port(remote_port) {
                warn!("Invalid port {} from {}", remote_port, client_addr);
                let _ = write_tx.send(Frame::Control(Message::CloseTunnel { tunnel_id })).await;
                return Ok(());
            }
            {
                let st = state.read().await;
                if st.tunnels.contains_key(&tunnel_id) {
                    warn!("Duplicate tunnel_id {} rejected", tunnel_id);
                    return Ok(());
                }
            }

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

                                // Per-stream byte counters shared with the registry.
                                let bytes_in  = Arc::new(AtomicU64::new(0));
                                let bytes_out = Arc::new(AtomicU64::new(0));

                                // Register the connection in the global registry.
                                {
                                    registry_tcp.write().await.insert(stream_id, ConnRecord {
                                        db_id,
                                        tunnel_id,
                                        peer_ip:          peer.ip().to_string(),
                                        bytes_in:         Arc::clone(&bytes_in),
                                        bytes_out:        Arc::clone(&bytes_out),
                                        bytes_in_per_sec:  0,
                                        bytes_out_per_sec: 0,
                                        bytes_in_prev:     0,
                                        bytes_out_prev:    0,
                                        connected_at:     Instant::now(),
                                        write_tx:         write_tx_tcp.clone(),
                                        server_state:     Arc::clone(&state_tcp),
                                    });
                                }

                                let (player_tx, player_rx) = mpsc::channel::<Vec<u8>>(2048);
                                {
                                    let mut st = state_tcp.write().await;
                                    st.streams.insert(stream_id, PlayerStream { tx: player_tx });
                                    st.stream_tunnel.insert(stream_id, tunnel_id);
                                }
                                let _ = write_tx_tcp.send(Frame::Control(Message::NewConnection {
                                    tunnel_id, stream_id, is_udp: false, peer_addr: Some(peer),
                                })).await;

                                let wtx = write_tx_tcp.clone();
                                let st  = Arc::clone(&state_tcp);
                                let reg = Arc::clone(&registry_tcp);
                                tokio::spawn(async move {
                                    handle_player_stream(
                                        player_stream, stream_id, player_rx, wtx, st,
                                        bytes_in, bytes_out, reg,
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
                    Ok(s) => Arc::new(s),
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
                    let mut peer_streams: HashMap<std::net::SocketAddr, u64>  = HashMap::new();
                    let mut last_seen:    HashMap<std::net::SocketAddr, Instant> = HashMap::new();
                    // Local map from stream_id → bytes_in counter for UDP sessions.
                    let mut udp_bytes_in: HashMap<u64, Arc<AtomicU64>>        = HashMap::new();
                    let mut cleanup_interval = tokio::time::interval(tokio::time::Duration::from_secs(10));

                    loop { tokio::select! {
                        res = socket.recv_from(&mut buf) => { match res {
                            Ok((len, peer_addr)) => {
                                last_seen.insert(peer_addr, Instant::now());

                                let stream_id = if let Some(&sid) = peer_streams.get(&peer_addr) {
                                    // Update inbound byte count for the existing session.
                                    if let Some(c) = udp_bytes_in.get(&sid) {
                                        c.fetch_add(len as u64, Ordering::Relaxed);
                                    }
                                    sid
                                } else {
                                    // NAT-rebinding detection: same IP, different port.
                                    let rebind = peer_streams.iter()
                                        .find(|(a, _)| a.ip() == peer_addr.ip())
                                        .map(|(a, &sid)| (*a, sid));

                                    if let Some((old_addr, existing_sid)) = rebind {
                                        info!("UDP NAT rebind detected: {} → {} (stream {})",
                                              old_addr, peer_addr, existing_sid);
                                        peer_streams.remove(&old_addr);
                                        last_seen.remove(&old_addr);
                                        peer_streams.insert(peer_addr, existing_sid);
                                        last_seen.insert(peer_addr, Instant::now());

                                        // Preserve the existing bytes_out counter on rebind.
                                        let existing_bytes_out = {
                                            state_udp.read().await.udp_peers.get(&existing_sid)
                                                .map(|p| Arc::clone(&p.bytes_out))
                                                .unwrap_or_else(|| Arc::new(AtomicU64::new(0)))
                                        };
                                        {
                                            let mut st = state_udp.write().await;
                                            st.udp_peers.insert(existing_sid, UdpPeer {
                                                addr:      peer_addr,
                                                socket:    Arc::clone(&socket),
                                                bytes_out: existing_bytes_out,
                                            });
                                        }
                                        // Update the peer IP in the registry.
                                        {
                                            let mut reg = registry_udp.write().await;
                                            if let Some(record) = reg.get_mut(&existing_sid) {
                                                record.peer_ip = peer_addr.ip().to_string();
                                            }
                                        }

                                        if let Some(c) = udp_bytes_in.get(&existing_sid) {
                                            c.fetch_add(len as u64, Ordering::Relaxed);
                                        }
                                        existing_sid
                                    } else {
                                        // Genuinely new player connection.
                                        let sid = STREAM_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
                                        peer_streams.insert(peer_addr, sid);

                                        let bytes_in  = Arc::new(AtomicU64::new(len as u64));
                                        let bytes_out = Arc::new(AtomicU64::new(0));
                                        udp_bytes_in.insert(sid, Arc::clone(&bytes_in));

                                        // Register in global registry.
                                        let db_id_udp = {
                                            state_udp.read().await.tunnels.get(&tunnel_id)
                                                .map(|t| t.db_id).unwrap_or(0)
                                        };
                                        registry_udp.write().await.insert(sid, ConnRecord {
                                            db_id:            db_id_udp,
                                            tunnel_id,
                                            peer_ip:          peer_addr.ip().to_string(),
                                            bytes_in:         Arc::clone(&bytes_in),
                                            bytes_out:        Arc::clone(&bytes_out),
                                            bytes_in_per_sec:  0,
                                            bytes_out_per_sec: 0,
                                            bytes_in_prev:     0,
                                            bytes_out_prev:    0,
                                            connected_at:     Instant::now(),
                                            write_tx:         write_tx_udp.clone(),
                                            server_state:     Arc::clone(&state_udp),
                                        });

                                        {
                                            let mut st = state_udp.write().await;
                                            st.udp_peers.insert(sid, UdpPeer {
                                                addr:      peer_addr,
                                                socket:    Arc::clone(&socket),
                                                bytes_out,
                                            });
                                            st.stream_tunnel.insert(sid, tunnel_id);
                                        }
                                        let _ = write_tx_udp.send(Frame::Control(Message::NewConnection {
                                            tunnel_id, stream_id: sid, is_udp: true, peer_addr: Some(peer_addr),
                                        })).await;
                                        sid
                                    }
                                };
                                let _ = write_tx_udp.send(Frame::Data {
                                    stream_id,
                                    payload: buf[..len].to_vec(),
                                }).await;
                            }
                            Err(e) => { error!("UDP recv error: {:?}", e); break; }
                        }}

                        _ = cleanup_interval.tick() => {
                            let now = Instant::now();
                            let stale: Vec<std::net::SocketAddr> = last_seen.iter()
                                .filter(|(_, t)| now.duration_since(**t).as_secs() > UDP_SESSION_TIMEOUT_SECS)
                                .map(|(addr, _)| *addr)
                                .collect();
                            for addr in stale {
                                last_seen.remove(&addr);
                                if let Some(sid) = peer_streams.remove(&addr) {
                                    udp_bytes_in.remove(&sid);
                                    {
                                        let mut st = state_udp.write().await;
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
                            // Clean up any remaining UDP sessions from the registry.
                            let sids: Vec<u64> = udp_bytes_in.keys().copied().collect();
                            if !sids.is_empty() {
                                let mut reg = registry_udp.write().await;
                                for sid in sids { reg.remove(&sid); }
                            }
                            info!("Shutting down port {} (UDP)", remote_port);
                            break;
                        }
                    }}
                });
            }

            {
                state.write().await.tunnels.insert(tunnel_id, ActiveTunnel {
                    tunnel_id, remote_port, protocol, shutdown_tx,
                    db_id,  // store the database id so new connections can read it
                });
            }
            write_tx.send(Frame::Control(Message::TunnelOpened { tunnel_id }))
                .await.context("send TunnelOpened")?;
        }

        Message::CloseTunnel { tunnel_id } => {
            info!("Closing tunnel {}", tunnel_id);

            // Collect sids, shut down listeners, clear local maps — hold state
            // lock only for this block, then update the registry separately.
            let sids: Vec<u64> = {
                let mut st = state.write().await;
                if let Some(t) = st.tunnels.remove(&tunnel_id) { let _ = t.shutdown_tx.send(true); }
                let sids: Vec<u64> = st.stream_tunnel.iter()
                    .filter(|(_, &tid)| tid == tunnel_id)
                    .map(|(&sid, _)| sid)
                    .collect();
                for sid in &sids {
                    st.streams.remove(sid);
                    st.udp_peers.remove(sid);
                    st.stream_tunnel.remove(sid);
                    let _ = write_tx.send(Frame::StreamClose { stream_id: *sid }).await;
                }
                if !sids.is_empty() {
                    info!("Closed {} connections for tunnel {}", sids.len(), tunnel_id);
                }
                sids
            };
            // Remove from global registry (state lock already released above).
            {
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
    player: TcpStream,
    stream_id: u64,
    mut from_tunnel: mpsc::Receiver<Vec<u8>>,
    to_tunnel: mpsc::Sender<Frame>,
    state: Arc<RwLock<ServerState>>,
    bytes_in:  Arc<AtomicU64>,
    bytes_out: Arc<AtomicU64>,
    registry: GlobalRegistry,
) {
    let (mut pr, mut pw) = player.into_split();
    let to_tunnel_r = to_tunnel.clone();

    let read_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match pr.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    bytes_in.fetch_add(n as u64, Ordering::Relaxed);
                    if to_tunnel_r.send(Frame::Data { stream_id, payload: buf[..n].to_vec() }).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let write_task = tokio::spawn(async move {
        while let Some(data) = from_tunnel.recv().await {
            bytes_out.fetch_add(data.len() as u64, Ordering::Relaxed);
            if pw.write_all(&data).await.is_err() { break; }
        }
    });

    tokio::select! { _ = read_task => {} _ = write_task => {} }

    let _ = to_tunnel.send(Frame::StreamClose { stream_id }).await;

    // Clean up local state, then registry — separate lock acquisitions.
    {
        let mut st = state.write().await;
        st.streams.remove(&stream_id);
        st.stream_tunnel.remove(&stream_id);
    }
    registry.write().await.remove(&stream_id);
}
