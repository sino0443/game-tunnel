
use anyhow::{Context, Result};
use game_tunnel_shared::config::{ClientConfig, ServerEntry};
use game_tunnel_shared::protocol::{self, Frame, Message, TunnelProtocol};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};
use tokio_rustls::rustls;
use tokio_rustls::TlsConnector;
use tracing::{error, info, warn};

mod database;
mod stats;

use stats::Stats;

static TUNNEL_ID_COUNTER: AtomicU32 = AtomicU32::new(1);

const HEARTBEAT_INTERVAL_SECS: u64 = 5;
const SERVER_IDLE_TIMEOUT_SECS: u64 = 120;

#[derive(Debug, Clone)]
pub struct DbTunnel {
    pub id: u32, pub uuid: String, pub name: String, pub online: bool,
    pub server_ip: String, pub server_port: u16, pub remote_port: u16,
    pub protocol: String, pub server_id: Option<u32>,
    pub subdomain: String, pub domain: String,
}

struct ActiveTunnel {
    tunnel_id: u32, server_id: u32,
    #[allow(dead_code)] db_id: u32,
    #[allow(dead_code)] remote_port: u16,
    #[allow(dead_code)] local_address: String,
}

struct LocalStream { tx: mpsc::Sender<Vec<u8>> }

struct ClientState {
    tunnels: HashMap<u32, ActiveTunnel>,
    tunnel_local_addrs: HashMap<u32, String>,
    tunnel_protocols: HashMap<u32, String>,
    streams: HashMap<u64, LocalStream>,
    stream_tunnel: HashMap<u64, u32>,
    tunnel_server: HashMap<u32, u32>,
}

struct ServerConnection {
    #[allow(dead_code)] id: u32,
    #[allow(dead_code)] name: String,
    write_tx: mpsc::Sender<Frame>,
}

fn load_tls_config(ca_path: &str) -> Result<Arc<rustls::ClientConfig>> {
    let ca_file = File::open(ca_path).with_context(|| format!("failed to open CA: {}", ca_path))?;
    let mut root_store = rustls::RootCertStore::empty();
    let certs: Vec<rustls::pki_types::CertificateDer> = rustls_pemfile::certs(&mut BufReader::new(ca_file))
        .collect::<std::result::Result<Vec<_>, _>>().context("parse CA certs")?;
    for cert in certs { root_store.add(cert).context("add CA cert")?; }
    Ok(Arc::new(rustls::ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth()))
}

const SOCKET_BUF_SIZE: usize = 256 * 1024;

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

/// Connects to a game-tunnel server, authenticates, and returns the TLS stream halves.
/// Sends the client's UUID in the Auth message so the server can verify it against
/// the pre-auth cache populated by the manager.
// Diese Hilfsstruktur wird benötigt, um die TLS-Zertifikatsprüfung zu umgehen.
// Sie akzeptiert jedes Zertifikat, damit die Verbindung lokal/selbstsigniert klappt.
#[derive(Debug)]
#[allow(dead_code)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

async fn connect_to_server(
    entry: &ServerEntry,
    client_uuid: Option<String>,
) -> Result<(
    impl AsyncReadExt + Unpin + Send,
    impl AsyncWriteExt + Unpin + Send,
)> {
    let tls_config = load_tls_config(&entry.tls_ca)?;
    let connector = TlsConnector::from(tls_config);
    let tcp = TcpStream::connect(&entry.address).await
        .with_context(|| format!("failed to connect to {}", entry.address))?;
    tcp.set_nodelay(true)?;
    apply_socket_options(&tcp);
    let server_name = rustls::pki_types::ServerName::try_from("game-tunnel")
        .context("invalid server name")?;
    let tls = connector.connect(server_name, tcp).await.context("TLS handshake failed")?;
    let (mut read_half, mut write_half) = tokio::io::split(tls);
    protocol::write_control(
        &mut write_half,
        &Message::Auth { secret: entry.secret.clone(), client_uuid },
    ).await?;
    let frame = tokio::time::timeout(
        tokio::time::Duration::from_secs(10),
        protocol::read_frame(&mut read_half),
    )
    .await.context("auth timeout")??;
    match frame {
        Frame::Control(Message::AuthOk) => {}
        Frame::Control(Message::AuthFailed { reason }) => anyhow::bail!("Auth failed: {}", reason),
        other => anyhow::bail!("Unexpected: {:?}", other),
    }
    Ok((read_half, write_half))
}








// ── Manager server-assignment ─────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct ServerAssignmentsResponse {
    server_ids: Vec<u32>,
}

/// Queries the manager for **all** servers this client should connect to.
///
/// The manager will:
/// 1. Resolve the client's tunnel assignments from the database
/// 2. Send pre-auth notifications to each server concurrently
/// 3. Return the list of server_ids
///
/// Each returned server_id has had pre-auth sent so the client can connect
/// within the 10-second TTL window.
async fn query_servers_from_manager(
    http_client: &reqwest::Client,
    manager_url: &str,
    client_uuid: &str,
) -> Result<Vec<u32>> {
    let url = format!(
        "{}/api/client/{}/servers",
        manager_url.trim_end_matches('/'),
        client_uuid
    );
    let resp = http_client
        .get(&url)
        .send()
        .await
        .context("manager request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("manager returned HTTP {}: {}", status, body.trim());
    }

    let r = resp
        .json::<ServerAssignmentsResponse>()
        .await
        .context("failed to parse manager response")?;
    Ok(r.server_ids)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
    ).init();
    let config_path = std::env::args().nth(1).map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("client.toml"));
    let config = ClientConfig::load(&config_path)
        .with_context(|| format!("failed to load {:?}", config_path))?;
    if config.servers.is_empty() { anyhow::bail!("No servers configured in [[servers]]"); }
    info!(
        "Game Tunnel Client '{}' starting (UUID: {}, manager: {})",
        config.client_name, config.client_uuid, config.manager_url
    );
    run_client(config).await
}

/// Manages the full lifecycle of a connection to **one** specific server.
///
/// The task:
/// 1. Calls the manager to get fresh pre-auth for this server (and all others)
/// 2. Verifies that this server is still in the returned list (stops if removed)
/// 3. Connects, runs the frame loop, cleans up on disconnect
/// 4. Backs off and retries from step 1
///
/// Runs forever until the server is removed from the manager's assignment list
/// or the task is cancelled by the connection manager.
async fn run_server_task(
    entry: ServerEntry,
    client_uuid: String,
    manager_url: String,
    http_client: reqwest::Client,
    state: Arc<RwLock<ClientState>>,
    servers: Arc<RwLock<HashMap<u32, ServerConnection>>>,
    stats: Stats,
) {
    let server_id = entry.id;
    let mut backoff = 2u64;

    loop {
        // Query the manager to get fresh pre-auth for this connection attempt.
        match query_servers_from_manager(&http_client, &manager_url, &client_uuid).await {
            Ok(ids) => {
                if !ids.contains(&server_id) {
                    // No tunnels on this server — stop this connection task.
                    // The connection manager will respawn it once the manager
                    // includes this server in the list again (new tunnel assigned).
                    info!(
                        "Server {} ('{}') no longer in manager list — stopping task",
                        server_id, entry.name
                    );
                    return;
                }
                backoff = 2;
            }
            Err(e) => {
                error!(
                    "Manager query failed for server '{}': {:?} (retry in {}s)",
                    entry.name, e, backoff
                );
                tokio::time::sleep(tokio::time::Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(60);
                continue;
            }
        }

        info!(
            "Connecting to server '{}' at {} (server_id: {}, UUID: {})",
            entry.name, entry.address, server_id, client_uuid
        );

        match connect_to_server(&entry, Some(client_uuid.clone())).await {
            Ok((read_half, write_half)) => {
                info!("Server '{}' connected and authenticated", entry.name);
                stats.set_server_tls_ok(entry.id).await;
                stats.set_server_auth_ok(entry.id).await;
                backoff = 2;

                let (write_tx, mut write_rx) = mpsc::channel::<Frame>(8192);
                let writer_task = tokio::spawn(async move {
                    let mut wh = write_half;
                    while let Some(frame) = write_rx.recv().await {
                        let r = match &frame {
                            Frame::Control(msg) => protocol::write_control(&mut wh, msg).await,
                            Frame::Data { stream_id, payload } => protocol::write_data(&mut wh, *stream_id, payload).await,
                            Frame::StreamClose { stream_id } => protocol::write_stream_close(&mut wh, *stream_id).await,
                        };
                        if r.is_err() { break; }
                    }
                });

                servers.write().await.insert(entry.id, ServerConnection {
                    id: entry.id, name: entry.name.clone(), write_tx,
                });

                let mut rh = read_half;
                let idle_timeout = tokio::time::Duration::from_secs(SERVER_IDLE_TIMEOUT_SECS);
                loop {
                    let frame = match tokio::time::timeout(idle_timeout, protocol::read_frame(&mut rh)).await {
                        Ok(Ok(f)) => f,
                        Ok(Err(e)) => {
                            let msg = e.to_string();
                            if !msg.contains("close_notify") && !msg.contains("peer closed") {
                                error!("Server '{}' error: {:?}", entry.name, e);
                            }
                            break;
                        }
                        Err(_) => {
                            warn!("Server '{}' idle timeout ({}s), reconnecting", entry.name, SERVER_IDLE_TIMEOUT_SECS);
                            break;
                        }
                    };
                    if let Err(e) = handle_server_frame(frame, entry.id, &state, &servers, &stats).await {
                        error!("Frame error on server '{}': {:?}", entry.name, e);
                        break;
                    }
                }

                stats.set_server_disconnected(entry.id).await;
                servers.write().await.remove(&entry.id);
                writer_task.abort();

                // Clean up tunnels that were on this server.
                let to_remove: Vec<(u32, u32)> = {
                    let st = state.read().await;
                    st.tunnels.iter()
                        .filter(|(_, t)| t.server_id == entry.id)
                        .map(|(db_id, t)| (*db_id, t.tunnel_id))
                        .collect()
                };
                if !to_remove.is_empty() {
                    let mut st = state.write().await;
                    for (db_id, tunnel_id) in &to_remove {
                        if let Some(t) = st.tunnels.remove(db_id) {
                            st.tunnel_local_addrs.remove(&t.tunnel_id);
                            st.tunnel_protocols.remove(&t.tunnel_id);
                            st.tunnel_server.remove(&t.tunnel_id);
                        }
                        stats.remove_tunnel(*tunnel_id).await;
                    }
                    info!("Cleaned up {} tunnels from '{}'", to_remove.len(), entry.name);
                }
                info!("Server '{}' disconnected, reconnecting in {}s", entry.name, backoff);
            }
            Err(e) => {
                stats.set_server_disconnected(entry.id).await;
                error!("Connect failed to '{}': {:?} (retry in {}s)", entry.name, e, backoff);
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(30);
    }
}

async fn run_client(config: ClientConfig) -> Result<()> {
    let db_pool = database::connect(&config.database).await?;
    info!("Connected to MySQL as client '{}'", config.client_id);
    database::ensure_columns(&db_pool).await?;

    let stats = Stats::new();

    for entry in &config.servers {
        stats.add_server(entry.id, entry.name.clone(), entry.address.clone()).await;
    }

    let stats_for_http = stats.clone();
    let client_id_http = config.client_id.clone();
    tokio::spawn(async move {
        let app = axum::Router::new()
            .route("/api/stats", axum::routing::get(move || {
                let s = stats_for_http.clone();
                async move { axum::Json(s.to_response().await) }
            }));
        info!("Stats HTTP server on 0.0.0.0:9090 (client: {})", client_id_http);
        let listener = tokio::net::TcpListener::bind("0.0.0.0:9090").await.unwrap();
        axum::serve(listener, app).await.unwrap();
    });

    let stats_for_rates = stats.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            stats_for_rates.tick_rates().await;
        }
    });

    let state = Arc::new(RwLock::new(ClientState {
        tunnels: HashMap::new(), tunnel_local_addrs: HashMap::new(),
        tunnel_protocols: HashMap::new(), streams: HashMap::new(),
        stream_tunnel: HashMap::new(), tunnel_server: HashMap::new(),
    }));

    let servers: Arc<RwLock<HashMap<u32, ServerConnection>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // HTTP client for manager queries (15s per-request timeout).
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    // Connection manager: polls the manager every 10 s for the full server list
    // and spawns one independent run_server_task per assigned server.
    // Tasks for newly assigned servers are started immediately; tasks for servers
    // that are no longer assigned are aborted.
    {
        let config_clone  = config.clone();
        let stats_clone   = stats.clone();
        let servers_clone = Arc::clone(&servers);
        let state_clone   = Arc::clone(&state);
        let http_clone    = http_client.clone();

        tokio::spawn(async move {
            // server_id → JoinHandle of the per-server task
            let mut active: HashMap<u32, tokio::task::JoinHandle<()>> = HashMap::new();
            let mut backoff = 5u64;

            loop {
                match query_servers_from_manager(
                    &http_clone,
                    &config_clone.manager_url,
                    &config_clone.client_uuid,
                ).await {
                    Ok(server_ids) => {
                        backoff = 5;

                        // Spawn tasks for newly assigned or finished servers.
                        for &sid in &server_ids {
                            let needs_spawn = match active.get(&sid) {
                                None    => true,
                                Some(h) => h.is_finished(),
                            };
                            if !needs_spawn { continue; }

                            let Some(entry) = config_clone.servers.iter().find(|s| s.id == sid).cloned() else {
                                warn!("Manager assigned server {} but it is not in [[servers]] config", sid);
                                continue;
                            };

                            info!("Spawning connection task for server {} (\'{}\')", sid, entry.name);
                            let handle = tokio::spawn(run_server_task(
                                entry,
                                config_clone.client_uuid.clone(),
                                config_clone.manager_url.clone(),
                                http_clone.clone(),
                                Arc::clone(&state_clone),
                                Arc::clone(&servers_clone),
                                stats_clone.clone(),
                            ));
                            active.insert(sid, handle);
                        }

                        // Abort tasks for servers that are no longer in the manager's
                        // server list (i.e. no tunnels assigned to them).
                        active.retain(|&sid, handle| {
                            if server_ids.contains(&sid) { return true; }
                            info!("Server {} has no tunnels — stopping connection task", sid);
                            handle.abort();
                            false
                        });
                    }
                    Err(e) => {
                        error!("Manager poll failed: {:?} (retry in {}s)", e, backoff);
                        tokio::time::sleep(tokio::time::Duration::from_secs(backoff)).await;
                        backoff = (backoff * 2).min(60);
                        continue;
                    }
                }

                // Re-check every 10 s to pick up new assignments.
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            }
        });
    }

    // Heartbeat task: sends Ping to all connected servers.
    let servers_hb = Arc::clone(&servers);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(
            tokio::time::Duration::from_secs(HEARTBEAT_INTERVAL_SECS)
        );
        loop {
            interval.tick().await;
            let svrs = servers_hb.read().await;
            for srv in svrs.values() {
                let _ = srv.write_tx.send(Frame::Control(Message::Ping)).await;
            }
        }
    });

    // DB polling loop: keeps tunnel state in sync and writes status updates.
    let db_poll_state = Arc::clone(&state);
    let db_poll_servers = Arc::clone(&servers);
    let db_poll_pool = db_pool.clone();
    let server_entries = config.servers.clone();
    let poll_interval = config.database.poll_interval_secs;
    let stats_for_db = stats.clone();
    let client_id = config.client_id.clone();

    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(poll_interval));
    loop {
        interval.tick().await;
        if let Err(e) = write_status_to_db(
            &db_poll_pool, &db_poll_state, &stats_for_db, &client_id,
        ).await {
            error!("Status write error: {:?}", e);
        }
        if let Err(e) = sync_tunnels_from_db(
            &db_poll_pool, &db_poll_state, &db_poll_servers,
            &server_entries, &stats_for_db, &client_id,
        ).await {
            error!("DB sync error: {:?}", e);
        }
    }
}

async fn write_status_to_db(
    pool: &sqlx::MySqlPool,
    state: &Arc<RwLock<ClientState>>,
    stats: &Stats,
    client_id: &str,
) -> Result<()> {
    let tunnels_snap = stats.tunnels.read().await;
    let st = state.read().await;
    for (tunnel_id, ts) in tunnels_snap.iter() {
        let db_id = st.tunnels.iter()
            .find(|(_, t)| t.tunnel_id == *tunnel_id)
            .map(|(k, _)| *k);
        let Some(db_id) = db_id else { continue; };
        let active = ts.active_connections.load(Ordering::Relaxed);
        let status = if active > 0 { "running" } else { "idle" };
        let _ = database::write_tunnel_status(pool, db_id, status, client_id).await;
    }
    Ok(())
}

async fn sync_tunnels_from_db(
    pool: &sqlx::MySqlPool,
    state: &Arc<RwLock<ClientState>>,
    servers: &Arc<RwLock<HashMap<u32, ServerConnection>>>,
    server_entries: &[ServerEntry],
    stats: &Stats,
    client_id: &str,
) -> Result<()> {
    let db_tunnels = database::get_client_tunnels(pool, client_id).await?;

    let (to_add, to_remove, to_update) = {
        let st = state.read().await;
        let current_ids: HashMap<u32, &ActiveTunnel> =
            st.tunnels.iter().map(|(k, v)| (*k, v)).collect();
        let mut add = Vec::new();
        let mut remove = Vec::new();
        let mut update: Vec<(DbTunnel, u32, u32)> = Vec::new();
        for dbt in &db_tunnels {
            if let Some(current) = current_ids.get(&dbt.id) {
                if let Some(desired_sid) = dbt.server_id {
                    if server_entries.iter().any(|s| s.id == desired_sid)
                        && desired_sid != current.server_id
                    {
                        update.push((dbt.clone(), current.server_id, desired_sid));
                    }
                }
            } else {
                add.push(dbt.clone());
            }
        }
        let db_ids: HashMap<u32, &DbTunnel> = db_tunnels.iter().map(|t| (t.id, t)).collect();
        for db_id in current_ids.keys() {
            if !db_ids.contains_key(db_id) { remove.push(*db_id); }
        }
        (add, remove, update)
    };

    for db_id in &to_remove {
        let (tunnel_id, server_id) = {
            let st = state.read().await;
            st.tunnels.get(db_id)
                .map(|t| (t.tunnel_id, t.server_id))
                .unwrap_or((0, 0))
        };
        if tunnel_id > 0 {
            {
                let svrs = servers.read().await;
                if let Some(srv) = svrs.get(&server_id) {
                    let _ = srv.write_tx.send(Frame::Control(Message::CloseTunnel { tunnel_id })).await;
                }
            }
            let mut st = state.write().await;
            if let Some(t) = st.tunnels.remove(db_id) {
                st.tunnel_local_addrs.remove(&t.tunnel_id);
                st.tunnel_server.remove(&t.tunnel_id);
            }
            stats.remove_tunnel(tunnel_id).await;
            let _ = sqlx::query("UPDATE tunnels SET tunnel_status = 'stopped' WHERE id = ?")
                .bind(db_id).execute(pool).await;
        }
    }

    for (dbt, old_sid, new_sid) in &to_update {
        let tunnel_id = {
            state.read().await.tunnels.get(&dbt.id).map(|t| t.tunnel_id).unwrap_or(0)
        };
        if tunnel_id == 0 { continue; }
        {
            let svrs = servers.read().await;
            if let Some(srv) = svrs.get(old_sid) {
                let _ = srv.write_tx.send(Frame::Control(Message::CloseTunnel { tunnel_id })).await;
            }
        }
        {
            let mut st = state.write().await;
            if let Some(t) = st.tunnels.remove(&dbt.id) {
                st.tunnel_local_addrs.remove(&t.tunnel_id);
                st.tunnel_server.remove(&t.tunnel_id);
                st.tunnel_protocols.remove(&t.tunnel_id);
            }
        }
        stats.remove_tunnel(tunnel_id).await;
        let new_tid = TUNNEL_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        let local_addr = format!("{}:{}", dbt.server_ip, dbt.server_port);
        {
            let svrs = servers.read().await;
            if let Some(srv) = svrs.get(new_sid) {
                let _ = srv.write_tx.send(Frame::Control(Message::OpenTunnel {
                    tunnel_id: new_tid,
                    remote_port: dbt.remote_port,
                    protocol: match dbt.protocol.as_str() {
                        "udp" => TunnelProtocol::Udp,
                        "both" => TunnelProtocol::Both,
                        _ => TunnelProtocol::Tcp,
                    },
                    db_id: dbt.id,
                })).await;
            } else {
                continue;
            }
        }
        {
            let mut st = state.write().await;
            st.tunnels.insert(dbt.id, ActiveTunnel {
                tunnel_id: new_tid, server_id: *new_sid, db_id: dbt.id,
                remote_port: dbt.remote_port, local_address: local_addr.clone(),
            });
            st.tunnel_local_addrs.insert(new_tid, local_addr);
            st.tunnel_protocols.insert(new_tid, dbt.protocol.clone());
            st.tunnel_server.insert(new_tid, *new_sid);
        }
        stats.add_tunnel(new_tid, dbt.id, dbt.name.clone(), dbt.subdomain.clone()).await;
    }

    let tunnel_counts: HashMap<u32, usize> = {
        let st = state.read().await;
        let mut c = HashMap::new();
        for t in st.tunnels.values() { *c.entry(t.server_id).or_insert(0) += 1; }
        c
    };

    for dbt in &to_add {
        let server_id = if let Some(sid) = dbt.server_id {
            if server_entries.iter().any(|s| s.id == sid) { sid }
            else {
                server_entries.iter()
                    .min_by_key(|s| tunnel_counts.get(&s.id).unwrap_or(&0))
                    .map(|s| s.id).unwrap_or(1)
            }
        } else {
            server_entries.iter()
                .min_by_key(|s| tunnel_counts.get(&s.id).unwrap_or(&0))
                .map(|s| s.id).unwrap_or(1)
        };
        { let svrs = servers.read().await; if !svrs.contains_key(&server_id) { continue; } }
        let tunnel_id = TUNNEL_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        let local_address = format!("{}:{}", dbt.server_ip, dbt.server_port);
        info!(
            "Opening tunnel '{}' on server {}: port {} -> {}",
            dbt.subdomain, server_id, dbt.remote_port, local_address
        );
        {
            let svrs = servers.read().await;
            if let Some(srv) = svrs.get(&server_id) {
                if srv.write_tx.send(Frame::Control(Message::OpenTunnel {
                    tunnel_id,
                    remote_port: dbt.remote_port,
                    protocol: match dbt.protocol.as_str() {
                        "udp" => TunnelProtocol::Udp,
                        "both" => TunnelProtocol::Both,
                        _ => TunnelProtocol::Tcp,
                    },
                    db_id: dbt.id,
                })).await.is_err() { continue; }
            } else { continue; }
        }
        {
            let mut st = state.write().await;
            st.tunnels.insert(dbt.id, ActiveTunnel {
                tunnel_id, server_id, db_id: dbt.id,
                remote_port: dbt.remote_port, local_address: local_address.clone(),
            });
            st.tunnel_local_addrs.insert(tunnel_id, local_address);
            st.tunnel_protocols.insert(tunnel_id, dbt.protocol.clone());
            st.tunnel_server.insert(tunnel_id, server_id);
        }
        stats.add_tunnel(tunnel_id, dbt.id, dbt.name.clone(), dbt.subdomain.clone()).await;
    }
    Ok(())
}

async fn handle_server_frame(
    frame: Frame,
    server_id: u32,
    state: &Arc<RwLock<ClientState>>,
    servers: &Arc<RwLock<HashMap<u32, ServerConnection>>>,
    stats: &Stats,
) -> Result<()> {
    match frame {
        Frame::Control(msg) => {
            handle_control_message(msg, server_id, state, servers, stats).await?;
        }
        Frame::Data { stream_id, payload } => {
            let len = payload.len() as u64;
            stats.total_bytes_in.fetch_add(len, Ordering::Relaxed);
            {
                let st = state.read().await;
                if let Some(&tid) = st.stream_tunnel.get(&stream_id) {
                    let t = stats.tunnels.read().await;
                    if let Some(ts) = t.get(&tid) { ts.bytes_in.fetch_add(len, Ordering::Relaxed); }
                }
            }
            let tx = { state.read().await.streams.get(&stream_id).map(|s| s.tx.clone()) };
            if let Some(tx) = tx {
                if tx.send(payload).await.is_err() {
                    let svrs = servers.read().await;
                    if let Some(srv) = svrs.get(&server_id) {
                        let _ = srv.write_tx.send(Frame::StreamClose { stream_id }).await;
                    }
                    let mut st = state.write().await;
                    st.streams.remove(&stream_id);
                    st.stream_tunnel.remove(&stream_id);
                }
            }
        }
        Frame::StreamClose { stream_id } => {
            let mut st = state.write().await;
            st.streams.remove(&stream_id);
            if let Some(tid) = st.stream_tunnel.remove(&stream_id) {
                let t = stats.tunnels.read().await;
                if let Some(ts) = t.get(&tid) {
                    ts.active_connections.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }
    }
    Ok(())
}

async fn handle_control_message(
    msg: Message,
    server_id: u32,
    state: &Arc<RwLock<ClientState>>,
    servers: &Arc<RwLock<HashMap<u32, ServerConnection>>>,
    stats: &Stats,
) -> Result<()> {
    match msg {
        Message::TunnelOpened { tunnel_id } => {
            let st = state.read().await;
            if let Some(addr) = st.tunnel_local_addrs.get(&tunnel_id) {
                info!("Tunnel {} opened on server {} -> {}", tunnel_id, server_id, addr);
            }
        }
        Message::NewConnection { tunnel_id, stream_id, is_udp } => {
            let local_addr = {
                state.read().await.tunnel_local_addrs.get(&tunnel_id)
                    .cloned()
                    .unwrap_or_else(|| "127.0.0.1:25565".into())
            };
            stats.total_connections.fetch_add(1, Ordering::Relaxed);
            {
                let t = stats.tunnels.read().await;
                if let Some(ts) = t.get(&tunnel_id) {
                    ts.active_connections.fetch_add(1, Ordering::Relaxed);
                    ts.total_connections.fetch_add(1, Ordering::Relaxed);
                }
            }
            { state.write().await.stream_tunnel.insert(stream_id, tunnel_id); }
            let state_clone = Arc::clone(state);
            let servers_clone = Arc::clone(servers);
            let stats_clone = stats.clone();

            if is_udp {
                let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);
                { state_clone.write().await.streams.insert(stream_id, LocalStream { tx }); }
                let local_addr_clone = local_addr.clone();
                tokio::spawn(async move {
                    info!("UDP stream {}: new connection, target={}", stream_id, local_addr_clone);
                    match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                        Ok(socket) => {
                            info!("UDP stream {}: socket bound, connecting to {}", stream_id, local_addr_clone);
                            if socket.connect(&local_addr_clone).await.is_err() {
                                warn!("UDP stream {}: connect to {} failed", stream_id, local_addr_clone);
                                { let t = stats_clone.tunnels.read().await; if let Some(ts) = t.get(&tunnel_id) { ts.active_connections.fetch_sub(1, Ordering::Relaxed); } }
                                let mut st = state_clone.write().await;
                                st.streams.remove(&stream_id);
                                st.stream_tunnel.remove(&stream_id);
                                let svrs = servers_clone.read().await;
                                if let Some(srv) = svrs.get(&server_id) { let _ = srv.write_tx.send(Frame::StreamClose { stream_id }).await; }
                                return;
                            }
                            info!("UDP stream {}: ready, forwarding to {}", stream_id, local_addr_clone);
                            handle_local_udp_stream(socket, stream_id, tunnel_id, server_id, rx, state_clone, servers_clone, stats_clone).await;
                        }
                        Err(e) => {
                            error!("UDP stream {}: bind failed: {:?}", stream_id, e);
                            { let t = stats_clone.tunnels.read().await; if let Some(ts) = t.get(&tunnel_id) { ts.active_connections.fetch_sub(1, Ordering::Relaxed); } }
                            let mut st = state_clone.write().await;
                            st.streams.remove(&stream_id);
                            st.stream_tunnel.remove(&stream_id);
                            let svrs = servers_clone.read().await;
                            if let Some(srv) = svrs.get(&server_id) { let _ = srv.write_tx.send(Frame::StreamClose { stream_id }).await; }
                        }
                    }
                });
            } else {
                let (tx, rx) = mpsc::channel::<Vec<u8>>(2048);
                { state_clone.write().await.streams.insert(stream_id, LocalStream { tx }); }
                tokio::spawn(async move {
                    match TcpStream::connect(&local_addr).await {
                        Ok(s) => {
                            s.set_nodelay(true).ok();
                            apply_socket_options(&s);
                            handle_local_stream(s, stream_id, tunnel_id, server_id, rx, state_clone, servers_clone, stats_clone).await;
                        }
                        Err(e) => {
                            error!("Connect error to {}: {:?}", local_addr, e);
                            { let t = stats_clone.tunnels.read().await; if let Some(ts) = t.get(&tunnel_id) { ts.active_connections.fetch_sub(1, Ordering::Relaxed); } }
                            let mut st = state_clone.write().await;
                            st.streams.remove(&stream_id);
                            st.stream_tunnel.remove(&stream_id);
                            let svrs = servers_clone.read().await;
                            if let Some(srv) = svrs.get(&server_id) { let _ = srv.write_tx.send(Frame::StreamClose { stream_id }).await; }
                        }
                    }
                });
            }
        }
        Message::CloseTunnel { tunnel_id } => {
            let mut st = state.write().await;
            let db_id = st.tunnels.iter()
                .find(|(_, t)| t.tunnel_id == tunnel_id)
                .map(|(k, _)| *k);
            if let Some(db_id) = db_id { st.tunnels.remove(&db_id); }
            st.tunnel_local_addrs.remove(&tunnel_id);
            st.tunnel_server.remove(&tunnel_id);
        }
        Message::Pong => {}
        other => { warn!("Unexpected: {:?}", other); }
    }
    Ok(())
}

async fn handle_local_stream(
    local: TcpStream, stream_id: u64, tunnel_id: u32, server_id: u32,
    mut from_tunnel: mpsc::Receiver<Vec<u8>>,
    state: Arc<RwLock<ClientState>>,
    servers: Arc<RwLock<HashMap<u32, ServerConnection>>>,
    stats: Stats,
) {
    let (mut lr, mut lw) = local.into_split();
    let servers_r = Arc::clone(&servers);
    let stats_r = stats.clone();
    let read_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match lr.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    stats_r.total_bytes_out.fetch_add(n as u64, Ordering::Relaxed);
                    { let t = stats_r.tunnels.read().await; if let Some(ts) = t.get(&tunnel_id) { ts.bytes_out.fetch_add(n as u64, Ordering::Relaxed); } }
                    let svrs = servers_r.read().await;
                    if let Some(srv) = svrs.get(&server_id) {
                        if srv.write_tx.send(Frame::Data { stream_id, payload: buf[..n].to_vec() }).await.is_err() { break; }
                    } else { break; }
                }
                Err(_) => break,
            }
        }
    });
    let write_task = tokio::spawn(async move {
        while let Some(data) = from_tunnel.recv().await {
            if lw.write_all(&data).await.is_err() { break; }
        }
    });
    tokio::select! { _ = read_task => {} _ = write_task => {} }
    let svrs = servers.read().await;
    if let Some(srv) = svrs.get(&server_id) {
        let _ = srv.write_tx.send(Frame::StreamClose { stream_id }).await;
    }
    drop(svrs);
    let mut st = state.write().await;
    st.streams.remove(&stream_id);
    if st.stream_tunnel.remove(&stream_id).is_some() {
        let t = stats.tunnels.read().await;
        if let Some(ts) = t.get(&tunnel_id) { ts.active_connections.fetch_sub(1, Ordering::Relaxed); }
    }
}

async fn handle_local_udp_stream(
    socket: tokio::net::UdpSocket, stream_id: u64, tunnel_id: u32, server_id: u32,
    mut from_tunnel: mpsc::Receiver<Vec<u8>>,
    state: Arc<RwLock<ClientState>>,
    servers: Arc<RwLock<HashMap<u32, ServerConnection>>>,
    stats: Stats,
) {
    let socket = Arc::new(socket);
    let sr = Arc::clone(&socket);
    let servers_r = Arc::clone(&servers);
    let stats_r = stats.clone();
    let read_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match sr.recv(&mut buf).await {
                Ok(n) => {
                    info!("UDP stream {}: {} bytes received from local server", stream_id, n);
                    stats_r.total_bytes_out.fetch_add(n as u64, Ordering::Relaxed);
                    { let t = stats_r.tunnels.read().await; if let Some(ts) = t.get(&tunnel_id) { ts.bytes_out.fetch_add(n as u64, Ordering::Relaxed); } }
                    let svrs = servers_r.read().await;
                    if let Some(srv) = svrs.get(&server_id) {
                        if srv.write_tx.send(Frame::Data { stream_id, payload: buf[..n].to_vec() }).await.is_err() { break; }
                    } else { break; }
                }
                Err(e) => {
                    warn!("UDP stream {}: recv from local server failed: {:?}", stream_id, e);
                    break;
                }
            }
        }
    });
    let sw = Arc::clone(&socket);
    // 120s inactivity timeout — no data from the game server to the player.
    // Raised from 35s to 120s so that games with long map-loading phases
    // (Satisfactory, ARK) don't lose their session while the player is still
    // loading.  Bedrock and other games that don't send explicit disconnects
    // will have stale sessions cleaned up after 2 minutes instead of 35s.
    let write_task = tokio::spawn(async move {
        loop {
            match tokio::time::timeout(
                tokio::time::Duration::from_secs(120),
                from_tunnel.recv(),
            ).await {
                Ok(Some(data)) => {
                    info!("UDP stream {}: {} bytes -> local server", stream_id, data.len());
                    if sw.send(&data).await.is_err() {
                        warn!("UDP stream {}: send to local server failed", stream_id);
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    info!("UDP stream {}: 120s inactivity timeout, closing", stream_id);
                    break;
                }
            }
        }
    });
    tokio::select! { _ = read_task => {} _ = write_task => {} }
    info!("UDP stream {}: closing", stream_id);
    let svrs = servers.read().await;
    if let Some(srv) = svrs.get(&server_id) {
        let _ = srv.write_tx.send(Frame::StreamClose { stream_id }).await;
    }
    drop(svrs);
    let mut st = state.write().await;
    st.streams.remove(&stream_id);
    if st.stream_tunnel.remove(&stream_id).is_some() {
        let t = stats.tunnels.read().await;
        if let Some(ts) = t.get(&tunnel_id) { ts.active_connections.fetch_sub(1, Ordering::Relaxed); }
    }
}
