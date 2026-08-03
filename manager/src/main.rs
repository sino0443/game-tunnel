use anyhow::{Context, Result};

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use axum::routing::{delete, get, post};
use game_tunnel_shared::config::{CloudflareConfig, ManagerConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tracing::{error, info, warn};

mod cloudflare;
mod database;

/// Deserialized from the server's `GET /api/connections` mgmt endpoint.
#[derive(Deserialize, Clone)]
struct ServerConnData {
    stream_id: u64,
    db_id: u32,
    #[allow(dead_code)] tunnel_id: u32,
    peer_ip: String,
    bytes_in: u64,
    bytes_out: u64,
    bytes_in_per_sec: u64,
    bytes_out_per_sec: u64,
    connected_secs: u64,
}

/// Per-connection info exposed by the manager's tunnel-connections endpoint.
#[derive(Serialize, Clone)]
struct TunnelConnInfo {
    stream_id: u64,
    peer_ip: String,
    bytes_in: u64,
    bytes_out: u64,
    bytes_in_per_sec: u64,
    bytes_out_per_sec: u64,
    connected_secs: u64,
}

#[derive(Clone, Default)]
struct ManagerState {
    tunnels: Vec<TunnelInfo>,
    clients: Vec<ClientInfo>,
    /// Active player connections grouped by tunnel db_id.
    connections_by_db_id: HashMap<u32, Vec<TunnelConnInfo>>,
    /// Maps stream_id → server_id so the disconnect handler knows which
    /// server to forward the DELETE to.
    stream_server_map: HashMap<u64, u32>,
}

#[derive(Clone, Serialize)]
struct TunnelInfo {
    id: u32, name: String, subdomain: String, domain: String,
    online: bool, client_id: Option<String>, server_id: Option<u32>,
    tunnel_status: String, last_seen: Option<String>,
    remote_port: u16, protocol: String,
    active_connections: u64,
    bytes_in: u64, bytes_out: u64,
    bytes_in_per_sec: u64, bytes_out_per_sec: u64,
}

#[derive(Clone, Serialize)]
struct ClientInfo {
    id: String, name: String, stats_url: String,
    reachable: bool,
    tunnel_count: usize,
    active_connections: u64,
    total_bytes_in: u64, total_bytes_out: u64,
    bytes_in_per_sec: u64, bytes_out_per_sec: u64,
    uptime_secs: u64,
    servers: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ClientStatsResponse {
    uptime_secs: u64,
    total_bytes_in: u64,
    total_bytes_out: u64,
    total_connections: u64,
    #[serde(default)] servers: Vec<serde_json::Value>,
    #[serde(default)] tunnels: Vec<ClientTunnelStats>,
}

#[derive(Deserialize)]
struct ClientTunnelStats {
    db_id: u32,
    #[serde(default)] bytes_in: u64,
    #[serde(default)] bytes_out: u64,
    #[serde(default)] active_connections: u64,
    #[serde(default)] bytes_in_per_sec: u64,
    #[serde(default)] bytes_out_per_sec: u64,
}

struct AppState {
    db: sqlx::MySqlPool,
    cf: CloudflareConfig,
    manager_state: Arc<RwLock<ManagerState>>,
    config: ManagerConfig,
    http_client: reqwest::Client,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
    ).init();

    let config_path = std::env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("manager.toml"));
    let config = ManagerConfig::load(&config_path).with_context(|| format!("failed to load {:?}", config_path))?;

    let pool = database::connect(&config.database).await?;
    info!("Connected to MySQL");
    database::ensure_columns(&pool).await?;
    database::ensure_client_server_table(&pool).await?;

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let manager_state = Arc::new(RwLock::new(ManagerState::default()));
    let state = Arc::new(AppState {
        db: pool, cf: config.cloudflare.clone(),
        manager_state: Arc::clone(&manager_state),
        config: config.clone(), http_client,
    });

    // Stats jede Sekunde refreshen.
    let state_stats = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            if let Err(e) = refresh_stats(&state_stats).await {
                error!("Stats refresh error: {:?}", e);
            }
        }
    });

    // Management-Zyklus (Tunnel zuweisen + DNS) im konfigurierten Interval.
    let state_loop = Arc::clone(&state);
    let interval_secs = config.assign_interval_secs;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
        loop {
            interval.tick().await;
            if let Err(e) = run_management_cycle(&state_loop).await {
                error!("Management cycle error: {:?}", e);
            }
        }
    });

    let app = Router::new()
        .route("/api/stats",   get(get_stats))
        .route("/api/tunnels", get(get_tunnels))
        .route("/api/clients", get(get_clients))
        .route("/api/tunnels/{db_id}/connections",
               get(get_tunnel_connections))
        .route("/api/tunnels/{db_id}/connections/{stream_id}",
               delete(disconnect_tunnel_connection))
        .route("/api/client/{uuid}/server",  get(get_server_for_client))
        .route("/api/client/{uuid}/servers", get(get_servers_for_client))
        .route("/api/client/{client_id}/tunnels", get(list_client_tunnels))
        .route("/api/client/{client_id}/tunnel-status", post(update_client_tunnel_status))
        .layer(CorsLayer::permissive())
        .with_state(state);

    info!("Tunnel Manager API on {}", config.bind_address);
    let listener = tokio::net::TcpListener::bind(&config.bind_address).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn run_management_cycle(state: &Arc<AppState>) -> Result<()> {
    assign_tunnels(state).await?;
    sync_client_server_mappings(state).await?;
    update_pending_dns(state).await?;
    Ok(())
}

/// Keeps `client_server_mappings` up to date automatically.
///
/// For every configured client that has a `uuid` set in `manager.toml`,
/// this function looks at the tunnels assigned to that client, finds the
/// VPS server that hosts the most of them, and upserts the mapping so the
/// client will be directed to that server on its next connection attempt.
///
/// Fallback chain when no tunnels have an explicit `server_id`:
///   1. Skip — no information available yet, leave the existing mapping intact.
///
/// The `allowed` flag is never overwritten, so manual bans in the table
/// survive automatic syncs.
async fn sync_client_server_mappings(state: &Arc<AppState>) -> Result<()> {
    for client in &state.config.clients {
        // Only process clients whose UUID is known in the manager config.
        let Some(ref uuid) = client.uuid else { continue; };

        // Derive the server this client should connect to from its tunnel assignments.
        let server_id = match database::get_best_server_for_client(&state.db, &client.id).await? {
            Some(sid) => sid,
            None => {
                // The client has tunnels but none with a server_id set yet,
                // or it has no tunnels at all.  Fall back to the first
                // configured server so the client can at least connect.
                match state.config.servers.first() {
                    Some(s) => s.id,
                    None => {
                        warn!(
                            "No servers configured — skipping mapping for client '{}'",
                            client.id
                        );
                        continue;
                    }
                }
            }
        };

        match database::upsert_client_server_mapping(&state.db, uuid, &client.id, server_id).await {
            Ok(true) => {
                info!(
                    "Client mapping synced: '{}' ({}) → server {}",
                    client.name, client.id, server_id
                );
            }
            Ok(false) => {} // already up-to-date, nothing to log
            Err(e) => {
                warn!(
                    "Failed to sync mapping for client '{}': {:?}",
                    client.id, e
                );
            }
        }
    }
    Ok(())
}

async fn assign_tunnels(state: &Arc<AppState>) -> Result<()> {
    if state.config.clients.is_empty() { return Ok(()); }

    let unassigned = database::get_unassigned_tunnels(&state.db).await?;
    if unassigned.is_empty() { return Ok(()); }

    let mut counts = database::get_tunnel_counts_per_client(&state.db).await?;
    for c in &state.config.clients { counts.entry(c.id.clone()).or_insert(0); }

    for t in unassigned {
        let best = state.config.clients.iter()
            .min_by_key(|c| counts.get(&c.id).unwrap_or(&0))
            .map(|c| c.id.clone());
        if let Some(client_id) = best {
            database::assign_tunnel(&state.db, t.id, &client_id).await?;
            *counts.entry(client_id.clone()).or_insert(0) += 1;
            info!("Assigned tunnel '{}' ({}) to client '{}'", t.name, t.subdomain, client_id);
        }
    }
    Ok(())
}

async fn update_pending_dns(state: &Arc<AppState>) -> Result<()> {
    let pending = database::get_tunnels_needing_dns(&state.db).await?;
    if pending.is_empty() { return Ok(()); }

    info!("Setting DNS for {} tunnel(s) with dns_set=FALSE", pending.len());

    for t in pending {
        let vps_ip = if let Some(sid) = t.server_id {
            state.config.servers.iter().find(|s| s.id == sid).map(|s| s.public_ip.clone())
        } else {
            state.config.servers.first().map(|s| s.public_ip.clone())
        };

        let Some(ip) = vps_ip else {
            warn!("No VPS IP found for tunnel {} (server_id={:?}), skipping", t.subdomain, t.server_id);
            continue;
        };

        match cloudflare::ensure_dns_records(&state.cf, &t.subdomain, &t.domain, &ip, t.remote_port, t.create_srv).await {
            Ok(_) => {
                if let Err(e) = database::mark_dns_set(&state.db, t.id).await {
                    warn!("Failed to mark dns_set for {}: {:?}", t.subdomain, e);
                } else {
                    info!("DNS configured for {}.{} -> {} ✓", t.subdomain, t.domain, ip);
                }
            }
            Err(e) => {
                warn!("DNS failed for {}.{}: {:?} — will retry", t.subdomain, t.domain, e);
            }
        }
    }
    Ok(())
}

/// Fetcht Stats von allen konfigurierten URLs eines Clients und aggregiert sie.
async fn refresh_stats(state: &Arc<AppState>) -> Result<()> {
    let db_rows = database::get_all_tunnels(&state.db).await?;

    let mut tunnel_map: HashMap<u32, TunnelInfo> = db_rows.into_iter().map(|r| {
        (r.id, TunnelInfo {
            id: r.id, name: r.name, subdomain: r.subdomain, domain: r.domain,
            online: r.online, client_id: r.client_id, server_id: r.server_id,
            tunnel_status: r.tunnel_status,
            last_seen: r.last_seen.map(|d| d.to_string()),
            remote_port: r.remote_port, protocol: r.protocol,
            active_connections: 0, bytes_in: 0, bytes_out: 0,
            bytes_in_per_sec: 0, bytes_out_per_sec: 0,
        })
    }).collect();

    let mut client_infos = Vec::new();

    for client_cfg in &state.config.clients {
        let urls = client_cfg.all_stats_urls();

        if urls.is_empty() {
            warn!("Client '{}' has no stats_urls configured", client_cfg.id);
            client_infos.push(unreachable_client(client_cfg));
            continue;
        }

        let mut total_bps_in    = 0u64;
        let mut total_bps_out   = 0u64;
        let mut total_conns     = 0u64;
        let mut total_bytes_in  = 0u64;
        let mut total_bytes_out = 0u64;
        let mut max_uptime      = 0u64;
        let mut all_servers: Vec<serde_json::Value> = Vec::new();
        let mut any_reachable   = false;

        // Jede URL dieses Clients abfragen und Ergebnisse zusammenführen.
        for url in &urls {
            let full_url = format!("{}/api/stats", url);
            match state.http_client.get(&full_url).send().await {
                Ok(resp) => match resp.json::<ClientStatsResponse>().await {
                    Ok(cs) => {
                        any_reachable = true;
                        for ts in &cs.tunnels {
                            if let Some(t) = tunnel_map.get_mut(&ts.db_id) {
                                t.active_connections = ts.active_connections;
                                t.bytes_in           = ts.bytes_in;
                                t.bytes_out          = ts.bytes_out;
                                t.bytes_in_per_sec   = ts.bytes_in_per_sec;
                                t.bytes_out_per_sec  = ts.bytes_out_per_sec;
                            }
                            total_bps_in  += ts.bytes_in_per_sec;
                            total_bps_out += ts.bytes_out_per_sec;
                            total_conns   += ts.active_connections;
                        }
                        total_bytes_in  += cs.total_bytes_in;
                        total_bytes_out += cs.total_bytes_out;
                        max_uptime       = max_uptime.max(cs.uptime_secs);
                        all_servers.extend(cs.servers);
                    }
                    Err(e) => { warn!("Parse error from '{}' (client '{}'): {:?}", url, client_cfg.id, e); }
                },
                Err(e) => { warn!("Cannot reach '{}' (client '{}'): {:?}", url, client_cfg.id, e); }
            }
        }

        let tc = tunnel_map.values()
            .filter(|t| t.client_id.as_deref() == Some(&client_cfg.id))
            .count();

        if any_reachable {
            client_infos.push(ClientInfo {
                id:               client_cfg.id.clone(),
                name:             client_cfg.name.clone(),
                stats_url:        urls.join(", "),
                reachable:        true,
                tunnel_count:     tc,
                active_connections: total_conns,
                total_bytes_in,
                total_bytes_out,
                bytes_in_per_sec:  total_bps_in,
                bytes_out_per_sec: total_bps_out,
                uptime_secs:      max_uptime,
                servers:          all_servers,
            });
        } else {
            client_infos.push(unreachable_client(client_cfg));
        }
    }

    // ── Poll active player connections from each server's mgmt API ──────────
    let mut connections_by_db_id: HashMap<u32, Vec<TunnelConnInfo>> = HashMap::new();
    let mut stream_server_map: HashMap<u64, u32> = HashMap::new();

    for server in &state.config.servers {
        let url = format!("{}/api/connections", server.mgmt_url.trim_end_matches('/'));
        match state.http_client.get(&url).send().await {
            Ok(resp) => match resp.json::<Vec<ServerConnData>>().await {
                Ok(conns) => {
                    for conn in conns {
                        stream_server_map.insert(conn.stream_id, server.id);
                        connections_by_db_id.entry(conn.db_id).or_default().push(TunnelConnInfo {
                            stream_id:         conn.stream_id,
                            peer_ip:           conn.peer_ip,
                            bytes_in:          conn.bytes_in,
                            bytes_out:         conn.bytes_out,
                            bytes_in_per_sec:  conn.bytes_in_per_sec,
                            bytes_out_per_sec: conn.bytes_out_per_sec,
                            connected_secs:    conn.connected_secs,
                        });
                    }
                }
                Err(e) => warn!("Failed to parse connections from server '{}': {:?}", server.name, e),
            },
            Err(e) => warn!("Cannot reach server '{}' for connections: {:?}", server.name, e),
        }
    }

    let mut ms = state.manager_state.write().await;
    ms.tunnels = tunnel_map.into_values().collect();
    ms.tunnels.sort_by(|a, b| a.name.cmp(&b.name));
    ms.clients = client_infos;
    ms.connections_by_db_id = connections_by_db_id;
    ms.stream_server_map    = stream_server_map;
    Ok(())
}

fn unreachable_client(cfg: &game_tunnel_shared::config::ManagedClient) -> ClientInfo {
    ClientInfo {
        id:               cfg.id.clone(),
        name:             cfg.name.clone(),
        stats_url:        cfg.all_stats_urls().join(", "),
        reachable:        false,
        tunnel_count:     0,
        active_connections: 0,
        total_bytes_in:   0,
        total_bytes_out:  0,
        bytes_in_per_sec: 0,
        bytes_out_per_sec: 0,
        uptime_secs:      0,
        servers:          vec![],
    }
}

#[derive(Serialize)]
struct StatsResponse {
    total_tunnels: usize, online_tunnels: usize,
    total_active_connections: u64,
    total_bytes_in: u64, total_bytes_out: u64,
    total_bytes_in_per_sec: u64, total_bytes_out_per_sec: u64,
    clients: Vec<ClientInfo>, tunnels: Vec<TunnelInfo>,
}

async fn get_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let ms = state.manager_state.read().await;
    Json(StatsResponse {
        total_tunnels:            ms.tunnels.len(),
        online_tunnels:           ms.tunnels.iter().filter(|t| t.online).count(),
        total_active_connections: ms.tunnels.iter().map(|t| t.active_connections).sum(),
        total_bytes_in:           ms.clients.iter().map(|c| c.total_bytes_in).sum(),
        total_bytes_out:          ms.clients.iter().map(|c| c.total_bytes_out).sum(),
        total_bytes_in_per_sec:   ms.clients.iter().map(|c| c.bytes_in_per_sec).sum(),
        total_bytes_out_per_sec:  ms.clients.iter().map(|c| c.bytes_out_per_sec).sum(),
        clients: ms.clients.clone(),
        tunnels: ms.tunnels.clone(),
    })
}

async fn get_tunnels(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.manager_state.read().await.tunnels.clone())
}

async fn get_clients(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.manager_state.read().await.clients.clone())
}

// ── Tunnel connection endpoints ──────────────────────────────────────────────

/// `GET /api/tunnels/{db_id}/connections`
async fn get_tunnel_connections(
    State(state): State<Arc<AppState>>,
    Path(db_id): Path<u32>,
) -> impl IntoResponse {
    let ms = state.manager_state.read().await;
    let conns = ms.connections_by_db_id.get(&db_id).cloned().unwrap_or_default();
    Json(conns)
}

/// `DELETE /api/tunnels/{db_id}/connections/{stream_id}`
///
/// Forwards a forced-disconnect request to the server that owns the stream.
async fn disconnect_tunnel_connection(
    State(state): State<Arc<AppState>>,
    Path((_db_id, stream_id)): Path<(u32, u64)>,
) -> impl IntoResponse {
    let server_id = {
        let ms = state.manager_state.read().await;
        ms.stream_server_map.get(&stream_id).copied()
    };
    let Some(server_id) = server_id else {
        return (StatusCode::NOT_FOUND, "connection not found").into_response();
    };
    let Some(server) = state.config.servers.iter().find(|s| s.id == server_id) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "server config not found").into_response();
    };
    let url = format!("{}/api/connections/{}", server.mgmt_url.trim_end_matches('/'), stream_id);
    match state.http_client.delete(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            Json(serde_json::json!({"message": "Disconnected"})).into_response()
        }
        Ok(resp) => (StatusCode::BAD_GATEWAY, format!("server returned {}", resp.status())).into_response(),
        Err(e)   => (StatusCode::BAD_GATEWAY, format!("cannot reach server: {}", e)).into_response(),
    }
}

// ── Client server-assignment endpoint ───────────────────────────────────────

#[derive(Serialize)]
struct ServerAssignmentResponse {
    server_id: u32,
}

/// `GET /api/client/:uuid/server`
///
/// Returns the server_id assigned to the given client UUID.
///
/// Before responding, the manager POSTs a pre-auth notification to the
/// server's management API with a 10-second timeout. If the server does
/// not acknowledge within 10 seconds, a 503 is returned to the client.
async fn get_server_for_client(
    Path(uuid): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // 1. Look up the client_server_mappings table.
    let mapping = database::get_server_for_client_uuid(&state.db, &uuid)
        .await
        .map_err(|e| {
            error!("DB error looking up client UUID {}: {:?}", uuid, e);
            (StatusCode::INTERNAL_SERVER_ERROR, "database error".to_string())
        })?;

    let mapping = match mapping {
        Some(m) if m.allowed => m,
        Some(_) => {
            warn!("Client UUID {} is not allowed", uuid);
            return Err((StatusCode::FORBIDDEN, "client not allowed".to_string()));
        }
        None => {
            warn!("No server mapping found for client UUID {}", uuid);
            return Err((StatusCode::NOT_FOUND, "no server mapping found".to_string()));
        }
    };

    // 2. Find the server's management URL in config.
    let server_cfg = state.config.servers.iter().find(|s| s.id == mapping.server_id);
    let mgmt_url = match server_cfg {
        Some(s) => s.mgmt_url.clone(),
        None => {
            error!(
                "Server id {} from mapping not found in manager config",
                mapping.server_id
            );
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "server config not found".to_string(),
            ));
        }
    };

    // 3. Notify the server about the incoming client UUID (10-second timeout).
    let pre_auth_url = format!("{}/api/manager/pre-auth", mgmt_url.trim_end_matches('/'));
    let body = serde_json::json!({ "client_uuid": uuid });

    let notify_result = tokio::time::timeout(
        tokio::time::Duration::from_secs(10),
        state.http_client.post(&pre_auth_url).json(&body).send(),
    )
    .await;

    match notify_result {
        Err(_) => {
            warn!(
                "Pre-auth notification to server {} timed out after 10s for UUID {}",
                mapping.server_id, uuid
            );
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "server did not respond to pre-auth in time".to_string(),
            ));
        }
        Ok(Err(e)) => {
            error!(
                "Failed to reach server {} mgmt API for pre-auth (UUID {}): {:?}",
                mapping.server_id, uuid, e
            );
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "could not reach server management API".to_string(),
            ));
        }
        Ok(Ok(resp)) => {
            if !resp.status().is_success() {
                warn!(
                    "Server {} rejected pre-auth for UUID {}: HTTP {}",
                    mapping.server_id,
                    uuid,
                    resp.status()
                );
                return Err((
                    StatusCode::BAD_GATEWAY,
                    "server rejected pre-auth".to_string(),
                ));
            }
        }
    }

    info!(
        "Pre-auth OK: client UUID {} assigned to server {} (client_id: {})",
        mapping.client_uuid, mapping.server_id, mapping.client_id
    );

    Ok(Json(ServerAssignmentResponse {
        server_id: mapping.server_id,
    }))
}

// ── Multi-server assignment endpoint ─────────────────────────────────────────

#[derive(Serialize)]
struct ServerAssignmentsResponse {
    server_ids: Vec<u32>,
}

/// `GET /api/client/:uuid/servers`
///
/// Returns **all** server_ids the client should connect to, based on which
/// VPS servers currently have tunnels assigned to it.  Sends pre-auth
/// notifications to all of those servers concurrently so the client can
/// establish connections to all of them in parallel.
///
/// Falls back to the single mapping in `client_server_mappings` when no
/// tunnel-based assignment exists yet.
async fn get_servers_for_client(
    Path(uuid): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // 1. Resolve client_id and check allowed flag.
    //    Try client_server_mappings first; fall back to manager config by UUID.
    let (client_id, fallback_server_id) = {
        let db_row = database::get_server_for_client_uuid(&state.db, &uuid)
            .await
            .map_err(|e| {
                error!("DB error looking up UUID {}: {:?}", uuid, e);
                (StatusCode::INTERNAL_SERVER_ERROR, "database error".to_string())
            })?;

        match db_row {
            Some(m) if !m.allowed => {
                warn!("Client UUID {} is not allowed", uuid);
                return Err((StatusCode::FORBIDDEN, "client not allowed".to_string()));
            }
            Some(m) => (m.client_id, Some(m.server_id)),
            None => {
                // Not in DB yet – look up by UUID in manager config (before first sync).
                match state.config.clients.iter().find(|c| c.uuid.as_deref() == Some(&uuid)) {
                    Some(c) => (c.id.clone(), None),
                    None => {
                        warn!("No mapping found for client UUID {}", uuid);
                        return Err((StatusCode::NOT_FOUND, "no server mapping found".to_string()));
                    }
                }
            }
        }
    };

    // 2. Determine which servers this client needs to connect to.
    let mut server_ids = database::get_servers_for_client(&state.db, &client_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Fallback: client has no tunnels with a server_id yet (bootstrap — first connection
    // before any tunnel has been created / assigned a VPS server).
    // We do NOT fall back when the client previously had tunnels that were deleted:
    // in that case we intentionally return [] so the client disconnects from servers
    // it no longer has any work to do on.
    if server_ids.is_empty() {
        // Count all tunnels for this client (includes stopped/offline ones).
        // Zero → genuine bootstrap; non-zero means server_id is NULL for all tunnels,
        // or they were recently deleted — either way, use the fallback to keep the
        // client reachable so new tunnels can be assigned.
        let tunnel_count: i64 = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM tunnels WHERE client_id = ?",
        )
        .bind(&client_id)
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

        if tunnel_count == 0 {
            // Bootstrap: no tunnels exist yet — fall back to configured server so the
            // client is ready to receive new tunnel assignments immediately.
            if let Some(sid) = fallback_server_id {
                server_ids.push(sid);
            } else if let Some(s) = state.config.servers.first() {
                server_ids.push(s.id);
            } else {
                return Err((StatusCode::SERVICE_UNAVAILABLE, "no servers configured".to_string()));
            }
        }
        // else: tunnels exist (or existed) but none have a known server_id right now.
        // Return empty list — the client will disconnect and reconnect once tunnel
        // assignments carry a server_id again.
    }

    // 3. Send pre-auth to all servers concurrently (best-effort: we always
    //    return the full list; the client handles individual auth failures).
    let tasks: Vec<_> = server_ids
        .iter()
        .filter_map(|&sid| {
            let cfg = state.config.servers.iter().find(|s| s.id == sid)?;
            let url = format!("{}/api/manager/pre-auth", cfg.mgmt_url.trim_end_matches('/'));
            let body = serde_json::json!({ "client_uuid": uuid });
            let http = state.http_client.clone();
            let uuid_c = uuid.clone();
            Some((sid, tokio::spawn(async move {
                tokio::time::timeout(
                    tokio::time::Duration::from_secs(10),
                    http.post(&url).json(&body).send(),
                )
                .await
                .map(|r| r.map(|resp| (resp.status().is_success(), uuid_c)))
            })))
        })
        .collect();

    for (sid, task) in tasks {
        match task.await {
            Ok(Ok(Ok((true, ref u)))) => {
                info!("Pre-auth OK: client UUID {} → server {}", u, sid);
            }
            Ok(Ok(Ok((false, _)))) => {
                warn!("Server {} rejected pre-auth for UUID {}", sid, uuid);
            }
            Ok(Ok(Err(e))) => {
                warn!("Could not reach server {} mgmt for UUID {}: {:?}", sid, uuid, e);
            }
            Ok(Err(_)) => {
                warn!("Pre-auth timed out for server {} (UUID {})", sid, uuid);
            }
            Err(e) => {
                warn!("Pre-auth task panicked for server {}: {:?}", sid, e);
            }
        }
    }

    info!(
        "Servers for client UUID {} ({}): {:?}",
        uuid, client_id, server_ids
    );

    Ok(Json(ServerAssignmentsResponse { server_ids }))
}

// ── Client tunnel list endpoint ───────────────────────────────────────────────

/// Wire format sent to the client for each tunnel.
/// Matches `DbTunnel` on the client side.
#[derive(Serialize)]
struct ClientTunnelEntry {
    id: u32,
    uuid: String,
    name: String,
    server_ip: String,
    server_port: u16,
    remote_port: u16,
    protocol: String,
    server_id: Option<u32>,
    subdomain: String,
    domain: String,
    /// When true the client must send a PROXY Protocol v1 header before game data
    /// so the backend (e.g. Velocity) sees the real player IP.
    proxy_protocol: bool,
}

/// `GET /api/client/{client_id}/tunnels`
///
/// Returns all online tunnels assigned to the given client_id, with every
/// field the client needs to open its tunnels (server_ip, server_port, …).
/// The client calls this endpoint instead of querying the database directly.
async fn list_client_tunnels(
    Path(client_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    match database::get_tunnels_for_client(&state.db, &client_id).await {
        Ok(rows) => {
            let entries: Vec<ClientTunnelEntry> = rows.into_iter().map(|t| ClientTunnelEntry {
                id:             t.id,
                uuid:           t.uuid,
                name:           t.name,
                server_ip:      t.server_ip,
                server_port:    t.server_port,
                remote_port:    t.remote_port,
                protocol:       t.protocol,
                server_id:      t.server_id,
                subdomain:      t.subdomain,
                domain:         t.domain,
                proxy_protocol: t.proxy_protocol,
            }).collect();
            Json(entries).into_response()
        }
        Err(e) => {
            error!("Failed to fetch tunnels for client '{}': {:?}", client_id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response()
        }
    }
}

// ── Client tunnel-status endpoint ────────────────────────────────────────────

/// One status entry sent by the client in a batch update.
#[derive(Deserialize)]
struct TunnelStatusUpdate {
    db_id: u32,
    status: String,
}

/// `POST /api/client/{client_id}/tunnel-status`
///
/// The client calls this endpoint (instead of writing to MySQL directly) to
/// report the current status ("running", "idle", "stopped") of its tunnels.
/// Accepts a JSON array so the client can batch-update all tunnels in one call.
async fn update_client_tunnel_status(
    Path(client_id): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(updates): Json<Vec<TunnelStatusUpdate>>,
) -> impl IntoResponse {
    for u in &updates {
        if let Err(e) = database::update_tunnel_status(&state.db, u.db_id, &u.status, &client_id).await {
            warn!(
                "Status update failed for tunnel {} (client '{}'): {:?}",
                u.db_id, client_id, e
            );
        }
    }
    StatusCode::NO_CONTENT
}
