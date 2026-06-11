use anyhow::{Context, Result};

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use axum::routing::get;
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

#[derive(Clone, Default)]
struct ManagerState {
    tunnels: Vec<TunnelInfo>,
    clients: Vec<ClientInfo>,
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
        .route("/api/stats", get(get_stats))
        .route("/api/tunnels", get(get_tunnels))
        .route("/api/clients", get(get_clients))
        // Client asks manager: "which server should I connect to?"
        .route("/api/client/:uuid/server", get(get_server_for_client))
        .layer(CorsLayer::permissive())
        .with_state(state);

    info!("Tunnel Manager API on {}", config.bind_address);
    let listener = tokio::net::TcpListener::bind(&config.bind_address).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn run_management_cycle(state: &Arc<AppState>) -> Result<()> {
    assign_tunnels(state).await?;
    update_pending_dns(state).await?;
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

    let mut ms = state.manager_state.write().await;
    ms.tunnels = tunnel_map.into_values().collect();
    ms.tunnels.sort_by(|a, b| a.name.cmp(&b.name));
    ms.clients = client_infos;
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
        total_bytes_out_per_sec:  ms.clients.iter().map(|c| c.total_bytes_out).sum(),
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