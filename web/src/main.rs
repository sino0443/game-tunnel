use anyhow::{Context, Result};
use axum::extract::{Path, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::{delete, get, post, put};
use axum::Router;
use base64::{Engine, engine::general_purpose};
use game_tunnel_shared::config::CloudflareConfig;
use serde::{Deserialize, Serialize};
use sqlx::mysql::MySqlPoolOptions;
use sqlx::{MySqlPool, Row};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::{error, info};

mod cloudflare;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WebConfig {
    bind_address: String,
    database: DbConfig,
    cloudflare: CloudflareConfig,
    #[serde(default)]
    manager_url: Option<String>,
    /// Shared secret sent as `X-Api-Key` on every request to `manager_url`.
    /// Required whenever `manager_url` is set (must match the manager's
    /// `api_key`).
    #[serde(default)]
    manager_api_key: Option<String>,
    #[serde(default)]
    servers: Vec<WebServerEntry>,
    #[serde(default)]
    admin_credentials: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WebServerEntry { id: u32, name: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DbConfig { host: String, port: u16, user: String, password: String, database: String }

struct AppState {
    db: MySqlPool,
    cf: CloudflareConfig,
    manager_url: Option<String>,
    manager_api_key: Option<String>,
    servers: Vec<WebServerEntry>,
    admin_credentials: Option<String>,
    http_client: reqwest::Client,
}

/// Attaches the `X-Api-Key` header for manager requests, if configured.
fn with_manager_auth(
    state: &Arc<AppState>,
    b: reqwest::RequestBuilder,
) -> reqwest::RequestBuilder {
    match &state.manager_api_key {
        Some(k) => b.header("X-Api-Key", k),
        None => b,
    }
}

async fn basic_auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let Some(ref expected) = state.admin_credentials else {
        return next.run(req).await;
    };
    if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(encoded) = auth_str.strip_prefix("Basic ") {
                if let Ok(decoded) = general_purpose::STANDARD.decode(encoded) {
                    if let Ok(creds) = String::from_utf8(decoded) {
                        let eb = expected.as_bytes(); let pb = creds.as_bytes();
                        let valid = eb.len() == pb.len() && eb.iter().zip(pb.iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
                        if valid { return next.run(req).await; }
                    }
                }
            }
        }
    }
    (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, "Basic realm=\"Game Tunnel Manager\"")], "Unauthorized").into_response()
}

/// Ensures all columns the web server reads or writes exist in the `tunnels`
/// table.  The manager normally adds these via its own `ensure_columns`, but
/// the web server may start before (or without) the manager.  Running this at
/// startup is idempotent — duplicate-column errors are silently ignored.
async fn ensure_web_columns(pool: &MySqlPool) -> Result<()> {
    let columns: &[(&str, &str)] = &[
        ("create_srv",      "BOOLEAN NOT NULL DEFAULT TRUE"),
        ("client_id",       "VARCHAR(50) DEFAULT NULL"),
        ("tunnel_status",   "VARCHAR(20) NOT NULL DEFAULT 'stopped'"),
        ("last_seen",       "DATETIME DEFAULT NULL"),
        ("dns_set",         "BOOLEAN NOT NULL DEFAULT FALSE"),
        // Proxy Protocol v1 support (e.g. for Velocity): when TRUE the client
        // prepends a "PROXY TCP4 ..." header so the backend sees the real player IP.
        ("proxy_protocol",  "BOOLEAN NOT NULL DEFAULT FALSE"),
    ];
    for (col, def) in columns {
        let sql = format!("ALTER TABLE tunnels ADD COLUMN {} {}", col, def);
        if let Err(e) = sqlx::query(&sql).execute(pool).await {
            if !e.to_string().contains("Duplicate column") {
                tracing::warn!("Column check for '{}': {:?}", col, e);
            }
        }
    }
    info!("DB columns verified");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
    ).init();

    let config_path = std::env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("web.toml"));
    let content = std::fs::read_to_string(&config_path).with_context(|| format!("failed to read {:?}", config_path))?;
    let config: WebConfig = toml::from_str(&content)?;

    if config.admin_credentials.is_none() {
        anyhow::bail!(
            "No admin_credentials configured — refusing to start with an open admin panel. \
             Set `admin_credentials = \"user:pass\"` in web.toml, or explicitly bind to \
             127.0.0.1 and put a reverse proxy with auth in front if you really want no \
             built-in auth."
        );
    }
    if config.manager_url.is_none() { tracing::warn!("No manager_url configured."); }
    if config.manager_url.is_some() && config.manager_api_key.is_none() {
        anyhow::bail!("manager_url is set but manager_api_key is missing — the manager API requires it.");
    }

    let db_url = format!("mysql://{}:{}@{}:{}/{}", config.database.user, config.database.password, config.database.host, config.database.port, config.database.database);
    let pool = MySqlPoolOptions::new().max_connections(10).connect(&db_url).await.context("failed to connect to MySQL")?;
    info!("Connected to MySQL");
    ensure_web_columns(&pool).await?;

    let http_client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)).build()?;
    let domains: Vec<String> = config.cloudflare.zones.iter().map(|z| z.domain.clone()).collect();
    let state = Arc::new(AppState {
        db: pool, cf: config.cloudflare, manager_url: config.manager_url,
        manager_api_key: config.manager_api_key,
        servers: config.servers, admin_credentials: config.admin_credentials, http_client,
    });

    let domains_clone = domains.clone();
    let app = Router::new()
        .route("/", get(index_page))
        .route("/api/tunnels", get(list_tunnels))
        .route("/api/tunnels", post(create_tunnel))
        .route("/api/tunnels/{id}", get(get_tunnel))
        .route("/api/tunnels/{id}", put(update_tunnel))
        .route("/api/tunnels/{id}", delete(delete_tunnel))
        .route("/api/tunnels/{id}/start", post(start_tunnel))
        .route("/api/tunnels/{id}/stop", post(stop_tunnel))
        .route("/api/tunnels/{id}/connections", get(proxy_tunnel_connections))
        .route("/api/tunnels/{id}/connections/{stream_id}", delete(proxy_disconnect_connection))
        .route("/api/domains", get(move || async move { Json(domains_clone.clone()) }))
        .route("/api/stats", get(proxy_stats))
        .route("/api/clients", get(proxy_clients))
        .route("/api/servers", get(list_servers))
        .layer(middleware::from_fn_with_state(Arc::clone(&state), basic_auth_middleware))
        .layer(CorsLayer::permissive())
        .with_state(state);

    info!("Starting web server on {}", config.bind_address);
    let listener = tokio::net::TcpListener::bind(&config.bind_address).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Serialize)]
struct TunnelResponse {
    id: u32, uuid: String, name: String, status: String, online: bool,
    server_ip: String, server_port: u16, remote_ip: String,
    remote_port: u16, protocol: String, domain: String, subdomain: String,
    server_id: Option<u32>, client_id: Option<String>,
    tunnel_status: String, last_seen: Option<String>, created_at: String,
    create_srv: bool,
    /// Proxy Protocol v1 enabled — client prepends a PROXY header so the
    /// backend (e.g. Velocity) receives the real player IP.
    proxy_protocol: bool,
}

#[derive(Deserialize)]
struct CreateTunnelRequest {
    name: Option<String>, server_ip: String, server_port: u16,
    remote_port: u16, protocol: Option<String>, subdomain: String,
    domain: Option<String>, server_id: Option<u32>,
    client_id: Option<String>,
    #[serde(default = "default_true")]
    create_srv: bool,
    /// Enable Proxy Protocol v1 for this tunnel (Velocity / BungeeCord).
    #[serde(default)]
    proxy_protocol: bool,
}
fn default_true() -> bool { true }

#[derive(Deserialize)]
struct UpdateTunnelRequest {
    name: Option<String>, server_ip: Option<String>, server_port: Option<u16>,
    remote_port: Option<u16>, protocol: Option<String>, subdomain: Option<String>,
    domain: Option<String>, online: Option<bool>, server_id: Option<i32>,
    client_id: Option<String>,
    create_srv: Option<bool>,
    /// Enable / disable Proxy Protocol v1.
    proxy_protocol: Option<bool>,
}

fn row_to_tunnel(r: &sqlx::mysql::MySqlRow) -> TunnelResponse {
    TunnelResponse {
        id: r.try_get("id").unwrap_or(0), uuid: r.try_get("uuid").unwrap_or_default(),
        name: r.try_get("name").unwrap_or_default(), status: r.try_get("status").unwrap_or_default(),
        online: r.try_get("online").unwrap_or(false), server_ip: r.try_get("server_ip").unwrap_or_default(),
        server_port: r.try_get("server_port").unwrap_or(0), remote_ip: r.try_get("remote_ip").unwrap_or_default(),
        remote_port: r.try_get("remote_port").unwrap_or(0), protocol: r.try_get("protocol").unwrap_or_default(),
        domain: r.try_get("domain").unwrap_or_default(), subdomain: r.try_get("subdomain").unwrap_or_default(),
        server_id: r.try_get::<Option<u32>, _>("server_id").unwrap_or(None),
        client_id: r.try_get::<Option<String>, _>("client_id").unwrap_or(None),
        tunnel_status: r.try_get("tunnel_status").unwrap_or_else(|_| "stopped".into()),
        last_seen: r.try_get::<Option<chrono::NaiveDateTime>, _>("last_seen").ok().flatten().map(|d| d.to_string()),
        created_at: r.try_get::<chrono::NaiveDateTime, _>("created_at").map(|d| d.to_string()).unwrap_or_default(),
        create_srv: r.try_get("create_srv").unwrap_or(true),
        proxy_protocol: r.try_get("proxy_protocol").unwrap_or(false),
    }
}

async fn list_tunnels(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match sqlx::query("SELECT * FROM tunnels ORDER BY protocol ASC, name ASC, id DESC").fetch_all(&state.db).await {
        Ok(rows) => Json(rows.iter().map(row_to_tunnel).collect::<Vec<_>>()).into_response(),
        Err(e) => { error!("db error: {:?}", e); (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response() },
    }
}

async fn get_tunnel(State(state): State<Arc<AppState>>, Path(id): Path<u32>) -> impl IntoResponse {
    match sqlx::query("SELECT * FROM tunnels WHERE id = ?").bind(id).fetch_optional(&state.db).await {
        Ok(Some(r)) => Json(row_to_tunnel(&r)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "Not found").into_response(),
        Err(e) => { error!("db error: {:?}", e); (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response() },
    }
}

async fn create_tunnel(State(state): State<Arc<AppState>>, Json(req): Json<CreateTunnelRequest>) -> impl IntoResponse {
    let uuid = uuid::Uuid::new_v4().to_string();
    let protocol = req.protocol.unwrap_or_else(|| "tcp".into());
    let name = req.name.unwrap_or_default();
    let domain = req.domain.unwrap_or_else(|| "sinomcit.com".into());

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => { error!("db error: {:?}", e); return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response(); },
    };

    // Read all existing IDs into a HashSet, then find the lowest free one in Rust.
    // CAST(id AS UNSIGNED) forces MySQL to return BIGINT UNSIGNED regardless of
    // whether tunnels.id is INT, INT UNSIGNED, or BIGINT — sqlx maps that cleanly
    // to u64 without type-mismatch errors.
    let taken: HashSet<u32> = match sqlx::query_scalar::<_, u64>("SELECT CAST(id AS UNSIGNED) FROM tunnels")
        .fetch_all(&mut *tx).await
    {
        Ok(ids) => ids.into_iter().filter_map(|n| if n > 0 && n <= u32::MAX as u64 { Some(n as u32) } else { None }).collect(),
        Err(e) => { error!("db error: {:?}", e); return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response(); },
    };
    // (1u32..) is infinite so unwrap_or is unreachable, but keeps the type checker happy.
    let next_id = (1u32..).find(|n| !taken.contains(n)).unwrap_or(1);

    match sqlx::query(
        "INSERT INTO tunnels \
         (id, uuid, name, server_ip, server_port, remote_port, protocol, domain, subdomain, server_id, client_id, create_srv, proxy_protocol, online) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, TRUE)",
    )
    .bind(next_id)
    .bind(&uuid).bind(&name).bind(&req.server_ip).bind(req.server_port).bind(req.remote_port)
    .bind(&protocol).bind(&domain).bind(&req.subdomain).bind(req.server_id).bind(req.client_id)
    .bind(req.create_srv).bind(req.proxy_protocol)
    .execute(&mut *tx).await
    {
        Ok(_) => {
            if let Err(e) = tx.commit().await {
                error!("commit error: {:?}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response();
            }
            info!("Created tunnel '{}' (subdomain={}, id={})", name, req.subdomain, next_id);
            (StatusCode::CREATED, Json(serde_json::json!({"message": "Created", "uuid": uuid, "id": next_id}))).into_response()
        }
        Err(e) => {
            let _ = tx.rollback().await;
            error!("insert tunnel error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

async fn update_tunnel(State(state): State<Arc<AppState>>, Path(id): Path<u32>, Json(req): Json<UpdateTunnelRequest>) -> impl IntoResponse {
    let mut u = Vec::new();
    if req.name.is_some() { u.push("name = ?"); }
    if req.server_ip.is_some() { u.push("server_ip = ?"); }
    if req.server_port.is_some() { u.push("server_port = ?"); }
    if req.remote_port.is_some() { u.push("remote_port = ?"); }
    if req.protocol.is_some() { u.push("protocol = ?"); }
    if req.subdomain.is_some() { u.push("subdomain = ?"); }
    if req.domain.is_some() { u.push("domain = ?"); }
    if req.online.is_some() { u.push("online = ?"); }
    if req.server_id.is_some() { u.push("server_id = ?"); }
    if req.client_id.is_some() { u.push("client_id = ?"); }
    if req.create_srv.is_some() { u.push("create_srv = ?"); }
    if req.proxy_protocol.is_some() { u.push("proxy_protocol = ?"); }
    if u.is_empty() { return (StatusCode::BAD_REQUEST, "No fields").into_response(); }

    // Reset dns_set whenever a field that affects DNS is changed, so the
    // manager picks it up next cycle and re-sets the Cloudflare records.
    let dns_reset = req.server_id.is_some() || req.subdomain.is_some()
        || req.domain.is_some() || req.create_srv.is_some();
    if dns_reset { u.push("dns_set = FALSE"); }

    let sql = format!("UPDATE tunnels SET {} WHERE id = ?", u.join(", "));
    let mut q = sqlx::query(&sql);
    if let Some(v) = &req.name { q = q.bind(v); }
    if let Some(v) = &req.server_ip { q = q.bind(v); }
    if let Some(v) = req.server_port { q = q.bind(v); }
    if let Some(v) = req.remote_port { q = q.bind(v); }
    if let Some(v) = &req.protocol { q = q.bind(v); }
    if let Some(v) = &req.subdomain { q = q.bind(v); }
    if let Some(v) = &req.domain { q = q.bind(v); }
    if let Some(v) = req.online { q = q.bind(v); }
    if let Some(v) = req.server_id {
        if v < 0 { q = q.bind(Option::<u32>::None); } else { q = q.bind(Some(v as u32)); }
    }
    if let Some(v) = &req.client_id {
        if v == "-" { q = q.bind(Option::<String>::None); } else { q = q.bind(Some(v.clone())); }
    }
    if let Some(v) = req.create_srv { q = q.bind(v); }
    if let Some(v) = req.proxy_protocol { q = q.bind(v); }
    q = q.bind(id);

    match q.execute(&state.db).await {
        Ok(_) => Json(serde_json::json!({"message": "Updated"})).into_response(),
        Err(e) => { error!("db error: {:?}", e); (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response() },
    }
}

async fn delete_tunnel(State(state): State<Arc<AppState>>, Path(id): Path<u32>) -> impl IntoResponse {
    match sqlx::query("SELECT subdomain, domain FROM tunnels WHERE id = ?").bind(id).fetch_optional(&state.db).await {
        Ok(Some(r)) => {
            let sub: String = r.try_get("subdomain").unwrap_or_default();
            let dom: String = r.try_get("domain").unwrap_or_default();
            if let Err(e) = cloudflare::delete_dns_records(&state.cf, &sub, &dom).await { error!("DNS error: {:?}", e); }
            let _ = sqlx::query("DELETE FROM tunnels WHERE id = ?").bind(id).execute(&state.db).await;
            Json(serde_json::json!({"message": "Deleted"})).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "Not found").into_response(),
        Err(e) => { error!("db error: {:?}", e); (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response() },
    }
}

async fn start_tunnel(State(state): State<Arc<AppState>>, Path(id): Path<u32>) -> impl IntoResponse {
    // Reset dns_set so the manager re-configures DNS (server may have changed).
    // tunnel_status is set to 'starting' so the UI shows transitional state.
    // client_id is intentionally NOT reset: if the tunnel already has a client
    // assigned (dynamically or manually), that assignment must persist across
    // stop/start cycles.  The manager only auto-assigns when client_id IS NULL,
    // so a brand-new tunnel (client_id = NULL) will still get a dynamic
    // assignment on its first start.
    match sqlx::query(
        "UPDATE tunnels SET online = TRUE, dns_set = FALSE, tunnel_status = 'starting' WHERE id = ?",
    )
    .bind(id)
    .execute(&state.db)
    .await
    {
        Ok(_) => Json(serde_json::json!({"message": "Started"})).into_response(),
        Err(e) => { error!("db error: {:?}", e); (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response() },
    }
}

async fn stop_tunnel(State(state): State<Arc<AppState>>, Path(id): Path<u32>) -> impl IntoResponse {
    // client_id is intentionally NOT reset on stop so the assignment is
    // preserved when the tunnel is started again later.
    match sqlx::query("UPDATE tunnels SET online = FALSE, tunnel_status = 'stopped' WHERE id = ?").bind(id).execute(&state.db).await {
        Ok(_) => Json(serde_json::json!({"message": "Stopped"})).into_response(),
        Err(e) => { error!("db error: {:?}", e); (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response() },
    }
}

async fn list_servers(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.servers.iter().map(|s| serde_json::json!({"id": s.id, "name": s.name})).collect::<Vec<_>>())
}

async fn proxy_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let Some(ref url) = state.manager_url else {
        return Json(serde_json::json!({"error": "manager_url not configured"})).into_response();
    };
    let req = with_manager_auth(&state, state.http_client.get(&format!("{}/api/stats", url)));
    match req.send().await {
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(json) => Json(json).into_response(),
            Err(e) => { error!("manager /api/stats parse error: {:?}", e); (StatusCode::BAD_GATEWAY, "invalid response from manager").into_response() }
        },
        Err(e) => { error!("manager unavailable: {:?}", e); (StatusCode::BAD_GATEWAY, "manager unavailable").into_response() }
    }
}

async fn proxy_clients(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let Some(ref url) = state.manager_url else {
        return Json(serde_json::json!([])).into_response();
    };
    let req = with_manager_auth(&state, state.http_client.get(&format!("{}/api/clients", url)));
    match req.send().await {
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(json) => Json(json).into_response(),
            Err(e) => { error!("manager /api/clients parse error: {:?}", e); (StatusCode::BAD_GATEWAY, "invalid response from manager").into_response() }
        },
        Err(e) => { error!("manager unavailable: {:?}", e); (StatusCode::BAD_GATEWAY, "manager unavailable").into_response() }
    }
}

async fn index_page() -> Html<&'static str> {
    Html(include_str!("index.html"))
}

/// `GET /api/tunnels/{id}/connections`
async fn proxy_tunnel_connections(
    State(state): State<Arc<AppState>>,
    Path(id): Path<u32>,
) -> impl IntoResponse {
    let Some(ref url) = state.manager_url else {
        return Json(serde_json::json!([])).into_response();
    };
    let req = with_manager_auth(&state, state.http_client.get(&format!("{}/api/tunnels/{}/connections", url, id)));
    match req.send().await {
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(json) => Json(json).into_response(),
            Err(e) => { error!("manager connections parse error: {:?}", e); (StatusCode::BAD_GATEWAY, "invalid response from manager").into_response() }
        },
        Err(e) => { error!("manager unavailable: {:?}", e); (StatusCode::BAD_GATEWAY, "manager unavailable").into_response() }
    }
}

/// `DELETE /api/tunnels/{id}/connections/{stream_id}`
async fn proxy_disconnect_connection(
    State(state): State<Arc<AppState>>,
    Path((id, stream_id)): Path<(u32, u64)>,
) -> impl IntoResponse {
    let Some(ref url) = state.manager_url else {
        return (StatusCode::SERVICE_UNAVAILABLE, "manager_url not configured").into_response();
    };
    let req = with_manager_auth(&state, state.http_client
        .delete(&format!("{}/api/tunnels/{}/connections/{}", url, id, stream_id)));
    match req.send().await {
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(json) => Json(json).into_response(),
            Err(e) => { error!("manager disconnect parse error: {:?}", e); (StatusCode::BAD_GATEWAY, "invalid response from manager").into_response() }
        },
        Err(e) => { error!("manager unavailable: {:?}", e); (StatusCode::BAD_GATEWAY, "manager unavailable").into_response() }
    }
}
