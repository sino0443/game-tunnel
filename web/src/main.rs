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
    servers: Vec<WebServerEntry>,
    admin_credentials: Option<String>,
    http_client: reqwest::Client,
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
    ).init();

    let config_path = std::env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("web.toml"));
    let content = std::fs::read_to_string(&config_path).with_context(|| format!("failed to read {:?}", config_path))?;
    let config: WebConfig = toml::from_str(&content)?;

    if config.admin_credentials.is_none() { tracing::warn!("No admin_credentials configured!"); }
    if config.manager_url.is_none() { tracing::warn!("No manager_url configured."); }

    let db_url = format!("mysql://{}:{}@{}:{}/{}", config.database.user, config.database.password, config.database.host, config.database.port, config.database.database);
    let pool = MySqlPoolOptions::new().max_connections(10).connect(&db_url).await.context("failed to connect to MySQL")?;
    info!("Connected to MySQL");

    let http_client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)).build()?;
    let domains: Vec<String> = config.cloudflare.zones.iter().map(|z| z.domain.clone()).collect();
    let state = Arc::new(AppState {
        db: pool, cf: config.cloudflare, manager_url: config.manager_url,
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
}

#[derive(Deserialize)]
struct CreateTunnelRequest {
    name: Option<String>, server_ip: String, server_port: u16,
    remote_port: u16, protocol: Option<String>, subdomain: String,
    domain: Option<String>, server_id: Option<u32>,
    client_id: Option<String>,
    #[serde(default = "default_true")]
    create_srv: bool,
}
fn default_true() -> bool { true }

#[derive(Deserialize)]
struct UpdateTunnelRequest {
    name: Option<String>, server_ip: Option<String>, server_port: Option<u16>,
    remote_port: Option<u16>, protocol: Option<String>, subdomain: Option<String>,
    domain: Option<String>, online: Option<bool>, server_id: Option<i64>,
    client_id: Option<String>,
    create_srv: Option<bool>,
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
    }
}

async fn list_tunnels(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match sqlx::query("SELECT * FROM tunnels ORDER BY protocol ASC, name ASC, id DESC").fetch_all(&state.db).await {
        Ok(rows) => Json(rows.iter().map(row_to_tunnel).collect::<Vec<_>>()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response(),
    }
}

async fn get_tunnel(State(state): State<Arc<AppState>>, Path(id): Path<u32>) -> impl IntoResponse {
    match sqlx::query("SELECT * FROM tunnels WHERE id = ?").bind(id).fetch_optional(&state.db).await {
        Ok(Some(r)) => Json(row_to_tunnel(&r)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "Not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response(),
    }
}

async fn create_tunnel(State(state): State<Arc<AppState>>, Json(req): Json<CreateTunnelRequest>) -> impl IntoResponse {
    let uuid = uuid::Uuid::new_v4().to_string();
    let protocol = req.protocol.unwrap_or_else(|| "tcp".into());
    let name = req.name.unwrap_or_default();
    let domain = req.domain.unwrap_or_else(|| "sinomcit.com".into());

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response(),
    };

    // Read all existing IDs into a HashSet, then find the lowest free one in Rust.
    // Avoids MySQL BIGINT type-casting issues that arise from arithmetic on id columns.
    let taken: HashSet<u32> = match sqlx::query_scalar("SELECT id FROM tunnels")
        .fetch_all(&mut *tx).await
    {
        Ok(ids) => ids.into_iter().collect(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response(),
    };
    // (1u32..) is infinite so unwrap_or is unreachable, but keeps the type checker happy.
    let next_id = (1u32..).find(|n| !taken.contains(n)).unwrap_or(1);

    match sqlx::query(
        "INSERT INTO tunnels \
         (id, uuid, name, server_ip, server_port, remote_port, protocol, domain, subdomain, server_id, client_id, create_srv, online) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, TRUE)",
    )
    .bind(next_id)
    .bind(&uuid).bind(&name).bind(&req.server_ip).bind(req.server_port).bind(req.remote_port)
    .bind(&protocol).bind(&domain).bind(&req.subdomain).bind(req.server_id).bind(req.client_id)
    .bind(req.create_srv)
    .execute(&mut *tx).await
    {
        Ok(_) => {
            if let Err(e) = tx.commit().await {
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response();
            }
            info!("Created tunnel '{}' (subdomain={}, id={})", name, req.subdomain, next_id);
            (StatusCode::CREATED, Json(serde_json::json!({"message": "Created", "uuid": uuid, "id": next_id}))).into_response()
        }
        Err(e) => {
            let _ = tx.rollback().await;
            (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response()
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
    q = q.bind(id);

    match q.execute(&state.db).await {
        Ok(_) => Json(serde_json::json!({"message": "Updated"})).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response(),
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
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response(),
    }
}

async fn start_tunnel(State(state): State<Arc<AppState>>, Path(id): Path<u32>) -> impl IntoResponse {
    match sqlx::query("UPDATE tunnels SET online = TRUE WHERE id = ?").bind(id).execute(&state.db).await {
        Ok(_) => Json(serde_json::json!({"message": "Started"})).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response(),
    }
}

async fn stop_tunnel(State(state): State<Arc<AppState>>, Path(id): Path<u32>) -> impl IntoResponse {
    match sqlx::query("UPDATE tunnels SET online = FALSE, tunnel_status = 'stopped', client_id = NULL WHERE id = ?").bind(id).execute(&state.db).await {
        Ok(_) => Json(serde_json::json!({"message": "Stopped"})).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)).into_response(),
    }
}

async fn list_servers(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.servers.iter().map(|s| serde_json::json!({"id": s.id, "name": s.name})).collect::<Vec<_>>())
}

async fn proxy_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let Some(ref url) = state.manager_url else {
        return Json(serde_json::json!({"error": "manager_url not configured"})).into_response();
    };
    match state.http_client.get(&format!("{}/api/stats", url)).send().await {
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(json) => Json(json).into_response(),
            Err(e) => (StatusCode::BAD_GATEWAY, format!("parse error: {}", e)).into_response(),
        },
        Err(e) => (StatusCode::BAD_GATEWAY, format!("manager unavailable: {}", e)).into_response(),
    }
}

async fn proxy_clients(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let Some(ref url) = state.manager_url else {
        return Json(serde_json::json!([])).into_response();
    };
    match state.http_client.get(&format!("{}/api/clients", url)).send().await {
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(json) => Json(json).into_response(),
            Err(e) => (StatusCode::BAD_GATEWAY, format!("parse error: {}", e)).into_response(),
        },
        Err(e) => (StatusCode::BAD_GATEWAY, format!("manager unavailable: {}", e)).into_response(),
    }
}

async fn index_page() -> Html<&'static str> {
    Html(include_str!("index.html"))
}