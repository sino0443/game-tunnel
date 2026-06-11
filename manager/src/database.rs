use anyhow::{Context, Result};
use game_tunnel_shared::config::DatabaseConfig;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::{MySqlPool, Row};
use tracing::{info, warn};

pub async fn connect(config: &DatabaseConfig) -> Result<MySqlPool> {
    let url = format!("mysql://{}:{}@{}:{}/{}", config.user, config.password, config.host, config.port, config.database);
    MySqlPoolOptions::new().max_connections(10).connect(&url).await.context("failed to connect to MySQL")
}

/// Ensure manager-specific columns exist (idempotent).
pub async fn ensure_columns(pool: &MySqlPool) -> Result<()> {
    let columns = [
        ("client_id", "VARCHAR(50) DEFAULT NULL"),
        ("tunnel_status", "VARCHAR(20) NOT NULL DEFAULT 'stopped'"),
        ("last_seen", "DATETIME DEFAULT NULL"),
        ("dns_set", "BOOLEAN NOT NULL DEFAULT FALSE"),
    ];
    for (col, def) in &columns {
        let sql = format!("ALTER TABLE tunnels ADD COLUMN {} {}", col, def);
        if let Err(e) = sqlx::query(&sql).execute(pool).await {
            if !e.to_string().contains("Duplicate column") { warn!("Column check {}: {:?}", col, e); }
        }
    }
    let _ = sqlx::query("CREATE INDEX idx_client_id ON tunnels(client_id)").execute(pool).await;
    let _ = sqlx::query("CREATE INDEX idx_online_client ON tunnels(online, client_id)").execute(pool).await;
    info!("DB columns ensured");
    Ok(())
}

pub struct UnassignedTunnel {
    pub id: u32,
    pub name: String,
    pub subdomain: String,
}

/// Get online tunnels with no client assigned yet.
pub async fn get_unassigned_tunnels(pool: &MySqlPool) -> Result<Vec<UnassignedTunnel>> {
    let rows = sqlx::query(
        "SELECT id, name, subdomain FROM tunnels WHERE online = TRUE AND client_id IS NULL"
    ).fetch_all(pool).await?;
    Ok(rows.iter().map(|r| UnassignedTunnel {
        id: r.try_get("id").unwrap_or(0),
        name: r.try_get("name").unwrap_or_default(),
        subdomain: r.try_get("subdomain").unwrap_or_default(),
    }).collect())
}

/// Count tunnels per client (only online tunnels).
pub async fn get_tunnel_counts_per_client(pool: &MySqlPool) -> Result<std::collections::HashMap<String, usize>> {
    let rows: Vec<(Option<String>,)> = sqlx::query_as(
        "SELECT client_id FROM tunnels WHERE online = TRUE AND client_id IS NOT NULL"
    ).fetch_all(pool).await?;
    let mut counts = std::collections::HashMap::new();
    for (cid,) in rows { if let Some(id) = cid { *counts.entry(id).or_insert(0) += 1; } }
    Ok(counts)
}

/// Assign a tunnel to a specific client.
pub async fn assign_tunnel(pool: &MySqlPool, tunnel_id: u32, client_id: &str) -> Result<()> {
    sqlx::query("UPDATE tunnels SET client_id = ? WHERE id = ?")
        .bind(client_id).bind(tunnel_id).execute(pool).await?;
    Ok(())
}

/// Unassign a tunnel (set client_id to NULL).
#[allow(dead_code)]
pub async fn unassign_tunnel(pool: &MySqlPool, tunnel_id: u32) -> Result<()> {
    sqlx::query("UPDATE tunnels SET client_id = NULL, tunnel_status = 'stopped', dns_set = FALSE WHERE id = ?")
        .bind(tunnel_id).execute(pool).await?;
    Ok(())
}

pub struct DnsTunnel {
    pub id: u32,
    pub subdomain: String,
    pub domain: String,
    pub remote_port: u16,
    pub server_id: Option<u32>,
    pub create_srv: bool,
}

/// Get all online assigned tunnels that still need DNS configured.
pub async fn get_tunnels_needing_dns(pool: &MySqlPool) -> Result<Vec<DnsTunnel>> {
    let rows = sqlx::query(
        "SELECT id, subdomain, domain, remote_port, server_id, create_srv FROM tunnels WHERE online = TRUE AND client_id IS NOT NULL AND dns_set = FALSE"
    ).fetch_all(pool).await?;
    Ok(rows.iter().map(|r| DnsTunnel {
        id: r.try_get("id").unwrap_or(0),
        subdomain: r.try_get("subdomain").unwrap_or_default(),
        domain: r.try_get("domain").unwrap_or_default(),
        remote_port: r.try_get("remote_port").unwrap_or(0),
        server_id: r.try_get::<Option<u32>, _>("server_id").unwrap_or(None),
        create_srv: r.try_get("create_srv").unwrap_or(true),
    }).collect())
}

/// Mark a tunnel's DNS as configured.
pub async fn mark_dns_set(pool: &MySqlPool, tunnel_id: u32) -> Result<()> {
    sqlx::query("UPDATE tunnels SET dns_set = TRUE WHERE id = ?")
        .bind(tunnel_id).execute(pool).await?;
    Ok(())
}

/// Reset DNS flag when tunnel settings change.
#[allow(dead_code)]
pub async fn reset_dns_flag(pool: &MySqlPool, tunnel_id: u32) -> Result<()> {
    sqlx::query("UPDATE tunnels SET dns_set = FALSE WHERE id = ?")
        .bind(tunnel_id).execute(pool).await?;
    Ok(())
}

/// Get a single tunnel for DNS update (by id).
#[allow(dead_code)]
pub async fn get_tunnel_for_dns(pool: &MySqlPool, tunnel_id: u32) -> Result<Option<DnsTunnel>> {
    let row = sqlx::query(
        "SELECT id, subdomain, domain, remote_port, server_id, create_srv FROM tunnels WHERE id = ?"
    ).bind(tunnel_id).fetch_optional(pool).await?;
    Ok(row.map(|r| DnsTunnel {
        id: r.try_get("id").unwrap_or(0),
        subdomain: r.try_get("subdomain").unwrap_or_default(),
        domain: r.try_get("domain").unwrap_or_default(),
        remote_port: r.try_get("remote_port").unwrap_or(0),
        server_id: r.try_get::<Option<u32>, _>("server_id").unwrap_or(None),
        create_srv: r.try_get("create_srv").unwrap_or(true),
    }))
}

/// Get all online assigned tunnels for DNS management.
#[allow(dead_code)]
pub async fn get_assigned_tunnels_for_dns(pool: &MySqlPool) -> Result<Vec<DnsTunnel>> {
    let rows = sqlx::query(
        "SELECT id, subdomain, domain, remote_port, server_id, create_srv FROM tunnels WHERE online = TRUE AND client_id IS NOT NULL"
    ).fetch_all(pool).await?;
    Ok(rows.iter().map(|r| DnsTunnel {
        id: r.try_get("id").unwrap_or(0),
        subdomain: r.try_get("subdomain").unwrap_or_default(),
        domain: r.try_get("domain").unwrap_or_default(),
        remote_port: r.try_get("remote_port").unwrap_or(0),
        server_id: r.try_get::<Option<u32>, _>("server_id").unwrap_or(None),
        create_srv: r.try_get("create_srv").unwrap_or(true),
    }).collect())
}

// ── client_server_mappings ──────────────────────────────────────────────────

/// Creates the `client_server_mappings` table if it does not yet exist.
/// Call once at startup after `ensure_columns`.
pub async fn ensure_client_server_table(pool: &MySqlPool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS client_server_mappings (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            client_uuid VARCHAR(36)  NOT NULL,
            client_id   VARCHAR(50)  NOT NULL,
            server_id   INT          NOT NULL,
            allowed     BOOLEAN      NOT NULL DEFAULT TRUE,
            created_at  DATETIME     NOT NULL DEFAULT NOW(),
            updated_at  DATETIME     NOT NULL DEFAULT NOW() ON UPDATE NOW(),
            UNIQUE KEY  uq_client_uuid (client_uuid),
            INDEX       idx_csm_server (server_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    )
    .execute(pool)
    .await?;
    info!("client_server_mappings table ensured");
    Ok(())
}

pub struct ClientServerMapping {
    pub client_uuid: String,
    pub client_id: String,
    pub server_id: u32,
    pub allowed: bool,
}

/// Returns the server mapping for a given client UUID, if one exists.
pub async fn get_server_for_client_uuid(
    pool: &MySqlPool,
    client_uuid: &str,
) -> Result<Option<ClientServerMapping>> {
    let row = sqlx::query(
        "SELECT client_uuid, client_id, server_id, allowed
         FROM client_server_mappings
         WHERE client_uuid = ?",
    )
    .bind(client_uuid)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| ClientServerMapping {
        client_uuid: r.try_get("client_uuid").unwrap_or_default(),
        client_id:   r.try_get("client_id").unwrap_or_default(),
        server_id:   r.try_get("server_id").unwrap_or(0),
        allowed:     r.try_get("allowed").unwrap_or(false),
    }))
}

pub struct TunnelRow {
    pub id: u32, pub name: String, pub subdomain: String, pub domain: String,
    pub online: bool, pub client_id: Option<String>, pub server_id: Option<u32>,
    pub tunnel_status: String, pub last_seen: Option<chrono::NaiveDateTime>,
    pub remote_port: u16, pub protocol: String,
}

/// Get all tunnels for stats aggregation.
pub async fn get_all_tunnels(pool: &MySqlPool) -> Result<Vec<TunnelRow>> {
    let rows = sqlx::query(
        "SELECT id, name, subdomain, domain, online, client_id, server_id, tunnel_status, last_seen, remote_port, protocol FROM tunnels ORDER BY name ASC"
    ).fetch_all(pool).await?;
    Ok(rows.iter().map(|r| TunnelRow {
        id: r.try_get("id").unwrap_or(0),
        name: r.try_get("name").unwrap_or_default(),
        subdomain: r.try_get("subdomain").unwrap_or_default(),
        domain: r.try_get("domain").unwrap_or_default(),
        online: r.try_get("online").unwrap_or(false),
        client_id: r.try_get::<Option<String>, _>("client_id").unwrap_or(None),
        server_id: r.try_get::<Option<u32>, _>("server_id").unwrap_or(None),
        tunnel_status: r.try_get("tunnel_status").unwrap_or_else(|_| "stopped".into()),
        last_seen: r.try_get::<Option<chrono::NaiveDateTime>, _>("last_seen").ok().flatten(),
        remote_port: r.try_get("remote_port").unwrap_or(0),
        protocol: r.try_get("protocol").unwrap_or_default(),
    }).collect())
}
