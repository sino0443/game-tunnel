use anyhow::{Context, Result};
use game_tunnel_shared::config::DatabaseConfig;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::{MySqlPool, Row};
use tracing::info;
use crate::DbTunnel;

pub async fn connect(config: &DatabaseConfig) -> Result<MySqlPool> {
    let url = format!("mysql://{}:{}@{}:{}/{}", config.user, config.password, config.host, config.port, config.database);
    MySqlPoolOptions::new().max_connections(5).connect(&url).await.context("failed to connect to MySQL")
}

pub async fn ensure_columns(pool: &MySqlPool) -> Result<()> {
    let columns = [
        ("client_id", "VARCHAR(50) DEFAULT NULL"),
        ("tunnel_status", "VARCHAR(20) NOT NULL DEFAULT 'stopped'"),
        ("last_seen", "DATETIME DEFAULT NULL"),
    ];
    for (col, def) in &columns {
        let sql = format!("ALTER TABLE tunnels ADD COLUMN IF NOT EXISTS {} {}", col, def);
        if let Err(e) = sqlx::query(&sql).execute(pool).await {
            let msg = e.to_string();
            if !msg.contains("Duplicate column") { tracing::warn!("Column check {}: {:?}", col, e); }
        }
    }
    info!("DB columns verified");
    Ok(())
}

pub async fn get_client_tunnels(pool: &MySqlPool, client_id: &str) -> Result<Vec<DbTunnel>> {
    let rows = sqlx::query(
        "SELECT id, uuid, name, online, server_ip, server_port, remote_port, protocol, server_id, subdomain, domain FROM tunnels WHERE online = TRUE AND client_id = ?"
    ).bind(client_id).fetch_all(pool).await.context("query client tunnels")?;
    Ok(rows.iter().map(|r| DbTunnel {
        id: r.try_get("id").unwrap_or(0), uuid: r.try_get("uuid").unwrap_or_default(),
        name: r.try_get("name").unwrap_or_default(), online: r.try_get("online").unwrap_or(false),
        server_ip: r.try_get("server_ip").unwrap_or_default(), server_port: r.try_get("server_port").unwrap_or(0),
        remote_port: r.try_get("remote_port").unwrap_or(0), protocol: r.try_get("protocol").unwrap_or_default(),
        server_id: r.try_get::<Option<u32>, _>("server_id").unwrap_or(None),
        subdomain: r.try_get("subdomain").unwrap_or_default(), domain: r.try_get("domain").unwrap_or_default(),
    }).collect())
}

pub async fn write_tunnel_status(pool: &MySqlPool, db_id: u32, status: &str, client_id: &str) -> Result<()> {
    sqlx::query("UPDATE tunnels SET tunnel_status = ?, last_seen = NOW() WHERE id = ? AND client_id = ?")
        .bind(status).bind(db_id).bind(client_id).execute(pool).await?;
    Ok(())
}

#[allow(dead_code)]
pub async fn mark_all_stopped(pool: &MySqlPool, client_id: &str) {
    let _ = sqlx::query("UPDATE tunnels SET tunnel_status = 'stopped', last_seen = NOW() WHERE client_id = ?")
        .bind(client_id).execute(pool).await;
}