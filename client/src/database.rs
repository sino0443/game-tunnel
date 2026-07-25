use anyhow::{Context, Result};
use game_tunnel_shared::config::DatabaseConfig;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::{MySqlPool, Row};
use tracing::info;

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

/// Writes the current tunnel status and last-seen timestamp back to the DB.
/// The client still needs direct write access for status tracking; reading
/// of tunnels is now done via the manager API (see `query_tunnels_from_manager`).
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
