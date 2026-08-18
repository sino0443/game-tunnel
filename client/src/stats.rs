use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use serde::Serialize;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct Stats {
    pub start_time: Instant,
    pub tunnels: Arc<RwLock<HashMap<u32, TunnelStats>>>,
    pub servers: Arc<RwLock<HashMap<u32, ServerStatus>>>,
    pub total_bytes_in: Arc<AtomicU64>,
    pub total_bytes_out: Arc<AtomicU64>,
    pub total_connections: Arc<AtomicU64>,
}

pub struct ServerStatus {
    pub id: u32, pub name: String, pub address: String,
    pub connected: AtomicBool, pub tls_ok: AtomicBool, pub auth_ok: AtomicBool,
}

pub struct TunnelStats {
    pub db_id: u32, pub name: String, pub subdomain: String,
    pub bytes_in: AtomicU64, pub bytes_out: AtomicU64,
    pub active_connections: AtomicU64, pub total_connections: AtomicU64,
    /// Echtzeit-Sekundenrate — wird von tick_rates() jede Sekunde gesetzt.
    pub bytes_in_per_sec: AtomicU64,
    pub bytes_out_per_sec: AtomicU64,
    /// Vorheriger Abtastwert für Differenzberechnung.
    prev_bytes_in: AtomicU64,
    prev_bytes_out: AtomicU64,
}

#[derive(Serialize)]
pub struct StatsResponse {
    pub uptime_secs: u64,
    pub total_bytes_in: u64, pub total_bytes_out: u64, pub total_connections: u64,
    pub servers: Vec<ServerStatusResponse>,
    pub tunnels: Vec<TunnelStatsResponse>,
}

#[derive(Serialize)]
pub struct ServerStatusResponse {
    pub id: u32, pub name: String, pub address: String,
    pub connected: bool, pub tls_ok: bool, pub auth_ok: bool,
}

#[derive(Serialize)]
pub struct TunnelStatsResponse {
    pub db_id: u32, pub name: String, pub subdomain: String,
    pub bytes_in: u64, pub bytes_out: u64,
    pub active_connections: u64, pub total_connections: u64,
    pub bytes_in_per_sec: u64, pub bytes_out_per_sec: u64,
}

#[allow(dead_code)]
impl Stats {
    pub fn new() -> Self {
        Stats {
            start_time: Instant::now(),
            tunnels: Arc::new(RwLock::new(HashMap::new())),
            servers: Arc::new(RwLock::new(HashMap::new())),
            total_bytes_in: Arc::new(AtomicU64::new(0)),
            total_bytes_out: Arc::new(AtomicU64::new(0)),
            total_connections: Arc::new(AtomicU64::new(0)),
        }
    }

    pub async fn add_server(&self, id: u32, name: String, address: String) {
        self.servers.write().await.insert(id, ServerStatus {
            id, name, address,
            connected: AtomicBool::new(false),
            tls_ok: AtomicBool::new(false),
            auth_ok: AtomicBool::new(false),
        });
    }

    pub async fn set_server_tls_ok(&self, id: u32) {
        let s = self.servers.read().await;
        if let Some(srv) = s.get(&id) {
            srv.connected.store(true, Ordering::Relaxed);
            srv.tls_ok.store(true, Ordering::Relaxed);
        }
    }

    pub async fn set_server_auth_ok(&self, id: u32) {
        let s = self.servers.read().await;
        if let Some(srv) = s.get(&id) { srv.auth_ok.store(true, Ordering::Relaxed); }
    }

    pub async fn set_server_disconnected(&self, id: u32) {
        let s = self.servers.read().await;
        if let Some(srv) = s.get(&id) {
            srv.connected.store(false, Ordering::Relaxed);
            srv.auth_ok.store(false, Ordering::Relaxed);
        }
    }

    /// Tunnel hinzufügen. Entfernt vorher alle veralteten Einträge mit derselben
    /// db_id um Race Conditions beim Server-Reconnect zu verhindern.
    /// Bug Fix: Ghost-Entries mit derselben db_id können sonst dazu führen dass
    /// active_connections und bytes_per_sec falsch aggregiert werden.
    pub async fn add_tunnel(&self, tunnel_id: u32, db_id: u32, name: String, subdomain: String) {
        let mut tunnels = self.tunnels.write().await;
        tunnels.retain(|_, v| v.db_id != db_id);
        tunnels.insert(tunnel_id, TunnelStats {
            db_id, name, subdomain,
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            total_connections: AtomicU64::new(0),
            bytes_in_per_sec: AtomicU64::new(0),
            bytes_out_per_sec: AtomicU64::new(0),
            prev_bytes_in: AtomicU64::new(0),
            prev_bytes_out: AtomicU64::new(0),
        });
    }

    pub async fn remove_tunnel(&self, tunnel_id: u32) {
        self.tunnels.write().await.remove(&tunnel_id);
    }

    /// Decrements `active_connections` by 1, saturating at 0.
    ///
    /// Plain `fetch_sub(1)` on a zero value wraps around to `u64::MAX`, which
    /// causes the tunnel to appear permanently active in the dashboard.  This
    /// can happen when a `NewConnection` message arrives before `add_tunnel`
    /// has been called (the increment is silently skipped) but the connection
    /// later closes and triggers the decrement.  Using saturating subtraction
    /// as a defence-in-depth measure keeps the counter at 0 in that case.
    pub fn saturating_decrement_active(&self) {
        // CAS loop: read current value, subtract 1 (clamped to 0), write back.
        // Uses `fetch_update` which retries automatically on contention.
        self.active_connections
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1))
            .ok(); // `Err` means value was already 0 — that's fine, nothing to do.
    }

    /// Sekundenraten für alle Tunnel aktualisieren.
    /// Muss jede Sekunde aufgerufen werden.
    pub async fn tick_rates(&self) {
        let tunnels = self.tunnels.read().await;
        for ts in tunnels.values() {
            let bi = ts.bytes_in.load(Ordering::Relaxed);
            let bo = ts.bytes_out.load(Ordering::Relaxed);
            let prev_bi = ts.prev_bytes_in.swap(bi, Ordering::Relaxed);
            let prev_bo = ts.prev_bytes_out.swap(bo, Ordering::Relaxed);
            ts.bytes_in_per_sec.store(bi.saturating_sub(prev_bi), Ordering::Relaxed);
            ts.bytes_out_per_sec.store(bo.saturating_sub(prev_bo), Ordering::Relaxed);
        }
    }

    pub async fn to_response(&self) -> StatsResponse {
        let uptime = self.start_time.elapsed().as_secs();
        let tunnels = self.tunnels.read().await;
        let servers = self.servers.read().await;
        StatsResponse {
            uptime_secs: uptime,
            total_bytes_in: self.total_bytes_in.load(Ordering::Relaxed),
            total_bytes_out: self.total_bytes_out.load(Ordering::Relaxed),
            total_connections: self.total_connections.load(Ordering::Relaxed),
            servers: servers.values().map(|s| ServerStatusResponse {
                id: s.id, name: s.name.clone(), address: s.address.clone(),
                connected: s.connected.load(Ordering::Relaxed),
                tls_ok: s.tls_ok.load(Ordering::Relaxed),
                auth_ok: s.auth_ok.load(Ordering::Relaxed),
            }).collect(),
            tunnels: tunnels.values().map(|t| TunnelStatsResponse {
                db_id: t.db_id,
                name: t.name.clone(),
                subdomain: t.subdomain.clone(),
                bytes_in: t.bytes_in.load(Ordering::Relaxed),
                bytes_out: t.bytes_out.load(Ordering::Relaxed),
                active_connections: t.active_connections.load(Ordering::Relaxed),
                total_connections: t.total_connections.load(Ordering::Relaxed),
                // Echtzeit-Raten aus tick_rates(), kein Lifetime-Durchschnitt mehr.
                bytes_in_per_sec: t.bytes_in_per_sec.load(Ordering::Relaxed),
                bytes_out_per_sec: t.bytes_out_per_sec.load(Ordering::Relaxed),
            }).collect(),
        }
    }
}