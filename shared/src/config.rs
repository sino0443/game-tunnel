use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol { Tcp, Udp, Both }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub client_id: String,
    /// UUID used to identify this client towards the manager and server.
    pub client_uuid: String,
    pub client_name: String,
    /// Base URL of the manager API (e.g. "http://manager:8080").
    pub manager_url: String,
    /// How often (in seconds) the client polls the manager for tunnel changes
    /// and reports status back.  Defaults to 5.
    #[serde(default = "default_client_poll")]
    pub poll_interval_secs: u64,
    /// Shared secret required by the manager's HTTP API (sent as the
    /// `X-Api-Key` header on every request to `manager_url`). Must match
    /// `api_key` in the manager's config.
    pub manager_api_key: String,
    /// Server connection details (TLS CA, address, secret). The manager
    /// decides which server_id to use; the client looks up the entry here.
    pub servers: Vec<ServerEntry>,
}
fn default_client_poll() -> u64 { 5 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEntry {
    pub id: u32,
    pub name: String,
    pub address: String,
    pub secret: String,
    pub tls_ca: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub host: String, pub port: u16, pub user: String, pub password: String, pub database: String,
    #[serde(default = "default_poll")] pub poll_interval_secs: u64,
}
fn default_poll() -> u64 { 5 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareConfig { pub api_token: String, pub zones: Vec<CloudflareZone> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareZone { pub domain: String, pub zone_id: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Numeric ID of this server instance (must match the id in manager config).
    pub server_id: u32,
    pub bind_address: String,
    pub secret: String,
    pub public_bind_address: Option<String>,
    pub tls_cert: String,
    pub tls_key: String,
    /// Address the management HTTP listener binds to.
    /// Defaults to "0.0.0.0:9001" so the manager (often on a different host)
    /// can reach it. Access control comes from `mgmt_secret` below, not from
    /// network placement — if you *can* put this behind a firewall/VPN as
    /// well, that's extra defense in depth, but it's not required.
    #[serde(default = "default_mgmt_bind")]
    pub mgmt_bind_address: String,
    /// Shared secret required on every request to the management HTTP API
    /// (`/api/manager/pre-auth`, `/api/connections`, ...), sent as the
    /// `X-Mgmt-Secret` header. Must match the corresponding server entry's
    /// `mgmt_secret` in the manager's config.
    pub mgmt_secret: String,
}
fn default_mgmt_bind() -> String { "0.0.0.0:9001".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagerConfig {
    pub bind_address: String,
    pub database: DatabaseConfig,
    pub cloudflare: CloudflareConfig,
    pub clients: Vec<ManagedClient>,
    #[serde(default = "default_assign_interval")]
    pub assign_interval_secs: u64,
    pub servers: Vec<ManagedServer>,
    /// Shared secret that callers (game-tunnel clients, the web panel) must
    /// send as the `X-Api-Key` header on every request to this API.
    pub api_key: String,
}
fn default_assign_interval() -> u64 { 5 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedClient {
    pub id: String,
    pub name: String,
    /// UUID des Clients (aus client.toml `client_uuid`).
    /// Wird vom Manager benötigt, um `client_server_mappings` automatisch
    /// aktuell zu halten. Ohne diesen Wert erfolgt kein automatisches Upsert.
    #[serde(default)]
    pub uuid: Option<String>,
    /// Einzelne Stats-URL (alt, für Rückwärtskompatibilität).
    #[serde(default)]
    pub stats_url: Option<String>,
    /// Mehrere Stats-URLs — eine pro Client-Instanz / Prozess.
    #[serde(default)]
    pub stats_urls: Vec<String>,
}

impl ManagedClient {
    /// Gibt alle konfigurierten Stats-URLs zurück.
    /// Kombiniert stats_url (alt) und stats_urls (neu).
    pub fn all_stats_urls(&self) -> Vec<&str> {
        let mut urls: Vec<&str> = self.stats_urls.iter().map(|s| s.as_str()).collect();
        if let Some(url) = &self.stats_url {
            if !urls.iter().any(|&u| u == url.as_str()) {
                urls.push(url.as_str());
            }
        }
        urls
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedServer {
    pub id: u32,
    pub name: String,
    pub public_ip: String,
    /// Management API URL of this server (reachable from manager).
    /// Example: "http://10.0.0.2:9001"
    pub mgmt_url: String,
    /// Shared secret for this server's management API. Must match
    /// `mgmt_secret` in that server's own config.
    pub mgmt_secret: String,
}

impl ClientConfig { pub fn load(path: &Path) -> anyhow::Result<Self> { Ok(toml::from_str(&std::fs::read_to_string(path)?)?) } }
impl ServerConfig { pub fn load(path: &Path) -> anyhow::Result<Self> { Ok(toml::from_str(&std::fs::read_to_string(path)?)?) } }
impl ManagerConfig { pub fn load(path: &Path) -> anyhow::Result<Self> { Ok(toml::from_str(&std::fs::read_to_string(path)?)?) } }
