use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol { Tcp, Udp, Both }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub client_id: String,
    pub client_name: String,
    pub database: DatabaseConfig,
    pub servers: Vec<ServerEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEntry { pub id: u32, pub name: String, pub address: String, pub secret: String, pub tls_ca: String }

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
    pub bind_address: String, pub secret: String,
    pub public_bind_address: Option<String>,
    pub tls_cert: String, pub tls_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagerConfig {
    pub bind_address: String,
    pub database: DatabaseConfig,
    pub cloudflare: CloudflareConfig,
    pub clients: Vec<ManagedClient>,
    #[serde(default = "default_assign_interval")]
    pub assign_interval_secs: u64,
    pub servers: Vec<ManagedServer>,
}
fn default_assign_interval() -> u64 { 5 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedClient {
    pub id: String,
    pub name: String,
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
}

impl ClientConfig { pub fn load(path: &Path) -> anyhow::Result<Self> { Ok(toml::from_str(&std::fs::read_to_string(path)?)?) } }
impl ServerConfig { pub fn load(path: &Path) -> anyhow::Result<Self> { Ok(toml::from_str(&std::fs::read_to_string(path)?)?) } }
impl ManagerConfig { pub fn load(path: &Path) -> anyhow::Result<Self> { Ok(toml::from_str(&std::fs::read_to_string(path)?)?) } }