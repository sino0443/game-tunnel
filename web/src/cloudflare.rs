use anyhow::{Context, Result};
use game_tunnel_shared::config::CloudflareConfig;
use serde::Deserialize;
use tracing::info;

const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";

pub async fn delete_dns_records(config: &CloudflareConfig, subdomain: &str, domain: &str) -> Result<()> {
    let zone = config.zones.iter().find(|z| z.domain == domain)
        .with_context(|| format!("no zone configured for domain {}", domain))?;

    let client = reqwest::Client::new();

    let a_name = format!("{}.{}", subdomain, domain);
    if let Some(id) = find_record(&client, &config.api_token, &zone.zone_id, "A", &a_name).await? {
        delete_record(&client, &config.api_token, &zone.zone_id, &id).await?;
        info!("Deleted A record for {}", a_name);
    }

    let srv_name = format!("_minecraft._tcp.{}.{}", subdomain, domain);
    if let Some(id) = find_record(&client, &config.api_token, &zone.zone_id, "SRV", &srv_name).await? {
        delete_record(&client, &config.api_token, &zone.zone_id, &id).await?;
        info!("Deleted SRV record for {}", srv_name);
    }

    Ok(())
}

async fn find_record(client: &reqwest::Client, api_token: &str, zone_id: &str, record_type: &str, name: &str) -> Result<Option<String>> {
    let url = format!("{}/zones/{}/dns_records?type={}&name={}", CF_API_BASE, zone_id, record_type, name);
    let resp: DnsListResponse = client.get(&url).bearer_auth(api_token).send().await
        .context("list records")?.error_for_status().context("CF error")?.json().await?;
    Ok(resp.result.first().map(|r| r.id.clone()))
}

async fn delete_record(client: &reqwest::Client, api_token: &str, zone_id: &str, record_id: &str) -> Result<()> {
    let url = format!("{}/zones/{}/dns_records/{}", CF_API_BASE, zone_id, record_id);
    client.delete(&url).bearer_auth(api_token).send().await
        .context("delete record")?.error_for_status().context("CF error")?;
    Ok(())
}

#[derive(Deserialize)]
struct DnsListResponse { result: Vec<DnsRecord> }
#[derive(Deserialize)]
struct DnsRecord { id: String }