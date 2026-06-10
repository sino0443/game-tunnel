
use anyhow::{Context, Result};
use game_tunnel_shared::config::CloudflareConfig;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";
const DNS_TTL: u32 = 120;

pub async fn ensure_dns_records(config: &CloudflareConfig, subdomain: &str, domain: &str, vps_ip: &str, port: u16, create_srv: bool) -> Result<()> {
    let subdomain = subdomain.trim();
    let domain = domain.trim();
    let vps_ip = vps_ip.trim();

    let zone = config.zones.iter().find(|z| z.domain == domain).with_context(|| format!("no zone for '{}'", domain))?;
    let client = reqwest::Client::new();
    let fqdn = format!("{}.{}", subdomain, domain);

    info!("DNS: name='{}' ip='{}' zone='{}'", fqdn, vps_ip, zone.zone_id);

    ensure_a_record(&client, &config.api_token, &zone.zone_id, &fqdn, vps_ip).await?;

    if create_srv {
        ensure_srv_record(&client, &config.api_token, &zone.zone_id, subdomain, domain, &fqdn, port).await?;
        info!("DNS records set (A + SRV) for {} -> {}, port {}", fqdn, vps_ip, port);
    } else {
        info!("DNS records set (A only) for {} -> {}", fqdn, vps_ip);
    }
    Ok(())
}

#[allow(dead_code)]
pub async fn delete_dns_records(config: &CloudflareConfig, subdomain: &str, domain: &str) -> Result<()> {
    let zone = config.zones.iter().find(|z| z.domain == domain).with_context(|| format!("no zone for {}", domain))?;
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

async fn ensure_a_record(c: &reqwest::Client, token: &str, zid: &str, name: &str, ip: &str) -> Result<()> {
    let body = DnsCreate { record_type: "A".into(), name: name.into(), content: ip.into(), ttl: DNS_TTL, proxied: false };

    match find_record(c, token, zid, "A", name).await {
        Ok(Some(rid)) if !rid.is_empty() => {
            // Record exists — UPDATE in-place via PUT (don't delete first!).
            info!("Updating existing A record {} (id={})", name, rid);
            let resp = c.put(&format!("{}/zones/{}/dns_records/{}", CF_API_BASE, zid, rid))
                .bearer_auth(token).json(&body).send().await?;
            if let Err(e) = resp.error_for_status_ref() {
                let err_text = resp.text().await.unwrap_or_default();
                return Err(anyhow::anyhow!("PUT failed: {}: {}", e, err_text));
            }
            return Ok(());
        }
        Ok(Some(_)) => {
            warn!("find_record returned empty ID for {}, trying POST", name);
        }
        Ok(None) => {
            info!("No existing A record for {}, creating new", name);
        }
        Err(e) => {
            warn!("find_record error for {}: {:?}, trying POST", name, e);
        }
    }

    // No existing record — create new via POST.
    let resp = c.post(&format!("{}/zones/{}/dns_records", CF_API_BASE, zid))
        .bearer_auth(token).json(&body).send().await?;
    if let Err(e) = resp.error_for_status_ref() {
        let body_text = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("POST failed: {}: {}", e, body_text));
    }
    Ok(())
}

async fn ensure_srv_record(c: &reqwest::Client, token: &str, zid: &str, sub: &str, domain: &str, target: &str, port: u16) -> Result<()> {
    let name = format!("_minecraft._tcp.{}.{}", sub, domain);
    let data = SrvData { priority: 1, weight: 5, port, target: format!("{}.", target) };
    let body = SrvCreate { record_type: "SRV".into(), name: name.clone(), data, ttl: DNS_TTL };

    match find_record(c, token, zid, "SRV", &name).await {
        Ok(Some(rid)) if !rid.is_empty() => {
            info!("Updating existing SRV record {} (id={})", name, rid);
            let resp = c.put(&format!("{}/zones/{}/dns_records/{}", CF_API_BASE, zid, rid))
                .bearer_auth(token).json(&body).send().await?;
            if let Err(e) = resp.error_for_status_ref() {
                let err_text = resp.text().await.unwrap_or_default();
                return Err(anyhow::anyhow!("SRV PUT failed: {}: {}", e, err_text));
            }
            return Ok(());
        }
        _ => {}
    }

    let resp = c.post(&format!("{}/zones/{}/dns_records", CF_API_BASE, zid))
        .bearer_auth(token).json(&body).send().await?;
    if let Err(e) = resp.error_for_status_ref() {
        let body_text = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("SRV POST failed: {}: {}", e, body_text));
    }
    Ok(())
}

async fn find_record(c: &reqwest::Client, token: &str, zid: &str, rt: &str, name: &str) -> Result<Option<String>> {
    let r: DnsList = c.get(&format!("{}/zones/{}/dns_records?type={}&name={}", CF_API_BASE, zid, rt, name))
        .bearer_auth(token).send().await?.error_for_status()?.json().await?;
    Ok(r.result.first().map(|x| x.id.clone()).filter(|id| !id.is_empty()))
}

async fn delete_record(c: &reqwest::Client, token: &str, zid: &str, rid: &str) -> Result<()> {
    c.delete(&format!("{}/zones/{}/dns_records/{}", CF_API_BASE, zid, rid))
        .bearer_auth(token).send().await?.error_for_status()?;
    Ok(())
}

#[derive(Serialize)] struct DnsCreate { #[serde(rename="type")] record_type: String, name: String, content: String, ttl: u32, proxied: bool }
#[derive(Serialize)] struct SrvCreate { #[serde(rename="type")] record_type: String, name: String, data: SrvData, ttl: u32 }
#[derive(Serialize)] struct SrvData { priority: u16, weight: u16, port: u16, target: String }
#[derive(Deserialize)] struct DnsList { result: Vec<DnsRec> }
#[derive(Deserialize)] struct DnsRec { id: String }