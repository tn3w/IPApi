use std::collections::HashSet;
use std::io::{self};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::{fs::File as TokioFile, time};

const CACHE_DIR: &str = "cache";
const ONIONOO_URL: &str = "https://onionoo.torproject.org/details?flag=exit";
const DATASET_FILE: &str = "tor_onionoo_list.dataset";
const CACHE_EXPIRATION: Duration = Duration::from_secs(60 * 60 * 24);
const TIMESTAMP_MARKER: &str = "TIMESTAMP:";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TorOnionooData {
    pub ipv4_nodes: HashSet<String>,
    pub ipv6_nodes: HashSet<String>,
}

pub struct TorExitNodeChecker {
    ipv4_nodes: HashSet<String>,
    ipv6_nodes: HashSet<String>,
    last_updated: DateTime<Utc>,
}

impl TorExitNodeChecker {
    fn new() -> Self {
        TorExitNodeChecker {
            ipv4_nodes: HashSet::new(),
            ipv6_nodes: HashSet::new(),
            last_updated: Utc::now(),
        }
    }

    pub fn is_exit_node(&self, ip_address: &IpAddr) -> bool {
        match ip_address {
            IpAddr::V4(ipv4) => {
                let ip_str = ipv4.to_string();
                self.ipv4_nodes.contains(&ip_str)
            }
            IpAddr::V6(ipv6) => {
                let ip_str = ipv6.to_string();

                if self.ipv6_nodes.contains(&ip_str) {
                    return true;
                }

                if let Ok(normalized_ipv6) = ip_str.parse::<Ipv6Addr>() {
                    return self.ipv6_nodes.contains(&normalized_ipv6.to_string());
                }

                false
            }
        }
    }
}

pub static TOR_DATABASE: Lazy<Arc<RwLock<TorExitNodeChecker>>> =
    Lazy::new(|| Arc::new(RwLock::new(TorExitNodeChecker::new())));

pub async fn initialize_tor_database() -> io::Result<()> {
    tokio::fs::create_dir_all(CACHE_DIR).await?;
    update_tor_database(false).await?;

    tokio::spawn(async {
        let mut interval = time::interval(Duration::from_secs(60 * 60));
        loop {
            interval.tick().await;
            let needs_update = {
                let cache = TOR_DATABASE.read().unwrap();
                Utc::now().signed_duration_since(cache.last_updated)
                    > chrono::Duration::from_std(CACHE_EXPIRATION).unwrap()
            };

            if needs_update {
                if let Err(e) = update_tor_database(false).await {
                    eprintln!("Failed to update Tor database: {}", e);
                }
            }
        }
    });

    Ok(())
}

async fn update_tor_database(force: bool) -> io::Result<()> {
    let dataset_path = get_dataset_path();

    let should_download = if force {
        true
    } else if dataset_path.exists() {
        match read_embedded_timestamp(&dataset_path).await {
            Some(timestamp) => {
                let file_time =
                    DateTime::from_timestamp(timestamp, 0).unwrap_or(DateTime::<Utc>::MIN_UTC);
                Utc::now().signed_duration_since(file_time)
                    > chrono::Duration::from_std(CACHE_EXPIRATION).unwrap()
            }
            None => true,
        }
    } else {
        true
    };

    if should_download {
        println!("Downloading {}", ONIONOO_URL);
        match download_and_parse_onionoo_data().await {
            Ok((ipv4_nodes, ipv6_nodes)) => {
                save_tor_data(&ipv4_nodes, &ipv6_nodes, &dataset_path).await?;

                let mut db = TOR_DATABASE.write().unwrap();
                db.ipv4_nodes = ipv4_nodes;
                db.ipv6_nodes = ipv6_nodes;
                db.last_updated = Utc::now();
            }
            Err(e) => {
                eprintln!("Error downloading Tor data: {}", e);
                if !dataset_path.exists() {
                    create_empty_dataset(&dataset_path).await?;
                } else {
                    load_from_dataset(&dataset_path).await?;
                }
            }
        }
    } else {
        load_from_dataset(&dataset_path).await?;
    }

    Ok(())
}

fn extract_ipv6(addr: &str) -> Option<Ipv6Addr> {
    if addr.starts_with('[') && addr.contains(']') {
        let end_bracket = addr.find(']')?;
        let ipv6_str = &addr[1..end_bracket];
        return ipv6_str.parse::<Ipv6Addr>().ok();
    }

    if addr.parse::<Ipv6Addr>().is_ok() {
        return addr.parse::<Ipv6Addr>().ok();
    }

    None
}

fn extract_ipv4(addr: &str) -> Option<Ipv4Addr> {
    let clean_addr = if addr.starts_with("::ffff:") {
        &addr[7..]
    } else {
        addr
    };

    let ip_part = clean_addr.split(':').next()?;

    ip_part.parse::<Ipv4Addr>().ok()
}

async fn download_and_parse_onionoo_data() -> io::Result<(HashSet<String>, HashSet<String>)> {
    let response = reqwest::get(ONIONOO_URL)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let bytes = response
        .bytes()
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let json_data: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut ipv4_nodes = HashSet::new();
    let mut ipv6_nodes = HashSet::new();

    if let Some(relays) = json_data.get("relays").and_then(|r| r.as_array()) {
        for relay in relays {
            if let Some(exit_addresses) = relay.get("exit_addresses").and_then(|a| a.as_array()) {
                for addr in exit_addresses {
                    if let Some(addr_str) = addr.as_str() {
                        if addr_str.chars().filter(|&c| c == ':').count() > 1 {
                            if let Some(ipv6) = extract_ipv6(addr_str) {
                                ipv6_nodes.insert(ipv6.to_string());
                            }
                        } else {
                            if let Some(ipv4) = extract_ipv4(addr_str) {
                                ipv4_nodes.insert(ipv4.to_string());
                            }
                        }
                    }
                }
            }

            if let Some(or_addresses) = relay.get("or_addresses").and_then(|a| a.as_array()) {
                for addr in or_addresses {
                    if let Some(addr_str) = addr.as_str() {
                        if addr_str.starts_with('[')
                            || addr_str.chars().filter(|&c| c == ':').count() > 1
                        {
                            if let Some(ipv6) = extract_ipv6(addr_str) {
                                ipv6_nodes.insert(ipv6.to_string());
                            }
                        } else {
                            if let Some(ipv4) = extract_ipv4(addr_str) {
                                ipv4_nodes.insert(ipv4.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    Ok((ipv4_nodes, ipv6_nodes))
}

async fn save_tor_data(
    ipv4_nodes: &HashSet<String>,
    ipv6_nodes: &HashSet<String>,
    dataset_path: &Path,
) -> io::Result<()> {
    let cache_data = TorOnionooData {
        ipv4_nodes: ipv4_nodes.clone(),
        ipv6_nodes: ipv6_nodes.clone(),
    };

    let json_data = serde_json::to_string(&cache_data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut file = TokioFile::create(dataset_path).await?;
    file.write_all(json_data.as_bytes()).await?;

    let timestamp: i64 = Utc::now().timestamp();
    let timestamp_data = format!("\n{}{}", TIMESTAMP_MARKER, timestamp);
    file.write_all(timestamp_data.as_bytes()).await?;

    Ok(())
}

async fn create_empty_dataset(dataset_path: &Path) -> io::Result<()> {
    let cache_data = TorOnionooData {
        ipv4_nodes: HashSet::new(),
        ipv6_nodes: HashSet::new(),
    };

    let json_data = serde_json::to_string(&cache_data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut file = TokioFile::create(dataset_path).await?;
    file.write_all(json_data.as_bytes()).await?;

    let timestamp = Utc::now().timestamp();
    let timestamp_data = format!("\n{}{}", TIMESTAMP_MARKER, timestamp);
    file.write_all(timestamp_data.as_bytes()).await?;

    let mut db = TOR_DATABASE.write().unwrap();
    db.ipv4_nodes.clear();
    db.ipv6_nodes.clear();
    db.last_updated = Utc::now();

    Ok(())
}

async fn load_from_dataset(dataset_path: &Path) -> io::Result<()> {
    let file_content = tokio::fs::read_to_string(dataset_path).await?;

    let json_str = if let Some(pos) = file_content.find(TIMESTAMP_MARKER) {
        &file_content[0..pos]
    } else {
        &file_content
    };

    let data = serde_json::from_str::<TorOnionooData>(json_str.trim()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "JSON parse error: {} - in content: {}",
                e,
                if json_str.len() > 100 {
                    &json_str[0..100]
                } else {
                    json_str
                }
            ),
        )
    })?;

    let mut db = TOR_DATABASE.write().unwrap();
    db.ipv4_nodes = data.ipv4_nodes;
    db.ipv6_nodes = data.ipv6_nodes;
    db.last_updated = Utc::now();

    Ok(())
}

fn get_dataset_path() -> PathBuf {
    Path::new(CACHE_DIR).join(DATASET_FILE)
}

async fn read_embedded_timestamp(path: &Path) -> Option<i64> {
    if let Ok(content) = tokio::fs::read_to_string(path).await {
        if let Some(pos) = content.find(TIMESTAMP_MARKER) {
            let timestamp_str = &content[pos + TIMESTAMP_MARKER.len()..];
            if let Ok(timestamp) = timestamp_str.trim().parse::<i64>() {
                return Some(timestamp);
            }
        }
    }
    None
}

pub async fn is_tor_exit_node(ip: &IpAddr) -> bool {
    let cache = TOR_DATABASE.read().unwrap();
    cache.is_exit_node(ip)
}
