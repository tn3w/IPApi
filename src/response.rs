use actix_web::{HttpRequest, HttpResponse, Responder, web};
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::dnsdata;
use crate::geodata::{self, GeoResponse};
use crate::ipdata;

const IP_CACHE_EXPIRATION: Duration = Duration::from_secs(60 * 60 * 3);
const DNS_CACHE_EXPIRATION: Duration = Duration::from_secs(60 * 60 * 6);
const GEO_CACHE_EXPIRATION: Duration = Duration::from_secs(60 * 60 * 12);
const TOR_CACHE_EXPIRATION: Duration = Duration::from_secs(60 * 60 * 6);

#[derive(Serialize, Deserialize, Clone)]
pub struct IpResponse {
    pub ip: String,
    #[serde(flatten)]
    pub geo_data: GeoResponse,
    pub reverse: String,
    pub tor: bool,
}

static IP_CACHE: Lazy<Arc<RwLock<HashMap<String, (IpResponse, DateTime<Utc>)>>>> =
    Lazy::new(|| Arc::new(RwLock::new(HashMap::new())));

static DNS_CACHE: Lazy<Arc<RwLock<HashMap<String, (String, DateTime<Utc>)>>>> =
    Lazy::new(|| Arc::new(RwLock::new(HashMap::new())));

static GEO_CACHE: Lazy<Arc<RwLock<HashMap<String, (GeoResponse, DateTime<Utc>)>>>> =
    Lazy::new(|| Arc::new(RwLock::new(HashMap::new())));

static TOR_CACHE: Lazy<Arc<RwLock<HashMap<String, (bool, DateTime<Utc>)>>>> =
    Lazy::new(|| Arc::new(RwLock::new(HashMap::new())));

impl IpResponse {
    pub fn new(ip_string: String, geo_data: GeoResponse, reverse: String, tor: bool) -> Self {
        IpResponse {
            ip: ip_string,
            geo_data,
            reverse,
            tor,
        }
    }
}

pub fn get_cached_ip_info(ip_string: &str) -> Option<IpResponse> {
    let cache = IP_CACHE.read().unwrap();
    if let Some((cached_info, timestamp)) = cache.get(ip_string) {
        let age = Utc::now().signed_duration_since(*timestamp);
        if age < chrono::Duration::from_std(IP_CACHE_EXPIRATION).unwrap() {
            return Some(cached_info.clone());
        }
    }
    None
}

pub fn cache_ip_info(ip_string: String, response: IpResponse) {
    let mut cache = IP_CACHE.write().unwrap();
    cache.insert(ip_string, (response, Utc::now()));
}

pub async fn with_cache<T, F, Fut>(
    cache: &Arc<RwLock<HashMap<String, (T, DateTime<Utc>)>>>,
    expiration: Duration,
    key: String,
    f: F,
) -> T
where
    T: Clone,
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    {
        let cache_guard = cache.read().unwrap();
        if let Some((cached_value, timestamp)) = cache_guard.get(&key) {
            let age = Utc::now().signed_duration_since(*timestamp);
            if age < chrono::Duration::from_std(expiration).unwrap() {
                return cached_value.clone();
            }
        }
    }

    let result = f().await;

    {
        let mut cache_guard = cache.write().unwrap();
        cache_guard.insert(key, (result.clone(), Utc::now()));
    }

    result
}

pub async fn get_reverse_dns_cached(ip: &str) -> String {
    with_cache(&DNS_CACHE, DNS_CACHE_EXPIRATION, ip.to_string(), || async {
        dnsdata::get_reverse_dns(ip).await.unwrap_or_default()
    })
    .await
}

pub async fn get_geo_data_cached(ip: std::net::IpAddr) -> Result<GeoResponse, String> {
    let ip_str = ip.to_string();
    {
        let cache = GEO_CACHE.read().unwrap();
        if let Some((cached_geo, timestamp)) = cache.get(&ip_str) {
            let age = Utc::now().signed_duration_since(*timestamp);
            if age < chrono::Duration::from_std(GEO_CACHE_EXPIRATION).unwrap() {
                return Ok(cached_geo.clone());
            }
        }
    }

    let result = geodata::get_geo_data(ip).await;

    if let Ok(geo_data) = &result {
        let mut cache = GEO_CACHE.write().unwrap();
        cache.insert(ip_str, (geo_data.clone(), Utc::now()));
    }

    result
}

pub async fn get_tor_status_cached(ip: &str) -> bool {
    with_cache(&TOR_CACHE, TOR_CACHE_EXPIRATION, ip.to_string(), || async {
        match ip.parse::<std::net::IpAddr>() {
            Ok(ip_addr) => {
                if ipdata::is_tor_exit_node(&ip_addr).await {
                    return true;
                }

                false
            }
            Err(_) => false,
        }
    })
    .await
}

pub async fn get_ip_info(ip_addr: web::Path<String>) -> impl Responder {
    let ip_string = ip_addr.into_inner();

    if let Some(cached_response) = get_cached_ip_info(&ip_string) {
        return HttpResponse::Ok().json(cached_response);
    }

    let ip: std::net::IpAddr = match ip_string.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid IP address"
            }));
        }
    };

    let geo_result = match get_geo_data_cached(ip).await {
        Ok(data) => data,
        Err(err) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to get geodata: {}", err)
            }));
        }
    };

    let reverse = get_reverse_dns_cached(&ip_string).await;
    let is_tor = get_tor_status_cached(&ip_string).await;

    let ip_response = IpResponse::new(ip_string.clone(), geo_result, reverse, is_tor);

    cache_ip_info(ip_string, ip_response.clone());

    HttpResponse::Ok().json(ip_response)
}

pub async fn get_self_ip_info(req: HttpRequest) -> impl Responder {
    let client_ip = match req.connection_info().realip_remote_addr() {
        Some(ip) => {
            let ip_str = if ip.starts_with('[') && ip.contains("]:") {
                match ip.split("]:").next() {
                    Some(addr) => addr.trim_start_matches('[').to_string(),
                    None => ip.to_string(),
                }
            } else if ip.starts_with('[') && ip.ends_with(']') {
                ip[1..ip.len() - 1].to_string()
            } else if ip.contains(':') && ip.contains('.') {
                match ip.split(':').next() {
                    Some(ip_part) => ip_part.to_string(),
                    None => ip.to_string(),
                }
            } else {
                ip.to_string()
            };

            if ip_str == "127.0.0.1" {
                match req.headers().get("x-forwarded-for") {
                    Some(forwarded) => match forwarded.to_str() {
                        Ok(f) => match f.split(',').next() {
                            Some(first_ip) => first_ip.trim().to_string(),
                            None => {
                                return HttpResponse::InternalServerError().json(
                                    serde_json::json!({
                                        "error": "Failed to extract client IP address"
                                    }),
                                );
                            }
                        },
                        Err(_) => {
                            return HttpResponse::InternalServerError().json(serde_json::json!({
                                "error": "Failed to extract client IP address"
                            }));
                        }
                    },
                    None => {
                        return HttpResponse::InternalServerError().json(serde_json::json!({
                            "error": "Failed to extract client IP address"
                        }));
                    }
                }
            } else {
                ip_str
            }
        }
        None => match req.headers().get("x-forwarded-for") {
            Some(forwarded) => match forwarded.to_str() {
                Ok(f) => match f.split(',').next() {
                    Some(first_ip) => first_ip.trim().to_string(),
                    None => {
                        return HttpResponse::InternalServerError().json(serde_json::json!({
                            "error": "Failed to extract client IP address"
                        }));
                    }
                },
                Err(_) => {
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "Failed to extract client IP address"
                    }));
                }
            },
            None => {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to extract client IP address"
                }));
            }
        },
    };

    if let Some(cached_response) = get_cached_ip_info(&client_ip) {
        return HttpResponse::Ok().json(cached_response);
    }

    let ip: std::net::IpAddr = match client_ip.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid IP address"
            }));
        }
    };

    let geo_result = match get_geo_data_cached(ip).await {
        Ok(data) => data,
        Err(err) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to get geodata: {}", err)
            }));
        }
    };

    let reverse = get_reverse_dns_cached(&client_ip).await;
    let is_tor = get_tor_status_cached(&client_ip).await;

    let ip_response = IpResponse::new(client_ip.clone(), geo_result, reverse, is_tor);

    cache_ip_info(client_ip, ip_response.clone());

    HttpResponse::Ok().json(ip_response)
}
