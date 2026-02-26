mod database;

use axum::{
    extract::{Path, State},
    http::{header::HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use database::DatabaseManager;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, sync::Arc};
use tokio::time::{interval, Duration};

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct IPResponse {
    ip: String,
    ipv4: Option<String>,
    ipv6: Option<String>,
    #[serde(rename = "type")]
    ip_type: u8,
    classification: String,
    hostname: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    city: Option<String>,
    region: Option<String>,
    region_code: Option<String>,
    district: Option<String>,
    postal_code: Option<String>,
    country_code: Option<String>,
    country_name: Option<String>,
    continent_code: Option<String>,
    continent_name: Option<String>,
    is_eu: Option<bool>,
    timezone: Option<String>,
    timezone_abbr: Option<String>,
    utc_offset: Option<i32>,
    utc_offset_str: Option<String>,
    dst_active: Option<bool>,
    currency: Option<String>,
    cidr: Option<String>,
    asn: Option<String>,
    as_name: Option<String>,
    proxy_type: Option<String>,
    isp: Option<String>,
    domain: Option<String>,
    provider: Option<String>,
    blocklists: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct CacheEntry {
    response: IPResponse,
    search_count: u64,
    elapsed_us: u64,
}

#[derive(Clone)]
struct AppState {
    db: Arc<DatabaseManager>,
    redis: redis::aio::ConnectionManager,
}

const RATE_LIMIT: u32 = 40;
const RATE_WINDOW: u32 = 60;
const CACHE_TTL: u32 = 3600;

#[tokio::main]
async fn main() {
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| panic!("REDIS_URL not set"));
    let redis = redis::aio::ConnectionManager::new(
        redis::Client::open(redis_url).expect("Invalid Redis URL"),
    )
    .await
    .expect("Redis connection failed");

    let db = Arc::new(DatabaseManager::new(redis.clone()));
    db.initialize().await;
    tokio::task::spawn_blocking(|| genom::lookup(0.0, 0.0))
        .await
        .ok();

    let state = AppState {
        db: db.clone(),
        redis,
    };

    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(3600));
        loop {
            ticker.tick().await;
            if db.should_refresh() {
                db.download_and_reload().await;
            }
        }
    });

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/api/{query}", get(get_api_info))
        .route("/health", get(health))
        .with_state(state);

    axum::serve(
        tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap(),
        app,
    )
    .await
    .unwrap();
}

async fn get_api_info(
    State(state): State<AppState>,
    Path(query): Path<String>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<IPResponse>), (StatusCode, HeaderMap, Json<serde_json::Value>)> {
    let client_ip = get_client_ip(&headers);

    if let Ok(ip) = parse_query_as_ip(&query, &headers) {
        handle_ip_lookup(state, ip, client_ip).await
    } else {
        handle_domain_lookup(state, query, client_ip).await
    }
}

async fn handle_ip_lookup(
    state: AppState,
    ip: IpAddr,
    client_ip: String,
) -> Result<(HeaderMap, Json<IPResponse>), (StatusCode, HeaderMap, Json<serde_json::Value>)> {
    let cache_key = format!("cache:{}", ip);
    let mut conn = state.redis.clone();

    if let Ok(cached) = conn.get::<_, String>(&cache_key).await {
        if let Ok(entry) = serde_json::from_str::<CacheEntry>(&cached) {
            let (remaining, reset) = rate_limit_status(&state, &client_ip).await;
            return Ok(build_response(entry, remaining, reset, true));
        }
    }

    enforce_rate_limit(&state, &client_ip).await?;

    let (mut response, search_count, elapsed_us) = state.db.lookup_async(&ip).await;
    response.ip = ip.to_string();

    let entry = CacheEntry {
        response,
        search_count,
        elapsed_us,
    };

    if let Ok(json) = serde_json::to_string(&entry) {
        let _: Result<(), _> = conn.set_ex(&cache_key, json, CACHE_TTL as u64).await;
    }

    let (remaining, reset) = rate_limit_status(&state, &client_ip).await;
    Ok(build_response(entry, remaining, reset, false))
}

async fn handle_domain_lookup(
    state: AppState,
    hostname: String,
    client_ip: String,
) -> Result<(HeaderMap, Json<IPResponse>), (StatusCode, HeaderMap, Json<serde_json::Value>)> {
    let cache_key = format!("cache:domain:{}", hostname);
    let mut conn = state.redis.clone();

    if let Ok(cached) = conn.get::<_, String>(&cache_key).await {
        if let Ok(entry) = serde_json::from_str::<CacheEntry>(&cached) {
            let (remaining, reset) = rate_limit_status(&state, &client_ip).await;
            return Ok(build_response(entry, remaining, reset, true));
        }
    }

    enforce_rate_limit(&state, &client_ip).await?;

    let (response, search_count, elapsed_us) = state
        .db
        .lookup_domain(&hostname)
        .await
        .map_err(|e| error_response_with_headers(StatusCode::BAD_REQUEST, &e, 0, 0))?;

    let entry = CacheEntry {
        response,
        search_count,
        elapsed_us,
    };

    if let Ok(json) = serde_json::to_string(&entry) {
        let _: Result<(), _> = conn.set_ex(&cache_key, json, CACHE_TTL as u64).await;
    }

    let (remaining, reset) = rate_limit_status(&state, &client_ip).await;
    Ok(build_response(entry, remaining, reset, false))
}

fn parse_query_as_ip(query: &str, headers: &HeaderMap) -> Result<IpAddr, ()> {
    if query == "me" {
        client_ip_from_headers(headers)
            .and_then(|s| s.parse().ok())
            .ok_or(())
    } else {
        query.parse().map_err(|_| ())
    }
}

fn get_client_ip(headers: &HeaderMap) -> String {
    client_ip_from_headers(headers).unwrap_or_else(|| "0.0.0.0".to_string())
}

fn client_ip_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .filter(|ip| is_public_ip(ip))
        .map(String::from)
}

fn is_public_ip(ip: &str) -> bool {
    ip.parse::<IpAddr>().map_or(false, |addr| match addr {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.octets()[0] == 0
                || (v4.octets()[0] == 169 && v4.octets()[1] == 254))
        }
        IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified(),
    })
}

async fn enforce_rate_limit(
    state: &AppState,
    ip: &str,
) -> Result<(), (StatusCode, HeaderMap, Json<serde_json::Value>)> {
    let key = format!("rl:{}", ip);
    let mut conn = state.redis.clone();

    let count: u32 = conn.incr(&key, 1).await.map_err(|_| {
        error_response_with_headers(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Rate limit check failed",
            0,
            0,
        )
    })?;

    if count == 1 {
        let _: () = conn.expire(&key, RATE_WINDOW as i64).await.map_err(|_| {
            error_response_with_headers(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Rate limit setup failed",
                0,
                0,
            )
        })?;
    }

    if count > RATE_LIMIT {
        let ttl: i64 = conn.ttl(&key).await.unwrap_or(RATE_WINDOW as i64);
        return Err(error_response_with_headers(
            StatusCode::TOO_MANY_REQUESTS,
            "Rate limit exceeded",
            0,
            ttl.max(0) as u64,
        ));
    }

    Ok(())
}

async fn rate_limit_status(state: &AppState, ip: &str) -> (u32, u64) {
    let key = format!("rl:{}", ip);
    let mut conn = state.redis.clone();
    let count: u32 = conn.get(&key).await.unwrap_or(0);
    let ttl: i64 = conn.ttl(&key).await.unwrap_or(RATE_WINDOW as i64);
    (RATE_LIMIT.saturating_sub(count), ttl.max(0) as u64)
}

fn build_response(
    entry: CacheEntry,
    remaining: u32,
    reset: u64,
    cached: bool,
) -> (HeaderMap, Json<IPResponse>) {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-search-count",
        entry.search_count.to_string().parse().unwrap(),
    );
    headers.insert(
        "x-server-time-us",
        entry.elapsed_us.to_string().parse().unwrap(),
    );
    headers.insert(
        "x-cache-status",
        (if cached { "hit" } else { "miss" }).parse().unwrap(),
    );
    headers.insert("ratelimit-limit", RATE_LIMIT.to_string().parse().unwrap());
    headers.insert(
        "ratelimit-remaining",
        remaining.to_string().parse().unwrap(),
    );
    headers.insert("ratelimit-reset", reset.to_string().parse().unwrap());
    (headers, Json(entry.response))
}

fn error_response_with_headers(
    status: StatusCode,
    message: &str,
    remaining: u32,
    reset: u64,
) -> (StatusCode, HeaderMap, Json<serde_json::Value>) {
    let mut headers = HeaderMap::new();
    headers.insert("ratelimit-limit", RATE_LIMIT.to_string().parse().unwrap());
    headers.insert(
        "ratelimit-remaining",
        remaining.to_string().parse().unwrap(),
    );
    headers.insert("ratelimit-reset", reset.to_string().parse().unwrap());
    (status, headers, Json(serde_json::json!({"error": message})))
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "last_refresh": state.db.last_refresh(),
    }))
}

async fn serve_index() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "text/html; charset=utf-8".parse().unwrap());
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert("x-xss-protection", "1; mode=block".parse().unwrap());
    headers.insert(
        "content-security-policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline' \
        https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' \
        https://cdn.jsdelivr.net; img-src 'self' data: \
        https://*.fastly.net https://*.ssl.fastly.net; \
        connect-src 'self' https://raw.githubusercontent.com; \
        form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
            .parse()
            .unwrap(),
    );
    headers.insert(
        "referrer-policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    headers.insert(
        "permissions-policy",
        "geolocation=(), microphone=(), camera=()".parse().unwrap(),
    );
    headers.insert("cross-origin-opener-policy", "same-origin".parse().unwrap());
    headers.insert(
        "cross-origin-resource-policy",
        "same-origin".parse().unwrap(),
    );
    headers.insert(
        "strict-transport-security",
        "max-age=31536000; includeSubDomains".parse().unwrap(),
    );
    (StatusCode::OK, headers, include_str!("../build/index.html"))
}
