use std::collections::HashMap;
use std::io::{self, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use csv;
use maxminddb::Reader;
use once_cell::sync::Lazy;
use reverse_geocoder::ReverseGeocoder;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::{fs::File as TokioFile, time};

#[derive(Serialize, Deserialize, Clone)]
pub struct GeoResponse {
    pub continent: String,
    pub continent_code: String,
    pub country: String,
    pub country_code: String,
    pub state: String,
    pub state_code: String,
    pub city: String,
    pub district: String,
    pub zip: Option<u32>,
    pub lat: f64,
    pub lon: f64,
    pub timezone: String,
    pub offset: i32,
    pub currency: String,
    pub isp: String,
    pub org: String,
    #[serde(rename = "as")]
    pub as_name: String,
    pub as_code: u32,
}

impl GeoResponse {
    pub fn new() -> Self {
        GeoResponse {
            continent: String::new(),
            continent_code: String::new(),
            country: String::new(),
            country_code: String::new(),
            state: String::new(),
            state_code: String::new(),
            city: String::new(),
            district: String::new(),
            zip: None,
            lat: 0.0,
            lon: 0.0,
            timezone: String::new(),
            offset: 0,
            currency: String::new(),
            isp: String::new(),
            org: String::new(),
            as_name: String::new(),
            as_code: 0,
        }
    }
}

struct DbConfig {
    url: &'static str,
    filename: &'static str,
}

const DB_CONFIGS: [DbConfig; 2] = [
    DbConfig {
        url: "https://git.io/GeoLite2-City.mmdb",
        filename: "GeoLite2-City.mmdb",
    },
    DbConfig {
        url: "https://git.io/GeoLite2-ASN.mmdb",
        filename: "GeoLite2-ASN.mmdb",
    },
];

const CACHE_DIR: &str = "cache";
const TIMESTAMP_MARKER: &[u8] = b"TIMESTAMP:";
const CACHE_EXPIRATION: Duration = Duration::from_secs(60 * 60 * 24 * 3);

pub static DATABASES: Lazy<Arc<RwLock<GeoDbCache>>> = Lazy::new(|| {
    Arc::new(RwLock::new(GeoDbCache {
        city_db: None,
        asn_db: None,
        last_updated: Utc::now(),
    }))
});

pub struct GeoDbCache {
    city_db: Option<Reader<Vec<u8>>>,
    asn_db: Option<Reader<Vec<u8>>>,
    last_updated: DateTime<Utc>,
}

static REVERSE_GEOCODER: Lazy<ReverseGeocoder> = Lazy::new(|| ReverseGeocoder::new());

struct StateCodesCache {
    state_codes: HashMap<String, String>,
    last_updated: DateTime<Utc>,
}

static STATE_CODES: Lazy<RwLock<StateCodesCache>> = Lazy::new(|| {
    RwLock::new(StateCodesCache {
        state_codes: HashMap::new(),
        last_updated: DateTime::<Utc>::MIN_UTC,
    })
});

const COUNTRIES_DB_URL: &str = "https://raw.githubusercontent.com/dr5hn/countries-states-cities-database/refs/heads/master/json/countries%2Bstates%2Bcities.json";
const COUNTRIES_DB_REFRESH: Duration = Duration::from_secs(60 * 60 * 24 * 7);
const PROCESSED_STATECODES_FILE: &str = "statecodes.json";

const COUNTRIES_JSON_URL: &str = "https://gist.githubusercontent.com/fogonwater/bc2b98baeb2aa16b5e6fbc1cf3d7d545/raw/6fd2951260d8f171181a45d2f09ee8b2c7767330/countries.json";
const COUNTRIES_JSON_FILE: &str = "countries.json";
const ZIP_CODES_URL: &str = "https://raw.githubusercontent.com/wouterdebie/zip_codes_plus/refs/heads/main/data/zip_codes.csv";
const ZIP_CODES_FILE: &str = "zip_codes.csv";

#[derive(Serialize, Deserialize)]
struct CountryInfo {
    continent_code: String,
    continent_name: String,
    country_code2: String,
}

static COUNTRY_DATA: Lazy<RwLock<HashMap<String, CountryInfo>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

#[allow(dead_code)]
struct ZipCodeEntry {
    zip_code: String,
    city: String,
    state: String,
    lat: f64,
    lon: f64,
}

static ZIP_CODES: Lazy<RwLock<HashMap<String, Vec<ZipCodeEntry>>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

async fn save_state_codes_to_disk(state_codes: &HashMap<String, String>) -> io::Result<()> {
    let file_path = get_cache_path(PROCESSED_STATECODES_FILE);
    let mut file = TokioFile::create(&file_path).await?;

    let data = json!({
        "_timestamp": Utc::now().timestamp(),
        "state_codes": state_codes
    });

    let json_str = serde_json::to_string(&data)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to serialize: {}", e)))?;

    file.write_all(json_str.as_bytes()).await?;

    Ok(())
}

async fn load_state_codes_from_disk() -> io::Result<Option<(HashMap<String, String>, DateTime<Utc>)>>
{
    let file_path = get_cache_path(PROCESSED_STATECODES_FILE);

    if !file_path.exists() {
        return Ok(None);
    }

    let mut file = TokioFile::open(&file_path).await?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).await?;

    let data: Value = serde_json::from_str(&contents).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to parse cached data: {}", e),
        )
    })?;

    let timestamp = match data.get("_timestamp").and_then(|v| v.as_i64()) {
        Some(ts) => match DateTime::from_timestamp(ts, 0) {
            Some(dt) => dt,
            None => return Ok(None),
        },
        None => return Ok(None),
    };

    let state_codes_value = match data.get("state_codes") {
        Some(sc) => sc,
        None => return Ok(None),
    };

    let state_codes: HashMap<String, String> = serde_json::from_value(state_codes_value.clone())
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to deserialize state codes: {}", e),
            )
        })?;

    Ok(Some((state_codes, timestamp)))
}

async fn download_countries_database() -> io::Result<()> {
    if let Ok(Some((cached_codes, timestamp))) = load_state_codes_from_disk().await {
        let now = Utc::now();
        let elapsed = now - timestamp;

        if elapsed < chrono::Duration::from_std(COUNTRIES_DB_REFRESH).unwrap() {
            let mut cache = STATE_CODES.write().unwrap();
            cache.state_codes = cached_codes;
            cache.last_updated = timestamp;
            return Ok(());
        }
    }

    {
        let cache = STATE_CODES.read().unwrap();
        let now = Utc::now();
        let elapsed = now - cache.last_updated;

        if !cache.state_codes.is_empty()
            && elapsed < chrono::Duration::from_std(COUNTRIES_DB_REFRESH).unwrap()
        {
            return Ok(());
        }
    }

    println!("Downloading {}", COUNTRIES_DB_URL);

    let response = reqwest::get(COUNTRIES_DB_URL)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to download: {}", e)))?;

    let bytes = response
        .bytes()
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to get bytes: {}", e)))?;

    let json_data: Value = match serde_json::from_slice(&bytes) {
        Ok(parsed) => parsed,
        Err(e) => {
            let error_message = format!("Failed to parse JSON: {}", e);
            eprintln!("{}", error_message);

            return Err(io::Error::new(io::ErrorKind::InvalidData, error_message));
        }
    };

    let countries = match json_data.as_array() {
        Some(arr) => arr,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Expected JSON array for countries",
            ));
        }
    };

    let mut new_state_codes = HashMap::new();

    for country in countries {
        let country_code = match country.get("iso2").and_then(|v| v.as_str()) {
            Some(code) => code,
            None => continue,
        };

        if let Some(states) = country.get("states").and_then(|v| v.as_array()) {
            for state in states {
                let state_name = match state.get("name").and_then(|v| v.as_str()) {
                    Some(name) => name,
                    None => continue,
                };

                let state_code = match state.get("state_code").and_then(|v| v.as_str()) {
                    Some(code) => {
                        if code.chars().all(|c| c.is_numeric()) {
                            let name_parts: Vec<&str> = state_name.split_whitespace().collect();
                            if name_parts.len() >= 2 {
                                let first_initial = name_parts[0].chars().next().unwrap_or(' ');
                                let second_initial = name_parts[1].chars().next().unwrap_or(' ');
                                format!("{}{}", first_initial, second_initial)
                                    .to_uppercase()
                                    .trim()
                                    .to_string()
                            } else if name_parts.len() == 1 && name_parts[0].len() >= 2 {
                                let chars: Vec<char> = name_parts[0].chars().take(2).collect();
                                chars
                                    .iter()
                                    .collect::<String>()
                                    .to_uppercase()
                                    .trim()
                                    .to_string()
                            } else {
                                let chars: Vec<char> = state_name.chars().take(2).collect();
                                if chars.len() >= 2 {
                                    chars
                                        .iter()
                                        .collect::<String>()
                                        .to_uppercase()
                                        .trim()
                                        .to_string()
                                } else {
                                    "".to_string()
                                }
                            }
                        } else if code.len() > 2 {
                            let chars: Vec<char> = code.chars().take(2).collect();
                            chars.iter().collect::<String>().to_uppercase()
                        } else {
                            code.to_string().to_uppercase()
                        }
                    }
                    None => {
                        continue;
                    }
                };

                let key = format!("{}_{}", country_code, state_name.to_lowercase());
                new_state_codes.insert(key, state_code);
            }
        }
    }

    let mut cache = STATE_CODES.write().unwrap();
    cache.state_codes = new_state_codes.clone();
    cache.last_updated = Utc::now();

    if let Err(e) = save_state_codes_to_disk(&new_state_codes).await {
        eprintln!("Failed to save state codes to disk: {}", e);
    }

    Ok(())
}

pub fn get_state_code(country_code: &str, state_name: &str) -> Option<String> {
    if state_name.is_empty() || country_code.is_empty() {
        return None;
    }

    let cache = STATE_CODES.read().unwrap();

    let country_code = country_code.trim().to_uppercase();
    let state_name = state_name.trim().to_lowercase();

    let key = format!("{}_{}", country_code, state_name);
    if let Some(code) = cache.state_codes.get(&key) {
        return Some(code.clone());
    }

    if country_code == "AT" && (state_name == "vienna" || state_name == "wien") {
        return Some("9".to_string());
    }

    let cleaned_state = state_name
        .chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace())
        .collect::<String>();
    if cleaned_state != state_name {
        let alt_key = format!("{}_{}", country_code, cleaned_state);
        if let Some(code) = cache.state_codes.get(&alt_key) {
            return Some(code.clone());
        }
    }

    None
}

pub async fn initialize_geo_databases() -> io::Result<()> {
    tokio::fs::create_dir_all(CACHE_DIR).await?;

    download_and_cache_databases(false).await?;

    if let Err(e) = download_countries_database().await {
        eprintln!("Failed to download countries database: {}", e);
    }

    if let Err(e) = download_countries_json().await {
        eprintln!("Failed to download countries JSON: {}", e);
    }

    if let Err(e) = download_zip_codes().await {
        eprintln!("Failed to download ZIP codes: {}", e);
    }

    tokio::spawn(async {
        let mut interval = time::interval(Duration::from_secs(60 * 60));

        loop {
            interval.tick().await;

            let needs_update = {
                let cache = DATABASES.read().unwrap();
                let elapsed = Utc::now() - cache.last_updated;
                elapsed > chrono::Duration::from_std(CACHE_EXPIRATION).unwrap()
            };

            if needs_update {
                if let Err(e) = download_and_cache_databases(false).await {
                    eprintln!("Failed to update databases: {}", e);
                }

                if let Err(e) = download_countries_json().await {
                    eprintln!("Failed to update countries JSON: {}", e);
                }

                if let Err(e) = download_zip_codes().await {
                    eprintln!("Failed to update ZIP codes: {}", e);
                }
            }
        }
    });

    Ok(())
}

async fn download_and_cache_databases(force: bool) -> io::Result<()> {
    let mut city_db_bytes = Vec::new();
    let mut asn_db_bytes = Vec::new();

    for config in &DB_CONFIGS {
        let file_path = get_cache_path(config.filename);
        let bytes = download_file(config.url, &file_path, force).await?;

        match config.filename {
            "GeoLite2-City.mmdb" => city_db_bytes = bytes,
            "GeoLite2-ASN.mmdb" => asn_db_bytes = bytes,
            _ => {}
        }
    }

    let city_reader = Reader::from_source(city_db_bytes.clone())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let asn_reader = Reader::from_source(asn_db_bytes.clone())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let mut cache = DATABASES.write().unwrap();
    cache.city_db = Some(city_reader);
    cache.asn_db = Some(asn_reader);
    cache.last_updated = Utc::now();

    Ok(())
}

fn get_cache_path(filename: &str) -> PathBuf {
    Path::new(CACHE_DIR).join(filename)
}

async fn read_embedded_timestamp(path: &Path) -> Option<i64> {
    if let Ok(mut file) = TokioFile::open(path).await {
        if let Ok(metadata) = file.metadata().await {
            let file_size = metadata.len();
            if file_size > 30 {
                if file.seek(SeekFrom::End(-30)).await.is_ok() {
                    let mut buffer = [0; 30];
                    if file.read_exact(&mut buffer).await.is_ok() {
                        let content = String::from_utf8_lossy(&buffer);
                        if let Some(pos) = content.find("TIMESTAMP:") {
                            let timestamp_str = &content[pos + 10..];
                            if let Ok(timestamp) = timestamp_str.trim().parse::<i64>() {
                                return Some(timestamp);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

async fn write_embedded_timestamp(path: &Path) -> io::Result<()> {
    let mut file = TokioFile::options()
        .write(true)
        .append(true)
        .open(path)
        .await?;

    let timestamp = Utc::now().timestamp();
    let timestamp_data = format!(
        "\n{}{}",
        String::from_utf8_lossy(TIMESTAMP_MARKER),
        timestamp
    );

    file.write_all(timestamp_data.as_bytes()).await?;
    Ok(())
}

async fn download_file(url: &str, path: &Path, force: bool) -> io::Result<Vec<u8>> {
    let should_download = if force {
        true
    } else if path.exists() {
        if let Some(timestamp) = read_embedded_timestamp(path).await {
            let file_time = chrono::DateTime::from_timestamp(timestamp, 0)
                .unwrap_or(chrono::DateTime::<Utc>::MIN_UTC);
            let now = Utc::now();
            let age = now.signed_duration_since(file_time);

            age > chrono::Duration::from_std(CACHE_EXPIRATION).unwrap()
        } else {
            true
        }
    } else {
        true
    };

    if should_download {
        println!("Downloading {}", url);

        let response = reqwest::get(url)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let bytes = response
            .bytes()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let data = bytes.to_vec();

        let mut file = TokioFile::create(path).await?;
        file.write_all(&data).await?;

        write_embedded_timestamp(path).await?;

        let mut updated_file = TokioFile::open(path).await?;
        let mut buffer = Vec::new();
        updated_file.read_to_end(&mut buffer).await?;
        Ok(buffer)
    } else {
        let mut file = TokioFile::open(path).await?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).await?;
        Ok(buffer)
    }
}

fn extract_city_info(data: &maxminddb::geoip2::City, geo: &mut GeoResponse) {
    if geo.continent.is_empty() || geo.continent_code.is_empty() {
        if let Some(cont) = &data.continent {
            if geo.continent.is_empty() {
                if let Some(names) = &cont.names {
                    if let Some(name) = names.get("en") {
                        geo.continent = name.to_string();
                    }
                }
            }
            if geo.continent_code.is_empty() {
                if let Some(code) = cont.code {
                    geo.continent_code = code.to_string();
                }
            }
        }
    }

    if geo.country.is_empty() || geo.country_code.is_empty() {
        let country_info = if let Some(ctry) = &data.country {
            Some(ctry)
        } else if let Some(reg_ctry) = &data.registered_country {
            Some(reg_ctry)
        } else {
            None
        };

        if let Some(ctry) = country_info {
            if geo.country.is_empty() {
                if let Some(names) = &ctry.names {
                    if let Some(name) = names.get("en") {
                        geo.country = name.to_string();
                    }
                }
            }
            if geo.country_code.is_empty() {
                if let Some(code) = ctry.iso_code {
                    geo.country_code = code.to_string();
                }
            }
        }
    }

    if let Some(subdivisions) = &data.subdivisions {
        if let Some(first) = subdivisions.first() {
            if let Some(names) = &first.names {
                if let Some(name) = names.get("en") {
                    geo.state = name.to_string();
                }
            }
            if let Some(code) = first.iso_code {
                geo.state_code = code.to_string();
            }
        }

        if !subdivisions.is_empty() {
            if let Some(names) = &subdivisions[0].names {
                if let Some(name) = names.get("en") {
                    geo.district = name.to_string();
                }
            }
        }
    }

    if let Some(city) = &data.city {
        if let Some(names) = &city.names {
            if let Some(name) = names.get("en") {
                geo.city = name.to_string();
            }
        }
    }

    if let Some(postal) = &data.postal {
        if let Some(code) = postal.code {
            if let Ok(zip_num) = code.parse::<u32>() {
                geo.zip = Some(zip_num);
            }
        }
    }

    if let Some(loc) = &data.location {
        if let Some(lat) = loc.latitude {
            geo.lat = lat;
        }
        if let Some(lon) = loc.longitude {
            geo.lon = lon;
        }
        if let Some(tz) = loc.time_zone {
            geo.timezone = tz.to_string();
        }
    }
}

fn get_currency_from_country(country_code: &str) -> String {
    match country_code {
        "AF" => "AFN",
        "AL" => "ALL",
        "DZ" => "DZD",
        "AS" => "USD",
        "AD" => "EUR",
        "AO" => "AOA",
        "AI" => "XCD",
        "AQ" => "USD",
        "AG" => "XCD",
        "AR" => "ARS",
        "AM" => "AMD",
        "AW" => "AWG",
        "AU" => "AUD",
        "AT" => "EUR",
        "AZ" => "AZN",
        "BS" => "BSD",
        "BH" => "BHD",
        "BD" => "BDT",
        "BB" => "BBD",
        "BY" => "BYR",
        "BE" => "EUR",
        "BZ" => "BZD",
        "BJ" => "XOF",
        "BM" => "BMD",
        "BT" => "BTN",
        "BO" => "BOB",
        "BA" => "BAM",
        "BW" => "BWP",
        "BV" => "NOK",
        "BR" => "BRL",
        "IO" => "USD",
        "VG" => "USD",
        "BN" => "BND",
        "BG" => "BGN",
        "BF" => "XOF",
        "BI" => "BIF",
        "KH" => "KHR",
        "CM" => "XAF",
        "CA" => "CAD",
        "CV" => "CVE",
        "KY" => "KYD",
        "CF" => "XAF",
        "TD" => "XAF",
        "CL" => "CLP",
        "CN" => "CNY",
        "CX" => "AUD",
        "CC" => "AUD",
        "CO" => "COP",
        "KM" => "KMF",
        "CK" => "NZD",
        "CR" => "CRC",
        "HR" => "HRK",
        "CU" => "CUP",
        "CY" => "CYP",
        "CZ" => "CZK",
        "CD" => "CDF",
        "DK" => "DKK",
        "DJ" => "DJF",
        "DM" => "XCD",
        "DO" => "DOP",
        "TL" => "USD",
        "EC" => "USD",
        "EG" => "EGP",
        "SV" => "SVC",
        "GQ" => "XAF",
        "ER" => "ERN",
        "EE" => "EEK",
        "ET" => "ETB",
        "FK" => "FKP",
        "FO" => "DKK",
        "FJ" => "FJD",
        "FI" => "EUR",
        "FR" => "EUR",
        "GF" => "EUR",
        "PF" => "XPF",
        "TF" => "EUR",
        "GA" => "XAF",
        "GM" => "GMD",
        "GE" => "GEL",
        "DE" => "EUR",
        "GH" => "GHC",
        "GI" => "GIP",
        "GR" => "EUR",
        "GL" => "DKK",
        "GD" => "XCD",
        "GP" => "EUR",
        "GU" => "USD",
        "GT" => "GTQ",
        "GN" => "GNF",
        "GW" => "XOF",
        "GY" => "GYD",
        "HT" => "HTG",
        "HM" => "AUD",
        "HN" => "HNL",
        "HK" => "HKD",
        "HU" => "HUF",
        "IS" => "ISK",
        "IN" => "INR",
        "ID" => "IDR",
        "IR" => "IRR",
        "IQ" => "IQD",
        "IE" => "EUR",
        "IL" => "ILS",
        "IT" => "EUR",
        "CI" => "XOF",
        "JM" => "JMD",
        "JP" => "JPY",
        "JO" => "JOD",
        "KZ" => "KZT",
        "KE" => "KES",
        "KI" => "AUD",
        "KW" => "KWD",
        "KG" => "KGS",
        "LA" => "LAK",
        "LV" => "LVL",
        "LB" => "LBP",
        "LS" => "LSL",
        "LR" => "LRD",
        "LY" => "LYD",
        "LI" => "CHF",
        "LT" => "LTL",
        "LU" => "EUR",
        "MO" => "MOP",
        "MK" => "MKD",
        "MG" => "MGA",
        "MW" => "MWK",
        "MY" => "MYR",
        "MV" => "MVR",
        "ML" => "XOF",
        "MT" => "MTL",
        "MH" => "USD",
        "MQ" => "EUR",
        "MR" => "MRO",
        "MU" => "MUR",
        "YT" => "EUR",
        "MX" => "MXN",
        "FM" => "USD",
        "MD" => "MDL",
        "MC" => "EUR",
        "MN" => "MNT",
        "MS" => "XCD",
        "MA" => "MAD",
        "MZ" => "MZN",
        "MM" => "MMK",
        "NA" => "NAD",
        "NR" => "AUD",
        "NP" => "NPR",
        "NL" => "EUR",
        "AN" => "ANG",
        "NC" => "XPF",
        "NZ" => "NZD",
        "NI" => "NIO",
        "NE" => "XOF",
        "NG" => "NGN",
        "NU" => "NZD",
        "NF" => "AUD",
        "KP" => "KPW",
        "MP" => "USD",
        "NO" => "NOK",
        "OM" => "OMR",
        "PK" => "PKR",
        "PW" => "USD",
        "PS" => "ILS",
        "PA" => "PAB",
        "PG" => "PGK",
        "PY" => "PYG",
        "PE" => "PEN",
        "PH" => "PHP",
        "PN" => "NZD",
        "PL" => "PLN",
        "PT" => "EUR",
        "PR" => "USD",
        "QA" => "QAR",
        "CG" => "XAF",
        "RE" => "EUR",
        "RO" => "RON",
        "RU" => "RUB",
        "RW" => "RWF",
        "SH" => "SHP",
        "KN" => "XCD",
        "LC" => "XCD",
        "PM" => "EUR",
        "VC" => "XCD",
        "WS" => "WST",
        "SM" => "EUR",
        "ST" => "STD",
        "SA" => "SAR",
        "SN" => "XOF",
        "CS" => "RSD",
        "SC" => "SCR",
        "SL" => "SLL",
        "SG" => "SGD",
        "SK" => "SKK",
        "SI" => "EUR",
        "SB" => "SBD",
        "SO" => "SOS",
        "ZA" => "ZAR",
        "GS" => "GBP",
        "KR" => "KRW",
        "ES" => "EUR",
        "LK" => "LKR",
        "SD" => "SDD",
        "SR" => "SRD",
        "SJ" => "NOK",
        "SZ" => "SZL",
        "SE" => "SEK",
        "CH" => "CHF",
        "SY" => "SYP",
        "TW" => "TWD",
        "TJ" => "TJS",
        "TZ" => "TZS",
        "TH" => "THB",
        "TG" => "XOF",
        "TK" => "NZD",
        "TO" => "TOP",
        "TT" => "TTD",
        "TN" => "TND",
        "TR" => "TRY",
        "TM" => "TMM",
        "TC" => "USD",
        "TV" => "AUD",
        "VI" => "USD",
        "UG" => "UGX",
        "UA" => "UAH",
        "AE" => "AED",
        "GB" => "GBP",
        "US" => "USD",
        "UM" => "USD",
        "UY" => "UYU",
        "UZ" => "UZS",
        "VU" => "VUV",
        "VA" => "EUR",
        "VE" => "VEF",
        "VN" => "VND",
        "WF" => "XPF",
        "EH" => "MAD",
        "YE" => "YER",
        "ZM" => "ZMK",
        "ZW" => "ZWD",
        _ => "",
    }
    .to_string()
}

fn fill_empty_fields_with_geocoder(geo: &mut GeoResponse) {
    if geo.lat != 0.0
        && geo.lon != 0.0
        && (geo.state.is_empty()
            || geo.state_code.is_empty()
            || geo.city.is_empty()
            || geo.district.is_empty()
            || geo.zip.is_none())
    {
        let result = REVERSE_GEOCODER.search((geo.lat, geo.lon));

        if geo.state.is_empty() && !result.record.admin1.is_empty() {
            geo.state = result.record.admin1.clone();
        }

        if geo.state_code.is_empty() && !geo.country_code.is_empty() && !geo.state.is_empty() {
            if let Some(state_code) = get_state_code(&geo.country_code, &geo.state) {
                geo.state_code = state_code;
            }
        }

        if geo.city.is_empty() && !result.record.name.is_empty() {
            geo.city = result.record.name.clone();
        }

        if geo.district.is_empty() && !result.record.admin2.is_empty() {
            geo.district = result.record.admin2.clone();
        }

        if geo.country.is_empty() && !result.record.cc.is_empty() {
            geo.country = result.record.cc.clone();
        }

        if geo.country_code.is_empty() && !result.record.cc.is_empty() {
            geo.country_code = result.record.cc.clone();
            println!("geo.country_code: {}", geo.country_code);
            if geo.state_code.is_empty() && !geo.state.is_empty() {
                if let Some(state_code) = get_state_code(&geo.country_code, &geo.state) {
                    geo.state_code = state_code;
                }
            }
        }
    }
}

async fn download_countries_json() -> io::Result<()> {
    let file_path = get_cache_path(COUNTRIES_JSON_FILE);

    let should_download = if file_path.exists() {
        let mut file = TokioFile::open(&file_path).await?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).await?;

        let json_data: Value = serde_json::from_str(&contents).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse cached data: {}", e),
            )
        })?;

        if let Some(timestamp) = json_data.get("_timestamp").and_then(|t| t.as_i64()) {
            let file_time = chrono::DateTime::from_timestamp(timestamp, 0)
                .unwrap_or(chrono::DateTime::<Utc>::MIN_UTC);
            let now = Utc::now();
            let age = now.signed_duration_since(file_time);

            age > chrono::Duration::from_std(CACHE_EXPIRATION).unwrap()
        } else {
            true
        }
    } else {
        true
    };

    if should_download {
        println!("Downloading {}", COUNTRIES_JSON_URL);

        let response = reqwest::get(COUNTRIES_JSON_URL).await.map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Failed to download: {}", e))
        })?;

        let bytes = response.bytes().await.map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Failed to get bytes: {}", e))
        })?;

        let json_data: Value = serde_json::from_slice(&bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse JSON: {}", e),
            )
        })?;

        let mut country_map = HashMap::new();

        if let Some(obj) = json_data.as_object() {
            for (_, country_value) in obj {
                if let Some(country_obj) = country_value.as_object() {
                    if let (
                        Some(country_name),
                        Some(continent_code),
                        Some(continent_name),
                        Some(country_code2),
                    ) = (
                        country_obj.get("country_name").and_then(|v| v.as_str()),
                        country_obj.get("continent_code").and_then(|v| v.as_str()),
                        country_obj.get("continent_name").and_then(|v| v.as_str()),
                        country_obj.get("country_code2").and_then(|v| v.as_str()),
                    ) {
                        country_map.insert(
                            country_name.to_string(),
                            CountryInfo {
                                continent_code: continent_code.to_string(),
                                continent_name: continent_name.to_string(),
                                country_code2: country_code2.to_string(),
                            },
                        );
                    }
                }
            }
        }

        let mut final_json = serde_json::Map::new();
        final_json.insert("_timestamp".to_string(), json!(Utc::now().timestamp()));
        final_json.insert("data".to_string(), json!(country_map));

        let json_str = serde_json::to_string(&final_json).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Failed to serialize: {}", e))
        })?;

        let mut file = TokioFile::create(&file_path).await?;
        file.write_all(json_str.as_bytes()).await?;

        let mut cache = COUNTRY_DATA.write().unwrap();
        *cache = country_map;
    } else {
        let mut file = TokioFile::open(&file_path).await?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).await?;

        let json_data: Value = serde_json::from_str(&contents).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse cached data: {}", e),
            )
        })?;

        let country_map: HashMap<String, CountryInfo> = if let Some(data) = json_data.get("data") {
            serde_json::from_value(data.clone()).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to parse country data: {}", e),
                )
            })?
        } else {
            serde_json::from_value(json_data.clone()).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to parse country data: {}", e),
                )
            })?
        };

        let mut cache = COUNTRY_DATA.write().unwrap();
        *cache = country_map;
    }

    Ok(())
}

fn fill_country_continent_data(geo: &mut GeoResponse) {
    if !geo.country.is_empty()
        && (geo.country_code.is_empty()
            || geo.continent.is_empty()
            || geo.continent_code.is_empty())
    {
        let cache = COUNTRY_DATA.read().unwrap();
        if let Some(country_info) = cache.get(&geo.country) {
            if geo.country_code.is_empty() {
                geo.country_code = country_info.country_code2.clone();
            }
            if geo.continent_code.is_empty() {
                geo.continent_code = country_info.continent_code.clone();
            }
            if geo.continent.is_empty() {
                geo.continent = country_info.continent_name.clone();
            }
        }
    }

    if !geo.country_code.is_empty()
        && (geo.country.is_empty() || geo.continent.is_empty() || geo.continent_code.is_empty())
    {
        let cache = COUNTRY_DATA.read().unwrap();
        for (country_name, country_info) in cache.iter() {
            if country_info.country_code2 == geo.country_code {
                if geo.country.is_empty() {
                    geo.country = country_name.clone();
                }
                if geo.continent_code.is_empty() {
                    geo.continent_code = country_info.continent_code.clone();
                }
                if geo.continent.is_empty() {
                    geo.continent = country_info.continent_name.clone();
                }
                break;
            }
        }
    }
}

async fn download_zip_codes() -> io::Result<()> {
    let file_path = get_cache_path(ZIP_CODES_FILE);

    let should_download = if file_path.exists() {
        let mut file = TokioFile::open(&file_path).await?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).await?;

        if contents.starts_with("{") {
            if let Ok(json_data) = serde_json::from_str::<Value>(&contents) {
                if let Some(timestamp) = json_data.get("_timestamp").and_then(|t| t.as_i64()) {
                    let file_time = chrono::DateTime::from_timestamp(timestamp, 0)
                        .unwrap_or(chrono::DateTime::<Utc>::MIN_UTC);
                    let now = Utc::now();
                    let age = now.signed_duration_since(file_time);

                    age > chrono::Duration::from_std(CACHE_EXPIRATION).unwrap()
                } else {
                    true
                }
            } else {
                true
            }
        } else {
            true
        }
    } else {
        true
    };

    if should_download {
        println!("Downloading {}", ZIP_CODES_URL);

        let response = reqwest::get(ZIP_CODES_URL).await.map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Failed to download: {}", e))
        })?;

        let bytes = response.bytes().await.map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Failed to get bytes: {}", e))
        })?;

        let content = String::from_utf8(bytes.to_vec()).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("Invalid UTF-8: {}", e))
        })?;

        let mut zip_map: HashMap<String, Vec<ZipCodeEntry>> = HashMap::new();
        let mut csv_reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .from_reader(content.as_bytes());

        for result in csv_reader.records() {
            if let Ok(record) = result {
                if record.len() >= 7 {
                    let zip_code = record.get(0).unwrap_or("").trim().to_string();
                    let city = record.get(2).unwrap_or("").trim().to_uppercase();
                    let state = record.get(3).unwrap_or("").trim().to_uppercase();

                    let lat: f64 = record.get(5).unwrap_or("0").parse().unwrap_or(0.0);
                    let lon: f64 = record.get(6).unwrap_or("0").parse().unwrap_or(0.0);

                    if !city.is_empty() && !state.is_empty() && !zip_code.is_empty() {
                        let key = format!("{}_{}", city, state);
                        let entry = ZipCodeEntry {
                            zip_code,
                            city: city.clone(),
                            state: state.clone(),
                            lat,
                            lon,
                        };

                        zip_map.entry(key).or_insert_with(Vec::new).push(entry);
                    }
                }
            }
        }

        let mut final_json = serde_json::Map::new();
        final_json.insert("_timestamp".to_string(), json!(Utc::now().timestamp()));
        final_json.insert("csv_data".to_string(), json!(content));

        let json_str = serde_json::to_string(&final_json).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Failed to serialize: {}", e))
        })?;

        let mut file = TokioFile::create(&file_path).await?;
        file.write_all(json_str.as_bytes()).await?;

        let mut cache = ZIP_CODES.write().unwrap();
        *cache = zip_map;
    } else {
        let mut file = TokioFile::open(&file_path).await?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).await?;

        let json_data: Value = serde_json::from_str(&contents).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse cached data: {}", e),
            )
        })?;

        let csv_data = if let Some(data) = json_data.get("csv_data").and_then(|d| d.as_str()) {
            data
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Missing CSV data in cache file",
            ));
        };

        let mut zip_map: HashMap<String, Vec<ZipCodeEntry>> = HashMap::new();
        let mut csv_reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .from_reader(csv_data.as_bytes());

        for result in csv_reader.records() {
            if let Ok(record) = result {
                if record.len() >= 7 {
                    let zip_code = record.get(0).unwrap_or("").trim().to_string();
                    let city = record.get(2).unwrap_or("").trim().to_uppercase();
                    let state = record.get(3).unwrap_or("").trim().to_uppercase();

                    let lat: f64 = record.get(5).unwrap_or("0").parse().unwrap_or(0.0);
                    let lon: f64 = record.get(6).unwrap_or("0").parse().unwrap_or(0.0);

                    if !city.is_empty() && !state.is_empty() && !zip_code.is_empty() {
                        let key = format!("{}_{}", city, state);
                        let entry = ZipCodeEntry {
                            zip_code,
                            city: city.clone(),
                            state: state.clone(),
                            lat,
                            lon,
                        };

                        zip_map.entry(key).or_insert_with(Vec::new).push(entry);
                    }
                }
            }
        }

        let mut cache = ZIP_CODES.write().unwrap();
        *cache = zip_map;
    }

    Ok(())
}

pub fn get_us_zip_code(city: &str, state: Option<&str>) -> Option<String> {
    if city.is_empty() {
        return None;
    }

    let city_upper = city.trim().to_uppercase();
    let cache = ZIP_CODES.read().unwrap();

    if let Some(state_code) = state {
        let state_upper = state_code.trim().to_uppercase();
        let key = format!("{}_{}", city_upper, state_upper);

        if let Some(entries) = cache.get(&key) {
            if !entries.is_empty() {
                for entry in entries.iter() {
                    if entry.zip_code.len() == 5 {
                        return Some(entry.zip_code.clone());
                    }
                }
                return Some(entries[0].zip_code.clone());
            }
        }
    }

    for (key, entries) in cache.iter() {
        if key.starts_with(&format!("{}_", city_upper)) && !entries.is_empty() {
            for entry in entries.iter() {
                if entry.zip_code.len() == 5 {
                    return Some(entry.zip_code.clone());
                }
            }
            return Some(entries[0].zip_code.clone());
        }
    }

    None
}

fn fill_zip_code(geo: &mut GeoResponse) {
    if geo.zip.is_none() && !geo.city.is_empty() && geo.country_code == "US" {
        let state_code = if !geo.state_code.is_empty() {
            Some(geo.state_code.as_str())
        } else {
            None
        };

        if let Some(zip) = get_us_zip_code(&geo.city, state_code) {
            if let Ok(zip_num) = zip.parse::<u32>() {
                geo.zip = Some(zip_num);
            }
        }
    }
}

pub async fn get_geo_data(ip: std::net::IpAddr) -> Result<GeoResponse, String> {
    let cache = DATABASES.read().unwrap();

    let city_db = match &cache.city_db {
        Some(db) => db,
        None => {
            return Err("City database not available".to_string());
        }
    };

    let asn_db = match &cache.asn_db {
        Some(db) => db,
        None => {
            return Err("ASN database not available".to_string());
        }
    };

    let city_lookup_result = city_db.lookup(ip);
    let city_data: maxminddb::geoip2::City = match city_lookup_result {
        Ok(Some(data)) => data,
        Ok(None) => {
            return Err("IP not found in City database".to_string());
        }
        Err(e) => {
            return Err(format!("IP not found: {}", e));
        }
    };

    let asn_lookup_result = asn_db.lookup(ip);
    let asn_data: maxminddb::geoip2::Asn = match asn_lookup_result {
        Ok(Some(data)) => data,
        Ok(None) => {
            return Err("IP not found in ASN database".to_string());
        }
        Err(_) => {
            return Err("IP not found in ASN database".to_string());
        }
    };

    let mut geo = GeoResponse::new();

    geo.isp = asn_data
        .autonomous_system_organization
        .unwrap_or_default()
        .to_string();
    geo.org = asn_data
        .autonomous_system_organization
        .unwrap_or_default()
        .to_string();
    geo.as_name = asn_data
        .autonomous_system_organization
        .unwrap_or_default()
        .to_string();
    geo.as_code = asn_data.autonomous_system_number.unwrap_or(0);

    extract_city_info(&city_data, &mut geo);

    geo.currency = get_currency_from_country(&geo.country_code);

    fill_empty_fields_with_geocoder(&mut geo);

    fill_country_continent_data(&mut geo);

    fill_zip_code(&mut geo);

    Ok(geo)
}
