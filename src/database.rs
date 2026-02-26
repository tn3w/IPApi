use crate::IPResponse;
use redis::AsyncCommands;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

type Range2 = (u128, u128);
type Range4 = (u128, u128, f64, f64);
type Range5 = (u128, u128, usize, usize, usize);

type BlocklistRanges = Vec<Range2>;

pub struct DatabaseManager {
    data_dir: PathBuf,
    geo: RwLock<Vec<Range4>>,
    proxy: RwLock<HashMap<String, Vec<Range2>>>,
    asn_str: RwLock<Vec<String>>,
    asn: RwLock<Vec<Range5>>,
    isp_str: RwLock<Vec<String>>,
    isp: RwLock<Vec<Range5>>,
    isp_u16: RwLock<bool>,
    blocklist: RwLock<HashMap<String, BlocklistRanges>>,
    last_refresh: RwLock<Option<u64>>,
    resolver: Arc<TokioAsyncResolver>,
    redis: redis::aio::ConnectionManager,
}

impl DatabaseManager {
    pub fn new(redis: redis::aio::ConnectionManager) -> Self {
        let mut config = ResolverConfig::new();
        for server in ["1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"] {
            if let Ok(addr) = server.parse() {
                config.add_name_server(NameServerConfig {
                    socket_addr: addr,
                    protocol: Protocol::Udp,
                    tls_dns_name: None,
                    trust_negative_responses: true,
                    bind_addr: None,
                });
            }
        }

        let resolver = Arc::new(TokioAsyncResolver::tokio(config, ResolverOpts::default()));

        Self {
            data_dir: PathBuf::from("data"),
            geo: RwLock::new(Vec::new()),
            proxy: RwLock::new(HashMap::new()),
            asn_str: RwLock::new(Vec::new()),
            asn: RwLock::new(Vec::new()),
            isp_str: RwLock::new(Vec::new()),
            isp: RwLock::new(Vec::new()),
            isp_u16: RwLock::new(true),
            blocklist: RwLock::new(HashMap::new()),
            last_refresh: RwLock::new(None),
            resolver,
            redis,
        }
    }

    pub async fn initialize(&self) {
        tokio::fs::create_dir_all(&self.data_dir).await.ok();

        if self.all_exist() {
            self.load_all();
            let mtime = self.oldest_mtime();
            *self.last_refresh.write().unwrap() = Some(mtime);

            if now() - mtime > 86400 {
                tokio::spawn({
                    let db = Arc::new(Self::new(self.redis.clone()));
                    async move {
                        db.download().await;
                    }
                });
            }
        } else if self.should_refresh() {
            self.download_and_reload().await;
        }
    }

    pub fn should_refresh(&self) -> bool {
        self.last_refresh
            .read()
            .unwrap()
            .is_none_or(|t| now() - t > 86400)
    }

    pub fn last_refresh(&self) -> Option<u64> {
        *self.last_refresh.read().unwrap()
    }

    pub async fn download_and_reload(&self) {
        self.download().await;
        self.load_all();
        *self.last_refresh.write().unwrap() = Some(now());
    }

    pub async fn lookup_async(&self, ip: &IpAddr) -> (IPResponse, u64, u64) {
        let (mut result, mut search_count, elapsed) = self.lookup(ip);

        if matches!(result.classification.as_str(), "public" | "ipv4_mapped") {
            if let Some(lookup) = result.ipv4.as_ref().or(result.ipv6.as_ref()) {
                if let Some(host) = self.reverse_dns_cached(lookup).await {
                    result.hostname = Some(host.clone());

                    let is_mapped = result.classification == "ipv4_mapped";
                    let needs_v4 = result.ipv4.is_none();
                    let needs_v6 = result.ipv6.is_none() || is_mapped;

                    if needs_v4 || needs_v6 {
                        let (v4_opt, v6_opt) = tokio::join!(
                            async {
                                if needs_v4 {
                                    self.v4_from_hostname_cached(&host).await
                                } else {
                                    None
                                }
                            },
                            async {
                                if needs_v6 {
                                    self.v6_from_hostname_cached(&host).await
                                } else {
                                    None
                                }
                            }
                        );

                        let (v4_blocks, v6_blocks) =
                            self.check_additional_ips(v4_opt, v6_opt, &mut result).await;
                        search_count += v4_blocks + v6_blocks;
                    }
                }
            }
        } else if result.classification == "loopback" {
            result.hostname = Some(
                if matches!(ip, IpAddr::V4(_)) {
                    "localhost"
                } else {
                    "ip6-localhost"
                }
                .into(),
            );
        }

        (result, search_count, elapsed)
    }

    pub async fn lookup_domain(&self, hostname: &str) -> Result<(IPResponse, u64, u64), String> {
        let start = Instant::now();
        let mut search_count = 0u64;

        let (v4_opt, v6_opt) = tokio::join!(
            self.v4_from_hostname_cached(hostname),
            self.v6_from_hostname_cached(hostname)
        );

        if v4_opt.is_none() && v6_opt.is_none() {
            return Err("Unable to resolve hostname".to_string());
        }

        let primary_ip = if let Some(ref v4) = v4_opt {
            v4.parse::<IpAddr>().ok()
        } else {
            v6_opt.as_ref().and_then(|v6| v6.parse::<IpAddr>().ok())
        };

        let Some(ip) = primary_ip else {
            return Err("Invalid IP address resolved".to_string());
        };

        let (mut result, count, _) = self.lookup(&ip);
        search_count += count;

        result.hostname = Some(hostname.to_string());
        result.ipv4 = v4_opt.clone();
        result.ipv6 = v6_opt.clone();

        let (v4_blocks, v6_blocks) = self.check_additional_ips(v4_opt, v6_opt, &mut result).await;
        search_count += v4_blocks + v6_blocks;

        let elapsed = start.elapsed().as_micros() as u64;
        Ok((result, search_count, elapsed))
    }

    async fn check_additional_ips(
        &self,
        v4_opt: Option<String>,
        v6_opt: Option<String>,
        result: &mut IPResponse,
    ) -> (u64, u64) {
        let blocklist = self.blocklist.read().unwrap();
        let mut v4_count = 0u64;
        let mut v6_count = 0u64;

        if let Some(v4) = v4_opt {
            result.ipv4 = Some(v4.clone());
            if let Ok(addr) = v4.parse::<Ipv4Addr>() {
                let (new_blocks, count) = check_blocks(&blocklist, to_int_plain(&IpAddr::V4(addr)));
                v4_count = count;
                result.blocklists.extend(new_blocks);
            }
        }

        if let Some(v6) = v6_opt {
            result.ipv6 = Some(v6.clone());
            if let Ok(addr) = v6.parse::<Ipv6Addr>() {
                let (new_blocks, count) = check_blocks(&blocklist, to_int_plain(&IpAddr::V6(addr)));
                v6_count = count;
                result.blocklists.extend(new_blocks);
            }
        }

        result.blocklists.sort_unstable();
        result.blocklists.dedup();

        (v4_count, v6_count)
    }

    async fn reverse_dns_cached(&self, ip: &str) -> Option<String> {
        let key = format!("dns:ptr:{}", ip);
        let mut conn = self.redis.clone();

        if let Ok(cached) = conn.get::<_, String>(&key).await {
            return Some(cached);
        }

        let addr = ip.parse::<IpAddr>().ok()?;
        let result = self
            .resolver
            .reverse_lookup(addr)
            .await
            .ok()?
            .iter()
            .next()
            .map(|n| n.to_string().trim_end_matches('.').to_string())?;

        let _: Result<(), _> = conn.set_ex(&key, &result, 3600).await;
        Some(result)
    }

    async fn v4_from_hostname_cached(&self, hostname: &str) -> Option<String> {
        let key = format!("dns:a:{}", hostname);
        let mut conn = self.redis.clone();

        if let Ok(cached) = conn.get::<_, String>(&key).await {
            return Some(cached);
        }

        let result = self
            .resolver
            .ipv4_lookup(hostname)
            .await
            .ok()?
            .iter()
            .next()
            .map(|ip| ip.to_string())?;

        let _: Result<(), _> = conn.set_ex(&key, &result, 3600).await;
        Some(result)
    }

    async fn v6_from_hostname_cached(&self, hostname: &str) -> Option<String> {
        let key = format!("dns:aaaa:{}", hostname);
        let mut conn = self.redis.clone();

        if let Ok(cached) = conn.get::<_, String>(&key).await {
            return Some(cached);
        }

        let result = self
            .resolver
            .ipv6_lookup(hostname)
            .await
            .ok()?
            .iter()
            .next()
            .map(|ip| ip.to_string())?;

        let _: Result<(), _> = conn.set_ex(&key, &result, 3600).await;
        Some(result)
    }

    fn lookup(&self, ip: &IpAddr) -> (IPResponse, u64, u64) {
        let start = Instant::now();
        let mut search_count = 0u64;
        let (ipv4, ipv6, lookup, extracted_v4, is_mapped) = match ip {
            IpAddr::V4(v4) => (Some(v4.to_string()), None, *ip, None, false),
            IpAddr::V6(v6) => {
                let v4 = extract_ipv4(v6);
                let is_mapped = v4.is_some();
                (
                    v4.as_ref().map(ToString::to_string),
                    if is_mapped {
                        None
                    } else {
                        Some(v6.to_string())
                    },
                    v4.map(IpAddr::V4).unwrap_or(*ip),
                    v4,
                    is_mapped,
                )
            }
        };

        let target = to_int(&lookup);
        let classification = classify(ip);
        let public = matches!(classification.as_str(), "public" | "ipv4_mapped");

        let mut resp = IPResponse {
            ipv4: ipv4.clone(),
            ipv6: ipv6.clone(),
            ip_type: if matches!(ip, IpAddr::V4(_)) || is_mapped {
                4
            } else {
                6
            },
            classification,
            ..Default::default()
        };

        if public {
            let geo = self.geo.read().unwrap();
            let (idx_opt, count) = search4(&geo, target);
            search_count += count;
            if let Some(idx) = idx_opt {
                let g = &geo[idx];
                resp.latitude = Some(g.2);
                resp.longitude = Some(g.3);
            }
            drop(geo);

            if let (Some(lat), Some(lon)) = (resp.latitude, resp.longitude) {
                if let Some(p) = genom::lookup(lat, lon) {
                    resp.latitude = Some(p.latitude);
                    resp.longitude = Some(p.longitude);
                    resp.city = Some(p.city);
                    resp.region = Some(p.region);
                    resp.region_code = Some(p.region_code);
                    resp.district = Some(p.district);
                    resp.postal_code = Some(p.postal_code);
                    resp.country_code = Some(p.country_code);
                    resp.country_name = Some(p.country_name);
                    resp.continent_code = Some(p.continent_code);
                    resp.continent_name = Some(p.continent_name);
                    resp.is_eu = Some(p.is_eu);
                    resp.timezone = Some(p.timezone);
                    resp.timezone_abbr = Some(p.timezone_abbr);
                    resp.utc_offset = Some(p.utc_offset);
                    resp.utc_offset_str = Some(p.utc_offset_str);
                    resp.dst_active = Some(p.dst_active);
                    resp.currency = Some(p.currency);
                }
            }

            let asn = self.asn.read().unwrap();
            let asn_str = self.asn_str.read().unwrap();
            let (idx_opt, count) = search5(&asn, target);
            search_count += count;
            if let Some(idx) = idx_opt {
                let a = &asn[idx];
                resp.cidr = Some(asn_str[a.2].clone());
                resp.asn = Some(asn_str[a.3].clone());
                resp.as_name = Some(asn_str[a.4].clone());
            }
            drop(asn);
            drop(asn_str);

            let proxy = self.proxy.read().unwrap();
            for (name, ranges) in proxy.iter() {
                let (idx_opt, count) = search2(ranges, target);
                search_count += count;
                if idx_opt.is_some() {
                    resp.proxy_type = Some(name.clone());
                    break;
                }
            }
            drop(proxy);

            let isp = self.isp.read().unwrap();
            let isp_str = self.isp_str.read().unwrap();
            let (idx_opt, count) = search5(&isp, target);
            search_count += count;
            if let Some(idx) = idx_opt {
                let i = &isp[idx];
                if &isp_str[i.2] != "-" {
                    resp.isp = Some(isp_str[i.2].clone());
                }
                if &isp_str[i.3] != "-" {
                    resp.domain = Some(isp_str[i.3].clone());
                }
                if &isp_str[i.4] != "-" {
                    resp.provider = Some(isp_str[i.4].clone());
                }
            }
            drop(isp);
            drop(isp_str);
        }

        let blocklist = self.blocklist.read().unwrap();
        let mut blocks = Vec::new();

        match ip {
            IpAddr::V4(v4) => {
                let (new_blocks, count) = check_blocks(&blocklist, to_int_plain(&IpAddr::V4(*v4)));
                search_count += count;
                blocks.extend(new_blocks);
            }
            IpAddr::V6(v6) => {
                if let Some(v4) = extracted_v4 {
                    let (new_blocks, count) =
                        check_blocks(&blocklist, to_int_plain(&IpAddr::V4(v4)));
                    search_count += count;
                    blocks.extend(new_blocks);
                }
                let (new_blocks, count) = check_blocks(&blocklist, to_int_plain(&IpAddr::V6(*v6)));
                search_count += count;
                blocks.extend(new_blocks);
            }
        }

        blocks.sort_unstable();
        blocks.dedup();
        resp.blocklists = blocks;

        let elapsed = start.elapsed().as_micros() as u64;
        (resp, search_count, elapsed)
    }

    fn all_exist(&self) -> bool {
        [
            "geo.bin",
            "proxy_types.bin",
            "asn.bin",
            "isp.bin",
            "blocklist.bin",
        ]
        .iter()
        .all(|f| self.data_dir.join(f).exists())
    }

    fn oldest_mtime(&self) -> u64 {
        [
            "geo.bin",
            "proxy_types.bin",
            "asn.bin",
            "isp.bin",
            "blocklist.bin",
        ]
        .iter()
        .filter_map(|f| {
            std::fs::metadata(self.data_dir.join(f))
                .ok()?
                .modified()
                .ok()?
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs())
        })
        .min()
        .unwrap_or(0)
    }

    async fn download(&self) {
        let base = "https://github.com/tn3w/IP2X/releases/latest/download";
        let urls = [
            (format!("{}/geo.bin", base), "geo.bin"),
            (format!("{}/proxy_types.bin", base), "proxy_types.bin"),
            (format!("{}/asn.bin", base), "asn.bin"),
            (format!("{}/isp.bin", base), "isp.bin"),
            (
                "https://github.com/tn3w/IPBlocklist/releases/latest/download/blocklist.bin".into(),
                "blocklist.bin",
            ),
        ];

        let client = reqwest::Client::new();
        for (url, name) in urls {
            if let Ok(resp) = client.get(&url).send().await {
                if let Ok(bytes) = resp.bytes().await {
                    if let Ok(mut f) = std::fs::File::create(self.data_dir.join(name)) {
                        f.write_all(&bytes).ok();
                    }
                }
            }
        }
    }

    fn load_all(&self) {
        self.load_geo();
        self.load_proxy();
        self.load_asn();
        self.load_isp();
        self.load_blocklist();
    }

    fn load_geo(&self) {
        let Ok(f) = File::open(self.data_dir.join("geo.bin")) else {
            return;
        };
        let mut r = BufReader::new(f);
        let count = u32(&mut r) as usize;
        let mut ranges = Vec::with_capacity(count);
        let mut cur = 0u128;

        for _ in 0..count {
            cur += varint(&mut r);
            let size = varint(&mut r);
            let lat = i32(&mut r) as f64 / 1000.0;
            let lon = i32(&mut r) as f64 / 1000.0;
            ranges.push((cur, cur + size, lat, lon));
        }

        *self.geo.write().unwrap() = ranges;
    }

    fn load_proxy(&self) {
        let Ok(f) = File::open(self.data_dir.join("proxy_types.bin")) else {
            return;
        };
        let mut r = BufReader::new(f);
        let type_count = u16(&mut r) as usize;
        let mut types = HashMap::new();

        for _ in 0..type_count {
            let name_len = u8(&mut r) as usize;
            let name = string(&mut r, name_len);
            let range_count = u32(&mut r) as usize;
            let mut ranges = Vec::with_capacity(range_count);
            let mut cur = 0u128;

            for _ in 0..range_count {
                cur += varint(&mut r);
                let size = varint(&mut r);
                ranges.push((cur, cur + size));
            }

            types.insert(name, ranges);
        }

        *self.proxy.write().unwrap() = types;
    }

    fn load_asn(&self) {
        let Ok(f) = File::open(self.data_dir.join("asn.bin")) else {
            return;
        };
        let mut r = BufReader::new(f);
        let str_count = u32(&mut r) as usize;
        let mut strings = Vec::with_capacity(str_count);
        for _ in 0..str_count {
            let len = u16(&mut r) as usize;
            strings.push(string(&mut r, len));
        }

        let range_count = u32(&mut r) as usize;
        let mut ranges = Vec::with_capacity(range_count);
        let (mut cur, mut cidr, mut asn, mut name) = (0u128, 0i128, 0i128, 0i128);

        for _ in 0..range_count {
            cur += varint(&mut r);
            let size = varint(&mut r);
            cidr += svarint(&mut r);
            asn += svarint(&mut r);
            name += svarint(&mut r);
            ranges.push((cur, cur + size, cidr as usize, asn as usize, name as usize));
        }

        *self.asn_str.write().unwrap() = strings;
        *self.asn.write().unwrap() = ranges;
    }

    fn load_isp(&self) {
        let Ok(f) = File::open(self.data_dir.join("isp.bin")) else {
            return;
        };
        let mut r = BufReader::new(f);
        let str_count = u32(&mut r) as usize;
        let mut strings = Vec::with_capacity(str_count);
        for _ in 0..str_count {
            let len = u16(&mut r) as usize;
            strings.push(if len == 0 {
                "-".into()
            } else {
                string(&mut r, len)
            });
        }

        let use_u16 = str_count < 65536;
        *self.isp_u16.write().unwrap() = use_u16;

        let range_count = u32(&mut r) as usize;
        let mut ranges = Vec::with_capacity(range_count);
        let mut cur = 0u128;

        for _ in 0..range_count {
            cur += varint(&mut r);
            let size = varint(&mut r);
            let (isp, dom, prov) = if use_u16 {
                (
                    u16(&mut r) as usize,
                    u16(&mut r) as usize,
                    u16(&mut r) as usize,
                )
            } else {
                (
                    u32(&mut r) as usize,
                    u32(&mut r) as usize,
                    u32(&mut r) as usize,
                )
            };
            ranges.push((cur, cur + size, isp, dom, prov));
        }

        *self.isp_str.write().unwrap() = strings;
        *self.isp.write().unwrap() = ranges;
    }

    fn load_blocklist(&self) {
        let Ok(f) = File::open(self.data_dir.join("blocklist.bin")) else {
            return;
        };
        let mut r = BufReader::new(f);

        let _timestamp = u32(&mut r);
        let feed_count = u16(&mut r) as usize;
        let mut feeds = HashMap::new();

        for _ in 0..feed_count {
            let name_len = u8(&mut r) as usize;
            let name = string(&mut r, name_len);
            let range_count = u32(&mut r) as usize;
            let mut ranges = Vec::with_capacity(range_count);
            let mut cur = 0u128;

            for _ in 0..range_count {
                cur += varint(&mut r);
                let size = varint(&mut r);
                ranges.push((cur, cur + size));
            }

            feeds.insert(name, ranges);
        }

        *self.blocklist.write().unwrap() = feeds;
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn to_int(ip: &IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            (0xFFFF_u128 << 32)
                | ((o[0] as u128) << 24)
                | ((o[1] as u128) << 16)
                | ((o[2] as u128) << 8)
                | (o[3] as u128)
        }
        IpAddr::V6(v6) => v6
            .segments()
            .iter()
            .fold(0u128, |acc, &s| (acc << 16) | s as u128),
    }
}

fn to_int_plain(ip: &IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            ((o[0] as u128) << 24) | ((o[1] as u128) << 16) | ((o[2] as u128) << 8) | (o[3] as u128)
        }
        IpAddr::V6(v6) => v6
            .segments()
            .iter()
            .fold(0u128, |acc, &s| (acc << 16) | s as u128),
    }
}

fn search2(ranges: &[Range2], target: u128) -> (Option<usize>, u64) {
    let (mut left, mut right) = (0, ranges.len());
    let (mut best, mut best_size) = (None, u128::MAX);
    let mut count = 0u64;

    while left < right {
        let mid = (left + right) / 2;
        let (start, end) = ranges[mid];
        count += 1;

        if start <= target && target <= end {
            let size = end - start;
            if size < best_size {
                best_size = size;
                best = Some(mid);
            }
            left = mid + 1;
        } else if target < start {
            right = mid;
        } else {
            left = mid + 1;
        }
    }

    (best, count)
}

fn search4(ranges: &[Range4], target: u128) -> (Option<usize>, u64) {
    let (mut left, mut right) = (0, ranges.len());
    let (mut best, mut best_size) = (None, u128::MAX);
    let mut count = 0u64;

    while left < right {
        let mid = (left + right) / 2;
        let (start, end, _, _) = ranges[mid];
        count += 1;

        if start <= target && target <= end {
            let size = end - start;
            if size < best_size {
                best_size = size;
                best = Some(mid);
            }
            left = mid + 1;
        } else if target < start {
            right = mid;
        } else {
            left = mid + 1;
        }
    }

    (best, count)
}

fn search5(ranges: &[Range5], target: u128) -> (Option<usize>, u64) {
    let (mut left, mut right) = (0, ranges.len());
    let (mut best, mut best_size) = (None, u128::MAX);
    let mut count = 0u64;

    while left < right {
        let mid = (left + right) / 2;
        let (start, end, _, _, _) = ranges[mid];
        count += 1;

        if start <= target && target <= end {
            let size = end - start;
            if size < best_size {
                best_size = size;
                best = Some(mid);
            }
            left = mid + 1;
        } else if target < start {
            right = mid;
        } else {
            left = mid + 1;
        }
    }

    (best, count)
}

fn extract_ipv4(addr: &Ipv6Addr) -> Option<Ipv4Addr> {
    if addr.is_loopback() {
        return Some(Ipv4Addr::new(127, 0, 0, 1));
    }

    if let Some(v4) = addr.to_ipv4_mapped() {
        return Some(v4);
    }

    let s = addr.segments();
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::new(
            (s[1] >> 8) as u8,
            (s[1] & 0xFF) as u8,
            (s[2] >> 8) as u8,
            (s[2] & 0xFF) as u8,
        ));
    }

    None
}

fn classify(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                "loopback"
            } else if v4.is_private() {
                "private"
            } else if v4.is_multicast() {
                "multicast"
            } else if v4.is_link_local() {
                "link_local"
            } else if reserved_v4(v4) {
                "reserved"
            } else {
                "public"
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                "loopback"
            } else if v6.to_ipv4_mapped().is_some() {
                "ipv4_mapped"
            } else if v6.is_multicast() {
                "multicast"
            } else if reserved_v6(v6) {
                "reserved"
            } else {
                "public"
            }
        }
    }
    .into()
}

fn reserved_v4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 0
        || o[0] == 10
        || (o[0] == 100 && (o[1] & 0xC0) == 64)
        || o[0] == 127
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 172 && (o[1] & 0xF0) == 16)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        || (o[0] & 0xF0) == 224
        || (o[0] & 0xF0) == 240
}

fn reserved_v6(ip: &Ipv6Addr) -> bool {
    if ip.is_unspecified() {
        return true;
    }

    let s = ip.segments();

    s[0] == 0
        && s[1] == 0
        && s[2] == 0
        && s[3] == 0
        && s[4] == 0
        && s[5] == 0
        && s[6] == 0
        && s[7] == 1
        || (s[0] == 0x0100 && s[1] == 0)
        || (s[0] == 0x2001 && s[1] == 0x0DB8)
        || (s[0] == 0x2001 && (s[1] & 0xFFF0) == 0x0010)
        || (s[0] & 0xFE00) == 0xFC00
        || (s[0] & 0xFFC0) == 0xFE80
        || (s[0] & 0xFFC0) == 0xFEC0
        || (s[0] & 0xFF00) == 0xFF00
        || (s[0] == 0x2002 && s[1] == 0)
        || (s[0] == 0x2002 && s[1] == 0x0A00)
        || (s[0] == 0x2002 && s[1] == 0x7F00)
        || (s[0] == 0x2002 && s[1] == 0xA9FE)
        || (s[0] == 0x2002 && (s[1] & 0xFFF0) == 0xAC10)
        || (s[0] == 0x2002 && s[1] == 0xC000 && s[2] == 0)
        || (s[0] == 0x2002 && s[1] == 0xC000 && s[2] == 0x0200)
        || (s[0] == 0x2002 && s[1] == 0xC0A8)
        || (s[0] == 0x2002 && (s[1] == 0xC612 || s[1] == 0xC613))
        || (s[0] == 0x2002 && s[1] == 0xC633 && s[2] == 0x6400)
        || (s[0] == 0x2002 && s[1] == 0xCB00 && s[2] == 0x7100)
        || (s[0] == 0x2002 && (s[1] & 0xF000) == 0xE000)
        || (s[0] == 0x2002 && (s[1] & 0xF000) == 0xF000)
        || (s[0] == 0x2002 && s[1] == 0xFFFF && s[2] == 0xFFFF)
        || (s[0] == 0x2001 && s[1] == 0 && s[2] == 0)
        || (s[0] == 0x2001 && s[1] == 0 && s[2] == 0x0A00)
        || (s[0] == 0x2001 && s[1] == 0 && s[2] == 0x7F00)
        || (s[0] == 0x2001 && s[1] == 0 && s[2] == 0xA9FE)
        || (s[0] == 0x2001 && s[1] == 0 && (s[2] & 0xFFF0) == 0xAC10)
        || (s[0] == 0x2001 && s[1] == 0 && s[2] == 0xC000 && s[3] == 0)
        || (s[0] == 0x2001 && s[1] == 0 && s[2] == 0xC000 && s[3] == 0x0200)
        || (s[0] == 0x2001 && s[1] == 0 && s[2] == 0xC0A8)
        || (s[0] == 0x2001 && s[1] == 0 && (s[2] == 0xC612 || s[2] == 0xC613))
        || (s[0] == 0x2001 && s[1] == 0 && s[2] == 0xC633 && s[3] == 0x6400)
        || (s[0] == 0x2001 && s[1] == 0 && s[2] == 0xCB00 && s[3] == 0x7100)
        || (s[0] == 0x2001 && s[1] == 0 && (s[2] & 0xF000) == 0xE000)
        || (s[0] == 0x2001 && s[1] == 0 && (s[2] & 0xF000) == 0xF000)
        || (s[0] == 0x2001 && s[1] == 0 && s[2] == 0xFFFF && s[3] == 0xFFFF)
}

fn check_blocks(feeds: &HashMap<String, BlocklistRanges>, target: u128) -> (Vec<String>, u64) {
    let mut total_count = 0u64;
    let result = feeds
        .iter()
        .filter_map(|(name, ranges)| {
            let (idx_opt, count) = search2(ranges, target);
            total_count += count;
            if idx_opt.is_some() {
                Some(name.clone())
            } else {
                None
            }
        })
        .collect();
    (result, total_count)
}

fn u8<R: Read>(r: &mut R) -> u8 {
    let mut buf = [0u8; 1];
    r.read_exact(&mut buf).unwrap();
    buf[0]
}

fn u16<R: Read>(r: &mut R) -> u16 {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf).unwrap();
    u16::from_le_bytes(buf)
}

fn u32<R: Read>(r: &mut R) -> u32 {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf).unwrap();
    u32::from_le_bytes(buf)
}

fn i32<R: Read>(r: &mut R) -> i32 {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf).unwrap();
    i32::from_le_bytes(buf)
}

fn varint<R: Read>(r: &mut R) -> u128 {
    let mut result = 0u128;
    let mut shift = 0;
    loop {
        let byte = u8(r);
        result |= ((byte & 0x7F) as u128) << shift;
        if byte & 0x80 == 0 {
            return result;
        }
        shift += 7;
    }
}

fn svarint<R: Read>(r: &mut R) -> i128 {
    let mut result = 0u128;
    let mut shift = 0;
    loop {
        let byte = u8(r);
        result |= ((byte & 0x7F) as u128) << shift;
        if byte & 0x80 == 0 {
            return ((result >> 1) as i128) ^ -((result & 1) as i128);
        }
        shift += 7;
    }
}

fn string<R: Read>(r: &mut R, len: usize) -> String {
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).unwrap();
    String::from_utf8_lossy(&buf).into()
}
