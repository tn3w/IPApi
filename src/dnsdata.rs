use std::net::IpAddr;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

pub async fn get_reverse_dns(ip: &str) -> Option<String> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let ip_addr = match ip.parse::<IpAddr>() {
        Ok(addr) => addr,
        Err(_) => return None,
    };

    let lookup_result = match resolver.reverse_lookup(ip_addr).await {
        Ok(result) => result,
        Err(_) => return None,
    };

    lookup_result.iter().next().map(|name| {
        let name_str = name.to_string();
        name_str.strip_suffix('.').unwrap_or(&name_str).to_string()
    })
}
