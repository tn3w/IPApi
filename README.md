<p align="center"><img src="https://github.com/tn3w/IPApi/releases/download/img/ipapi.webp" alt="IPApi - Fast IP geolocation and threat intelligence API"></p>

<h1 align="center">IPApi</h1>

<h3 align="center">Fast IP geolocation and threat intelligence API</h3>
<p align="center">
  Comprehensive IP lookup with geolocation, ASN, ISP, proxy detection, and blocklist checking
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue?style=for-the-badge&logo=rust&logoColor=white" alt="Version">
  <img src="https://img.shields.io/badge/license-Apache%202.0-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/rust-2021-orange?style=for-the-badge&logo=rust&logoColor=white" alt="Rust">
</p>

<p align="center">
  <a href="#-quick-start">🚀 Quick Start</a> •
  <a href="#-api-reference">📚 API Reference</a> •
  <a href="#-examples">💡 Examples</a>
</p>

## Overview

**IPApi** is a high-performance IP intelligence service built in Rust. It provides detailed information about IP addresses including geolocation, network ownership, proxy detection, and security threat assessment through multiple blocklist feeds.

The service combines multiple data sources (IP2Location-style databases, DNS resolution, and threat intelligence feeds) to deliver comprehensive IP analysis with sub-millisecond response times. Perfect for security applications, fraud detection, content localization, and network analytics.

```bash
curl https://ipapi.tn3w.dev/api/8.8.8.8
```

## ✨ Features

<table>
<tr>
<td width="50%">

### Geolocation Data

- City, region, country identification
- Latitude/longitude coordinates
- Timezone with DST support
- Postal codes and districts
- Currency information

</td>
<td width="50%">

### Network Intelligence

- ASN and CIDR information
- ISP and organization details
- Domain ownership
- Proxy/VPN detection
- IPv4 and IPv6 support

</td>
</tr>
<tr>
<td width="50%">

### Security Features

- Multi-source blocklist checking
- IP classification (public/private/reserved)
- Reverse DNS lookup with caching
- Rate limiting (40 req/min)
- Redis-backed response caching

</td>
<td width="50%">

### Performance

- Sub-millisecond binary search
- Automatic data refresh (24h)
- Connection pooling
- Zero-copy parsing
- Async-first architecture

</td>
</tr>
</table>

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/tn3w/ipapi.git
cd ipapi

# Set Redis URL
export REDIS_URL="redis://localhost:6379"

# Build and run
cargo run --release
```

### Basic Usage

```bash
# Look up your own IP
curl https://ipapi.tn3w.dev/api/me

# Look up specific IP
curl https://ipapi.tn3w.dev/api/1.1.1.1

# Look up domain
curl https://ipapi.tn3w.dev/api/example.com
```

## 📚 API Reference

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Web interface |
| `GET /api/:query` | IP or domain lookup |
| `GET /health` | Service health check |

### Query Parameter

The `:query` parameter accepts:
- **IPv4 address**: `8.8.8.8`
- **IPv6 address**: `2001:4860:4860::8888`
- **Domain name**: `example.com`
- **Special value**: `me` (returns your IP)

### Response Format

```json
{
  "ip": "8.8.8.8",
  "ipv4": "8.8.8.8",
  "ipv6": null,
  "type": 4,
  "classification": "public",
  "hostname": "dns.google",
  "latitude": 37.386,
  "longitude": -122.084,
  "city": "Mountain View",
  "region": "California",
  "region_code": "CA",
  "district": null,
  "postal_code": "94035",
  "country_code": "US",
  "country_name": "United States",
  "continent_code": "NA",
  "continent_name": "North America",
  "is_eu": false,
  "timezone": "America/Los_Angeles",
  "timezone_abbr": "PST",
  "utc_offset": -28800,
  "utc_offset_str": "-08:00",
  "dst_active": false,
  "currency": "USD",
  "cidr": "8.8.8.0/24",
  "asn": "AS15169",
  "as_name": "GOOGLE",
  "proxy_type": null,
  "isp": "Google LLC",
  "domain": "google.com",
  "provider": "Google",
  "blocklists": []
}
```

### Response Headers

| Header | Description |
|--------|-------------|
| `x-search-count` | Number of binary searches performed |
| `x-server-time-us` | Server processing time in microseconds |
| `x-cache-status` | Cache hit/miss status |
| `ratelimit-limit` | Rate limit maximum (40) |
| `ratelimit-remaining` | Remaining requests in window |
| `ratelimit-reset` | Seconds until rate limit reset |

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `ip` | string | Queried IP address |
| `ipv4` | string? | IPv4 address (if available) |
| `ipv6` | string? | IPv6 address (if available) |
| `type` | number | IP version (4 or 6) |
| `classification` | string | IP type: `public`, `private`, `loopback`, `reserved`, `multicast`, `link_local`, `ipv4_mapped` |
| `hostname` | string? | Reverse DNS hostname |
| `latitude` | number? | Geographic latitude |
| `longitude` | number? | Geographic longitude |
| `city` | string? | City name |
| `region` | string? | Region/state name |
| `region_code` | string? | Region/state code |
| `district` | string? | District name |
| `postal_code` | string? | Postal/ZIP code |
| `country_code` | string? | ISO 3166-1 alpha-2 country code |
| `country_name` | string? | Country name |
| `continent_code` | string? | Continent code |
| `continent_name` | string? | Continent name |
| `is_eu` | boolean? | EU membership status |
| `timezone` | string? | IANA timezone identifier |
| `timezone_abbr` | string? | Timezone abbreviation |
| `utc_offset` | number? | UTC offset in seconds |
| `utc_offset_str` | string? | UTC offset string (e.g., "+02:00") |
| `dst_active` | boolean? | Daylight saving time status |
| `currency` | string? | ISO 4217 currency code |
| `cidr` | string? | CIDR notation |
| `asn` | string? | Autonomous System Number |
| `as_name` | string? | AS organization name |
| `proxy_type` | string? | Detected proxy type |
| `isp` | string? | Internet Service Provider |
| `domain` | string? | Organization domain |
| `provider` | string? | Service provider name |
| `blocklists` | string[] | Matched blocklist names |

### Rate Limiting

- **Limit**: 40 requests per minute per IP
- **Window**: 60 seconds rolling
- **Status Code**: `429 Too Many Requests` when exceeded
- **Headers**: Rate limit info in all responses

### Caching

- **TTL**: 1 hour for all lookups
- **Backend**: Redis
- **Keys**: `cache:{ip}` for IPs, `cache:domain:{hostname}` for domains
- **DNS Cache**: 1 hour for reverse DNS and forward lookups

### Error Responses

```json
{
  "error": "Rate limit exceeded"
}
```

**Status Codes**:
- `200 OK` — Successful lookup
- `400 Bad Request` — Invalid query or unresolvable domain
- `429 Too Many Requests` — Rate limit exceeded
- `500 Internal Server Error` — Server error

## 💡 Examples

### Check Your IP

```bash
curl https://ipapi.tn3w.dev/api/me
```

### IPv4 Lookup

```bash
curl https://ipapi.tn3w.dev/api/1.1.1.1
```

### IPv6 Lookup

```bash
curl https://ipapi.tn3w.dev/api/2606:4700:4700::1111
```

### Domain Lookup

```bash
curl https://ipapi.tn3w.dev/api/cloudflare.com
```

### Check Rate Limit Status

```bash
curl -I https://ipapi.tn3w.dev/api/8.8.8.8 | grep ratelimit
```

### Python Integration

```python
import requests

response = requests.get("https://ipapi.tn3w.dev/api/8.8.8.8")
data = response.json()

print(f"Location: {data['city']}, {data['country_name']}")
print(f"ISP: {data['isp']}")
print(f"Blocklists: {len(data['blocklists'])}")
```

### JavaScript Integration

```javascript
fetch('https://ipapi.tn3w.dev/api/me')
  .then(res => res.json())
  .then(data => {
    console.log(`Your IP: ${data.ip}`);
    console.log(`Location: ${data.city}, ${data.country_name}`);
    console.log(`ISP: ${data.isp}`);
  });
```

### Check Blocklist Status

```bash
curl https://ipapi.tn3w.dev/api/suspicious-ip.example | jq '.blocklists'
```

## 🛠️ Requirements

- **Rust**: 1.70+ (2021 edition)
- **Redis**: 6.0+ for caching and rate limiting
- **System**: Linux/macOS/Windows with network access
- **Memory**: ~2GB for database storage
- **Disk**: ~300MB for binary data files

## ⚡ Performance

- **Lookup time**: < 1ms for cached results
- **Cold lookup**: 1-5ms for database queries
- **DNS resolution**: 10-50ms (cached for 1 hour)
- **Binary search**: O(log n) complexity
- **Memory usage**: Efficient varint encoding
- **Throughput**: 1000+ req/s per core

## 🔒 Security

- **Input validation**: All queries sanitized
- **Rate limiting**: Per-IP request throttling
- **CSP headers**: Strict content security policy
- **HSTS**: Enforced HTTPS connections
- **No unsafe code**: Memory-safe Rust implementation
- **Blocklist integration**: Multi-source threat intelligence

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `REDIS_URL` | Redis connection URL | Required |

### Data Sources

The service automatically downloads and refreshes data every 24 hours from:
- **Geolocation**: IP2X database (github.com/tn3w/IP2X)
- **Blocklists**: IPBlocklist feeds (github.com/tn3w/IPBlocklist)

Data files are stored in the `data/` directory:
- `geo.bin` — Geolocation data
- `asn.bin` — ASN information
- `isp.bin` — ISP details
- `proxy_types.bin` — Proxy detection
- `blocklist.bin` — Threat intelligence

## Health Check

```bash
curl https://ipapi.tn3w.dev/health
```

Response:
```json
{
  "status": "ok",
  "last_refresh": 1709000000
}
```

## License

Copyright 2026 TN3W

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

<p align="center">
  <sub>Built with ❤️ using Rust and Axum</sub>
</p>
