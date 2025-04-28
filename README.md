# IPApi
A fast, efficient, and free Rust-powered API for retrieving IP address information.

## Example Usage
```bash
curl http://localhost:5000/8.8.8.8 | jq
```

Output:
```json
{
    "ip": "8.8.8.8",
    "continent": "North America",
    "continent_code": "NA",
    "country": "United States",
    "country_code": "US",
    "state": "Kansas",
    "state_code": "KS",
    "city": "Cheney",
    "district": "Sedgwick County",
    "zip": 67025,
    "lat": 37.751,
    "lon": -97.822,
    "timezone": "America/Chicago",
    "offset": 0,
    "currency": "USD",
    "isp": "GOOGLE",
    "org": "GOOGLE",
    "as": "GOOGLE",
    "as_code": 15169,
    "reverse": "dns.google",
    "tor": false
}
```