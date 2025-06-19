<h3 align="center">
  <img src="static/favicon.ico" alt="IPApi Logo" height="64" width="64" align="middle">
  IPAPI
</h3>

<p align="center">A fast, efficient, and free Python-powered API for retrieving IP address information.</p>

## Installation and Usage

### Prerequisites

- Python 3.6 or higher
- Git

### Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/tn3w/IPApi.git
    cd IPApi
    ```

2. Create/activate an virtual environment:

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3. Install the dependencies:

    ```bash
    pip install -r requirements.txt
    ```

4. Run the application:

    ```bash
    python3 app.py
    ```

## Usage

Request:

```
curl http://127.0.0.1:5000/1.1.1.1
```

Easy, isn't it? 1 KB of data, 500ms.

Response:

```json
{
    "ip_address": "1.1.1.1",
    "version": 4,
    "classification": "public",
    "hostname": "one.one.one.one",
    "ipv4_address": "1.1.1.1",
    "ipv6_address": "2606:4700:4700::1111",
    "continent": "Oceania",
    "continent_code": "OC",
    "country": "Australia",
    "country_code": "AU",
    "is_eu": false,
    "region": "Queensland",
    "region_code": "QLD",
    "city": "Brisbane",
    "district": null,
    "postal_code": "4007",
    "latitude": -27.467541,
    "longitude": 153.028091,
    "timezone_name": "Australia/Brisbane",
    "timezone_abbreviation": "AEST",
    "utc_offset": 36000,
    "utc_offset_str": "UTC+10:00",
    "dst_active": false,
    "currency": "AUD",
    "asn": "13335",
    "as_name": "CLOUDFLARENET",
    "org": "Cloudflare, Inc.",
    "isp": "Cloudflare",
    "domain": "cloudflare.com",
    "prefix": "1.1.1.0/24",
    "date_allocated": "2018-04-01",
    "rir": "apnic",
    "abuse_contact": "abuse@cloudflare.com",
    "rpki_status": "valid",
    "rpki_roa_count": 1,
    "is_vpn": false,
    "vpn_provider": null,
    "is_proxy": false,
    "is_firehol": false,
    "is_datacenter": false,
    "is_forum_spammer": false,
    "is_tor_exit_node": false,
    "fraud_score": 0.0,
    "threat_type": null
}
```

## Deployment

This section covers how to deploy IPApi as a production service.

### Prerequisites for Deployment

- Server with Linux (Ubuntu/Debian recommended)
- Root or sudo access
- Python 3.6+ or PyPy 3.7+ (recommended for better performance)
- Git

### Step 1: Clone the Repository

```bash
# Clone the repository to your desired location
git clone https://github.com/tn3w/IPApi.git
cd IPApi
```

### Step 2: Set Up Python Environment

You can use either standard CPython or PyPy (for better performance):

#### Option A: Using CPython (Standard)

```bash
# Create a virtual environment
python3 -m venv /opt/ipapi/venv

# Activate the virtual environment
source /opt/ipapi/venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

### Step 3: Set Up Application Directory

```bash
# Create application directory
sudo mkdir -p /opt/ipapi/app

# Copy necessary files
sudo cp -r app.py src/ static/ styles/ scripts/ templates/ /opt/ipapi/app/

# Create .env file (if not existing)
sudo touch /opt/ipapi/app/.env
```

Create or modify the .env file with appropriate settings:

```bash
sudo nano /opt/ipapi/app/.env
```

Example .env content:

```
PORT=8765
IP2LOCATION_TOKEN=
```

### Step 4: Create Systemd Service

Create a systemd service file for automatic startup:

```bash
sudo nano /etc/systemd/system/ipapi.service
```

Add the following content to the service file:

```ini
[Unit]
Description=IP API Service
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/ipapi/app
ExecStart=/opt/ipapi/venv/bin/python app.py
Restart=always
StandardOutput=journal
StandardError=journal
Environment="PATH=/opt/ipapi/venv/bin:$PATH"

[Install]
WantedBy=multi-user.target
```

### Step 5: Set Permissions and Enable Service

```bash
# Set proper permissions
sudo chown -R www-data:www-data /opt/ipapi

# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable ipapi
sudo systemctl start ipapi
```

### Step 6: Check Service Status

```bash
# Check if service is running correctly
sudo systemctl status ipapi

# View logs if needed
sudo journalctl -u ipapi -f
```

### Step 7: Configure Reverse Proxy (Optional)

For production environments, it's recommended to use Nginx or Apache as a reverse proxy:

#### Nginx Configuration Example:

```bash
sudo nano /etc/nginx/sites-available/ipapi
```

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8765;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable the site and restart Nginx:

```bash
sudo ln -s /etc/nginx/sites-available/ipapi /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

Now your IPApi should be running as a system service with automatic startup on boot!

## TO-DO

- [ ] Add "whois" data
- [ ] Add hostname support back, extend the hostname information over the ip address.
- [ ] The "I'm feeling lucky" button should also generate random valid, relevant and public IPv6 addresses.
- [ ] Auto update databases in src/memory_server.py.
- [x] Implement IP2Proxy database for proxy detection (See experiments/ip2location.py)
- [x] Add more example IPs to the "Try Example" button.
- [x] Better error handling in index.html (404 error now means invalid IP Address)
- [x] Add ipv6 mapping to index.html template (line 710-728 in index.js)
- [x] Update the index.html template to use the new ip information format
- [x] Add embedded css and js minifying.
- [x] Fill in geo data
- [x] Make geo data cacheable
- [x] Combine templates.py and utils.py

## Credits

- <a href="https://www.flaticon.com/free-icons/ip-address" title="ip address icons">Ip address icons created by Freepik - Flaticon</a>
- IPApi uses the IP2Location LITE database for <a href="https://lite.ip2location.com">IP geolocation</a>.

## License

Copyright 2025 TN3W

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
