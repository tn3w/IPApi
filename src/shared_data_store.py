"""
Combined shared data store and memory server for IPApi application.
Provides IP data storage and shared memory access across multiple worker processes.
"""

import io
import json
import logging
import os
import threading
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Final, Any, Callable
from multiprocessing import managers

import maxminddb
import dns.resolver
from IP2Location import IP2Location
from IP2Proxy import IP2Proxy
from netaddr import IPNetwork, IPAddress, AddrFormatError

from src.utils import get_nested

logger = logging.getLogger(__name__)

DATASET_DIR = Path("datasets")
if not DATASET_DIR.exists():
    DATASET_DIR.mkdir(parents=True)


def get_github_release_assets(repo_path: str) -> dict[str, str]:
    """Get all assets from the latest releases of a GitHub repository."""
    api_url = f"https://api.github.com/repos/{repo_path}/releases"
    assets: dict[str, str] = {}

    try:
        with urllib.request.urlopen(api_url, timeout=5) as response:
            releases = json.loads(response.read().decode("utf-8"))

        for release in releases:
            for asset in release.get("assets", []):
                name = asset.get("name")
                url = asset.get("browser_download_url")
                if name and url and name not in assets:
                    assets[name] = url

        return assets
    except Exception as e:
        logger.error("Failed to get assets from %s: %s", repo_path, e)
        raise RuntimeError(f"Failed to get assets from {repo_path}: {e}") from e


GEOLITE_ASSETS: dict[str, str] = {}


def get_geolite_url(database_name: str) -> str:
    """Get the download URL for a specific GeoLite database file."""
    if not GEOLITE_ASSETS:
        try:
            GEOLITE_ASSETS.update(get_github_release_assets("P3TERX/GeoLite.mmdb"))
        except Exception as e:
            logger.error("Failed to get GeoLite assets: %s", e)
            raise RuntimeError(f"Failed to get GeoLite assets: {e}") from e

    if database_name not in GEOLITE_ASSETS:
        raise RuntimeError(f"Could not find {database_name} in any release")

    return GEOLITE_ASSETS[database_name]


def download_and_extract_ip2location(
    package_code: str, bin_name: str, dataset_dir: Path
) -> None:
    """Download and extract an IP2Location database file."""
    bin_path = os.path.join(dataset_dir, bin_name)
    if os.path.exists(bin_path):
        return

    token = os.environ.get("IP2LOCATION_TOKEN", "")
    if not token:
        return

    url = f"https://www.ip2location.com/download/?token={token}&file={package_code}"
    logger.info("Downloading IP2Location package %s...", package_code)

    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            content = response.read()

        with zipfile.ZipFile(io.BytesIO(content)) as zip_ref:
            for zip_info in zip_ref.infolist():
                if not zip_info.filename.endswith(".BIN"):
                    continue
                with open(bin_path, "wb") as f:
                    _ = f.write(zip_ref.read(zip_info.filename))

                logger.info("Extracted %s to %s", zip_info.filename, bin_path)
                break
    except urllib.error.URLError as e:
        logger.error("Failed to download %s: %s", package_code, e)
        raise RuntimeError(f"Failed to download {package_code}: {e}") from e
    except zipfile.BadZipFile as e:
        logger.error("Invalid zip file for %s: %s", package_code, e)
        raise RuntimeError(f"Invalid zip file for {package_code}: {e}") from e


IP2LOCATION_DATASETS = [
    {"code": "DB9LITEBINIPV6", "bin_name": "IP2LOCATION-LITE-DB9.BIN"},
    {"code": "PX12LITEBIN", "bin_name": "IP2PROXY-LITE-PX12.BIN"},
    {"code": "DBASNLITEBINIPV6", "bin_name": "IP2LOCATION-LITE-ASN.BIN"},
]

DATASETS: dict[str, tuple[str | Callable[[], str], str]] = {
    "GeoLite2-ASN": (
        lambda: get_geolite_url("GeoLite2-ASN.mmdb"),
        "GeoLite2-ASN.mmdb",
    ),
    "GeoLite2-City": (
        lambda: get_geolite_url("GeoLite2-City.mmdb"),
        "GeoLite2-City.mmdb",
    ),
    "IPSet": (
        "https://raw.githubusercontent.com/tn3w/IPSet/refs/heads/master/ipset.json",
        "ipset.json",
    ),
    "Data-Center-ASNS": (
        "https://raw.githubusercontent.com/tn3w/IPSet/refs/heads/master/datacenter_asns.json",
        "data-center-asns.json",
    ),
    "Anycast-IPv4-Prefixes": (
        "https://raw.githubusercontent.com/bgptools/anycast-prefixes/refs/heads/master/anycatch-v4-prefixes.txt",
        "anycast-ipv4-prefixes.json",
    ),
    "Anycast-IPv6-Prefixes": (
        "https://raw.githubusercontent.com/bgptools/anycast-prefixes/refs/heads/master/anycatch-v6-prefixes.txt",
        "anycast-ipv6-prefixes.json",
    ),
}


def download_and_process_anycast_prefixes(url: str, filename: str) -> None:
    """Download anycast prefix list and convert to JSON format with timestamp."""
    file_path = os.path.join(DATASET_DIR, filename)

    try:
        logger.info("Downloading anycast prefixes from %s", url)
        with urllib.request.urlopen(url, timeout=10) as response:
            content = response.read().decode("utf-8")

        prefixes = []
        for line in content.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                prefixes.append(line)

        data = {"timestamp": int(time.time()), "prefixes": prefixes}

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        logger.info("Processed %d anycast prefixes to %s", len(prefixes), filename)

    except Exception as e:
        logger.error("Failed to download/process anycast prefixes from %s: %s", url, e)
        raise RuntimeError(f"Failed to download/process anycast prefixes: {e}") from e


def download_all_datasets() -> None:
    """Download all datasets defined in the DATASETS dictionary and IP2Location databases."""
    for dataset_name, (url_or_getter, filename) in DATASETS.items():
        file_path = os.path.join(DATASET_DIR, filename)
        if os.path.exists(file_path):
            continue

        try:
            url = url_or_getter() if callable(url_or_getter) else url_or_getter

            if dataset_name in ["Anycast-IPv4-Prefixes", "Anycast-IPv6-Prefixes"]:
                download_and_process_anycast_prefixes(url, filename)
            else:
                logger.info("Downloading dataset %s from %s", dataset_name, url)
                _ = urllib.request.urlretrieve(str(url), file_path)
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
            raise RuntimeError(f"Failed to download dataset {dataset_name}: {e}") from e

    for dataset_info in IP2LOCATION_DATASETS:
        try:
            download_and_extract_ip2location(
                dataset_info["code"], dataset_info["bin_name"], DATASET_DIR
            )
        except Exception as e:
            logger.error(
                "Failed to download IP2Location dataset %s: %s",
                dataset_info["bin_name"],
                e,
            )


class IPDataStore:
    """Stores and provides access to IP datasets."""

    def __init__(self) -> None:
        self.ip_to_groups: dict[str, list[str]] = {}
        self.datacenter_asns: set[str] = set()
        self.asn_reader: maxminddb.Reader | None = None
        self.city_reader: maxminddb.Reader | None = None

        self.ip2location_db: IP2Location | None = None
        self.ip2proxy_db: IP2Proxy | None = None
        self.ip2location_asn_db: IP2Location | None = None

        self.dns_cache: dict[str, list[str] | None] = {}
        self.resolver: dns.resolver.Resolver = dns.resolver.Resolver()
        self.resolver.timeout = 0.3
        self.resolver.lifetime = 0.5

        self.anycast_ipv4_networks: list[IPNetwork] = []
        self.anycast_ipv6_networks: list[IPNetwork] = []
        self.anycast_ipv4_timestamp: int = 0
        self.anycast_ipv6_timestamp: int = 0
        self._anycast_update_thread: threading.Thread | None = None
        self._anycast_stop_event: threading.Event = threading.Event()

        self.is_loaded: bool = False

        self.ip_groups_cache: dict[str, list[str]] = {}
        self.datacenter_asn_cache: dict[str, bool] = {}
        self.ip_asn_maxmind_cache: dict[str, tuple[str | None, str | None]] = {}
        self.ip_city_maxmind_cache: dict[str, dict[str, Any]] = {}
        self.ip_asn_ip2location_cache: dict[str, tuple[str | None, str | None]] = {}
        self.ip_city_ip2location_cache: dict[str, dict[str, Any]] = {}
        self.ip_ip2proxy_cache: dict[str, dict[str, Any]] = {}
        self._rpki_cache: dict[str, tuple[str, int]] = {}
        self._abuse_contact_cache: dict[str, str | None] = {}
        self._ripe_geolocation_cache: dict[str, dict[str, Any]] = {}
        self._anycast_cache: dict[str, bool] = {}

    def load_datasets(self) -> None:
        """Load all datasets into memory."""
        if self.is_loaded:
            return

        download_all_datasets()

        ipset_path = os.path.join(DATASET_DIR, DATASETS["IPSet"][1])
        if os.path.exists(ipset_path):
            with open(ipset_path, "r", encoding="utf-8") as f:
                group_to_ips: dict[str, list[str]] = json.load(f)

            for group, ips in group_to_ips.items():
                for ip in ips:
                    if ip not in self.ip_to_groups:
                        self.ip_to_groups[ip] = []
                    self.ip_to_groups[ip].append(group)

            logger.info("Loaded %d IPs with group mappings", len(self.ip_to_groups))

        datacenter_asns_path = os.path.join(
            DATASET_DIR, DATASETS["Data-Center-ASNS"][1]
        )
        if os.path.exists(datacenter_asns_path):
            with open(datacenter_asns_path, "r", encoding="utf-8") as f:
                asn_list = json.load(f)
                self.datacenter_asns = set(str(asn) for asn in asn_list)
            logger.info("Loaded %d data center ASNs", len(self.datacenter_asns))

        geolite2_asn_path = os.path.join(DATASET_DIR, DATASETS["GeoLite2-ASN"][1])
        if os.path.exists(geolite2_asn_path):
            self.asn_reader = maxminddb.open_database(geolite2_asn_path)
            logger.info("Loaded GeoLite2 ASN database")

        geolite2_city_path = os.path.join(DATASET_DIR, DATASETS["GeoLite2-City"][1])
        if os.path.exists(geolite2_city_path):
            self.city_reader = maxminddb.open_database(geolite2_city_path)
            logger.info("Loaded GeoLite2 City database")

        ip2location_path = os.path.join(DATASET_DIR, "IP2LOCATION-LITE-DB9.BIN")
        if os.path.exists(ip2location_path):
            try:
                self.ip2location_db = IP2Location(ip2location_path)
            except Exception as e:
                logger.error("Failed to load IP2Location database: %s", e)

        ip2proxy_path = os.path.join(DATASET_DIR, "IP2PROXY-LITE-PX12.BIN")
        if os.path.exists(ip2proxy_path):
            try:
                self.ip2proxy_db = IP2Proxy(ip2proxy_path)
            except Exception as e:
                logger.error("Failed to load IP2Proxy database: %s", e)

        ip2location_asn_path = os.path.join(DATASET_DIR, "IP2LOCATION-LITE-ASN.BIN")
        if os.path.exists(ip2location_asn_path):
            try:
                self.ip2location_asn_db = IP2Location(ip2location_asn_path)
            except Exception as e:
                logger.error("Failed to load IP2Location ASN database: %s", e)

        self._load_anycast_prefixes()
        self._start_anycast_background_updates()

        self.is_loaded = True
        logger.info("All datasets loaded into memory")

    def _load_anycast_prefixes(self) -> None:
        """Load anycast prefix data from JSON files."""
        ipv4_path = os.path.join(DATASET_DIR, DATASETS["Anycast-IPv4-Prefixes"][1])
        if os.path.exists(ipv4_path):
            try:
                with open(ipv4_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                self.anycast_ipv4_timestamp = data.get("timestamp", 0)
                prefixes = data.get("prefixes", [])

                self.anycast_ipv4_networks = []
                for prefix in prefixes:
                    try:
                        network = IPNetwork(prefix)
                        if network.version == 4:
                            self.anycast_ipv4_networks.append(network)
                        else:
                            logger.warning(
                                "Expected IPv4 prefix but got IPv6: %s", prefix
                            )
                    except (ValueError, AddrFormatError) as e:
                        logger.warning("Invalid IPv4 prefix %s: %s", prefix, e)

                logger.info(
                    "Loaded %d IPv4 anycast prefixes", len(self.anycast_ipv4_networks)
                )
            except Exception as e:
                logger.error("Failed to load IPv4 anycast prefixes: %s", e)

        ipv6_path = os.path.join(DATASET_DIR, DATASETS["Anycast-IPv6-Prefixes"][1])
        if os.path.exists(ipv6_path):
            try:
                with open(ipv6_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                self.anycast_ipv6_timestamp = data.get("timestamp", 0)
                prefixes = data.get("prefixes", [])

                self.anycast_ipv6_networks = []
                for prefix in prefixes:
                    try:
                        network = IPNetwork(prefix)
                        if network.version == 6:
                            self.anycast_ipv6_networks.append(network)
                        else:
                            logger.warning(
                                "Expected IPv6 prefix but got IPv4: %s", prefix
                            )
                    except (ValueError, AddrFormatError) as e:
                        logger.warning("Invalid IPv6 prefix %s: %s", prefix, e)

                logger.info(
                    "Loaded %d IPv6 anycast prefixes", len(self.anycast_ipv6_networks)
                )
            except Exception as e:
                logger.error("Failed to load IPv6 anycast prefixes: %s", e)

    def get_ip_groups(self, ip: str) -> list[str]:
        """Get groups associated with an IP address."""
        if not self.is_loaded:
            self.load_datasets()

        if ip in self.ip_groups_cache:
            return self.ip_groups_cache[ip]

        matching_groups = self.ip_to_groups.get(ip, [])
        self.ip_groups_cache[ip] = matching_groups
        return matching_groups

    def is_datacenter_asn(self, asn: str) -> bool:
        """Check if an ASN is a data center ASN."""
        if asn in self.datacenter_asn_cache:
            return self.datacenter_asn_cache[asn]

        result = asn in self.datacenter_asns
        self.datacenter_asn_cache[asn] = result
        return result

    def get_ip_asn_maxmind(self, ip: str) -> tuple[str | None, str | None]:
        """Get the ASN for an IP address using MaxMind database."""
        if ip in self.ip_asn_maxmind_cache:
            return self.ip_asn_maxmind_cache[ip]

        if not self.asn_reader:
            return None, None

        try:
            result = self.asn_reader.get(ip)
            if (
                result
                and isinstance(result, dict)
                and "autonomous_system_number" in result
            ):
                asn = str(result["autonomous_system_number"])
                asn_name = str(result["autonomous_system_organization"])
                self.ip_asn_maxmind_cache[ip] = (asn, asn_name)
                return asn, asn_name
        except Exception as e:
            logger.error("Error looking up ASN for IP %s: %s", ip, e)

        self.ip_asn_maxmind_cache[ip] = (None, None)
        return None, None

    def get_ip_city_maxmind(self, ip: str) -> dict[str, Any]:
        """Get the city for an IP address using MaxMind database."""
        if ip in self.ip_city_maxmind_cache:
            return self.ip_city_maxmind_cache[ip]

        if not self.city_reader:
            return {}

        city_data: dict[str, Any] = {}

        try:
            result: dict[str, Any] = self.city_reader.get(ip)

            country = get_nested(result, "country", "names", "en")
            if country:
                city_data["country"] = country
                city_data["country_code"] = get_nested(result, "country", "iso_code")
            else:
                registered_country = get_nested(
                    result, "registered_country", "names", "en"
                )
                if registered_country:
                    city_data["country"] = registered_country
                    city_data["country_code"] = get_nested(
                        result, "registered_country", "iso_code"
                    )

            city_data["continent"] = get_nested(result, "continent", "names", "en")
            city_data["continent_code"] = get_nested(result, "continent", "code")

            subdivisions = get_nested(result, "subdivisions")
            if isinstance(subdivisions, list) and subdivisions:
                subdivision = subdivisions[0]
                city_data["region"] = get_nested(subdivision, "names", "en")
                region_code = get_nested(subdivision, "iso_code")
                if region_code and region_code != "0":
                    city_data["region_code"] = region_code

            city_data["city"] = get_nested(result, "city", "names", "en")
            city_data["postal_code"] = get_nested(result, "postal", "code")

            location = get_nested(result, "location")
            if location:
                city_data["latitude"] = get_nested(location, "latitude")
                city_data["longitude"] = get_nested(location, "longitude")
                city_data["accuracy_radius"] = get_nested(location, "accuracy_radius")

            self.ip_city_maxmind_cache[ip] = city_data
            return city_data
        except Exception as e:
            logger.error("Error looking up city for IP %s: %s", ip, e)
            self.ip_city_maxmind_cache[ip] = {}
            return {}

    def get_ip_asn_ip2location(self, ip: str) -> tuple[str | None, str | None]:
        """Get the ASN for an IP address using IP2Location database."""
        if ip in self.ip_asn_ip2location_cache:
            return self.ip_asn_ip2location_cache[ip]

        if not self.ip2location_asn_db:
            return None, None

        try:
            result = self.ip2location_asn_db.get_all(ip)
            if result:
                asn = str(result.asn) if result.asn != "-" else None
                asn_name = (
                    result.as_name if result.as_name and result.as_name != "-" else None
                )
                self.ip_asn_ip2location_cache[ip] = (asn, asn_name)
                return asn, asn_name
        except Exception as e:
            logger.error("Error looking up ASN for IP %s: %s", ip, e)

        self.ip_asn_ip2location_cache[ip] = (None, None)
        return None, None

    def get_ip_city_ip2location(self, ip: str) -> dict[str, Any]:
        """Get the city for an IP address using IP2Location database."""
        if ip in self.ip_city_ip2location_cache:
            return self.ip_city_ip2location_cache[ip]

        if not self.ip2location_db:
            return {}

        city_data: dict[str, Any] = {}

        try:
            result = self.ip2location_db.get_all(ip)

            if result:
                city_data["country_code"] = result.country_short
                city_data["region"] = result.region
                city_data["city"] = result.city
                city_data["latitude"] = result.latitude
                city_data["longitude"] = result.longitude

                for field in [
                    "country_code",
                    "region",
                    "city",
                    "latitude",
                    "longitude",
                ]:
                    if city_data.get(field, ...) in (None, "-", "0.000000"):
                        del city_data[field]

                self.ip_city_ip2location_cache[ip] = city_data
                return city_data
        except Exception as e:
            logger.error("Error looking up city for IP %s: %s", ip, e)

        self.ip_city_ip2location_cache[ip] = {}
        return {}

    def get_ip_ip2proxy(self, ip: str) -> dict[str, Any]:
        """Get the IP2Proxy data for an IP address."""
        if ip in self.ip_ip2proxy_cache:
            return self.ip_ip2proxy_cache[ip]

        if not self.ip2proxy_db:
            return {}

        try:
            result = self.ip2proxy_db.get_all(ip)

            fraud_score = result.get("fraud_score")
            if isinstance(fraud_score, str) and fraud_score.isdigit():
                fraud_score = int(fraud_score) / 100
            else:
                fraud_score = None

            data = {
                "is_proxy": result.get("proxy_type") == "1",
                "isp": result.get("isp") if result.get("isp") != "-" else None,
                "domain": result.get("domain") if result.get("domain") != "-" else None,
                "fraud_score": fraud_score,
                "threat_type": (
                    result.get("threat", "").lower()
                    if isinstance(result.get("threat"), str)
                    and result.get("threat") != "-"
                    else None
                ),
            }

            self.ip_ip2proxy_cache[ip] = data
            return data
        except Exception as e:
            logger.error("Error looking up IP2Proxy for IP %s: %s", ip, e)
            self.ip_ip2proxy_cache[ip] = {}
            return {}

    def dns_query(self, qname: str, qtype: str) -> list[str] | None:
        """Make a DNS query and cache the response as a list of strings."""
        cache_key = f"{qname}:{qtype}"
        if cache_key in self.dns_cache:
            return self.dns_cache[cache_key]

        try:
            result = self.resolver.resolve(qname, qtype)
            records = [str(record) for record in result]
            self.dns_cache[cache_key] = records
            return records
        except Exception:
            self.dns_cache[cache_key] = None
            return None

    def is_anycast_ip(self, ip: str) -> bool:
        """Check if an IP address belongs to an anycast prefix."""
        if ip in self._anycast_cache:
            return self._anycast_cache[ip]

        try:
            ip_obj = IPAddress(ip)

            if ip_obj.version == 4:
                for network in self.anycast_ipv4_networks:
                    if ip_obj in network:
                        self._anycast_cache[ip] = True
                        return True

            elif ip_obj.version == 6:
                for network in self.anycast_ipv6_networks:
                    if ip_obj in network:
                        self._anycast_cache[ip] = True
                        return True

        except (ValueError, AddrFormatError):
            pass

        self._anycast_cache[ip] = False
        return False

    def get_anycast_info(self) -> dict[str, Any]:
        """Get information about loaded anycast prefixes."""
        return {
            "ipv4_prefixes_count": len(self.anycast_ipv4_networks),
            "ipv6_prefixes_count": len(self.anycast_ipv6_networks),
            "ipv4_timestamp": self.anycast_ipv4_timestamp,
            "ipv6_timestamp": self.anycast_ipv6_timestamp,
        }

    def update_anycast_prefixes_background(self) -> None:
        """Update anycast prefixes in the background."""
        try:
            ipv4_url_or_getter, ipv4_filename = DATASETS["Anycast-IPv4-Prefixes"]
            ipv4_url = (
                ipv4_url_or_getter()
                if callable(ipv4_url_or_getter)
                else ipv4_url_or_getter
            )
            download_and_process_anycast_prefixes(ipv4_url, ipv4_filename)

            ipv6_url_or_getter, ipv6_filename = DATASETS["Anycast-IPv6-Prefixes"]
            ipv6_url = (
                ipv6_url_or_getter()
                if callable(ipv6_url_or_getter)
                else ipv6_url_or_getter
            )
            download_and_process_anycast_prefixes(ipv6_url, ipv6_filename)

            self._load_anycast_prefixes()

            self._anycast_cache.clear()

            logger.info("Anycast prefixes updated successfully")
        except Exception as e:
            logger.error("Failed to update anycast prefixes: %s", e)

    def _start_anycast_background_updates(self) -> None:
        """Start background thread for updating anycast prefixes."""
        if (
            self._anycast_update_thread is None
            or not self._anycast_update_thread.is_alive()
        ):
            self._anycast_stop_event.clear()
            self._anycast_update_thread = threading.Thread(
                target=self._anycast_background_worker,
                daemon=True,
                name="anycast-updater",
            )
            self._anycast_update_thread.start()
            logger.info("Started anycast background update thread")

    def _anycast_background_worker(self) -> None:
        """Background worker that periodically updates anycast prefixes."""
        update_interval = 6 * 60 * 60

        while not self._anycast_stop_event.is_set():
            try:
                if self._anycast_stop_event.wait(timeout=update_interval):
                    break

                current_time = int(time.time())
                needs_update = False

                if (current_time - self.anycast_ipv4_timestamp) > (24 * 60 * 60):
                    needs_update = True
                    logger.info("IPv4 anycast prefixes are outdated, updating...")

                if (current_time - self.anycast_ipv6_timestamp) > (24 * 60 * 60):
                    needs_update = True
                    logger.info("IPv6 anycast prefixes are outdated, updating...")

                if needs_update:
                    self.update_anycast_prefixes_background()

            except Exception as e:
                logger.error("Error in anycast background worker: %s", e)

    def stop_anycast_background_updates(self) -> None:
        """Stop the background update thread."""
        if self._anycast_update_thread and self._anycast_update_thread.is_alive():
            self._anycast_stop_event.set()
            self._anycast_update_thread.join(timeout=5)
            logger.info("Stopped anycast background update thread")

    def get_rpki_cache_item(self, prefix: str) -> tuple[str, int] | None:
        """Get an item from the RPKI cache."""
        return self._rpki_cache.get(prefix)

    def set_rpki_cache_item(self, prefix: str, value: tuple[str, int]) -> None:
        """Set an item in the RPKI cache."""
        self._rpki_cache[prefix] = value

    def get_abuse_contact_cache_item(self, ip_address: str) -> str | None:
        """Get an item from the abuse contact cache."""
        return self._abuse_contact_cache.get(ip_address)

    def set_abuse_contact_cache_item(self, ip_address: str, value: str | None) -> None:
        """Set an item in the abuse contact cache."""
        self._abuse_contact_cache[ip_address] = value

    def get_ripe_geolocation_cache_item(self, ip_address: str) -> dict[str, Any] | None:
        """Get an item from the RIPE geolocation cache."""
        return self._ripe_geolocation_cache.get(ip_address)

    def set_ripe_geolocation_cache_item(
        self, ip_address: str, value: dict[str, Any]
    ) -> None:
        """Set an item in the RIPE geolocation cache."""
        self._ripe_geolocation_cache[ip_address] = value


_global_data_store: IPDataStore | None = None


class MemoryManager(managers.BaseManager):
    """Custom multiprocessing manager for shared data store."""

    pass


def get_shared_data_store() -> IPDataStore:
    """Get the shared data store instance."""
    global _global_data_store
    if _global_data_store is None:
        logger.info("Initializing shared data store in memory server...")
        _global_data_store = IPDataStore()
        _global_data_store.load_datasets()
        logger.info("Shared data store initialized successfully")
    return _global_data_store


def start_memory_server(port: int = 50000) -> None:
    """Start the memory server."""
    MemoryManager.register(
        "get_data_store",
        get_shared_data_store,
        exposed=[
            "get_ip_groups",
            "is_datacenter_asn",
            "get_ip_asn_maxmind",
            "get_ip_city_maxmind",
            "get_ip_asn_ip2location",
            "get_ip_city_ip2location",
            "get_ip_ip2proxy",
            "dns_query",
            "get_rpki_cache_item",
            "set_rpki_cache_item",
            "get_abuse_contact_cache_item",
            "set_abuse_contact_cache_item",
            "get_ripe_geolocation_cache_item",
            "set_ripe_geolocation_cache_item",
            "is_anycast_ip",
            "get_anycast_info",
            "update_anycast_prefixes_background",
            "stop_anycast_background_updates",
            "is_loaded",
        ],
    )

    manager = MemoryManager(address=("localhost", port), authkey=b"ipapi_shared_memory")
    server = manager.get_server()

    logger.info("Memory server starting on localhost:%d", port)
    server.serve_forever()


def get_memory_client(port: int = 50000) -> IPDataStore:
    """Get a client connection to the memory server."""
    MemoryManager.register("get_data_store")

    manager = MemoryManager(address=("localhost", port), authkey=b"ipapi_shared_memory")
    manager.connect()

    return manager.get_data_store()


class SharedDataStoreClient:
    """Client wrapper for shared data store access."""

    def __init__(self, port: int = 50000):
        self.port: Final[int] = port
        self._client: IPDataStore | None = None

    def get_client(self) -> IPDataStore:
        """Get or create the client connection."""
        if self._client is None:
            try:
                self._client = get_memory_client(self.port)
                logger.info("Connected to shared memory server")
            except Exception as e:
                logger.error("Failed to connect to memory server: %s", e)
                logger.info("Falling back to local data store")
                self._client = IPDataStore()
                self._client.load_datasets()
        return self._client


_shared_client: SharedDataStoreClient | None = None


def get_shared_client(port: int = 50000) -> IPDataStore:
    """Get the shared data store client."""
    global _shared_client
    if _shared_client is None:
        _shared_client = SharedDataStoreClient(port)
    return _shared_client.get_client()
