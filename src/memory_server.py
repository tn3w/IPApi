import atexit
import io
import json
import logging
import multiprocessing
from multiprocessing.managers import BaseManager
import os
import signal
import socket
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

import maxminddb
from netaddr import IPNetwork, IPAddress
import dns.resolver
import dns.reversename
import dns.message
import dns.query
from IP2Location import IP2Location
from IP2Proxy import IP2Proxy

from src.utils import get_nested

logger = logging.getLogger(__name__)


DATASET_DIR = Path("datasets")
if not DATASET_DIR.exists():
    DATASET_DIR.mkdir(parents=True)


def get_github_release_assets(repo_path: str) -> Dict[str, str]:
    """Get all assets from the latest releases of a GitHub repository."""
    api_url = f"https://api.github.com/repos/{repo_path}/releases"
    req = urllib.request.Request(api_url, headers={"User-Agent": "ip-address-info"})
    assets = {}

    try:
        with urllib.request.urlopen(req) as response:
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


GEOLITE_ASSETS: Dict[str, str] = {}


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
) -> str:
    """Download and extract an IP2Location database file.

    Args:
        package_code: The code for the IP2Location package
        bin_name: The name of the binary file
        dataset_dir: Directory to store the extracted file

    Returns:
        Path to the extracted binary file
    """
    bin_path = os.path.join(dataset_dir, bin_name)
    if os.path.exists(bin_path):
        return bin_path

    token = os.environ.get("IP2LOCATION_TOKEN", "")
    if not token:
        logger.warning("IP2LOCATION_TOKEN environment variable not set")

    url = f"https://www.ip2location.com/download/?token={token}&file={package_code}"
    logger.info("Downloading IP2Location package %s...", package_code)

    try:
        with urllib.request.urlopen(url) as response:
            content = response.read()

        with zipfile.ZipFile(io.BytesIO(content)) as zip_ref:
            for zip_info in zip_ref.infolist():
                if not zip_info.filename.endswith(".BIN"):
                    continue
                with open(bin_path, "wb") as f:
                    f.write(zip_ref.read(zip_info.filename))

                logger.info("Extracted %s to %s", zip_info.filename, bin_path)
                break

        return bin_path
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

DATASETS: Dict[str, Tuple[Union[str, Callable[[], str]], str]] = {
    # GeoLite2 ASN Database
    "GeoLite2-ASN": (
        lambda: get_geolite_url("GeoLite2-ASN.mmdb"),
        "GeoLite2-ASN.mmdb",
    ),
    # GeoLite2 City Database
    "GeoLite2-City": (
        lambda: get_geolite_url("GeoLite2-City.mmdb"),
        "GeoLite2-City.mmdb",
    ),
    # Abuse: VPNs / Proxies / Spam
    "IPSet": (
        "https://raw.githubusercontent.com/tn3w/IPSet/refs/heads/master/ipset.json",
        "ipset.json",
    ),
    # Abuse: Data Center
    "Data-Center-ASNS": (
        "https://raw.githubusercontent.com/tn3w/IPSet/refs/heads/master/datacenter_asns.json",
        "data-center-asns.json",
    ),
    # Abuse: Firehol Level 1
    "Firehol-Level-1": (
        "https://raw.githubusercontent.com/tn3w/IPSet/refs/heads/master/firehol_level1.json",
        "firehol_level1.json",
    ),
}


def download_all_datasets() -> None:
    """Download all datasets defined in the DATASETS dictionary and IP2Location databases."""
    for dataset_name, (url_or_getter, filename) in DATASETS.items():
        file_path = os.path.join(DATASET_DIR, filename)
        if os.path.exists(file_path):
            continue

        try:
            url = (
                url_or_getter()  # pylint: disable=not-callable
                if callable(url_or_getter)
                else url_or_getter
            )
            logger.info("Downloading dataset %s from %s", dataset_name, url)
            urllib.request.urlretrieve(str(url), file_path)
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
            raise RuntimeError(f"Failed to download IP2Location dataset: {e}") from e


class IPNetworkEncoder(json.JSONEncoder):
    """Encoder for IPNetwork objects."""

    def default(self, o: Any) -> Any:
        if isinstance(o, IPNetwork):
            return str(o)
        return json.JSONEncoder.default(self, o)


class MemoryDataStore:
    """Stores and provides access to IP datasets in memory."""

    def __init__(self) -> None:
        self.ip_to_groups: Dict[str, List[str]] = {}
        self.datacenter_asns: Set[str] = set()
        self.firehol_networks: List[IPNetwork] = []
        self.asn_reader: Optional[maxminddb.Reader] = None
        self.city_reader: Optional[maxminddb.Reader] = None

        self.ip2location_db: Optional[IP2Location] = None
        self.ip2proxy_db: Optional[IP2Proxy] = None
        self.ip2location_asn_db: Optional[IP2Location] = None

        self.dns_cache: Dict[str, dns.resolver.Answer] = {}
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 0.3
        self.resolver.lifetime = 0.5

        self.is_loaded = False

        self.ip_groups_cache: Dict[str, List[str]] = {}
        self.datacenter_asn_cache: Dict[str, bool] = {}
        self.firehol_ip_cache: Dict[str, bool] = {}
        self.ip_asn_maxmind_cache: Dict[str, str] = {}
        self.ip_city_maxmind_cache: Dict[str, str] = {}
        self.ip_asn_ip2location_cache: Dict[str, str] = {}
        self.ip_city_ip2location_cache: Dict[str, str] = {}
        self.ip_ip2proxy_cache: Dict[str, str] = {}
        self._rpki_cache: Dict[str, Tuple[str, int]] = {}
        self._abuse_contact_cache: Dict[str, Optional[str]] = {}

    def load_datasets(self) -> None:
        """Load all datasets into memory."""
        if self.is_loaded:
            return

        ipset_path = os.path.join(DATASET_DIR, DATASETS["IPSet"][1])
        if os.path.exists(ipset_path):
            with open(ipset_path, "r", encoding="utf-8") as f:
                group_to_ips = json.load(f)

            for group, ips in group_to_ips.items():
                for ip in ips:
                    if ip not in self.ip_to_groups:
                        self.ip_to_groups[ip] = []
                    self.ip_to_groups[ip].append(group)

            logger.info("Loaded %d IPs with group mappings", len(self.ip_to_groups))

        dc_asns_path = os.path.join(DATASET_DIR, DATASETS["Data-Center-ASNS"][1])
        if os.path.exists(dc_asns_path):
            with open(dc_asns_path, "r", encoding="utf-8") as f:
                asn_list = json.load(f)
                self.datacenter_asns = set(asn_list)

            logger.info("Loaded %d data center ASNs", len(self.datacenter_asns))

        firehol_path = os.path.join(DATASET_DIR, DATASETS["Firehol-Level-1"][1])
        if os.path.exists(firehol_path):
            with open(firehol_path, "r", encoding="utf-8") as f:
                firehol_data = json.load(f)

            self.firehol_networks = [IPNetwork(cidr) for cidr in firehol_data]
            logger.info(
                "Loaded %d Firehol Level 1 networks", len(self.firehol_networks)
            )

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
                logger.info("Loaded IP2Location DB9 database")
            except Exception as e:
                logger.error("Failed to load IP2Location DB9 database: %s", e)

        ip2proxy_path = os.path.join(DATASET_DIR, "IP2PROXY-LITE-PX12.BIN")
        if os.path.exists(ip2proxy_path):
            try:
                self.ip2proxy_db = IP2Proxy(ip2proxy_path)
                logger.info("Loaded IP2Proxy PX12 database")
            except Exception as e:
                logger.error("Failed to load IP2Proxy PX12 database: %s", e)

        ip2location_asn_path = os.path.join(DATASET_DIR, "IP2LOCATION-LITE-ASN.BIN")
        if os.path.exists(ip2location_asn_path):
            try:
                self.ip2location_asn_db = IP2Location(ip2location_asn_path)
                logger.info("Loaded IP2Location ASN database")
            except Exception as e:
                logger.error("Failed to load IP2Location ASN database: %s", e)

        self.is_loaded = True
        logger.info("All datasets loaded into memory")

    def get_ip_groups(self, ip: str) -> List[str]:
        """Get groups associated with an IP address."""
        if ip in self.ip_groups_cache:
            return self.ip_groups_cache[ip]

        result = self.ip_to_groups.get(ip, [])

        self.ip_groups_cache[ip] = result
        return result

    def is_datacenter_asn(self, asn: str) -> bool:
        """Check if an ASN is a data center ASN."""
        if asn in self.datacenter_asn_cache:
            return self.datacenter_asn_cache[asn]

        result = asn in self.datacenter_asns

        self.datacenter_asn_cache[asn] = result
        return result

    def is_ip_in_firehol(self, ip: str) -> bool:
        """Check if an IP is in the Firehol Level 1 list."""
        if ip in self.firehol_ip_cache:
            return self.firehol_ip_cache[ip]

        try:
            ip_obj = IPAddress(ip)
            result = any(ip_obj in network for network in self.firehol_networks)

            self.firehol_ip_cache[ip] = result
            return result
        except (ValueError, TypeError):
            self.firehol_ip_cache[ip] = False
            return False

    def get_ip_asn_maxmind(self, ip: str) -> Tuple[Optional[str], Optional[str]]:
        """Get the ASN for an IP address using MaxMind database."""
        if ip in self.ip_asn_maxmind_cache:
            return self.ip_asn_maxmind_cache[ip]

        if not self.asn_reader:
            logger.warning("ASN database not loaded")
            return None, None

        try:
            result = self.asn_reader.get(ip)
            if result and "autonomous_system_number" in result:
                asn = str(result["autonomous_system_number"])
                asn_name = str(result["autonomous_system_organization"])
                self.ip_asn_maxmind_cache[ip] = (asn, asn_name)
                return asn, asn_name
        except Exception as e:
            logger.error("Error looking up ASN for IP %s: %s", ip, e)

        self.ip_asn_maxmind_cache[ip] = (None, None)
        return None, None

    def get_ip_city_maxmind(self, ip: str) -> Dict[str, Any]:
        """Get the city for an IP address using MaxMind database."""
        if ip in self.ip_city_maxmind_cache:
            return self.ip_city_maxmind_cache[ip]

        if not self.city_reader:
            logger.warning("City database not loaded")
            return {}

        city_data = {}

        try:
            result = self.city_reader.get(ip)

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

    def get_ip_asn_ip2location(self, ip: str) -> Tuple[Optional[str], Optional[str]]:
        """Get the ASN for an IP address using IP2Location database."""
        if ip in self.ip_asn_ip2location_cache:
            return self.ip_asn_ip2location_cache[ip]

        if not self.ip2location_asn_db:
            logger.warning("IP2Location ASN database not loaded")
            return None, None

        try:
            result = self.ip2location_asn_db.get_all(ip)
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

    def get_ip_city_ip2location(self, ip: str) -> Dict[str, Any]:
        """Get the city for an IP address using IP2Location database."""
        if ip in self.ip_city_ip2location_cache:
            return self.ip_city_ip2location_cache[ip]

        if not self.ip2location_db:
            logger.warning("IP2Location database not loaded")
            return {}

        city_data = {}

        try:
            result = self.ip2location_db.get_all(ip)

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

    def get_ip_ip2proxy(self, ip: str) -> Dict[str, Any]:
        """Get the IP2Proxy data for an IP address."""
        if ip in self.ip_ip2proxy_cache:
            return self.ip_ip2proxy_cache[ip]

        if not self.ip2proxy_db:
            logger.warning("IP2Proxy database not loaded")
            return {}

        try:
            result = self.ip2proxy_db.get_all(ip)

            fraud_score = result.get("fraud_score")
            if fraud_score.isdigit():
                fraud_score = int(fraud_score) / 100
            else:
                fraud_score = None

            data = {
                "is_proxy": result.get("proxy_type") == "1",
                "isp": result.get("isp") if result.get("isp") != "-" else None,
                "domain": result.get("domain") if result.get("domain") != "-" else None,
                "fraud_score": fraud_score,
                "threat_type": (
                    result.get("threat").lower()
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

    def dns_query(self, qname: str, qtype: str) -> Optional[dns.resolver.Answer]:
        """Make a DNS query and cache the response."""
        cache_key = f"{qname}:{qtype}"
        if cache_key in self.dns_cache:
            return self.dns_cache[cache_key]

        try:
            result = self.resolver.resolve(qname, qtype)
            self.dns_cache[cache_key] = result
            return result
        except Exception:
            self.dns_cache[cache_key] = None
            return None

    def get_rpki_cache_item(self, prefix: str) -> Optional[Tuple[str, int]]:
        """Get an item from the RPKI cache."""
        return self._rpki_cache.get(prefix)

    def set_rpki_cache_item(self, prefix: str, value: Tuple[str, int]) -> None:
        """Set an item in the RPKI cache."""
        self._rpki_cache[prefix] = value

    def get_abuse_contact_cache_item(self, ip_address: str) -> Optional[str]:
        """Get an item from the abuse contact cache."""
        return self._abuse_contact_cache.get(ip_address)

    def set_abuse_contact_cache_item(
        self, ip_address: str, value: Optional[str]
    ) -> None:
        """Set an item in the abuse contact cache."""
        self._abuse_contact_cache[ip_address] = value


class MemoryServer:
    """Server that manages shared memory access across processes."""

    _instance: Optional["MemoryServer"] = None
    _manager: Optional[BaseManager] = None
    _server_process: Optional[multiprocessing.Process] = None
    _lock = multiprocessing.Lock()
    _lock_file = Path(".ipapi_memory_server.lock")

    @classmethod
    def get_instance(cls) -> "MemoryServer":
        """Get or create the singleton instance of the memory server."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self) -> None:
        self.port = self._get_port_from_lock_file() or self._find_available_port()
        self.authkey = b"ip-address-info"
        self.data_store = MemoryDataStore()
        self._datasets_loaded = False

    def _get_port_from_lock_file(self) -> Optional[int]:
        """Check if a lock file exists and get the port from it."""
        if self._lock_file.exists():
            try:
                with open(self._lock_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    port = data.get("port")
                    pid = data.get("pid")

                    if pid and self._is_process_running(pid):
                        return port

                logger.info("Found stale lock file, removing it")
                self._lock_file.unlink(missing_ok=True)
            except (json.JSONDecodeError, IOError) as e:
                logger.error("Error reading lock file: %s", e)
                self._lock_file.unlink(missing_ok=True)
        return None

    def _is_process_running(self, pid: int) -> bool:
        """Check if a process with the given PID is running."""
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    def _create_lock_file(self) -> None:
        """Create a lock file with the server port and PID."""
        with open(self._lock_file, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "port": self.port,
                    "pid": os.getpid(),
                    "started_at": time.time(),
                },
                f,
            )
        logger.info("Created lock file at %s", self._lock_file)

        atexit.register(self._remove_lock_file)

    def _remove_lock_file(self) -> None:
        """Remove the lock file."""
        if self._lock_file.exists():
            self._lock_file.unlink()
            logger.info("Removed lock file at %s", self._lock_file)

    def _find_available_port(
        self, start_port: int = 50000, max_attempts: int = 100
    ) -> int:
        """Find an available port for the manager to use."""
        for port in range(start_port, start_port + max_attempts):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(("localhost", port)) != 0:
                    return port
        raise RuntimeError("Could not find an available port")

    def start(self) -> None:
        """Start the memory server process if it's not already running."""
        if self._server_process is not None and self._server_process.is_alive():
            return

        port_in_use = False
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(("localhost", self.port))
                port_in_use = True
        except (ConnectionRefusedError, OSError):
            port_in_use = False

        if port_in_use:
            return

        download_all_datasets()
        self._create_lock_file()

        class MemoryManager(BaseManager):
            """Manager for the memory server."""

        MemoryManager.register("get_data_store", callable=lambda: self.data_store)

        self._manager = MemoryManager(address=("", self.port), authkey=self.authkey)

        self._server_process = multiprocessing.Process(
            target=self._run_server, args=(self._manager,), daemon=True
        )
        self._server_process.start()

        time.sleep(1)

        logger.info("Memory server started on port %d", self.port)

    def _run_server(self, manager: BaseManager) -> None:
        """Run the manager server in a separate process."""
        signal.signal(signal.SIGINT, lambda *args: os._exit(0))
        signal.signal(signal.SIGTERM, lambda *args: os._exit(0))

        logger.info("Memory server process starting...")

        server = manager.get_server()
        server.serve_forever()

    def get_client(self) -> BaseManager:
        """Get a client connection to the memory server."""

        class MemoryManager(BaseManager):
            """Manager for the memory server."""

        MemoryManager.register("get_data_store")

        manager = MemoryManager(address=("localhost", self.port), authkey=self.authkey)
        try:
            manager.connect()
            return manager
        except ConnectionRefusedError:
            logger.error("Failed to connect to memory server. Starting it now...")
            self.start()
            time.sleep(1)
            manager.connect()
            return manager
