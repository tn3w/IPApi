# pylint: disable=too-many-lines
import logging
from typing import Optional, Tuple, Final, Dict, Any, List

from netaddr import IPAddress, ipv6_verbose, IPNetwork, AddrFormatError
from fastapi import Request
import dns.reversename
import dns.name

from src.geo_info import (
    get_timezone_info,
    get_geo_country,
    get_rir_for_country,
    enrich_location_data,
)
from src.memory_server import MemoryDataStore
from src.utils import any_field_in_list, parse_fields_param, json_request

logger = logging.getLogger(__name__)


KNOWN_NETWORKS: Dict[str, Dict[str, str]] = {
    # Cloudflare
    "1.1.1.0/24": {
        "org": "Cloudflare, Inc.",
        "domain": "cloudflare.com",
        "abuse_contact": "abuse@cloudflare.com",
        "isp": "Cloudflare",
        "date_allocated": "2018-04-01",
    },
    "1.0.0.0/24": {
        "org": "APNIC Research and Development",
        "domain": "apnic.net",
        "abuse_contact": "helpdesk@apnic.net",
        "isp": "Cloudflare",
        "date_allocated": "2010-01-15",
    },
    "104.16.0.0/12": {
        "org": "Cloudflare, Inc.",
        "domain": "cloudflare.com",
        "abuse_contact": "abuse@cloudflare.com",
        "isp": "Cloudflare",
        "date_allocated": "2014-07-14",
    },
    "2606:4700::/32": {
        "org": "Cloudflare, Inc.",
        "domain": "cloudflare.com",
        "abuse_contact": "abuse@cloudflare.com",
        "isp": "Cloudflare",
        "date_allocated": "2012-08-24",
    },
    # Google
    "8.8.8.0/24": {
        "org": "Google LLC",
        "domain": "google.com",
        "abuse_contact": "network-abuse@google.com",
        "isp": "Google",
        "date_allocated": "2009-12-05",
    },
    "8.8.4.0/24": {
        "org": "Google LLC",
        "domain": "google.com",
        "abuse_contact": "network-abuse@google.com",
        "isp": "Google",
        "date_allocated": "2009-12-05",
    },
    "34.0.0.0/8": {
        "org": "Google LLC",
        "domain": "google.com",
        "abuse_contact": "network-abuse@google.com",
        "isp": "Google",
        "date_allocated": "2012-10-23",
    },
    "35.190.0.0/16": {
        "org": "Google LLC",
        "domain": "google.com",
        "abuse_contact": "network-abuse@google.com",
        "isp": "Google",
        "date_allocated": "2015-01-22",
    },
    "35.191.0.0/16": {
        "org": "Google LLC",
        "domain": "google.com",
        "abuse_contact": "network-abuse@google.com",
        "isp": "Google",
        "date_allocated": "2015-01-22",
    },
    "66.102.0.0/20": {
        "org": "Google LLC",
        "domain": "google.com",
        "abuse_contact": "network-abuse@google.com",
        "isp": "Google",
        "date_allocated": "2000-11-30",
    },
    "108.177.0.0/17": {
        "org": "Google LLC",
        "domain": "google.com",
        "abuse_contact": "network-abuse@google.com",
        "isp": "Google",
        "date_allocated": "2011-05-15",
    },
    "172.217.0.0/16": {
        "org": "Google LLC",
        "domain": "google.com",
        "abuse_contact": "network-abuse@google.com",
        "isp": "Google",
        "date_allocated": "2012-04-18",
    },
    "2607:f8b0::/32": {
        "org": "Google LLC",
        "domain": "google.com",
        "abuse_contact": "network-abuse@google.com",
        "isp": "Google",
        "date_allocated": "2008-03-22",
    },
    # Amazon AWS
    "3.0.0.0/8": {
        "org": "Amazon Web Services",
        "domain": "aws.amazon.com",
        "abuse_contact": "abuse@amazonaws.com",
        "isp": "Amazon",
        "date_allocated": "2017-07-08",
    },
    "18.32.0.0/11": {
        "org": "Amazon Web Services",
        "domain": "aws.amazon.com",
        "abuse_contact": "abuse@amazonaws.com",
        "isp": "Amazon",
        "date_allocated": "2016-09-27",
    },
    "52.0.0.0/8": {
        "org": "Amazon Web Services",
        "domain": "aws.amazon.com",
        "abuse_contact": "abuse@amazonaws.com",
        "isp": "Amazon",
        "date_allocated": "2014-11-11",
    },
    "54.0.0.0/8": {
        "org": "Amazon Web Services",
        "domain": "aws.amazon.com",
        "abuse_contact": "abuse@amazonaws.com",
        "isp": "Amazon",
        "date_allocated": "2012-07-25",
    },
    "2600:1f00::/24": {
        "org": "Amazon Web Services",
        "domain": "aws.amazon.com",
        "abuse_contact": "abuse@amazonaws.com",
        "isp": "Amazon",
        "date_allocated": "2016-11-10",
    },
    # Microsoft Azure
    "13.64.0.0/11": {
        "org": "Microsoft Corporation",
        "domain": "azure.microsoft.com",
        "abuse_contact": "abuse@microsoft.com",
        "isp": "Microsoft",
        "date_allocated": "2015-09-16",
    },
    "20.0.0.0/8": {
        "org": "Microsoft Corporation",
        "domain": "azure.microsoft.com",
        "abuse_contact": "abuse@microsoft.com",
        "isp": "Microsoft",
        "date_allocated": "2017-12-12",
    },
    "40.64.0.0/10": {
        "org": "Microsoft Corporation",
        "domain": "azure.microsoft.com",
        "abuse_contact": "abuse@microsoft.com",
        "isp": "Microsoft",
        "date_allocated": "2014-05-29",
    },
    "104.208.0.0/13": {
        "org": "Microsoft Corporation",
        "domain": "azure.microsoft.com",
        "abuse_contact": "abuse@microsoft.com",
        "isp": "Microsoft",
        "date_allocated": "2015-01-20",
    },
    "2603:1000::/24": {
        "org": "Microsoft Corporation",
        "domain": "azure.microsoft.com",
        "abuse_contact": "abuse@microsoft.com",
        "isp": "Microsoft",
        "date_allocated": "2014-10-15",
    },
    # Facebook
    "31.13.24.0/21": {
        "org": "Meta Platforms, Inc.",
        "domain": "facebook.com",
        "abuse_contact": "abuse@facebook.com",
        "isp": "Facebook",
        "date_allocated": "2011-10-28",
    },
    "66.220.144.0/20": {
        "org": "Meta Platforms, Inc.",
        "domain": "facebook.com",
        "abuse_contact": "abuse@facebook.com",
        "isp": "Facebook",
        "date_allocated": "2007-06-14",
    },
    "69.63.176.0/20": {
        "org": "Meta Platforms, Inc.",
        "domain": "facebook.com",
        "abuse_contact": "abuse@facebook.com",
        "isp": "Facebook",
        "date_allocated": "2006-05-08",
    },
    "157.240.0.0/16": {
        "org": "Meta Platforms, Inc.",
        "domain": "facebook.com",
        "abuse_contact": "abuse@facebook.com",
        "isp": "Facebook",
        "date_allocated": "2015-08-11",
    },
    "2a03:2880::/32": {
        "org": "Meta Platforms, Inc.",
        "domain": "facebook.com",
        "abuse_contact": "abuse@facebook.com",
        "isp": "Facebook",
        "date_allocated": "2010-08-18",
    },
    # Apple
    "17.0.0.0/8": {
        "org": "Apple Inc.",
        "domain": "apple.com",
        "abuse_contact": "abuse@apple.com",
        "isp": "Apple",
        "date_allocated": "1990-01-01",
    },
    "2620:149::/32": {
        "org": "Apple Inc.",
        "domain": "apple.com",
        "abuse_contact": "abuse@apple.com",
        "isp": "Apple",
        "date_allocated": "2011-09-14",
    },
    # Comcast
    "73.0.0.0/8": {
        "org": "Comcast Cable Communications",
        "domain": "comcast.net",
        "abuse_contact": "abuse@comcast.net",
        "isp": "Comcast",
        "date_allocated": "2013-11-22",
    },
    "76.96.0.0/12": {
        "org": "Comcast Cable Communications",
        "domain": "comcast.net",
        "abuse_contact": "abuse@comcast.net",
        "isp": "Comcast",
        "date_allocated": "2006-08-18",
    },
    "2601::/20": {
        "org": "Comcast Cable Communications",
        "domain": "comcast.net",
        "abuse_contact": "abuse@comcast.net",
        "isp": "Comcast",
        "date_allocated": "2012-03-30",
    },
    # Verizon
    "70.0.0.0/8": {
        "org": "Verizon Business",
        "domain": "verizon.com",
        "abuse_contact": "abuse@verizon.net",
        "isp": "Verizon",
        "date_allocated": "2005-07-15",
    },
    "72.0.0.0/8": {
        "org": "Verizon Business",
        "domain": "verizon.com",
        "abuse_contact": "abuse@verizon.net",
        "isp": "Verizon",
        "date_allocated": "2006-01-23",
    },
    "2600:6c00::/24": {
        "org": "Verizon Business",
        "domain": "verizon.com",
        "abuse_contact": "abuse@verizon.net",
        "isp": "Verizon",
        "date_allocated": "2013-06-05",
    },
    # AT&T
    "12.0.0.0/8": {
        "org": "AT&T Services, Inc.",
        "domain": "att.com",
        "abuse_contact": "abuse@att.com",
        "isp": "AT&T",
        "date_allocated": "1989-01-01",
    },
    "67.0.0.0/8": {
        "org": "AT&T Services, Inc.",
        "domain": "att.com",
        "abuse_contact": "abuse@att.com",
        "isp": "AT&T",
        "date_allocated": "2004-06-28",
    },
    "2600:1000::/24": {
        "org": "AT&T Services, Inc.",
        "domain": "att.com",
        "abuse_contact": "abuse@att.com",
        "isp": "AT&T",
        "date_allocated": "2012-09-19",
    },
    # Oracle Cloud
    "130.35.0.0/16": {
        "org": "Oracle Corporation",
        "domain": "oracle.com",
        "abuse_contact": "abuse@oracle.com",
        "isp": "Oracle",
        "date_allocated": "1991-05-22",
    },
    "134.70.0.0/16": {
        "org": "Oracle Corporation",
        "domain": "oracle.com",
        "abuse_contact": "abuse@oracle.com",
        "isp": "Oracle",
        "date_allocated": "1992-03-16",
    },
    "2603:c020::/32": {
        "org": "Oracle Corporation",
        "domain": "oracle.com",
        "abuse_contact": "abuse@oracle.com",
        "isp": "Oracle",
        "date_allocated": "2016-09-21",
    },
    # Akamai
    "23.0.0.0/8": {
        "org": "Akamai Technologies",
        "domain": "akamai.com",
        "abuse_contact": "abuse@akamai.com",
        "isp": "Akamai",
        "date_allocated": "2010-11-15",
    },
    "2600:1400::/24": {
        "org": "Akamai Technologies",
        "domain": "akamai.com",
        "abuse_contact": "abuse@akamai.com",
        "isp": "Akamai",
        "date_allocated": "2012-08-10",
    },
    # IBM Cloud
    "5.10.0.0/16": {
        "org": "IBM Corporation",
        "domain": "ibm.com",
        "abuse_contact": "abuse@ibm.com",
        "isp": "IBM",
        "date_allocated": "2012-04-30",
    },
    "2620:1ae::/32": {
        "org": "IBM Corporation",
        "domain": "ibm.com",
        "abuse_contact": "abuse@ibm.com",
        "isp": "IBM",
        "date_allocated": "2011-07-19",
    },
    # Alibaba Cloud
    "47.52.0.0/16": {
        "org": "Alibaba Group",
        "domain": "alibabacloud.com",
        "abuse_contact": "abuse@alibabacloud.com",
        "isp": "Alibaba Cloud",
        "date_allocated": "2016-02-25",
    },
    "2400:cb00::/32": {
        "org": "Alibaba Group",
        "domain": "alibabacloud.com",
        "abuse_contact": "abuse@alibabacloud.com",
        "isp": "Alibaba Cloud",
        "date_allocated": "2015-10-07",
    },
    # Digital Ocean
    "45.55.0.0/16": {
        "org": "DigitalOcean, LLC",
        "domain": "digitalocean.com",
        "abuse_contact": "abuse@digitalocean.com",
        "isp": "DigitalOcean",
        "date_allocated": "2014-12-18",
    },
    "104.236.0.0/16": {
        "org": "DigitalOcean, LLC",
        "domain": "digitalocean.com",
        "abuse_contact": "abuse@digitalocean.com",
        "isp": "DigitalOcean",
        "date_allocated": "2014-09-05",
    },
    "2604:a880::/32": {
        "org": "DigitalOcean, LLC",
        "domain": "digitalocean.com",
        "abuse_contact": "abuse@digitalocean.com",
        "isp": "DigitalOcean",
        "date_allocated": "2014-08-11",
    },
    # Tencent Cloud
    "43.242.0.0/16": {
        "org": "Tencent Holdings",
        "domain": "tencent.com",
        "abuse_contact": "abuse@tencent.com",
        "isp": "Tencent Cloud",
        "date_allocated": "2013-12-05",
    },
    "111.231.0.0/16": {
        "org": "Tencent Holdings",
        "domain": "tencent.com",
        "abuse_contact": "abuse@tencent.com",
        "isp": "Tencent Cloud",
        "date_allocated": "2017-06-15",
    },
    "2402:4e00::/32": {
        "org": "Tencent Holdings",
        "domain": "tencent.com",
        "abuse_contact": "abuse@tencent.com",
        "isp": "Tencent Cloud",
        "date_allocated": "2014-03-27",
    },
}

NETWORKS: List[tuple[IPNetwork, Dict[str, str]]] = [
    (IPNetwork(prefix), data) for prefix, data in KNOWN_NETWORKS.items()
]

VPN_PROVIDERS: Final[List[str]] = [
    "NordVPN",
    "ProtonVPN",
    "ExpressVPN",
    "Surfshark",
    "PrivateInternetAccess",
    "CyberGhost",
    "TunnelBear",
    "Mullvad",
]


TOR_EXIT_NODE_ASNS: Final[List[str]] = [
    "60729",
    "53667",
    "4224",
    "208323",
    "198093",
    "401401",
    "210731",
    "61125",
    "214503",
    "215125",
    "214094",
    "205100",
    "57860",
    "8283",
    "215659",
    "197648",
    "44925",
    "198985",
    "214996",
    "210083",
    "49770",
    "197422",
    "205235",
    "30893",
]


def lookup_known_network(ip_address: str) -> Optional[Dict[str, str]]:
    """
    Lookup an IP address in the known networks database.

    Args:
        ip_address: The IP address to lookup

    Returns:
        Dictionary with org, domain, abuse_contact, and isp if found,
        None otherwise
    """

    try:
        ip = IPNetwork(ip_address)
        for network, data in NETWORKS:
            if ip in network:
                data["prefix"] = str(network)
                return data
    except Exception:
        pass

    return None


def validate_ipv4(ip_address: str) -> bool:
    """
    Validate an IPv4 address without using regex.
    """
    octets = ip_address.split(".")
    if len(octets) != 4:
        return False

    for octet in octets:
        if not octet.isdigit():
            return False
        value = int(octet)
        if value < 0 or value > 255:
            return False
        if len(octet) > 1 and octet.startswith("0"):
            return False

    return True


def validate_ipv6(ip_address: str) -> bool:
    """
    Validate an IPv6 address without using regex.
    """
    segments = ip_address.split(":")
    if len(segments) > 8:
        return False

    if ip_address.count("::") > 1:
        return False

    for segment in segments:
        if not segment and "::" in ip_address:
            continue

        if len(segment) > 4:
            return False

        for char in segment.lower():
            if char not in "0123456789abcdef":
                return False

    return True


def get_ip_address_version(ip_address: str) -> Optional[int]:
    """
    Get the version of an IP address.

    Args:
        ip_address: The IP address to get the version of

    Returns:
        The version of the IP address (4 or 6) or None if invalid
    """
    if "." in ip_address and validate_ipv4(ip_address):
        return 4

    if ":" in ip_address and validate_ipv6(ip_address):
        return 6

    return None


def get_ip_address_classification(ip_address: IPAddress) -> Optional[str]:
    """
    Get the classification of an IP address.

    Args:
        ip_address: The IP address to get the classification of

    Returns:
        The classification of the IP address or None if invalid
    """
    classifications = {
        "private": (
            (ip_address.version == 4 and ip_address.is_ipv4_private_use())
            or (ip_address.version == 6 and ip_address.is_ipv6_unique_local())
        ),
        "loopback": ip_address.is_loopback(),
        "multicast": ip_address.is_multicast(),
        "reserved": ip_address.is_reserved(),
        "link_local": ip_address.is_link_local(),
        "public": ip_address.is_global(),
    }

    for classification, condition in classifications.items():
        if condition:
            return classification

    return "unknown"


def extract_ipv4_from_ipv6(ipv6_address: IPAddress) -> Optional[str]:
    """
    Extract IPv4 address from various IPv6 formats.

    Handles:
    - IPv4-mapped IPv6 addresses (::ffff:a.b.c.d)
    - 6to4 addresses (2002:AABB:CCDD::)
    - IPv6 with embedded IPv4 notation (2001:db8::192:168:0:1)

    Args:
        ipv6_address: The IPv6 address to extract IPv4 from

    Returns:
        The extracted IPv4 address as a string, or None if extraction fails
    """
    try:
        if ipv6_address.is_ipv4_mapped():
            ipv4_int = int(ipv6_address) & 0xFFFFFFFF
            return str(IPAddress(ipv4_int, version=4))

        ipv6_address_str = str(ipv6_address)
        if ipv6_address_str.lower().startswith("2002:"):
            parts = ipv6_address_str.split(":")
            if len(parts) >= 3:
                hex_ip = parts[1] + parts[2]
                if len(hex_ip) == 8:
                    ipv4_int = int(hex_ip, 16)
                    return str(IPAddress(ipv4_int, version=4))

        parts = ipv6_address_str.split(":")
        for i, part in enumerate(parts):
            if part and part.isdigit() and 0 <= int(part) <= 255:
                if i + 3 < len(parts) and all(
                    p and p.isdigit() and 0 <= int(p) <= 255 for p in parts[i : i + 4]
                ):
                    return ".".join(parts[i : i + 4])

        return None
    except ValueError:
        return None


def get_hostname_from_ip(addr: str, memory_store: MemoryDataStore) -> Optional[str]:
    """Get hostname from IP address."""
    try:
        rev_name = dns.reversename.from_address(addr)
        if isinstance(rev_name, dns.name.Name):
            rev_name = str(rev_name)
            ptr_records = memory_store.dns_query(rev_name, "PTR")
            if ptr_records and len(ptr_records) > 0:
                return str(ptr_records[0]).rstrip(".")
            return None
    except Exception as e:
        logger.error("Failed to get hostname for IP %s: %s", addr, e)
        return None


def get_ip_from_hostname(hostname: str, memory_store: MemoryDataStore) -> Optional[str]:
    """Resolve hostname to IP address."""
    a_records = memory_store.dns_query(hostname, "A")
    if a_records and len(a_records) > 0:
        return str(a_records[0])

    aaaa_records = memory_store.dns_query(hostname, "AAAA")
    if aaaa_records and len(aaaa_records) > 0:
        return str(aaaa_records[0])

    return None


def get_ipv4_from_hostname(
    hostname: str, memory_store: MemoryDataStore
) -> Optional[str]:
    """Extract IPv4 address from hostname."""
    a_records = memory_store.dns_query(hostname, "A")
    if a_records and len(a_records) > 0:
        return str(a_records[0])
    return None


def get_ipv6_from_hostname(
    hostname: str, memory_store: MemoryDataStore
) -> Optional[str]:
    """Extract IPv6 address from hostname."""
    aaaa_records = memory_store.dns_query(hostname, "AAAA")
    if aaaa_records and len(aaaa_records) > 0:
        return str(aaaa_records[0])
    return None


def reverse_ip_address(ip_address: str, ip_version: int) -> str:
    """Reverse an IP address."""
    if ip_version == 4:
        return ".".join(reversed(ip_address.split(".")))

    full_ipv6 = str(IPAddress(ip_address).format(ipv6_verbose))
    return ".".join(reversed(full_ipv6.replace(":", "")))


VALID_RIRS = ["arin", "ripe", "apnic", "lacnic", "afrinic"]


def get_team_cymru_info(
    ip_address: str,
    ip_version: int,
    memory_store: MemoryDataStore,
) -> Optional[Dict[str, Any]]:
    """Get Team Cymru info for an IP address."""
    reversed_ip_address = reverse_ip_address(ip_address, ip_version)
    query = reversed_ip_address + (
        ".origin.asn.cymru.com" if ip_version == 4 else ".origin6.asn.cymru.com"
    )

    txt_records = memory_store.dns_query(query, "TXT")
    if txt_records and len(txt_records) > 0:
        parts_text = str(txt_records[0]).strip('"')
        parts = [part.strip() for part in parts_text.split("|")]
        if len(parts) >= 3:
            rir = parts[3].strip().lower() if len(parts) > 3 else None
            if rir:
                for valid_rir in VALID_RIRS:
                    if valid_rir in rir:
                        rir = valid_rir
                        break

            result = {
                "asn": parts[0].strip(),
                "prefix": parts[1].strip(),
                "country": parts[2].strip(),
                "rir": rir,
                "date_allocated": parts[4].strip() if len(parts) > 4 else None,
            }
            return result

    return None


def get_rpki_info(
    asn: str,
    prefix: str,
    memory_store: MemoryDataStore,
) -> Tuple[str, int]:
    """Get RPKI info for an ASN and prefix."""
    if not prefix:
        return "unknown", 0

    cached_value = memory_store.get_rpki_cache_item(prefix)
    if cached_value is not None:
        return cached_value

    if not asn:
        return "unknown", 0

    url = (
        "https://stat.ripe.net/data/rpki-validation/data.json?resource="
        f"{'AS' + asn if asn.isdigit() else asn}&prefix={prefix}"
    )
    data = json_request(url).get("data", {})
    status, roa_count = "unknown", 0
    if data:
        status = data.get("status", "unknown").lower()
        roa_count = len(data.get("validating_roas", []))

    result = (status, roa_count)
    memory_store.set_rpki_cache_item(prefix, result)

    return result


def get_abuse_contact(ip_address: str, memory_store: MemoryDataStore) -> Optional[str]:
    """Get abuse contact for an IP address."""
    cached_value = memory_store.get_abuse_contact_cache_item(ip_address)
    if cached_value is not None:
        return cached_value

    url = (
        "https://stat.ripe.net/data/abuse-contact-finder/data.json"
        f"?resource={ip_address}"
    )

    data = json_request(url)
    abuse_contacts = data.get("data", {}).get("abuse_contacts", [])
    if abuse_contacts:
        abuse_contact = abuse_contacts[0]
        memory_store.set_abuse_contact_cache_item(ip_address, abuse_contact)
        return abuse_contact

    memory_store.set_abuse_contact_cache_item(ip_address, None)
    return None


def _get_general_info(
    ip_address: str,
    ip_address_object: IPAddress,
    ip_address_version: int,
    memory_store: MemoryDataStore,
    fields: list[str],
) -> dict:
    """Get general information about the IP address."""
    classification = get_ip_address_classification(ip_address_object)

    response = {
        "ip_address": ip_address,
        "version": ip_address_version,
        "classification": classification,
    }

    if "hostname" in fields:
        hostname = "localhost" if ip_address_version == 4 else "ip6-localhost"
        if classification != "loopback":
            hostname = get_hostname_from_ip(ip_address, memory_store)
        response["hostname"] = hostname

    if "ipv4_address" in fields:
        ipv4_address = ip_address
        if ip_address_version == 6:
            ipv4_address = extract_ipv4_from_ipv6(ip_address_object)
        if not ipv4_address and hostname:
            ipv4_address = get_ipv4_from_hostname(hostname, memory_store)
        response["ipv4_address"] = ipv4_address

    if "ipv6_address" in fields:
        ipv6_address = ip_address
        if ip_address_version == 4 and hostname:
            ipv6_address = get_ipv6_from_hostname(hostname, memory_store)
        response["ipv6_address"] = ipv6_address

    return response


def _get_abuse_info(
    ip_address: str,
    hostname: Optional[str],
    memory_store: MemoryDataStore,
    fields: list[str],
) -> dict:
    """Get abuse information about the IP address."""
    ip_groups = []
    if any_field_in_list(
        fields,
        ["is_proxy", "is_vpn", "vpn_provider", "is_forum_spammer", "is_tor_exit_node"],
    ):
        ip_groups = memory_store.get_ip_groups(ip_address)

    asn, as_name, org = None, None, None
    if any_field_in_list(fields, ["asn", "as_name", "is_datacenter"]):
        asn, as_name = memory_store.get_ip_asn_maxmind(ip_address)
        asn_ip2location, as_name_ip2location = memory_store.get_ip_asn_ip2location(
            ip_address
        )
        if not asn:
            asn = asn_ip2location
        if not as_name:
            as_name = as_name_ip2location
        if as_name and as_name != as_name_ip2location:
            org = as_name_ip2location

    is_firehol = False
    is_datacenter = False
    if "is_firehol" in fields:
        is_firehol = memory_store.is_ip_in_firehol(ip_address)

    if "is_datacenter" in fields:
        is_datacenter = memory_store.is_datacenter_asn(asn) if asn else False

    ip2proxy_data = {}
    if any_field_in_list(
        fields, ["is_proxy", "isp", "domain", "threat_type", "fraud_score"]
    ):
        ip2proxy_data = memory_store.get_ip_ip2proxy(ip_address)

    is_proxy = (
        "FireholProxies" in ip_groups
        or "AwesomeProxies" in ip_groups
        or ip2proxy_data.get("is_proxy") is True
    )
    vpn_provider = next((name for name in VPN_PROVIDERS if name in ip_groups), None)
    is_vpn = vpn_provider is not None
    is_forum_spammer = "StopForumSpam" in ip_groups
    is_tor_exit_node = "TorExitNodes" in ip_groups or asn in TOR_EXIT_NODE_ASNS

    fraud_score = 0.0
    threat_type = None

    for factor in [
        (is_firehol, 0.6, "spam"),
        (is_forum_spammer, 0.6, "spam"),
        (is_tor_exit_node, 0.5, "anonymous"),
        (is_proxy, 0.5, "spam"),
        (is_vpn, 0.4, "anonymous"),
        (is_datacenter, 0.4, "abuse"),
    ]:
        if factor[0]:
            fraud_score += factor[1]
            threat_type = factor[2]

    fraud_score = min(fraud_score, 1.0)

    return {
        "asn": asn,
        "as_name": as_name,
        "org": org,
        "isp": ip2proxy_data.get("isp"),
        "domain": ip2proxy_data.get("domain")
        or (
            ".".join(hostname.rsplit(".", 2)[-2:])
            if hostname and "." in hostname
            else None
        ),
        "is_vpn": is_vpn,
        "vpn_provider": vpn_provider,
        "is_proxy": is_proxy,
        "is_firehol": is_firehol,
        "is_datacenter": is_datacenter,
        "is_forum_spammer": is_forum_spammer,
        "is_tor_exit_node": is_tor_exit_node,
        "threat_type": ip2proxy_data.get("threat_type") or threat_type,
        "fraud_score": ip2proxy_data.get("fraud_score") or fraud_score,
    }


def _get_geographic_info(
    ip_address: str, memory_store: MemoryDataStore, fields: list[str]
) -> dict:
    """Get geographic information about the IP address."""
    geographic_info = memory_store.get_ip_city_ip2location(ip_address)
    if (
        not geographic_info
        or not geographic_info.get("latitude")
        or not geographic_info.get("longitude")
    ):
        geographic_info = memory_store.get_ip_city_maxmind(ip_address)

    if (
        any_field_in_list(
            fields,
            [
                "timezone_name",
                "timezone_abbreviation",
                "utc_offset",
                "utc_offset_str",
                "dst_active",
            ],
        )
        and geographic_info.get("latitude")
        and geographic_info.get("longitude")
    ):
        timezone_info = get_timezone_info(
            float(geographic_info.get("latitude", 0)),
            float(geographic_info.get("longitude", 0)),
        )
        if timezone_info:
            geographic_info.update(timezone_info)

    country_code, country_name = geographic_info.get(
        "country_code"
    ), geographic_info.get("country")
    if country_code or country_name:
        geographic_info.update(get_geo_country(country_code, country_name))

    return geographic_info


def _get_network_info(
    ip_address: str,
    ip_address_version: int,
    memory_store: MemoryDataStore,
    country_code: Optional[str],
    asn: Optional[str],
    fields: list[str],
) -> Tuple[dict[str, Any], Optional[str], Optional[str], Optional[str]]:
    """Get network information about the IP address."""
    network_info: dict[str, Any] = {}
    domain = None

    if any_field_in_list(
        fields,
        [
            "prefix",
            "org",
            "domain",
            "abuse_contact",
            "isp",
            "date_allocated",
            "rpki_status",
            "rpki_roa_count",
        ],
    ):
        known_network = lookup_known_network(ip_address)
        if known_network:
            network_info.update(known_network)
        else:
            team_cymru_data = get_team_cymru_info(
                ip_address, ip_address_version, memory_store
            )
            if team_cymru_data:
                country_code = team_cymru_data.get("country")
                asn = team_cymru_data.get("asn")
                for field in ["country", "asn"]:
                    if team_cymru_data.get(field):
                        del team_cymru_data[field]

                network_info.update(team_cymru_data)

    if any_field_in_list(fields, ["abuse_contact"]) and not network_info.get(
        "abuse_contact"
    ):
        abuse_contact = get_abuse_contact(ip_address, memory_store)
        if abuse_contact:
            network_info["abuse_contact"] = abuse_contact
            if not domain and "@" in abuse_contact:
                domain = abuse_contact.split("@")[-1]

    if any_field_in_list(fields, ["rir"]) and not network_info.get("rir"):
        rir = get_rir_for_country(country_code) if country_code else None
        if rir:
            network_info["rir"] = rir

    if any_field_in_list(fields, ["rpki_status", "rpki_roa_count"]):
        if asn and network_info.get("prefix"):
            prefix = network_info["prefix"]
            rpki_status, rpki_roa_count = get_rpki_info(asn, prefix, memory_store)
        else:
            rpki_status, rpki_roa_count = "unknown", 0

        network_info["rpki_status"] = rpki_status
        network_info["rpki_roa_count"] = rpki_roa_count

    return network_info, country_code, asn, domain


def format_response(
    ip_info: Dict[str, Any], fields: list[str], minify: bool = False
) -> Dict[str, Any]:
    """Format the response for the IP address information."""
    for field in ["latitude", "longitude"]:
        if ip_info.get(field) and not isinstance(ip_info[field], float):
            try:
                ip_info[field] = float(ip_info[field])
            except ValueError:
                pass

    if ip_info.get("region_code") and not isinstance(ip_info["region_code"], str):
        try:
            ip_info["region_code"] = str(ip_info["region_code"])
        except ValueError:
            pass

    if minify:
        return {
            field: ip_info.get(field)
            for field in fields
            if ip_info.get(field) is not None
        }

    return {field: ip_info.get(field) for field in fields}


def get_ip_info(
    ip_address: str, request: Request, memory_store: MemoryDataStore
) -> Optional[dict]:
    """
    Get IP address information.

    Args:
        ip_address: The IP address to get information for.
        fields: The fields to get information for.
        memory_store: The memory store to use.
    """
    if not ip_address or not isinstance(ip_address, str):
        return None

    ip_address = ip_address.strip()
    ip_address_version = get_ip_address_version(ip_address)
    if not ip_address_version:
        return None

    try:
        version = 4 if ip_address_version == 4 else 6
        ip_address_object = IPAddress(ip_address, version=version)
    except AddrFormatError:
        return None

    fields_param = request.query_params.get("fields", "")
    if not isinstance(fields_param, str):
        fields_param = ""

    fields = parse_fields_param(fields_param)

    min_param = request.query_params.get("min", "0")
    if not isinstance(min_param, str):
        min_param = "0"
    minify = min_param == "1"

    response = _get_general_info(
        ip_address, ip_address_object, ip_address_version, memory_store, fields
    )

    if response["classification"] != "public":
        return format_response(response, fields, minify)

    response.update(
        _get_abuse_info(ip_address, response.get("hostname"), memory_store, fields)
    )

    geographic_info = {}
    if any_field_in_list(
        fields,
        [
            "continent",
            "continent_code",
            "country",
            "country_code",
            "is_eu",
            "region",
            "region_code",
            "city",
            "district",
            "postal_code",
            "latitude",
            "longitude",
            "timezone_name",
            "timezone_abbreviation",
            "utc_offset",
            "utc_offset_str",
            "dst_active",
            "currency",
        ],
    ):
        geographic_info = _get_geographic_info(ip_address, memory_store, fields)

    network_info, country_code, asn, domain = _get_network_info(
        ip_address,
        ip_address_version,
        memory_store,
        geographic_info.get("country_code"),
        response.get("asn"),
        fields,
    )
    response.update(network_info)

    if country_code and not geographic_info.get("country_code"):
        geographic_info["country_code"] = country_code
    if asn and not response.get("asn"):
        response["asn"] = asn
    if domain:
        response["domain"] = domain

    if any_field_in_list(
        fields,
        [
            "city",
            "region",
            "region_code",
            "district",
            "latitude",
            "longitude",
            "postal_code",
        ],
    ) and geographic_info.get("country_code"):
        enriched_city_data = enrich_location_data(
            geographic_info.get("country_code"),
            geographic_info.get("postal_code"),
            geographic_info.get("latitude"),
            geographic_info.get("longitude"),
            geographic_info.get("city"),
            geographic_info.get("region"),
            geographic_info.get("district"),
        )
        if enriched_city_data:
            geographic_info.update(enriched_city_data)

    response.update(geographic_info)

    return format_response(response, fields, minify)


def get_ip_address(request: Request) -> Optional[str]:
    """
    Get the IP address from the request.
    """
    ip_address = None

    for header in ["CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"]:
        if header in request.headers:
            header_value = request.headers[header]
            if not header_value:
                continue

            if header == "X-Forwarded-For":
                forwarded_ips = header_value.split(",")
                if forwarded_ips:
                    ip_address = forwarded_ips[0].strip()
            else:
                ip_address = header_value.strip()

            if ip_address and (validate_ipv4(ip_address) or validate_ipv6(ip_address)):
                break

    if not ip_address and request.client and request.client.host:
        client_ip = request.client.host
        if validate_ipv4(client_ip) or validate_ipv6(client_ip):
            ip_address = client_ip

    return ip_address
