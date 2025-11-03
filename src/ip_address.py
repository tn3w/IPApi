import logging
from typing import Any

from netaddr import IPAddress, ipv6_verbose, IPNetwork, AddrFormatError
from fastapi import Request
import dns.reversename
import dns.name

from src.geo_info import (
    get_timezone_info,
    get_geo_country,
    enrich_location_data,
    get_rir_for_country,
    get_ripe_geolocation,
)
from src.utils import (
    any_field_in_list,
    json_request,
    xml_request,
    parse_fields_param,
    extract_domain_from_email_or_hostname,
)
from src.shared_data_store import IPDataStore
from src.embedded_data import NETWORKS, VALID_TLDS, VPN_PROVIDERS, TOR_EXIT_NODE_ASNS

logger = logging.getLogger(__name__)


def lookup_known_network(ip_address: str) -> dict[str, str] | None:
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
    except Exception as e:
        logger.error("Error looking up known network: %s", e)

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


def validate_hostname(hostname: str) -> bool:
    """
    Validate a hostname without using regex.
    """
    if not hostname or "." not in hostname or 4 > len(hostname) > 255:
        return False

    labels = hostname.lower().split(".")
    if len(labels) < 2:
        return False

    tld = labels[-1]
    if tld not in VALID_TLDS:
        return False

    for label in labels:
        if not label or len(label) > 63:
            return False

        if not (label[0].isalnum() and label[-1].isalnum()):
            return False

        for char in label:
            if not (char.isalnum() or char == "-"):
                return False

    return True


def get_ip_address_version(ip_address: str) -> int | None:
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


def get_ip_address_classification(ip_address: IPAddress) -> str | None:
    """
    Get the classification of an IP address.

    Args:
        ip_address: The IP address to get the classification of

    Returns:
        The classification of the IP address or None if invalid
    """
    classifications = {
        "ipv4_mapped": (ip_address.version == 6 and ip_address.is_ipv4_mapped()),
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


def extract_ipv4_from_ipv6(ipv6_address: IPAddress) -> str | None:
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


def get_hostname_from_ip(ip_address: str, memory_store: IPDataStore) -> str | None:
    """Get hostname from IP address."""
    try:
        rev_name = dns.reversename.from_address(ip_address)
        if isinstance(rev_name, dns.name.Name):
            rev_name = str(rev_name)
            ptr_records = memory_store.dns_query(rev_name, "PTR")
            if ptr_records and len(ptr_records) > 0:
                return str(ptr_records[0]).rstrip(".")
            return None
    except Exception as e:
        logger.error("Failed to get hostname for IP %s: %s", ip_address, e)
        return None


def get_ip_from_hostname(hostname: str, memory_store: IPDataStore) -> str | None:
    """Resolve hostname to IP address."""
    a_records = memory_store.dns_query(hostname, "A")
    if a_records and len(a_records) > 0:
        return str(a_records[0])

    aaaa_records = memory_store.dns_query(hostname, "AAAA")
    if aaaa_records and len(aaaa_records) > 0:
        return str(aaaa_records[0])

    return None


def get_ipv4_from_hostname(hostname: str, memory_store: IPDataStore) -> str | None:
    """Extract IPv4 address from hostname."""
    a_records = memory_store.dns_query(hostname, "A")
    if a_records and len(a_records) > 0:
        return str(a_records[0])
    return None


def get_ipv6_from_hostname(hostname: str, memory_store: IPDataStore) -> str | None:
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
    memory_store: IPDataStore,
) -> dict[str, Any] | None:
    """Get Team Cymru info for an IP address."""
    reversed_ip_address = reverse_ip_address(ip_address, ip_version)
    query = reversed_ip_address + (
        ".origin.asn.cymru.com" if ip_version == 4 else ".origin6.asn.cymru.com"
    )

    txt_records: list[str] | None = memory_store.dns_query(query, "TXT")
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
    memory_store: IPDataStore,
) -> tuple[str, int]:
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


def get_abuse_contact(ip_address: str, memory_store: IPDataStore) -> str | None:
    """Get abuse contact for an IP address."""
    cached_value = memory_store.get_abuse_contact_cache_item(ip_address)
    if cached_value is not None:
        return cached_value

    ripe_url = (
        "https://stat.ripe.net/data/abuse-contact-finder/data.json"
        f"?resource={ip_address}"
    )

    data: dict[str, dict[str, list[str]]] | None = json_request(ripe_url)
    abuse_contacts = data.get("data", {}).get("abuse_contacts", [])
    if abuse_contacts:
        abuse_contact = abuse_contacts[0]
        memory_store.set_abuse_contact_cache_item(ip_address, abuse_contact)
        return abuse_contact

    dshield_url = f"https://isc.sans.edu/api/ip/{ip_address}"
    xml_root = xml_request(dshield_url)
    if xml_root is not None:
        asabusecontact_elem = xml_root.find("asabusecontact")
        if asabusecontact_elem is not None and asabusecontact_elem.text:
            abuse_contact = asabusecontact_elem.text.strip()
            if abuse_contact:
                memory_store.set_abuse_contact_cache_item(ip_address, abuse_contact)
                return abuse_contact

    memory_store.set_abuse_contact_cache_item(ip_address, None)
    return None


def _get_general_info(
    ip_address: str,
    ip_address_object: IPAddress,
    ip_address_version: int,
    memory_store: IPDataStore,
    fields: list[str],
) -> dict[str, Any]:
    """Get general information about the IP address."""
    classification = get_ip_address_classification(ip_address_object)

    response = {
        "ip_address": ip_address,
        "version": ip_address_version,
        "classification": classification,
    }

    hostname: str | None = None
    if "hostname" in fields:
        hostname = "localhost" if ip_address_version == 4 else "ip6-localhost"
        if classification != "loopback":
            hostname = get_hostname_from_ip(ip_address, memory_store)
        response["hostname"] = hostname

    if classification == "ipv4_mapped":
        ipv4_address = extract_ipv4_from_ipv6(ip_address_object)
        response["ipv4_address"] = ipv4_address
        if ipv4_address:
            ip_address = ipv4_address
            ip_address_version = 4
    elif "ipv4_address" in fields:
        ipv4_address = ip_address
        if ip_address_version == 6:
            ipv4_address = extract_ipv4_from_ipv6(ip_address_object)
        if not ipv4_address and hostname:
            ipv4_address = get_ipv4_from_hostname(hostname, memory_store)
        response["ipv4_address"] = ipv4_address

    if "ipv6_address" in fields:
        ipv6_address = ip_address
        if ip_address_version == 4:
            ipv6_address = (
                get_ipv6_from_hostname(hostname, memory_store) if hostname else None
            )
        response["ipv6_address"] = ipv6_address

    return response


def _get_abuse_info(
    ip_address: str,
    hostname: str | None,
    memory_store: IPDataStore,
    fields: list[str],
) -> dict[str, Any]:
    """Get abuse information about the IP address."""
    ip_groups = []
    if any_field_in_list(
        fields,
        [
            "is_proxy",
            "is_vpn",
            "vpn_provider",
            "is_forum_spammer",
            "is_tor_exit_node",
            "is_datacenter",
            "is_firehol",
        ],
    ):
        ip_groups = memory_store.get_ip_groups(ip_address)

    asn, as_name, org = None, None, None
    if any_field_in_list(fields, ["asn", "as_name"]):
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

    is_datacenter = False
    if "is_datacenter" in fields:
        is_datacenter = "Datacenter" in ip_groups
        if asn and not is_datacenter:
            is_datacenter = is_datacenter or memory_store.is_datacenter_asn(asn)

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
    is_firehol = "Firehol" in ip_groups

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
        or (extract_domain_from_email_or_hostname(hostname) if hostname else None),
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
    ip_address: str, memory_store: IPDataStore, fields: list[str]
) -> dict[str, Any]:
    """Get geographic information about the IP address."""
    geographic_info: dict[str, Any] = memory_store.get_ip_city_ip2location(ip_address)
    if (
        not geographic_info
        or not geographic_info.get("latitude")
        or not geographic_info.get("longitude")
    ):
        geographic_info = memory_store.get_ip_city_maxmind(ip_address)

    if (
        not geographic_info
        or not geographic_info.get("latitude")
        or not geographic_info.get("longitude")
    ):
        geographic_info = get_ripe_geolocation(ip_address, memory_store)

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
    memory_store: IPDataStore,
    country_code: str | None,
    asn: str | None,
    fields: list[str],
) -> tuple[dict[str, Any], str | None, str | None, str | None]:
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
                domain = extract_domain_from_email_or_hostname(abuse_contact)

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

    if "is_anycast" in fields:
        is_anycast = memory_store.is_anycast_ip(ip_address)
        network_info["is_anycast"] = is_anycast

    return network_info, country_code, asn, domain


def format_response(
    ip_info: dict[str, Any], fields: list[str], minify: bool = False
) -> dict[str, Any]:
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
    ip_address: str, request: Request, memory_store: IPDataStore
) -> dict[str, Any] | None:
    """
    Get IP address information.

    Args:
        ip_address: The IP address to get information for.
        fields: The fields to get information for.
        memory_store: The memory store to use.
    """
    if not ip_address:
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

    fields = parse_fields_param(request.query_params.get("fields", ""))
    minify = request.query_params.get("min", "0") == "1"

    response = _get_general_info(
        ip_address, ip_address_object, ip_address_version, memory_store, fields
    )

    if response["classification"] == "ipv4_mapped":
        ip_address = response["ipv4_address"]
        if not ip_address:
            return format_response(response, fields, minify)
        ip_address_object = IPAddress(ip_address, version=4)
        ip_address_version = 4
    elif response["classification"] != "public":
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


def get_ip_address(request: Request) -> str | None:
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
