#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IP WHOIS data retrieval and parsing module.

This module provides functionality for querying and parsing WHOIS information for IP addresses
from various Regional Internet Registries (RIRs) including ARIN, RIPE, APNIC, LACNIC, and AFRINIC.
It implements specialized parsers for each registry's data format and provides utilities to extract
key information such as network ranges, organization names, ASNs, and abuse contacts. The module
maps country codes to appropriate registries and handles the different query formats required.
"""

import re
import json
import socket
from typing import Callable, Final, Optional, Tuple, Any, Dict
from netaddr import IPAddress, IPRange, AddrFormatError, cidr_merge
from redis import Redis


ARIN: Final[str] = "whois.arin.net"
RIPE: Final[str] = "whois.ripe.net"
APNIC: Final[str] = "whois.apnic.net"
LACNIC: Final[str] = "whois.lacnic.net"
AFRINIC: Final[str] = "whois.afrinic.net"
PWHOIS: Final[str] = "whois.pwhois.org"

# Regional Internet Registries (RIRs)
RIR_TO_COUNTRY_CODE: Final[Dict[str, str]] = {
    # North America
    "US": ARIN,
    "CA": ARIN,
    # Europe, Middle East, parts of Central Asia
    "GB": RIPE,
    "DE": RIPE,
    "FR": RIPE,
    "IT": RIPE,
    "ES": RIPE,
    "NL": RIPE,
    "BE": RIPE,
    "SE": RIPE,
    "AT": RIPE,
    "CH": RIPE,
    "NO": RIPE,
    "DK": RIPE,
    "FI": RIPE,
    "IE": RIPE,
    "PT": RIPE,
    "GR": RIPE,
    "CZ": RIPE,
    "HU": RIPE,
    "PL": RIPE,
    "RO": RIPE,
    "RU": RIPE,
    "TR": RIPE,
    # Asia Pacific
    "JP": APNIC,
    "CN": APNIC,
    "KR": APNIC,
    "IN": APNIC,
    "AU": APNIC,
    "NZ": APNIC,
    "SG": APNIC,
    "TH": APNIC,
    "MY": APNIC,
    "PH": APNIC,
    "ID": APNIC,
    "VN": APNIC,
    "HK": APNIC,
    "TW": APNIC,
    # Latin America and Caribbean
    "BR": LACNIC,
    "MX": LACNIC,
    "AR": LACNIC,
    "CL": LACNIC,
    "CO": LACNIC,
    "PE": LACNIC,
    "VE": LACNIC,
    "CR": LACNIC,
    "PA": LACNIC,
    # Africa
    "ZA": AFRINIC,
    "EG": AFRINIC,
    "NG": AFRINIC,
    "KE": AFRINIC,
    "GH": AFRINIC,
    "MA": AFRINIC,
    "TN": AFRINIC,
    "DZ": AFRINIC,
}

PREFIX_TO_RIR: Final[Dict[str, str]] = {ARIN: "n"}


def get_rir_and_prefix(country_code: str) -> Tuple[str, str]:
    """Return the best WHOIS server and prefix for a given country code."""
    rir = RIR_TO_COUNTRY_CODE.get(country_code, ARIN)
    prefix = PREFIX_TO_RIR.get(rir, "")

    return rir, prefix


def parse_pwhois_data(data: str) -> Dict[str, Any]:
    """
    Parse Team pwhois WHOIS data and extract specific information.

    Args:
        data: pwhois WHOIS response

    Returns:
        Dictionary containing extracted information including:
        - asn: Autonomous System Number
        - asn_name: Autonomous System Name (if available)
        - org: Organization name
        - net: Network name
        - prefix: IP range in CIDR notation
        - country: Country name
        - country_code: Two-letter country code
        - region: State/region
        - city: City
        - latitude: Latitude coordinate
        - longitude: Longitude coordinate
    """
    asn_code = 0
    asn_name: Optional[str] = None
    organization: Optional[str] = None
    net: Optional[str] = None
    prefix: Optional[str] = None

    location_data: Dict[str, Any] = {
        "country": None,
        "country_code": None,
        "city": None,
        "state": None,
        "latitude": None,
        "longitude": None,
    }
    geo_flags = {field: False for field in location_data}

    key_mapping = {
        "region": "state",
        "cc": "country_code",
        "country-code": "country_code",
    }

    for line in data.splitlines():
        line = line.strip()
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        original_key = key.strip().lower()
        key = original_key.replace("geo-", "")
        value = value.strip()

        is_geo = original_key.startswith("geo-")

        if key == "as" and value:
            parts = value.split(" ", 1)
            if parts and parts[0].startswith("AS"):
                try:
                    asn_code = int(parts[0][2:])
                except ValueError:
                    pass
        elif key == "origin-as" and value:
            try:
                asn_code = int(value.replace("AS", ""))
            except ValueError:
                pass

        if key == "net-name" and value:
            net = value
        elif key == "as-org-name" and value and value != r"\(^_^)/":
            asn_name = value
        elif key == "org-name" and value:
            organization = value

        if key == "prefix" and value:
            prefix = value

        if key in location_data and value:
            if is_geo or not geo_flags[key]:
                if key in ["latitude", "longitude"]:
                    try:
                        location_data[key] = float(value)
                    except ValueError:
                        pass
                else:
                    location_data[key] = value

                if is_geo:
                    geo_flags[key] = True

        if key in key_mapping and value:
            mapped_key = key_mapping[key]
            if (is_geo or not geo_flags[mapped_key]) and location_data[
                mapped_key
            ] is None:
                location_data[mapped_key] = value
                if is_geo:
                    geo_flags[mapped_key] = True

    def clean_field(field: Optional[str]) -> Optional[str]:
        """Clean organization and ISP fields."""
        if not field:
            return None

        parts = field.split("-")
        if len(parts) >= 3 and all(len(part.strip()) > 0 for part in parts):
            if (
                parts[0].strip().upper().startswith("AS")
                and parts[0].strip()[2:].isdigit()
            ):
                return parts[1]
        return field

    organization = clean_field(organization)
    net = clean_field(net)

    country = location_data.get("country")
    if isinstance(country, str) and len(country) == 2 and country.isupper():
        if not location_data.get("country_code"):
            location_data["country_code"] = country
        location_data["country"] = None

    result = {
        "asn": str(asn_code) if asn_code > 0 else None,
        "asn_name": asn_name,
        "org": organization,
        "net": net,
        "prefix": prefix,
        "country": location_data.get("country"),
        "country_code": location_data.get("country_code"),
        "region": location_data.get("state"),
        "city": location_data.get("city"),
        "latitude": location_data.get("latitude"),
        "longitude": location_data.get("longitude"),
    }

    if asn_code == 0:
        return {}

    return result


def parse_ripe_data(data: str) -> Dict[str, Optional[str]]:
    """
    Parse RIPE WHOIS data and extract specific information.

    Args:
        data: RIPE WHOIS response in RPSL format

    Returns:
        Dictionary containing extracted information:
        - abuse_contact: Email for abuse reports
        - asn: Autonomous System Number (if available)
        - asn_name: Autonomous System Name (if available)
        - prefix: IP range in CIDR notation
        - org: Organization name
        - net: Network name
    """
    result: Dict[str, Optional[str]] = {}

    abuse_match = re.search(r"Abuse contact for .+ is '([^']+)'", data)
    if abuse_match:
        result["abuse_contact"] = abuse_match.group(1)

    asn_match = re.search(r"AS(\d+)", data)
    if asn_match:
        result["asn"] = asn_match.group(1)

        route_section = re.search(r"route:[\s\S]+?origin:\s+AS\d+", data)
        if route_section:
            route_text = route_section.group(0)
            descr_match = re.search(r"descr:\s+(.+?)$", route_text, re.MULTILINE)
            if descr_match:
                result["asn_name"] = descr_match.group(1).strip()

    ip_range_match = re.search(r"inetnum:\s+([\d.]+)\s+-\s+([\d.]+)", data)
    if ip_range_match:
        start_ip = ip_range_match.group(1)
        end_ip = ip_range_match.group(2)
        try:
            start_int = int(IPAddress(start_ip))
            end_int = int(IPAddress(end_ip))

            if end_int - start_int > 65536:
                result["prefix"] = f"{start_ip}-{end_ip}"
            else:
                ip_range = IPRange(start_ip, end_ip)
                cidrs = cidr_merge(ip_range)
                if cidrs:
                    result["prefix"] = str(cidrs[0])
        except (ValueError, AddrFormatError) as e:
            print(f"Error converting IP range to CIDR: {e}")

    org_match = re.search(r"org-name:\s+(.+?)$", data, re.MULTILINE)
    if org_match:
        result["org"] = org_match.group(1).strip()

    net_match = re.search(r"netname:\s+(.+?)$", data, re.MULTILINE)
    if net_match:
        result["net"] = net_match.group(1).strip()

    return result


def parse_apnic_data(data: str) -> Dict[str, Optional[str]]:
    """
    Parse APNIC WHOIS data and extract specific information.

    Args:
        data: APNIC WHOIS response in RPSL format

    Returns:
        Dictionary containing extracted information:
        - abuse_contact: Email for abuse reports
        - asn: Autonomous System Number (if available)
        - asn_name: Autonomous System Name (if available)
        - prefix: IP range in CIDR notation
        - org: Organization name
        - net: Network name
    """
    result: Dict[str, Optional[str]] = {}

    abuse_match = re.search(r"Abuse contact for .+ is '([^']+)'", data)
    if abuse_match:
        result["abuse_contact"] = abuse_match.group(1)

    if "abuse_contact" not in result:
        abuse_mailbox_match = re.search(r"abuse-mailbox:\s+(.+?)$", data, re.MULTILINE)
        if abuse_mailbox_match:
            result["abuse_contact"] = abuse_mailbox_match.group(1).strip()

    route_section = re.search(r"route:[\s\S]+?origin:\s+AS(\d+)", data)
    if route_section:
        result["asn"] = route_section.group(1)

    if "asn" in result:
        asn_match = re.search(f"AS{result["asn"]}", data)
        if asn_match:
            route_section = re.search(r"route:[\s\S]+?source:", data)
            if route_section:
                route_text = route_section.group(0)
                descr_match = re.search(r"descr:\s+(.+?)$", route_text, re.MULTILINE)
                if descr_match:
                    result["asn_name"] = descr_match.group(1).strip()

    route_match = re.search(r"route:\s+(.+?)$", data, re.MULTILINE)
    if route_match:
        result["prefix"] = route_match.group(1).strip()
    else:
        ip_range_match = re.search(r"inetnum:\s+([\d.]+)\s+-\s+([\d.]+)", data)
        if ip_range_match:
            start_ip = ip_range_match.group(1)
            end_ip = ip_range_match.group(2)
            try:
                start_int = int(IPAddress(start_ip))
                end_int = int(IPAddress(end_ip))

                if end_int - start_int > 65536:
                    result["prefix"] = f"{start_ip}-{end_ip}"
                else:
                    ip_range = IPRange(start_ip, end_ip)
                    cidrs = cidr_merge(ip_range)
                    if cidrs:
                        result["prefix"] = str(cidrs[0])
            except (ValueError, AddrFormatError) as e:
                print(f"Error converting IP range to CIDR: {e}")

    org_section = re.search(
        r"organisation:.*?org-name:\s+(.+?)$.*?source:", data, re.DOTALL | re.MULTILINE
    )
    if org_section:
        org_match = re.search(r"org-name:\s+(.+?)$", org_section.group(0), re.MULTILINE)
        if org_match:
            result["org"] = org_match.group(1).strip()

    net_match = re.search(r"netname:\s+(.+?)$", data, re.MULTILINE)
    if net_match:
        result["net"] = net_match.group(1).strip()

    return result


def parse_arin_data(data: str) -> Dict[str, Optional[str]]:
    """
    Parse ARIN WHOIS data and extract specific information.

    Args:
        data: ARIN WHOIS response

    Returns:
        Dictionary containing extracted information:
        - abuse_contact: Email for abuse reports
        - asn: Autonomous System Number (if available)
        - asn_name: Autonomous System Name (if available)
        - prefix: IP range in CIDR notation
        - org: Organization name
        - net: Network name
    """
    result: Dict[str, Optional[str]] = {}

    cidr_match = re.search(r"CIDR:\s+(.+?)$", data, re.MULTILINE)
    if cidr_match:
        result["prefix"] = cidr_match.group(1).strip()

    net_match = re.search(r"NetName:\s+(.+?)$", data, re.MULTILINE)
    if net_match:
        result["net"] = net_match.group(1).strip()

    org_match = re.search(r"Organization:\s+(.+?)$", data, re.MULTILINE)
    if org_match:
        org_value = org_match.group(1).strip()
        result["org"] = re.sub(r"\s+\([^)]+\)$", "", org_value)
    else:
        org_name_match = re.search(r"OrgName:\s+(.+?)$", data, re.MULTILINE)
        if org_name_match:
            result["org"] = org_name_match.group(1).strip()

    asn_match = re.search(r"OriginAS:\s+AS(\d+)", data, re.MULTILINE)
    if asn_match:
        result["asn"] = asn_match.group(1)

    abuse_email_match = re.search(r"OrgAbuseEmail:\s+(.+?)$", data, re.MULTILINE)
    if abuse_email_match:
        result["abuse_contact"] = abuse_email_match.group(1).strip()

    return result


def parse_lacnic_data(data: str) -> Dict[str, Optional[str]]:
    """
    Parse LACNIC WHOIS data and extract specific information.

    Args:
        data: LACNIC WHOIS response

    Returns:
        Dictionary containing extracted information:
        - abuse_contact: Email for abuse reports
        - asn: Autonomous System Number (if available)
        - asn_name: Autonomous System Name (if available)
        - prefix: IP range in CIDR notation
        - org: Organization name
        - net: Network name
    """
    result: Dict[str, Optional[str]] = {}

    inetnum_match = re.search(r"inetnum:\s+(.+?)$", data, re.MULTILINE)
    if inetnum_match:
        result["prefix"] = inetnum_match.group(1).strip()

    asn_match = re.search(r"aut-num:\s+AS(\d+)", data, re.MULTILINE)
    if asn_match:
        result["asn"] = asn_match.group(1)

    owner_match = re.search(r"owner:\s+(.+?)$", data, re.MULTILINE)
    if owner_match:
        result["org"] = owner_match.group(1).strip()

    abuse_match = re.search(r"abuse-c:\s+(\w+)", data, re.MULTILINE)
    if abuse_match:
        abuse_handle = abuse_match.group(1)
        contact_section = re.search(
            rf"nic-hdl-br:\s+{abuse_handle}[\s\S]+?e-mail:\s+(.+?)$", data, re.MULTILINE
        )
        if contact_section and "e-mail:" in contact_section.group(0):
            email_match = re.search(
                r"e-mail:\s+(.+?)$", contact_section.group(0), re.MULTILINE
            )
            if email_match:
                result["abuse_contact"] = email_match.group(1).strip()

    if "abuse_contact" not in result:
        cert_match = re.search(r"mail-abuse@cert\.br", data)
        if cert_match:
            result["abuse_contact"] = "mail-abuse@cert.br"

    if "abuse_contact" not in result:
        email_match = re.search(r"e-mail:\s+(.+?)$", data, re.MULTILINE)
        if email_match:
            result["abuse_contact"] = email_match.group(1).strip()

    return result


def parse_afrinic_data(data: str) -> Dict[str, Optional[str]]:
    """
    Parse AFRINIC WHOIS data and extract specific information.

    Args:
        data: AFRINIC WHOIS response

    Returns:
        Dictionary containing extracted information:
        - abuse_contact: Email for abuse reports
        - asn: Autonomous System Number (if available)
        - asn_name: Autonomous System Name (if available)
        - prefix: IP range in CIDR notation
        - org: Organization name
        - net: Network name
    """
    result: Dict[str, Optional[str]] = {}

    ip_range_match = re.search(r"inetnum:\s+([\d.]+)\s+-\s+([\d.]+)", data)
    if ip_range_match:
        start_ip = ip_range_match.group(1)
        end_ip = ip_range_match.group(2)
        try:
            start_int = int(IPAddress(start_ip))
            end_int = int(IPAddress(end_ip))

            if end_int - start_int > 65536:
                result["prefix"] = f"{start_ip}-{end_ip}"
            else:
                ip_range = IPRange(start_ip, end_ip)
                cidrs = cidr_merge(ip_range)
                if cidrs:
                    result["prefix"] = str(cidrs[0])
        except (ValueError, AddrFormatError) as e:
            print(f"Error converting IP range to CIDR: {e}")

    net_match = re.search(r"netname:\s+(.+?)$", data, re.MULTILINE)
    if net_match:
        result["net"] = net_match.group(1).strip()

    org_section = re.search(
        r"organisation:.*?org-name:\s+(.+?)$.*?source:", data, re.DOTALL | re.MULTILINE
    )
    if org_section:
        org_match = re.search(r"org-name:\s+(.+?)$", org_section.group(0), re.MULTILINE)
        if org_match:
            result["org"] = org_match.group(1).strip()
    else:
        descr_match = re.search(r"descr:\s+(.+?)$", data, re.MULTILINE)
        if descr_match:
            result["org"] = descr_match.group(1).strip()

    abuse_note = re.search(r"No abuse contact registered for", data)
    if not abuse_note:
        person_sections = re.finditer(r"person:.*?source:.*?Filtered", data, re.DOTALL)
        for section in person_sections:
            person_text = section.group(0)
            email_match = re.search(r"e-mail:\s+(.+?)$", person_text, re.MULTILINE)
            if email_match and (
                "abuse" in email_match.group(1).lower()
                or "security" in email_match.group(1).lower()
            ):
                result["abuse_contact"] = email_match.group(1).strip()
                break

    return result


RIR_TO_PARSER_FUNCTION: Final[Dict[str, Callable[[str], Dict[str, Any]]]] = {
    ARIN: parse_arin_data,
    RIPE: parse_ripe_data,
    APNIC: parse_apnic_data,
    AFRINIC: parse_afrinic_data,
    LACNIC: parse_lacnic_data,
    PWHOIS: parse_pwhois_data,
}


def get_parser_func_from_rir(rir: str) -> Optional[Callable[[str], Dict[str, Any]]]:
    """Return the parser function for a given RIR."""
    return RIR_TO_PARSER_FUNCTION.get(rir)


def query_whois(server: str, query: str) -> Optional[str]:
    """Send a WHOIS query to a specified server."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((server, 43))
        s.sendall((query + "\r\n").encode())

        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data

        return response.decode("utf-8", errors="ignore")
    except (socket.timeout, socket.error) as e:
        print(f"Error querying {server}: {e}")
        return None
    finally:
        s.close()


def filter_whois_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Filter the WHOIS data to only include non-None values."""
    return {
        key: value
        for key, value in data.items()
        if value and str(value).lower() != "null"
    }


def ip_whois(
    ip_address: str, country_code: str, redis: Optional[Redis] = None
) -> Dict[str, Any]:
    """
    Return the WHOIS data for a given IP address.

    Args:
        ip_address: The IP address to query
        country_code: The country code for determining RIR
        redis: Optional Redis client for caching results

    Returns:
        Dictionary containing the parsed WHOIS data
    """
    if redis:
        cache_key = f"whois:{ip_address}:{country_code}"
        cached_data = redis.get(cache_key)
        if cached_data:
            return json.loads(cached_data)  # type: ignore

    rir, prefix = get_rir_and_prefix(country_code)

    whois_data = query_whois(rir, f"{prefix} {ip_address}".strip())

    result = {}
    if whois_data:
        parser_function = get_parser_func_from_rir(rir)
        if not parser_function:
            raise ValueError(f"No parser function found for RIR: {rir}")

        result = parser_function(whois_data)
        result = filter_whois_data(result)

    if redis:
        cache_key = f"whois:{ip_address}:{country_code}"
        redis.set(cache_key, json.dumps(result), ex=86400)

    return result


def ip_whois_pwhois(ip_address: str, redis: Optional[Redis] = None) -> Dict[str, Any]:
    """
    Return the pwhois WHOIS data for a given IP address.

    Args:
        ip_address: The IP address to query
        redis: Optional Redis client for caching results

    Returns:
        Dictionary containing the parsed WHOIS data
    """
    if redis:
        cache_key = f"pwhois:{ip_address}"
        cached_data = redis.get(cache_key)
        if cached_data:
            return json.loads(cached_data)  # type: ignore

    whois_data = query_whois(PWHOIS, ip_address)

    result = {}
    if whois_data:
        result = parse_pwhois_data(whois_data)
        result = filter_whois_data(result)

    if redis:
        cache_key = f"pwhois:{ip_address}"
        redis.set(cache_key, json.dumps(result), ex=86400)

    return result
