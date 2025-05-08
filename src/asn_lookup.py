#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ASN (Autonomous System Number) lookup and processing module.

This module provides functionality to retrieve ASN information for IP addresses,
including organization names, network ranges, and related data. It supports
lookups through MaxMind databases and WHOIS queries with response parsing,
using caching to improve performance.
"""

import socket
from functools import lru_cache
from typing import Optional, Dict, Any, Tuple, cast
import maxminddb
import maxminddb.errors


GEOLITE2_URL = "https://git.io/GeoLite2-ASN.mmdb"


@lru_cache(maxsize=1000)
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


def _parse_asn_fields(key: str, value: str) -> Tuple[int, Optional[str]]:
    """Parse ASN-related fields and return ASN code and name."""
    asn_code = 0
    asn_name = None

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
    elif key.lower() == "as-name" and value:
        asn_name = value

    return asn_code, asn_name


def _parse_org_fields(
    key: str, value: str, current_org: Optional[str] = None
) -> Tuple[Optional[str], Optional[str]]:
    """Parse organization and ISP related fields."""
    organization = current_org
    net = None

    if key == "net-name" and value:
        net = value
    elif key == "as-org-name" and value and value != r"\(^_^)/":
        organization = value
    elif key == "org-name" and value and not organization:
        organization = value

    return organization, net


def _parse_location_field(
    key: str,
    value: str,
    is_geo: bool,
    location_data: Dict[str, Any],
    geo_flags: Dict[str, bool],
) -> None:
    """Parse and update location data fields."""
    if key in location_data and value:
        if is_geo or not geo_flags[key]:
            if key in ["latitude", "longitude"]:
                try:
                    location_data[key] = float(value)
                except ValueError:
                    return
            else:
                location_data[key] = value

            if is_geo:
                geo_flags[key] = True


def _parse_mapped_key(
    key: str,
    value: str,
    is_geo: bool,
    key_mapping: Dict[str, str],
    location_data: Dict[str, Any],
    geo_flags: Dict[str, bool],
) -> None:
    """Parse keys that are mapped to other field names."""
    if key in key_mapping and value:
        mapped_key = key_mapping[key]
        if (is_geo or not geo_flags[mapped_key]) and location_data[mapped_key] is None:
            location_data[mapped_key] = value
            if is_geo:
                geo_flags[mapped_key] = True


def _clean_field(field: Optional[str]) -> Optional[str]:
    """Clean organization and ISP fields."""
    if not field:
        return None

    parts = field.split("-")
    if len(parts) >= 3:
        return parts[1]
    return field


def _process_line(
    line: str,
    asn_code: int,
    asn_name: Optional[str],
    organization: Optional[str],
    net: Optional[str],
    location_data: Dict[str, Any],
    geo_flags: Dict[str, bool],
    key_mapping: Dict[str, str],
) -> Tuple[int, Optional[str], Optional[str], Optional[str]]:
    """Process a single line from the whois response."""
    if ":" not in line:
        return asn_code, asn_name, organization, net

    key, value = line.split(":", 1)
    original_key = key.strip().lower()
    key = original_key.replace("geo-", "")
    value = value.strip()

    is_geo = original_key.startswith("geo-")

    code, name = _parse_asn_fields(key, value)
    if code > 0:
        asn_code = code
    if name:
        asn_name = name

    org, net_name = _parse_org_fields(key, value, organization)
    if org:
        organization = org
    if net_name:
        net = net_name

    _parse_location_field(key, value, is_geo, location_data, geo_flags)
    _parse_mapped_key(key, value, is_geo, key_mapping, location_data, geo_flags)

    return asn_code, asn_name, organization, net


def parse_pwhois_response(response: str) -> Optional[Dict[str, Any]]:
    """Parse the response from pwhois.org to extract ASN information."""
    asn_code = 0
    asn_name = None
    organization = None
    net = None

    location_data = {
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

    for line in response.splitlines():
        asn_code, asn_name, organization, net = _process_line(
            line.strip(),
            asn_code,
            asn_name,
            organization,
            net,
            location_data,
            geo_flags,
            key_mapping,
        )

    if asn_code == 0:
        return None

    organization = _clean_field(organization)
    net = _clean_field(net)

    if not asn_name and organization:
        asn_name = organization

    country = location_data.get("country")
    if country and len(country) == 2 and country.isupper():
        if not location_data.get("country_code"):
            location_data["country_code"] = country
        location_data["country"] = None
        country = None

    return {
        "asn": asn_code,
        "asn_name": asn_name,
        "organization": organization,
        "net": net,
        "country": location_data.get("country"),
        "country_code": location_data.get("country_code"),
        "region": location_data.get("state"),
        "city": location_data.get("city"),
        "latitude": location_data.get("latitude"),
        "longitude": location_data.get("longitude"),
    }


@lru_cache(maxsize=1000)
def lookup_asn_from_ip(ip_address: str) -> Optional[Dict[str, Any]]:
    """Get detailed ASN information for an IP address using pwhois.org"""
    pwhois_response = query_whois("whois.pwhois.org", ip_address)

    if not pwhois_response:
        return None

    result = parse_pwhois_response(pwhois_response)

    return result


@lru_cache(maxsize=1000)
def get_asn_from_maxmind(
    ip_address: str, database_path: str
) -> Optional[Dict[str, Any]]:
    """Get ASN information for an IP address using MaxMind database."""

    try:
        with maxminddb.open_database(database_path) as reader:  # type: ignore
            result = reader.get(ip_address)  # type: ignore
            if not result:
                return None

            record = cast(Dict[str, Any], result)

            def get_nested(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
                """Safely get a nested value from a dictionary."""
                current = d
                for key in keys:
                    if not isinstance(current, dict) or key not in current:
                        return default
                    current = current[key]
                return current

            return {
                "asn": get_nested(record, "autonomous_system_number"),
                "organization": get_nested(record, "autonomous_system_organization"),
            }

    except (
        maxminddb.errors.InvalidDatabaseError,
        FileNotFoundError,
        PermissionError,
        ValueError,
    ) as e:
        print(f"Error querying database: {e}")
        return {"ip": ip_address}
