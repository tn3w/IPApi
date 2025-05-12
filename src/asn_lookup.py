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
import json
from functools import lru_cache
from typing import Optional, Dict, Any, cast
import urllib.request
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

    result = {key: value for key, value in result.items() if key}
    return result


@lru_cache(maxsize=1000)
def lookup_ip_pwhois(ip_address: str) -> Optional[Dict[str, Any]]:
    """Get detailed ASN information for an IP address using pwhois.org"""
    pwhois_data = query_whois("whois.pwhois.org", ip_address)

    if not pwhois_data:
        return None

    return parse_pwhois_data(pwhois_data)


@lru_cache(maxsize=1000)
def get_abuse_contact(ip: str) -> Optional[str]:
    """Get abuse contact information for an IP/ASN"""
    try:
        url = (
            "https://stat.ripe.net/data/abuse-contact-finder/data.json"
            f"?resource={ip}&sourceapp=tn3w-IPApi"
        )
        with urllib.request.urlopen(urllib.request.Request(url), timeout=5) as response:
            data = json.loads(response.read().decode())
            contacts = data["data"]["abuse_contacts"]
            if contacts:
                return contacts[0]
    except Exception:
        pass

    try:
        url = f"https://isc.sans.edu/api/ip/{ip}?json"
        req = urllib.request.Request(url, headers={"User-Agent": "tn3w-IPApi"})
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode())
            if "asabusecontact" in data["ip"]:
                return data["ip"]["asabusecontact"]
    except Exception:
        pass

    return None


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
                "asn_name": get_nested(record, "autonomous_system_organization"),
            }

    except (
        maxminddb.errors.InvalidDatabaseError,
        FileNotFoundError,
        PermissionError,
        ValueError,
    ) as e:
        print(f"Error querying database: {e}")
        return {"ip": ip_address}
