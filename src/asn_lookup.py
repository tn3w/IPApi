#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ASN (Autonomous System Number) lookup and processing module.

This module provides functionality to retrieve ASN information for IP addresses,
including organization names, network ranges, and related data. It supports
lookups through MaxMind databases and WHOIS queries with response parsing,
using caching to improve performance.
"""

import json
from functools import lru_cache
from typing import Optional, Dict, Any, Tuple, cast
import urllib.request

from redis import Redis
import maxminddb
import maxminddb.errors


GEOLITE2_URL = "https://git.io/GeoLite2-ASN.mmdb"


def get_abuse_contact(ip: str, redis: Optional[Redis] = None) -> Optional[str]:
    """Get abuse contact information for an IP/ASN"""

    if redis:
        cache_key = f"abuse_contact:{ip}"
        cached_data = redis.get(cache_key)
        if isinstance(cached_data, str):
            if cached_data == "null":
                return None

            return cached_data

    contact = "null"
    try:
        url = (
            "https://stat.ripe.net/data/abuse-contact-finder/data.json"
            f"?resource={ip}&sourceapp=tn3w-IPApi"
        )
        with urllib.request.urlopen(urllib.request.Request(url), timeout=5) as response:
            data = json.loads(response.read().decode())
            contacts = data["data"]["abuse_contacts"]
            if contacts:
                contact = contacts[0]
    except Exception:
        pass

    if not contact:
        try:
            url = f"https://isc.sans.edu/api/ip/{ip}?json"
            req = urllib.request.Request(url, headers={"User-Agent": "tn3w-IPApi"})
            with urllib.request.urlopen(req, timeout=15) as response:
                data = json.loads(response.read().decode())
                if "asabusecontact" in data["ip"]:
                    contact = data["ip"]["asabusecontact"]
        except Exception:
            pass

    if redis:
        cache_key = f"abuse_contact:{ip}"
        redis.set(cache_key, contact.encode("utf-8"), ex=86400)

    return contact


def get_rpki_validity(
    asn: str, prefix: str, redis: Optional[Redis] = None
) -> Tuple[Optional[str], Optional[int]]:
    """Get RPKI validity status for ASN and prefix"""

    if redis:
        cache_key = f"rpki_validity:{asn}:{prefix}"
        cached_data = redis.get(cache_key)
        if cached_data:
            loaded_data = json.loads(cached_data)  # type: ignore

            return loaded_data.get("status"), loaded_data.get("roa_count")

    status = None
    roa_count = None

    try:
        url = (
            "https://stat.ripe.net/data/rpki-validation/data.json"
            f"?resource={asn}&prefix={prefix}&sourceapp=tn3w-IPApi"
        )
        with urllib.request.urlopen(urllib.request.Request(url), timeout=5) as response:
            data = json.loads(response.read().decode())
            status = data["data"]["status"].lower()
            roa_count = len(data["data"]["validating_roas"])
    except Exception:
        pass

    if redis:
        cache_key = f"rpki_validity:{asn}:{prefix}"
        redis.set(
            cache_key,
            json.dumps({"status": status, "roa_count": roa_count}),
            ex=86400,
        )

    return status, roa_count


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
