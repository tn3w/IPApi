#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IP address handling and validation module (simplified version).

This module provides utilities for working with IP addresses including validation,
classification, and conversion between formats.
"""

from functools import lru_cache
from typing import Optional

from netaddr import IPAddress, AddrFormatError


@lru_cache(maxsize=1000)
def is_valid_and_routable_ip(ip: str) -> bool:
    """Check if an IP address is valid and routable.

    Args:
        ip: IP address string (IPv4 or IPv6)

    Returns:
        bool: True if the IP is valid and routable, False otherwise
    """
    try:
        ip_obj = IPAddress(ip)

        is_private = (ip_obj.version == 4 and ip_obj.is_ipv4_private_use()) or (
            ip_obj.version == 6 and ip_obj.is_ipv6_unique_local()
        )

        return not (
            is_private
            or ip_obj.is_loopback()
            or ip_obj.is_multicast()
            or ip_obj.is_reserved()
            or ip_obj.is_link_local()
        )
    except (AddrFormatError, ValueError):
        return False


@lru_cache(maxsize=1000)
def get_ip_address_type(address: str) -> Optional[str]:
    """Determine the type of IP address.

    Args:
        address: The address string to check

    Returns:
        Optional[str]: 'ipv4' if IPv4, 'ipv6' if IPv6, None if not a valid IP address
    """
    try:
        ip = IPAddress(address)
        if ip.version == 4:
            return "ipv4"
        if ip.version == 6:
            return "ipv6"
    except (AddrFormatError, ValueError):
        pass

    return None


@lru_cache(maxsize=1000)
def extract_ipv4_from_ipv6(ipv6_address: str) -> Optional[str]:
    """
    Extract an IPv4 address from an IPv6 address if possible.

    Handles several cases:
    1. IPv4-mapped IPv6 addresses (::ffff:a.b.c.d)
    2. 6to4 addresses (2002:AABB:CCDD::)
    3. IPv6 addresses with embedded IPv4 (like 2001:67c:e60:c0c:192:42:116:202)
    4. IPv6 addresses with direct decimal notation (like 2001:db8::192:168:0:1)

    Args:
        ipv6_address: The IPv6 address to extract from

    Returns:
        The extracted IPv4 address or None if extraction isn't possible
    """
    try:
        ip = IPAddress(ipv6_address)
        if ip.version != 6:
            return None

        if ip.is_ipv4_mapped():
            ipv4_int = int(ip) & 0xFFFFFFFF
            return str(IPAddress(ipv4_int, version=4))

        if ipv6_address.lower().startswith("2002:"):
            parts = ipv6_address.split(":")
            if len(parts) >= 3:
                hex_ip = parts[1] + parts[2]
                if len(hex_ip) == 8:
                    try:
                        ipv4_int = int(hex_ip, 16)
                        return str(IPAddress(ipv4_int, version=4))
                    except (ValueError, AddrFormatError):
                        pass

        parts = ipv6_address.split(":")

        if len(parts) >= 8:
            try:
                last_four = parts[-4:]
                if all(0 <= int(p) <= 255 for p in last_four):
                    return ".".join(last_four)
            except ValueError:
                pass

        valid_segments = [p for p in parts if p]
        if len(valid_segments) >= 4:
            last_four_valid = valid_segments[-4:]
            try:
                as_decimals = [int(p) for p in last_four_valid]
                if all(0 <= d <= 255 for d in as_decimals):
                    return ".".join(str(d) for d in as_decimals)
            except ValueError:
                pass

        if len(parts) >= 4:
            last_four = parts[-4:]
            if all(p for p in last_four):
                try:
                    decimal_values = [int(p, 16) for p in last_four]
                    if all(0 <= d <= 255 for d in decimal_values):
                        return ".".join(str(d) for d in decimal_values)
                except ValueError:
                    pass

        for i in range(len(parts) - 3):
            possible_ipv4_segments = parts[i : i + 4]
            if all(p for p in possible_ipv4_segments):
                try:
                    if all(
                        p.isdigit() and 0 <= int(p) <= 255
                        for p in possible_ipv4_segments
                    ):
                        return ".".join(possible_ipv4_segments)

                    decimal_values = [int(p, 16) for p in possible_ipv4_segments]
                    if all(0 <= d <= 255 for d in decimal_values):
                        return ".".join(str(d) for d in decimal_values)
                except (ValueError, TypeError):
                    continue

    except (AddrFormatError, ValueError):
        pass

    return None
