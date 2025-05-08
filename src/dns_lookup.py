#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS lookup and IP address conversion utilities.

This module provides functions for DNS operations including hostname resolution,
reverse DNS lookups, and IPv6 to IPv4 address conversions. It implements caching
for improved performance and handles various DNS record types for IP address
format detection and conversion.
"""

import socket
from functools import lru_cache
from typing import Optional
import netaddr
import dns.resolver
import dns.reversename


@lru_cache(maxsize=1000)
def get_dns_info(addr: str) -> Optional[str]:
    """
    Get hostname from IP address.

    Args:
        addr: IP address string (IPv4 or IPv6)

    Returns:
        str: Hostname for the given IP address
        None: If reverse lookup fails
    """
    try:
        return socket.getfqdn(addr)
    except (socket.error, OSError):
        return None


def get_ipv4_from_ipv6(ipv6_address: str) -> Optional[str]:
    """
    Extract IPv4 address from a given IPv6 address.

    Args:
        ipv6_address: The IPv6 address string to convert

    Returns:
        Optional[str]: IPv4 address if conversion successful, None otherwise
    """
    try:
        ip = netaddr.IPAddress(ipv6_address)
        if ip.version != 6:
            return None

        if ip.is_ipv4_mapped():
            ipv4_int = int(ip) & 0xFFFFFFFF
            return str(netaddr.IPAddress(ipv4_int, version=4))

        if ipv6_address.lower().startswith("2002:"):
            parts = ipv6_address.split(":")
            if len(parts) >= 3:
                hex_ip = parts[1] + parts[2]
                if len(hex_ip) == 8:
                    try:
                        ipv4_int = int(hex_ip, 16)
                        return str(netaddr.IPAddress(ipv4_int, version=4))
                    except (ValueError, netaddr.AddrFormatError):
                        pass

    except (netaddr.AddrFormatError, ValueError):
        pass

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.0
        resolver.lifetime = 2.0

        rev_name = dns.reversename.from_address(ipv6_address)
        hostname_records = resolver.resolve(rev_name, "PTR")
        if hostname_records:
            hostname = str(hostname_records[0]).rstrip(".")  # type: ignore

            a_records = resolver.resolve(hostname, "A")
            if a_records:
                return str(a_records[0])  # type: ignore

            hostname_variations = [
                hostname,
                hostname.replace("ip6", "ip4"),
                hostname.replace("ipv6", "ipv4"),
                hostname.replace("v6", "v4"),
                hostname.replace("-v6", "-v4"),
            ]

            for variant in hostname_variations:
                try:
                    a_records = resolver.resolve(variant, "A")
                    if a_records:
                        return str(a_records[0])  # type: ignore
                except (
                    dns.resolver.NXDOMAIN,
                    dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers,
                    dns.resolver.YXDOMAIN,
                    ValueError,
                    OSError,
                ):
                    continue
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.resolver.YXDOMAIN,
        ValueError,
    ):
        pass

    return None
