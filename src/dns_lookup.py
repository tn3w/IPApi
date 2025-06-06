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
import dns.resolver
import dns.reversename


@lru_cache(maxsize=1000)
def get_hostname_from_ip(addr: str) -> Optional[str]:
    """
    Get hostname from IP address.

    Args:
        addr: IP address string (IPv4 or IPv6)

    Returns:
        str: Hostname for the given IP address
        None: If reverse lookup fails
    """
    socket.setdefaulttimeout(1.0)

    try:
        return socket.getfqdn(addr)
    except (socket.error, OSError):
        return None


@lru_cache(maxsize=1000)
def get_ip_from_hostname(hostname: str) -> Optional[str]:
    """
    Resolve hostname to IP address using the fastest methods available.

    Args:
        hostname: The hostname to resolve

    Returns:
        str: IP address as a string
        None: If resolution fails
    """
    socket.setdefaulttimeout(1.0)

    record_types = [socket.AF_INET, socket.AF_INET6]

    for record_type in record_types:
        try:
            result = socket.getaddrinfo(hostname, None, family=record_type)
            if result and len(result) > 0:
                return result[0][4][0]
        except (socket.gaierror, socket.error, OSError):
            continue

    resolver = dns.resolver.Resolver()
    resolver.timeout = 1.0
    resolver.lifetime = 2.0

    record_types = ["A", "AAAA"]

    for record_type in record_types:
        try:
            records = resolver.resolve(hostname, record_type)
            if records and len(records) > 0:
                return str(records[0])  # type: ignore
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.resolver.YXDOMAIN,
            dns.resolver.LifetimeTimeout,
            ValueError,
            OSError,
        ):
            continue

    return None


@lru_cache(maxsize=1000)
def get_ipv4_from_ipv6(ipv6_address: str) -> Optional[str]:
    """
    Extract IPv4 address from a given IPv6 address.

    Args:
        ipv6_address: The IPv6 address string to convert

    Returns:
        Optional[str]: IPv4 address if conversion successful, None otherwise
    """

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
        dns.resolver.LifetimeTimeout,
        ValueError,
        OSError,
    ):
        pass

    return None
