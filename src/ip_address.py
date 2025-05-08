#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IP address handling and validation module.

This module provides classes and utilities for working with IPv4 and IPv6 addresses,
including validation, classification, range checking, and various IP address operations.
It implements caching for performance and provides functionality to determine if an IP
is routable, check if it belongs to specific network ranges, and convert between formats.
"""

from functools import lru_cache
from typing import Union, Optional

import netaddr


class IPAddress:
    """Base class to represent and manipulate IP addresses."""

    def __init__(self, address: str):
        self.address = address
        self._netaddr_ip = None

    @property
    def is_ipv4(self) -> bool:
        """Check if the IP address is IPv4."""
        return False

    @property
    def is_ipv6(self) -> bool:
        """Check if the IP address is IPv6."""
        return False

    @staticmethod
    @lru_cache(maxsize=1000)
    def is_valid(_address: str) -> bool:
        """Check if the IP address is valid."""
        return False

    @lru_cache(maxsize=1000)
    def is_routable(self) -> bool:
        """Check if the IP address is routable."""
        return False

    @lru_cache(maxsize=1000)
    def is_in_range(self, _cidr_range: str) -> bool:
        """Check if the IP address is in the specified CIDR range."""
        return False

    def __str__(self) -> str:
        return self.address

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}('{self.address}')"


class IPv4(IPAddress):
    """Class to represent and manipulate IPv4 addresses."""

    def __init__(self, address: str):
        """Initialize an IPv4 address.

        Args:
            address: IPv4 address string in dotted decimal format (e.g., '192.168.1.1')

        Raises:
            ValueError: If the address is not a valid IPv4 address
        """
        if not self.is_valid(address):
            raise ValueError(f"Invalid IPv4 address: {address}")
        super().__init__(address)
        self._netaddr_ip = netaddr.IPAddress(address)

    @property
    def is_ipv4(self) -> bool:
        return True

    @staticmethod
    @lru_cache(maxsize=1000)
    def is_valid(address: str) -> bool:
        """Check if a string is a valid IPv4 address.

        Args:
            address: IPv4 address string to validate

        Returns:
            bool: True if the address is valid, False otherwise
        """
        try:
            ip = netaddr.IPAddress(address)
            return ip.version == 4
        except (netaddr.AddrFormatError, ValueError):
            return False

    @lru_cache(maxsize=1000)
    def is_in_range(self, cidr_range: str) -> bool:
        """Check if this IP address is within the specified CIDR range.

        Args:
            cidr_range: CIDR notation range (e.g., '192.168.1.0/24')

        Returns:
            bool: True if the IP is in the range, False otherwise

        Raises:
            ValueError: If the CIDR range is invalid
        """
        try:
            network = netaddr.IPNetwork(cidr_range)
            if network.version != 4:
                return False
            return self._netaddr_ip in network
        except (netaddr.AddrFormatError, ValueError) as exc:
            raise ValueError(f"Invalid CIDR range: {cidr_range}") from exc

    @lru_cache(maxsize=1000)
    def is_routable(self) -> bool:
        """Check if the IP address is routable (not a bogon address).

        Returns:
            bool: True if the IP is routable, False otherwise
        """
        return self._netaddr_ip.is_global and not (
            self._netaddr_ip.is_loopback()
            or self._netaddr_ip.is_reserved()
            or self._netaddr_ip.is_multicast()
            or self._netaddr_ip.is_link_local()
            or self._netaddr_ip.is_ipv4_private_use()
        )


class IPv6(IPAddress):
    """Class to represent and manipulate IPv6 addresses."""

    def __init__(self, address: str):
        """Initialize an IPv6 address.

        Args:
            address: IPv6 address string (e.g., '2001:db8::1')

        Raises:
            ValueError: If the address is not a valid IPv6 address
        """
        if not self.is_valid(address):
            raise ValueError(f"Invalid IPv6 address: {address}")

        super().__init__(address)
        self._netaddr_ip = netaddr.IPAddress(address)
        self.expanded_address = str(self._netaddr_ip.ipv6())

    @property
    def is_ipv6(self) -> bool:
        return True

    @staticmethod
    @lru_cache(maxsize=1000)
    def is_valid(address: str) -> bool:
        """Check if a string is a valid IPv6 address.

        Args:
            address: IPv6 address string to validate

        Returns:
            bool: True if the address is valid, False otherwise
        """
        try:
            ip = netaddr.IPAddress(address)
            return ip.version == 6
        except (netaddr.AddrFormatError, ValueError):
            return False

    @lru_cache(maxsize=1000)
    def is_in_range(self, cidr_range: str) -> bool:
        """Check if this IP address is within the specified CIDR range.

        Args:
            cidr_range: CIDR notation range (e.g., '2001:db8::/32')

        Returns:
            bool: True if the IP is in the range, False otherwise

        Raises:
            ValueError: If the CIDR range is invalid
        """
        try:
            network = netaddr.IPNetwork(cidr_range)
            if network.version != 6:
                return False
            return self._netaddr_ip in network
        except (netaddr.AddrFormatError, ValueError) as exc:
            raise ValueError(f"Invalid CIDR range: {cidr_range}") from exc

    @lru_cache(maxsize=1000)
    def is_routable(self) -> bool:
        """Check if the IP address is routable (not a bogon address).

        Returns:
            bool: True if the IP is routable, False otherwise
        """
        return self._netaddr_ip.is_global and not (
            self._netaddr_ip.is_loopback()
            or self._netaddr_ip.is_reserved()
            or self._netaddr_ip.is_multicast()
            or self._netaddr_ip.is_link_local()
            or self._netaddr_ip.is_ipv6_unique_local()
        )


@lru_cache(maxsize=1000)
def is_valid_and_routable_ip(ip: str) -> bool:
    """Check if an IP address is valid and routable.

    Args:
        ip: IP address string (IPv4 or IPv6)

    Returns:
        bool: True if the IP is valid and routable, False otherwise
    """
    try:
        ip_obj = get_ip_object(ip)
        return ip_obj.is_routable()
    except ValueError:
        return False


@lru_cache(maxsize=1000)
def get_valid_and_routable_ip_object(ip: str) -> Optional[IPAddress]:
    """Get an IP address object if it is valid and routable.

    Args:
        ip: IP address string (IPv4 or IPv6)

    Returns:
        Optional[IPAddress]: The IP address object if it is valid and routable, None otherwise
    """
    try:
        ip_obj = get_ip_object(ip)
        if ip_obj.is_routable():
            return ip_obj
    except ValueError:
        pass

    return None


@lru_cache(maxsize=1000)
def get_ip_object(address: str) -> Union[IPv4, IPv6]:
    """Factory function to return the appropriate IP address object based on the input.

    Args:
        address: IP address string (either IPv4 or IPv6)

    Returns:
        Either an IPv4 or IPv6 object

    Raises:
        ValueError: If the address is neither a valid IPv4 nor IPv6 address
    """
    try:
        ip = netaddr.IPAddress(address)
        if ip.version == 4:
            return IPv4(address)
        elif ip.version == 6:
            return IPv6(address)
    except (netaddr.AddrFormatError, ValueError):
        pass

    raise ValueError(f"Invalid IP address: {address}")


@lru_cache(maxsize=1000)
def is_ip_in_range(ip: str, cidr_range: str) -> bool:
    """Check if an IP address is within a CIDR range.

    Args:
        ip: IP address string (IPv4 or IPv6)
        cidr_range: CIDR notation range (e.g., '192.168.1.0/24' or '2001:db8::/32')

    Returns:
        bool: True if the IP is in the range, False otherwise

    Raises:
        ValueError: If either the IP or CIDR range is invalid
    """
    try:
        ip_obj = get_ip_object(ip)
        return ip_obj.is_in_range(cidr_range)
    except ValueError:
        return False


@lru_cache(maxsize=1000)
def is_ip_routable(ip: str) -> bool:
    """Check if an IP address is routable (not a bogon address).

    Args:
        ip: IP address string (IPv4 or IPv6)

    Returns:
        bool: True if the IP is routable, False otherwise

    Raises:
        ValueError: If the IP address is invalid
    """
    try:
        ip_obj = get_ip_object(ip)
        return ip_obj.is_routable()
    except ValueError:
        return False


@lru_cache(maxsize=1000)
def reverse_ip(ip_address: str) -> str:
    """
    Reverse the IP address for DNS lookup.

    Args:
        ip_address (str): The IP address to reverse.

    Returns:
        str: The reversed IP address.
    """
    try:
        ip = netaddr.IPAddress(ip_address)
        if ip.version == 4:
            octets = str(ip).split(".")
            return ".".join(reversed(octets))
        elif ip.version == 6:
            expanded = ip.format(netaddr.ipv6_verbose)
            segments = expanded.replace(":", "")
            return ".".join(reversed(segments))
    except (netaddr.AddrFormatError, ValueError):
        pass

    symbol = ":" if ":" in ip_address else "."
    return symbol.join(reversed(ip_address.split(symbol)))


@lru_cache(maxsize=1000)
def get_ip_address_type(address: str) -> Optional[str]:
    """Determine the type of IP address.

    Args:
        address: The address string to check

    Returns:
        Optional[str]: 'ipv4' if IPv4, 'ipv6' if IPv6, None if not a valid IP address
    """
    try:
        ip = netaddr.IPAddress(address)
        if ip.version == 4:
            return "ipv4"
        if ip.version == 6:
            return "ipv6"
    except (netaddr.AddrFormatError, ValueError):
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

    except (netaddr.AddrFormatError, ValueError):
        pass

    return None
