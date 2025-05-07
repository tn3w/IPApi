"""
A standalone module for handling IP address operations, validation, and transformations.

This module provides a robust replacement for the deprecated ipaddress module, offering:
- IPv4 and IPv6 address validation and manipulation
- CIDR range checking
- Routing and network checks
- Address format conversions
- Caching for performance optimization
"""

import socket
import re
from functools import lru_cache
from typing import Union, Optional


class IPAddress:
    """Class to represent and manipulate IP addresses."""

    def __init__(self, address: str):
        self.address = address

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
        return f"IPAddress('{self.address}')"


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
        self._int_value = self._to_integer(address)

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
        pattern = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
        match = re.match(pattern, address)
        if not match:
            return False
        return all(0 <= int(octet) <= 255 for octet in match.groups())

    @staticmethod
    @lru_cache(maxsize=1000)
    def _to_integer(address: str) -> int:
        """Convert an IPv4 address to its integer representation.

        Args:
            address: IPv4 address string

        Returns:
            int: Integer representation of the IP address
        """
        octets = address.split(".")
        return (
            (int(octets[0]) << 24)
            + (int(octets[1]) << 16)
            + (int(octets[2]) << 8)
            + int(octets[3])
        )

    @staticmethod
    @lru_cache(maxsize=1000)
    def _from_integer(integer: int) -> str:
        """Convert an integer to an IPv4 address string.

        Args:
            integer: Integer representation of the IP address

        Returns:
            str: IPv4 address in dotted decimal format
        """
        return ".".join(
            [
                str((integer >> 24) & 0xFF),
                str((integer >> 16) & 0xFF),
                str((integer >> 8) & 0xFF),
                str(integer & 0xFF),
            ]
        )

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
        if "/" not in cidr_range:
            raise ValueError(f"Invalid CIDR range: {cidr_range}")

        network_addr, prefix_len = cidr_range.split("/")
        if not self.is_valid(network_addr):
            raise ValueError(f"Invalid network address in CIDR: {network_addr}")

        try:
            prefix_len_int = int(prefix_len)
            if not 0 <= prefix_len_int <= 32:
                raise ValueError(f"Invalid prefix length: {prefix_len}")
        except ValueError as exc:
            raise ValueError(f"Invalid prefix length: {prefix_len}") from exc

        network_int = self._to_integer(network_addr)
        ip_int = self._int_value

        mask = (1 << 32) - 1 - ((1 << (32 - prefix_len_int)) - 1)

        return (network_int & mask) == (ip_int & mask)

    @lru_cache(maxsize=1000)
    def is_routable(self) -> bool:
        """Check if the IP address is routable (not a bogon address).

        Returns:
            bool: True if the IP is routable, False otherwise
        """
        bogon_ranges = [
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/4",
            "240.0.0.0/4",
            "255.255.255.255/32",
        ]

        return not any(self.is_in_range(bogon) for bogon in bogon_ranges)

    def __str__(self) -> str:
        return self.address

    def __repr__(self) -> str:
        return f"IPv4('{self.address}')"


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
        try:
            packed = socket.inet_pton(socket.AF_INET6, address)
            self.expanded_address = ":".join(
                f"{b:02x}{b2:02x}" for b, b2 in zip(packed[::2], packed[1::2])
            )
            self._bytes = packed
        except (socket.error, ValueError) as exc:
            raise ValueError(f"Invalid IPv6 address: {address}") from exc

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
            socket.inet_pton(socket.AF_INET6, address)
            return True
        except (socket.error, ValueError):
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
        if "/" not in cidr_range:
            raise ValueError(f"Invalid CIDR range: {cidr_range}")

        network_addr, prefix_len = cidr_range.split("/")
        if not self.is_valid(network_addr):
            raise ValueError(f"Invalid network address in CIDR: {network_addr}")

        try:
            prefix_len_int = int(prefix_len)
            if not 0 <= prefix_len_int <= 128:
                raise ValueError(f"Invalid prefix length: {prefix_len}")
        except ValueError as exc:
            raise ValueError(f"Invalid prefix length: {prefix_len}") from exc

        network_bytes = socket.inet_pton(socket.AF_INET6, network_addr)
        ip_bytes = self._bytes

        network_bits = "".join(format(byte, "08b") for byte in network_bytes)
        ip_bits = "".join(format(byte, "08b") for byte in ip_bytes)

        return network_bits[:prefix_len_int] == ip_bits[:prefix_len_int]

    @lru_cache(maxsize=1000)
    def is_routable(self) -> bool:
        """Check if the IP address is routable (not a bogon address).

        Returns:
            bool: True if the IP is routable, False otherwise
        """

        bogon_ranges = [
            "::/128",
            "::1/128",
            "::ffff:0:0/96",
            "100::/64",
            "2001:10::/28",
            "2001:db8::/32",
            "fc00::/7",
            "fe80::/10",
            "ff00::/8",
        ]

        return not any(self.is_in_range(bogon) for bogon in bogon_ranges)

    def __str__(self) -> str:
        return self.address

    def __repr__(self) -> str:
        return f"IPv6('{self.address}')"


@lru_cache(maxsize=1000)
def is_valid_and_routable_ip(ip: str) -> bool:
    """Check if an IP address is valid and routable.

    Args:
        ip: IP address string (IPv4 or IPv6)

    Returns:
        bool: True if the IP is valid and routable, False otherwise
    """
    if ip == "127.0.0.1":
        return False
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
    if ip == "127.0.0.1":
        return None
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
    if IPv4.is_valid(address):
        return IPv4(address)
    if IPv6.is_valid(address):
        return IPv6(address)

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
    if ip == "127.0.0.1":
        return False

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

    symbol = ":" if ":" in ip_address else "."
    return symbol.join(reversed(ip_address.split(symbol)))


@lru_cache(maxsize=1000)
def get_ipv4_from_ipv6(ipv6_address: str) -> Optional[str]:
    """Extract IPv4 address from a given IPv6 address.

    Args:
        ipv6_address: The IPv6 address string to convert

    Returns:
        Optional[str]: IPv4 address if conversion successful, None otherwise
    """

    if "::ffff:" in ipv6_address.lower():
        try:
            ipv4_part = ipv6_address.split(":")[-1]
            if IPv4.is_valid(ipv4_part):
                return ipv4_part
        except Exception:
            pass

    if ipv6_address.lower().startswith("2002:"):
        try:
            parts = ipv6_address.split(":")
            if len(parts) >= 3:
                hex_ip = parts[1] + parts[2]
                if len(hex_ip) == 8:
                    ipv4_octets = [
                        str(int(hex_ip[i : i + 2], 16)) for i in range(0, 8, 2)
                    ]
                    ipv4 = ".".join(ipv4_octets)
                    if IPv4.is_valid(ipv4):
                        return ipv4
        except Exception:
            pass

    try:
        socket.setdefaulttimeout(3)
        hostname = socket.gethostbyaddr(ipv6_address)[0]
        ipv4_addrs = socket.getaddrinfo(hostname, None, socket.AF_INET)
        if ipv4_addrs:
            return str(ipv4_addrs[0][4][0])
    except Exception:
        pass

    return None


@lru_cache(maxsize=1000)
def get_ip_address_type(address: str) -> Optional[str]:
    """Determine the type of IP address.

    Args:
        address: The address string to check

    Returns:
        Optional[str]: 'ipv4' if IPv4, 'ipv6' if IPv6, None if not a valid IP address
    """
    if IPv4.is_valid(address):
        return "ipv4"
    if IPv6.is_valid(address):
        return "ipv6"
    return None
