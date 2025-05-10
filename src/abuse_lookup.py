#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from typing import Set
from functools import lru_cache
from netaddr import IPAddress


def process_tor_exit_nodes_database(file_path: str) -> None:
    """
    Process Tor exit node data and write extracted IP addresses to a JSON file.

    Args:
        file_path: Path to the JSON file containing Tor exit node data
        output_file_path: Path where the processed data will be saved as JSON
    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error loading Tor exit node data: {e}")
        return

    tor_nodes: Set[str] = set()

    if "relays" not in data:
        print("No 'relays' found in the Tor exit node data")
        return

    for relay in data["relays"]:
        for field in ["exit_addresses", "or_addresses"]:
            for addr in relay.get(field, []):
                if ":" in addr and addr.count(":") > 1 or addr.startswith("["):
                    ipv6 = extract_ipv6(addr)
                    if ipv6:
                        tor_nodes.add(ipv6)
                else:
                    ipv4 = extract_ipv4(addr)
                    if ipv4:
                        tor_nodes.add(ipv4)

    try:
        with open(file_path, "w", encoding="utf-8") as output_file:
            json.dump(list(tor_nodes), output_file, ensure_ascii=False)
        print(f"Successfully wrote {len(tor_nodes)} Tor exit nodes to {file_path}")
    except IOError as e:
        print(f"Error writing Tor exit nodes to file: {e}")


def extract_ipv4(addr: str) -> str:
    """Extract IPv4 address from a string that may include a port."""
    parts = addr.split(":")
    return parts[0]


def extract_ipv6(addr: str) -> str:
    """
    Extract IPv6 address from a string that may include brackets and port.
    Returns the address in its full expanded form using netaddr.
    """
    if addr.startswith("["):
        end_bracket = addr.find("]")
        if end_bracket != -1:
            addr = addr[1:end_bracket]
    else:
        parts = addr.split(":")
        if len(parts) > 2 and parts[-2].isdigit() and parts[-1].isdigit():
            addr = ":".join(parts[:-1])

    try:
        return str(IPAddress(addr, version=6))
    except Exception:
        return addr


@lru_cache(maxsize=1000)
def is_tor_exit_node(ip: str, tor_nodes_file: str) -> bool:
    """
    Check if an IP address is a known Tor exit node.

    Args:
        ip: The IP address to check
        tor_nodes_file: Path to the JSON file containing Tor exit nodes

    Returns:
        True if the IP is a Tor exit node, False otherwise
    """
    try:
        with open(tor_nodes_file, "r", encoding="utf-8") as file:
            tor_nodes = json.load(file)

        if ":" in ip:
            try:
                ip = str(IPAddress(ip, version=6))
            except Exception:
                pass

        return ip in tor_nodes
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error checking Tor exit nodes: {e}")
        return False
