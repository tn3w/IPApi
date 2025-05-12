#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from typing import Set, List, Tuple, Optional, Dict
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor
import csv
import urllib.request
import zipfile
import io
import re
from netaddr import IPAddress, IPNetwork
from src.dns_lookup import resolve_hostname


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


def process_nordvpn_servers_database(file_path: str) -> None:
    """
    Process NordVPN server data and write extracted IP addresses to a JSON file.

    Args:
        file_path: Path to the JSON file containing NordVPN server data

    Returns:
        None
    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error loading NordVPN server data: {e}")
        return

    station_ips: Set[str] = set()

    for server in data:
        if "station" in server and server["station"]:
            station_ips.add(server["station"])

        if "ipv6_station" in server and server["ipv6_station"]:
            try:
                ipv6 = str(IPAddress(server["ipv6_station"], version=6))
                station_ips.add(ipv6)
            except Exception:
                if server["ipv6_station"]:
                    station_ips.add(server["ipv6_station"])

    try:
        with open(file_path, "w", encoding="utf-8") as output_file:
            json.dump(list(station_ips), output_file, ensure_ascii=False)
        print(
            f"Successfully wrote {len(station_ips)} NordVPN server IPs to {file_path}"
        )
    except IOError as e:
        print(f"Error writing NordVPN server IPs to file: {e}")


def process_sudesh0sudesh_servers_database(file_path: str) -> None:
    """
    Process sudesh0sudesh server data and write extracted IP addresses to a JSON file.

    Args:
        file_path: Path to the SVG file containing sudesh0sudesh server data

    Returns:
        None
    """
    try:
        ip_addresses: List[str] = []

        with open(file_path, "r", encoding="utf-8") as file:
            csv_reader = csv.reader(file)
            next(csv_reader, None)
            for row in csv_reader:
                if row and len(row) > 0:
                    ip_addresses.append(row[0])

        with open(file_path, "w", encoding="utf-8") as output_file:
            json.dump(ip_addresses, output_file, ensure_ascii=False)

        print(f"Successfully wrote {len(ip_addresses)} server IPs to {file_path}")
    except (IOError, json.JSONDecodeError, csv.Error) as e:
        print(f"Error processing sudesh0sudesh server data: {e}")
        return


def download_and_extract_surfshark_configs(url: str) -> Dict[str, str]:
    """
    Download and extract OpenVPN configuration files from Surfshark.

    Args:
        url: The URL of the Surfshark configuration file

    Returns:
        A dictionary mapping file names to their content
    """
    configs: Dict[str, str] = {}

    try:
        print(f"Downloading ZIP file from {url}...")
        response = urllib.request.urlopen(url)
        zip_data = io.BytesIO(response.read())

        with zipfile.ZipFile(zip_data) as zip_file:
            for filename in zip_file.namelist():
                if filename.endswith(".ovpn"):
                    with zip_file.open(filename) as file:
                        content = file.read().decode("utf-8", errors="replace")
                        configs[filename] = content

        return configs

    except Exception as e:
        print(f"Error processing ZIP file: {e}")
        return {}


def extract_surfshark_remote_addresses(configs: Dict[str, str]) -> Set[str]:
    """
    Extract all unique remote addresses from OpenVPN configuration files.

    Args:
        configs: A dictionary mapping file names to their content

    Returns:
        A set of unique remote addresses
    """
    remote_addresses: Set[str] = set()

    for _, content in configs.items():
        matches = re.findall(r"remote\s+([^\s]+)\s+\d+", content)
        if matches:
            remote_addresses.update(matches)

    return remote_addresses


def resolve_and_save_surfshark_hostnames_to_json(
    hostnames: Set[str], file_path: str
) -> None:
    """
    Resolve all hostnames to IPs and save them to a simple JSON array file

    Args:
        hostnames: Set of hostnames to resolve
        file_path: Path where to save the JSON file
    """
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(resolve_hostname, hostnames))

    all_ips: List[str] = []
    for _, ips in sorted(results):
        if not ips:
            continue

        all_ips.extend(ips)

    with open(file_path, "w", encoding="utf-8") as json_file:
        json.dump(all_ips, json_file)


def download_surfshark_hostnames_database(url: str, file_path: str) -> None:
    """
    Download Surfshark server data and write extracted IP addresses to a JSON file.

    Args:
        url: The URL of the Surfshark configuration file
        file_path: Path to the JSON file containing Surfshark server data
    """
    configs = download_and_extract_surfshark_configs(url)

    if not configs:
        print("Error processing Surfshark hostnames to server IPs data.")
        return

    remote_addresses = extract_surfshark_remote_addresses(configs)
    resolve_and_save_surfshark_hostnames_to_json(remote_addresses, file_path)


def process_pia_servers_database(file_path: str) -> None:
    """
    Process PIA server data and write extracted IP addresses to a JSON file.

    Args:
        file_path: Path to the JSON file containing PIA server data

    Returns:
        None
    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()

        last_bracket_index = content.rfind("}")
        if last_bracket_index != -1:
            valid_json = content[: last_bracket_index + 1]
            data = json.loads(valid_json)
        else:
            print(f"No valid JSON structure found in {file_path}")
            return

        ip_addresses: Set[str] = set()

        if "regions" in data:
            for region in data["regions"]:
                if "servers" in region:
                    for _, servers in region["servers"].items():
                        for server in servers:
                            if "ip" in server:
                                if ":" in server["ip"]:
                                    try:
                                        ipv6 = str(IPAddress(server["ip"], version=6))
                                        ip_addresses.add(ipv6)
                                    except Exception:
                                        ip_addresses.add(server["ip"])
                                else:
                                    ip_addresses.add(server["ip"])

        with open(file_path, "w", encoding="utf-8") as output_file:
            json.dump(list(ip_addresses), output_file, ensure_ascii=False)

        print(f"Successfully wrote {len(ip_addresses)} PIA server IPs to {file_path}")

    except (IOError, json.JSONDecodeError) as e:
        print(f"Error processing PIA server data: {e}")
        return


def process_cyberghost_servers_database(file_path: str) -> None:
    """
    Process Cyberghost server data and write extracted IP addresses to a JSON file.

    The input file is expected to be a text file with each line containing:
    IP_ADDRESS    SERVER_INFO

    Args:
        file_path: Path to the text file containing Cyberghost server data

    Returns:
        None
    """
    try:
        ip_addresses: Set[str] = set()

        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                if not line.strip():
                    continue

                parts = line.strip().split()
                if parts:
                    ip = parts[0].strip()

                    if ":" in ip and ip.count(":") > 1:
                        try:
                            ip = str(IPAddress(ip, version=6))
                        except Exception:
                            pass

                    ip_addresses.add(ip)

        with open(file_path, "w", encoding="utf-8") as output_file:
            json.dump(list(ip_addresses), output_file, ensure_ascii=False)

        print(
            f"Successfully wrote {len(ip_addresses)} Cyberghost server IPs to {file_path}"
        )

    except IOError as e:
        print(f"Error processing Cyberghost server data: {e}")
        return


def process_mullvad_servers_database(file_path: str) -> None:
    """
    Process Mullvad server data and write extracted IP addresses to a JSON file.

    Args:
        file_path: Path to the JSON file containing Mullvad server data

    Returns:
        None
    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)

        ip_addresses: Set[str] = set()

        for server in data:
            if "ipv4_addr_in" in server and server["ipv4_addr_in"]:
                ip_addresses.add(server["ipv4_addr_in"])

            if "ipv6_addr_in" in server and server["ipv6_addr_in"]:
                try:
                    ipv6 = str(IPAddress(server["ipv6_addr_in"], version=6))
                    ip_addresses.add(ipv6)
                except Exception:
                    if server["ipv6_addr_in"]:
                        ip_addresses.add(server["ipv6_addr_in"])

        with open(file_path, "w", encoding="utf-8") as output_file:
            json.dump(list(ip_addresses), output_file, ensure_ascii=False)

        print(
            f"Successfully wrote {len(ip_addresses)} Mullvad server IPs to {file_path}"
        )

    except (IOError, json.JSONDecodeError) as e:
        print(f"Error processing Mullvad server data: {e}")
        return


@lru_cache(maxsize=1000)
def is_vpn_server(ip: str, vpn_servers_files: Tuple[Tuple[str, str]]) -> Optional[str]:
    """
    Check if an IP address is a known VPN server.

    Args:
        ip: The IP address to check
        vpn_servers_files: List of tuples containing the file path and the type of VPN server

    Returns:
        The type of VPN server if the IP is a known VPN server, None otherwise
    """
    if ":" in ip:
        try:
            ip = str(IPAddress(ip, version=6))
        except Exception:
            pass

    for vpn_name, vpn_file in vpn_servers_files:
        with open(vpn_file, "r", encoding="utf-8") as file:
            vpn_servers = json.load(file)

        if ip in vpn_servers:
            return vpn_name

    return None


def process_firehol_proxies_database(file_path: str) -> None:
    """
    Process FireHOL proxies database and write extracted IP addresses to a JSON file.
    Expands CIDR notation to individual IP addresses.

    Args:
        file_path: Path to the FireHOL proxies database file

    Returns:
        None
    """
    try:
        ip_addresses: List[str] = []

        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                if "/" in line:
                    try:
                        for ip in IPNetwork(line):
                            ip_addresses.append(str(ip))
                    except Exception as e:
                        print(f"Error processing CIDR {line}: {e}")
                else:
                    # Regular IP address
                    ip_addresses.append(line)

        with open(file_path, "w", encoding="utf-8") as output_file:
            json.dump(ip_addresses, output_file, ensure_ascii=False)

        print(f"Successfully wrote {len(ip_addresses)} proxy IPs to {file_path}")

    except IOError as e:
        print(f"Error processing FireHOL proxies database: {e}")
        return


@lru_cache(maxsize=1000)
def is_proxy_server(ip: str, proxy_servers_files: Tuple[str]) -> bool:
    """
    Check if an IP address is a known proxy server.

    Args:
        ip: The IP address to check
        proxy_servers_files: List of file paths containing the proxy server data

    Returns:
        True if the IP is a known proxy server, False otherwise
    """
    if ":" in ip:
        try:
            ip = str(IPAddress(ip, version=6))
        except Exception:
            pass

    for proxy_file in proxy_servers_files:
        with open(proxy_file, "r", encoding="utf-8") as file:
            proxy_servers = json.load(file)

        if ip in proxy_servers:
            return True

    return False
