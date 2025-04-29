#!/usr/bin/env python3

"""
This script queries pwhois.org for ASN information.
This is a PoC.

Usage:
    ./get_asn_by_ip.py -i <ip_address>
    ./get_asn_by_ip.py -a <asn_code>
"""

import socket
import time
import argparse
from typing import Optional
from dataclasses import dataclass


@dataclass
class ASNInformation:
    """Class to store ASN information."""

    asn: str
    asn_code: int
    country: str = ""
    state: str = ""
    city: str = ""
    organization: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    response_time_ms: float = 0


def query_whois(server: str, query: str) -> str:
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
        return ""
    finally:
        s.close()


def parse_pwhois_response(response: str) -> Optional[ASNInformation]:
    """Parse the response from pwhois.org to extract ASN information."""
    asn_code = 0
    net_name = ""
    organization = ""
    country = ""
    city = ""
    state = ""
    latitude = 0.0
    longitude = 0.0

    # Process line by line
    for line in response.splitlines():
        line = line.strip()
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()

        if key == "as" and value:
            # Format is usually "AS123 Some ASN Name"
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
        elif key.lower() == "net-name" and value:
            net_name = value
        elif key.lower() == "as-org-name" and value:
            organization = value
        elif key == "country" and value:
            country = value
        elif key == "city" and value:
            city = value
        elif key == "region" and value:
            state = value
        elif key == "latitude" and value:
            try:
                latitude = float(value)
            except ValueError:
                pass
        elif key == "longitude" and value:
            try:
                longitude = float(value)
            except ValueError:
                pass

    if asn_code == 0:
        return None

    return ASNInformation(
        asn=net_name if net_name else f"AS{asn_code}",
        asn_code=asn_code,
        organization=organization,
        country=country,
        state=state,
        city=city,
        latitude=latitude,
        longitude=longitude,
    )


def get_detailed_asn_info(ip_address: str) -> Optional[ASNInformation]:
    """Get detailed ASN information for an IP address using pwhois.org"""
    start_time = time.time()

    # Query pwhois.org
    pwhois_response = query_whois("whois.pwhois.org", ip_address)

    if not pwhois_response:
        return None

    # Extract ASN information from the response
    result = parse_pwhois_response(pwhois_response)

    if not result:
        return None

    # Add response time
    result.response_time_ms = round((time.time() - start_time) * 1000)

    return result


def parse_registry_response(response: str, asn_code: int) -> Optional[ASNInformation]:
    """Parse registry response from pwhois.org"""
    org_name = ""
    country = ""
    state = ""
    city = ""

    # Process line by line
    for line in response.splitlines():
        line = line.strip()
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()

        if key == "Org-Name":
            org_name = value
        elif key == "Country":
            country = value
        elif key == "State":
            state = value
        elif key == "City":
            city = value

    if not org_name:
        return None

    return ASNInformation(
        asn=f"AS{asn_code}",
        asn_code=asn_code,
        organization=org_name,
        country=country,
        state=state,
        city=city,
    )


def get_asn_info_by_asn(asn_code: int) -> Optional[ASNInformation]:
    """Get detailed ASN information for an ASN code using pwhois.org."""
    start_time = time.time()

    # Format query for pwhois.org using the registry command
    query = f"registry source-as={asn_code}"

    # Query pwhois.org for AS information
    pwhois_response = query_whois("whois.pwhois.org", query)

    if not pwhois_response:
        return None

    # Parse the registry response
    result = parse_registry_response(pwhois_response, asn_code)

    if result:
        # Add response time
        result.response_time_ms = round((time.time() - start_time) * 1000)

    return result


def main():
    """Main function to handle command line arguments and execute ASN lookups."""
    parser = argparse.ArgumentParser(
        description="Get ASN information for IP addresses or ASN codes"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--ip", help="IP address to lookup")
    group.add_argument("-a", "--asn", type=int, help="ASN code to lookup")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Display verbose output"
    )

    args = parser.parse_args()

    if args.ip:
        print(f"Looking up ASN information for IP {args.ip}...")
        asn_info = get_detailed_asn_info(args.ip)
        if asn_info:
            if args.verbose:
                print(f"Response time: {asn_info.response_time_ms}ms")
            print(asn_info)
        else:
            print("Failed to retrieve ASN information")

    elif args.asn:
        print(f"Looking up information for ASN {args.asn}...")
        asn_info = get_asn_info_by_asn(args.asn)
        if asn_info:
            if args.verbose:
                print(f"Response time: {asn_info.response_time_ms}ms")
            print(asn_info)
        else:
            print("Failed to retrieve ASN information")


if __name__ == "__main__":
    main()
