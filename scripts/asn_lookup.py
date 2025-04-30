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
from typing import Optional, Dict, Any
from dataclasses import dataclass


@dataclass
class ASNInformation:
    """Class to store ASN information."""

    asn: int
    asn_name: str = ""
    country: str = ""
    country_code: str = ""
    state: str = ""
    city: str = ""
    organization: str = ""
    isp: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    response_time_ms: float = 0


@dataclass
class LocationContext:
    """Class to hold location data and geo flags during parsing."""

    data: Dict[str, Any]
    geo_flags: Dict[str, bool]


@dataclass
class ParserState:
    """Class to hold the current state of parsing."""

    asn_code: int = 0
    asn_name: str = ""
    organization: str = ""
    isp: str = ""
    location_ctx: LocationContext = None

    def __post_init__(self):
        if self.location_ctx is None:
            location_data = {
                "country": "",
                "country_code": "",
                "city": "",
                "state": "",
                "latitude": 0.0,
                "longitude": 0.0,
            }
            geo_flags = {field: False for field in location_data}
            self.location_ctx = LocationContext(location_data, geo_flags)


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


def _parse_asn_fields(key: str, value: str) -> tuple[int, str]:
    """Parse ASN-related fields and return ASN code and name."""
    asn_code = 0
    asn_name = ""

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
    elif key.lower() == "as-name" and value:
        asn_name = value

    return asn_code, asn_name


def _parse_org_fields(key: str, value: str, current_org: str = "") -> tuple[str, str]:
    """Parse organization and ISP related fields."""
    organization = current_org
    isp = ""

    if key == "net-name" and value:
        isp = value
    elif key == "as-org-name" and value and value != r"\(^_^)/":
        organization = value
    elif key == "org-name" and value and not organization:
        organization = value

    return organization, isp


def _parse_location_field(
    key: str, value: str, is_geo: bool, location_ctx: LocationContext
) -> None:
    """Parse and update location data fields."""
    if key in location_ctx.data and value:
        if is_geo or not location_ctx.geo_flags[key]:
            if key in ["latitude", "longitude"]:
                try:
                    location_ctx.data[key] = float(value)
                except ValueError:
                    return
            else:
                location_ctx.data[key] = value

            if is_geo:
                location_ctx.geo_flags[key] = True


def _parse_mapped_key(
    key: str,
    value: str,
    is_geo: bool,
    key_mapping: dict,
    location_ctx: LocationContext,
) -> None:
    """Parse keys that are mapped to other field names."""
    if key in key_mapping and value:
        mapped_key = key_mapping[key]
        if (is_geo or not location_ctx.geo_flags[mapped_key]) and not location_ctx.data[
            mapped_key
        ]:
            location_ctx.data[mapped_key] = value
            if is_geo:
                location_ctx.geo_flags[mapped_key] = True


def _clean_field(field: str) -> str:
    """Clean organization and ISP fields."""
    if not field:
        return ""

    parts = field.split("-")
    if len(parts) >= 3:
        return parts[1]
    return field


def _process_line(line: str, parser_state: ParserState, key_mapping: dict) -> None:
    """Process a single line from the whois response."""
    if ":" not in line:
        return

    key, value = line.split(":", 1)
    original_key = key.strip().lower()
    key = original_key.replace("geo-", "")
    value = value.strip()

    is_geo = original_key.startswith("geo-")

    code, name = _parse_asn_fields(key, value)
    if code > 0:
        parser_state.asn_code = code
    if name:
        parser_state.asn_name = name

    org, net_name = _parse_org_fields(key, value, parser_state.organization)
    if org:
        parser_state.organization = org
    if net_name:
        parser_state.isp = net_name

    _parse_location_field(key, value, is_geo, parser_state.location_ctx)
    _parse_mapped_key(key, value, is_geo, key_mapping, parser_state.location_ctx)


def parse_pwhois_response(response: str) -> Optional[ASNInformation]:
    """Parse the response from pwhois.org to extract ASN information."""
    state = ParserState()

    key_mapping = {
        "region": "state",
        "cc": "country_code",
        "country-code": "country_code",
    }

    for line in response.splitlines():
        _process_line(line.strip(), state, key_mapping)

    if state.asn_code == 0:
        return None

    state.organization = _clean_field(state.organization)
    state.isp = _clean_field(state.isp)

    if not state.asn_name and state.organization:
        state.asn_name = state.organization

    return ASNInformation(
        asn=state.asn_code,
        asn_name=state.asn_name,
        organization=state.organization,
        isp=state.isp,
        country=state.location_ctx.data["country"],
        country_code=state.location_ctx.data["country_code"],
        state=state.location_ctx.data["state"],
        city=state.location_ctx.data["city"],
        latitude=state.location_ctx.data["latitude"],
        longitude=state.location_ctx.data["longitude"],
    )


def get_detailed_asn_info(ip_address: str) -> Optional[ASNInformation]:
    """Get detailed ASN information for an IP address using pwhois.org"""
    start_time = time.time()

    pwhois_response = query_whois("whois.pwhois.org", ip_address)
    print(pwhois_response)

    if not pwhois_response:
        return None

    result = parse_pwhois_response(pwhois_response)

    if not result:
        return None

    result.response_time_ms = round((time.time() - start_time) * 1000)

    return result


def parse_registry_response(response: str, asn_code: int) -> Optional[ASNInformation]:
    """Parse registry response from pwhois.org"""
    field_mapping = {
        "Org-Name": "",
        "Country": "",
        "State": "",
        "City": "",
        "AS-Name": "",
    }

    for line in response.splitlines():
        line = line.strip()
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()

        if key in field_mapping:
            field_mapping[key] = value

    if not field_mapping["Org-Name"]:
        return None

    return ASNInformation(
        asn=asn_code,
        asn_name=field_mapping["AS-Name"],
        organization=field_mapping["Org-Name"],
        country=field_mapping["Country"],
        state=field_mapping["State"],
        city=field_mapping["City"],
    )


def get_asn_info_by_asn(asn_code: int) -> Optional[ASNInformation]:
    """Get detailed ASN information for an ASN code using pwhois.org."""
    start_time = time.time()

    query = f"registry source-as={asn_code}"

    pwhois_response = query_whois("whois.pwhois.org", query)
    print(pwhois_response)

    if not pwhois_response:
        return None

    result = parse_registry_response(pwhois_response, asn_code)

    if result:
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
