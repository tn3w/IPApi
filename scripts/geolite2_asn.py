#!/usr/bin/env python3
#
# Requirements:
#   pip install "maxminddb>=2.6.3"
#

"""
This script downloads GeoLite2-ASN.mmdb database and queries ASN information.
This is a PoC.

Usage:
    ./maxmind_geolite2_asn.py -i <ip_address>
    ./maxmind_geolite2_asn.py -d  # Download/update the database
"""

import os
import time
import argparse
import urllib.request
from typing import Optional, Dict, Any, cast
from dataclasses import dataclass
import maxminddb


GEOLITE2_URL = "https://git.io/GeoLite2-ASN.mmdb"
DATABASE_DIR = "test"
DATABASE_PATH = os.path.join(DATABASE_DIR, "GeoLite2-ASN.mmdb")


@dataclass
class ASNIPInformation:
    """Class to store ASN information."""

    ip: str
    asn: Optional[int] = None
    organization: Optional[str] = None
    response_time_ms: Optional[float] = None


RecordDict = Dict[str, Any]


def download_database() -> bool:
    """Download the GeoLite2 ASN database."""
    if not os.path.exists(DATABASE_DIR):
        os.makedirs(DATABASE_DIR)

    try:
        print(f"Downloading GeoLite2-ASN database from {GEOLITE2_URL}...")
        urllib.request.urlretrieve(GEOLITE2_URL, DATABASE_PATH)
        print(f"Successfully downloaded database to {DATABASE_PATH}")
        return True
    except Exception as e:
        print(f"Error downloading database: {e}")
        return False


def database_exists() -> bool:
    """Check if the GeoLite2 ASN database exists."""
    return os.path.exists(DATABASE_PATH)


def get_asn_information(ip_address: str) -> Optional[ASNIPInformation]:
    """Get ASN information for an IP address."""
    if not database_exists():
        print("Database not found. Please run with -d option to download it first.")
        return None

    start_time = time.time()

    try:
        with maxminddb.open_database(DATABASE_PATH) as reader:  # type: ignore
            result = reader.get(ip_address)  # type: ignore
            if not result:
                return None

            record = cast(RecordDict, result)
            asn_info = ASNIPInformation(ip=ip_address)

            def get_nested(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
                """Safely get a nested value from a dictionary."""
                current = d
                for key in keys:
                    if not isinstance(current, dict) or key not in current:
                        return default
                    current = current[key]
                return current

            asn_info.asn = get_nested(record, "autonomous_system_number")
            asn_info.organization = get_nested(record, "autonomous_system_organization")

            asn_info.response_time_ms = round((time.time() - start_time) * 1000)

            return asn_info

    except Exception as e:
        print(f"Error querying database: {e}")
        return None


def main():
    """Main function to handle command line arguments and execute ASN lookups."""
    parser = argparse.ArgumentParser(description="Get ASN information for IP addresses")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--ip", help="IP address to lookup")
    group.add_argument(
        "-d", "--download", action="store_true", help="Download/update the database"
    )

    args = parser.parse_args()

    if args.download:
        download_database()
        return

    if args.ip:
        if not database_exists():
            print("Database not found. Downloading it now...")
            if not download_database():
                print("Failed to download the database.")
                return

        print(f"Looking up ASN information for IP {args.ip}...")
        asn_info = get_asn_information(args.ip)
        if asn_info:
            print("\n~-~ ASN Information: ~-~")
            for key, value in asn_info.__dict__.items():
                key = key.replace("_", " ").capitalize()
                if value is None:
                    value = "N/A"
                print(f"{key}: {value}")
        else:
            print("Failed to retrieve ASN information")


if __name__ == "__main__":
    main()
