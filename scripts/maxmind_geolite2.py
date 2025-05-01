#!/usr/bin/env python3
#
# Requirements:
#   pip install "maxminddb>=2.6.3"
#

"""
This script downloads GeoLite2-City.mmdb database and queries IP geolocation information.
This is a PoC.

Usage:
    ./maxmind_geolite2.py -i <ip_address>
    ./maxmind_geolite2.py -d  # Download/update the database
"""

import os
import time
import argparse
import urllib.request
from typing import Optional, Dict, Any, cast
from dataclasses import dataclass
import maxminddb


GEOLITE2_URL = "https://git.io/GeoLite2-City.mmdb"
DATABASE_DIR = "test"
DATABASE_PATH = os.path.join(DATABASE_DIR, "GeoLite2-City.mmdb")


@dataclass
class GeoIPInformation:
    """Class to store GeoIP information."""

    ip: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    continent: Optional[str] = None
    continent_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    postal_code: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    accuracy_radius: Optional[int] = None
    response_time_ms: Optional[float] = None


RecordDict = Dict[str, Any]


def download_database() -> bool:
    """Download the GeoLite2 City database."""
    if not os.path.exists(DATABASE_DIR):
        os.makedirs(DATABASE_DIR)

    try:
        print(f"Downloading GeoLite2-City database from {GEOLITE2_URL}...")
        urllib.request.urlretrieve(GEOLITE2_URL, DATABASE_PATH)
        print(f"Successfully downloaded database to {DATABASE_PATH}")
        return True
    except Exception as e:
        print(f"Error downloading database: {e}")
        return False


def database_exists() -> bool:
    """Check if the GeoLite2 database exists."""
    return os.path.exists(DATABASE_PATH)


def get_geoip_information(ip_address: str) -> Optional[GeoIPInformation]:
    """Get detailed geolocation information for an IP address."""
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
            geoip_info = GeoIPInformation(ip=ip_address)

            def get_nested(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
                """Safely get a nested value from a dictionary."""
                current = d
                for key in keys:
                    if not isinstance(current, dict) or key not in current:
                        return default
                    current = current[key]
                return current

            country_value = get_nested(record, "country", "names", "en")
            if country_value is None:
                geoip_info.country = get_nested(
                    record, "registered_country", "names", "en"
                )
                geoip_info.country_code = get_nested(
                    record, "registered_country", "iso_code"
                )
            else:
                geoip_info.country = country_value
                geoip_info.country_code = get_nested(record, "country", "iso_code")

            geoip_info.continent = get_nested(record, "continent", "names", "en")
            geoip_info.continent_code = get_nested(record, "continent", "code")

            subdivisions = get_nested(record, "subdivisions")
            if subdivisions and len(subdivisions) > 0:
                geoip_info.region = get_nested(subdivisions[0], "names", "en")

            geoip_info.city = get_nested(record, "city", "names", "en")
            geoip_info.postal_code = get_nested(record, "postal", "code")

            location = get_nested(record, "location")
            if location:
                geoip_info.latitude = get_nested(location, "latitude")
                geoip_info.longitude = get_nested(location, "longitude")
                geoip_info.timezone = get_nested(location, "time_zone")
                geoip_info.accuracy_radius = get_nested(location, "accuracy_radius")

            geoip_info.response_time_ms = round((time.time() - start_time) * 1000)

            return geoip_info

    except Exception as e:
        print(f"Error querying database: {e}")
        return None


def main():
    """Main function to handle command line arguments and execute GeoIP lookups."""
    parser = argparse.ArgumentParser(
        description="Get GeoIP information for IP addresses"
    )
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

        print(f"Looking up GeoIP information for IP {args.ip}...")
        geoip_info = get_geoip_information(args.ip)
        if geoip_info:
            print(geoip_info)
        else:
            print("Failed to retrieve GeoIP information")


if __name__ == "__main__":
    main()
