#! /usr/bin/env python3
#
# Requirements:
#   pip install "Flask>=3.1.0" "maxminddb>=2.6.3" "reverse-geocode>=1.6.5"
#

"""
This is a simple API that returns the GeoIP and ASN information for the given IP address.
"""

from typing import Dict, Any, Optional
from functools import lru_cache
from flask import Flask, request, jsonify, Request

from geolite2_asn import (
    download_database as download_asn_database,
    get_asn_information,
    ASNIPInformation,
)
from geolite2_city import (
    download_database as download_city_database,
    download_countries_data,
    get_geoip_information,
    fill_empty_fields_with_geocoder,
    fill_country_continent_data,
    GeoIPInformation,
)
from asn_lookup import get_detailed_asn_info
from ip_address import is_valid_and_routable_ip

app = Flask(__name__)


@app.route("/")
def index():
    """
    Return a simple message to indicate the API is running.
    """
    return "Hello, World!"


def get_ip_address(flask_request: Request) -> Optional[str]:
    """
    Extract and validate the client IP address from the request.

    First checks the remote_addr attribute. If that's missing or localhost,
    falls back to the X-Forwarded-For header. Returns None if no valid
    routable IP address is found.

    Args:
        flask_request: The Flask request object

    Returns:
        A valid routable IP address or None
    """
    client_ip = flask_request.remote_addr

    if not client_ip or client_ip == "127.0.0.1":
        client_ip = flask_request.headers.get(
            "X-Forwarded-For", flask_request.remote_addr
        )

    if not client_ip or not is_valid_and_routable_ip(client_ip):
        return None

    return client_ip


def enrich_with_detailed_asn_info(
    geoip_info: GeoIPInformation, asn_info: ASNIPInformation, ip_address: str
) -> None:
    """
    Enrich GeoIP and ASN information with detailed ASN data when latitude/longitude is missing.
    """
    try:
        detailed_asn_info = get_detailed_asn_info(ip_address)
        if not detailed_asn_info:
            return

        geoip_info.accuracy_radius = 100

        field_mappings = [
            (
                geoip_info,
                "country",
                detailed_asn_info,
                "country",
                not geoip_info.country,
            ),
            (
                geoip_info,
                "country_code",
                detailed_asn_info,
                "country_code",
                not geoip_info.country_code,
            ),
            (geoip_info, "region", detailed_asn_info, "state", not geoip_info.region),
            (geoip_info, "city", detailed_asn_info, "city", not geoip_info.city),
            (
                geoip_info,
                "latitude",
                detailed_asn_info,
                "latitude",
                geoip_info.latitude is None,
            ),
            (
                geoip_info,
                "longitude",
                detailed_asn_info,
                "longitude",
                geoip_info.longitude is None,
            ),
            (asn_info, "asn", detailed_asn_info, "asn", not asn_info.asn),
            (
                asn_info,
                "asn_name",
                detailed_asn_info,
                "asn_name",
                not asn_info.asn_name,
            ),
            (
                asn_info,
                "organization",
                detailed_asn_info,
                "organization",
                not asn_info.organization,
            ),
        ]

        for target, target_field, source, source_field, condition in field_mappings:
            source_value = getattr(source, source_field, None)
            if condition and source_value:
                setattr(target, target_field, source_value)

        if hasattr(asn_info, "net") and not asn_info.net and detailed_asn_info.net:
            asn_info.net = detailed_asn_info.net
    except Exception as e:
        print(f"Error getting detailed ASN info: {e}")


@lru_cache(maxsize=1000)
def get_ip_information(ip_address: str) -> Dict[str, Any]:
    """
    Return the GeoIP and ASN information for the given IP address.
    """
    geoip_info = get_geoip_information(ip_address)
    asn_info = get_asn_information(ip_address)

    if geoip_info.latitude is None or geoip_info.longitude is None:
        enrich_with_detailed_asn_info(geoip_info, asn_info, ip_address)

    if geoip_info.latitude is not None and geoip_info.longitude is not None:
        fill_empty_fields_with_geocoder(geoip_info)

    fill_country_continent_data(geoip_info)

    geoip_dict = geoip_info.__dict__.copy()
    asn_dict = asn_info.__dict__.copy()

    if "response_time_ms" in geoip_dict:
        del geoip_dict["response_time_ms"]
    if "response_time_ms" in asn_dict:
        del asn_dict["response_time_ms"]

    return {**geoip_dict, **asn_dict}


@app.route("/self")
def self():
    """
    Return the GeoIP and ASN information for the current IP address.
    """
    ip_address = get_ip_address(request)
    if not ip_address:
        return jsonify({"error": "Not a valid IP address"})

    return jsonify(get_ip_information(ip_address))


@app.route("/<ip_address>")
def ip(ip_address: str):
    """
    Return the GeoIP and ASN information for the given IP address.
    """
    if not is_valid_and_routable_ip(ip_address):
        return jsonify({"error": "Not a valid IP address"})

    return jsonify(get_ip_information(ip_address))


if __name__ == "__main__":
    download_asn_database()
    download_city_database()
    download_countries_data()
    app.run(host="0.0.0.0", port=5000)
