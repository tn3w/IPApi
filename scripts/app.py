#! /usr/bin/env python3
#
# Requirements:
#   pip install "Flask>=3.1.0" "maxminddb>=2.6.3" "reverse-geocode>=1.6.5"
#

"""
This is a simple API that returns the GeoIP and ASN information for the given IP address.
"""

from typing import Dict, Any
from functools import lru_cache
from flask import Flask, request, jsonify

from geolite2_asn import get_asn_information
from geolite2_city import get_geoip_information
from ip_address import is_valid_and_routable_ip

app = Flask(__name__)


@app.route("/")
def index():
    """
    Return a simple message to indicate the API is running.
    """
    return "Hello, World!"


@lru_cache(maxsize=1000)
def get_ip_information(ip_address: str) -> Dict[str, Any]:
    """
    Return the GeoIP and ASN information for the given IP address.
    """
    geoip_info = get_geoip_information(ip_address)
    asn_info = get_asn_information(ip_address)

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
    ip_address = request.remote_addr
    if ip_address in (None, "127.0.0.1"):
        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ip_address is None:
        return jsonify({"error": "Not a valid IP address"})
    if not is_valid_and_routable_ip(ip_address):
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
    app.run(host="0.0.0.0", port=5000)
