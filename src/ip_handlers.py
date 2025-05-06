"""
Utility functions for handling IP address information.
"""

from typing import Dict, Any, Optional
from functools import lru_cache
from fastapi import Request

from src.geolite2_asn import (
    get_asn_information,
    ASNIPInformation,
)
from src.geolite2_city import (
    get_geoip_information,
    fill_empty_fields_with_geocoder,
    fill_country_continent_data,
    GeoIPInformation,
    get_us_zip_code,
)
from src.asn_lookup import get_detailed_asn_info
from src.ip_address import is_valid_and_routable_ip


def get_ip_address(request: Request) -> Optional[str]:
    """
    Extract and validate the client IP address from the request.

    First checks the client.host attribute. If that's missing or localhost,
    falls back to the X-Forwarded-For header. Returns None if no valid
    routable IP address is found.

    Args:
        request: The FastAPI request object

    Returns:
        A valid routable IP address or None
    """
    client_ip = request.client.host if request.client else None

    if not client_ip or client_ip == "127.0.0.1":
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()

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
            (geoip_info, "country", detailed_asn_info, "country"),
            (geoip_info, "country_code", detailed_asn_info, "country_code"),
            (geoip_info, "region", detailed_asn_info, "state"),
            (geoip_info, "city", detailed_asn_info, "city"),
            (geoip_info, "latitude", detailed_asn_info, "latitude"),
            (geoip_info, "longitude", detailed_asn_info, "longitude"),
            (asn_info, "asn", detailed_asn_info, "asn"),
            (asn_info, "asn_name", detailed_asn_info, "asn_name"),
            (asn_info, "organization", detailed_asn_info, "organization"),
        ]

        for target, target_field, source, source_field in field_mappings:
            source_value = getattr(source, source_field, None)
            if source_value:
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

    print(geoip_info)
    print(asn_info)

    if geoip_info.latitude is None or geoip_info.longitude is None:
        enrich_with_detailed_asn_info(geoip_info, asn_info, ip_address)

    if geoip_info.latitude is not None and geoip_info.longitude is not None:
        fill_empty_fields_with_geocoder(geoip_info)

    fill_country_continent_data(geoip_info)

    if (
        geoip_info.country_code == "US"
        and geoip_info.city
        and not geoip_info.postal_code
    ):
        zip_code = get_us_zip_code(geoip_info.city, geoip_info.region_code)
        if zip_code:
            geoip_info.postal_code = zip_code
            print(
                f"Found ZIP code for {geoip_info.city}, {geoip_info.region_code}: {zip_code}"
            )

    geoip_dict = geoip_info.__dict__.copy()
    asn_dict = asn_info.__dict__.copy()

    return {**geoip_dict, **asn_dict}
