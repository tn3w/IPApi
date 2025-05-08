#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Request handling and data processing module.

This module provides the core business logic for processing IP information requests,
extracting client IP addresses from requests, gathering IP geolocation and ASN data,
and downloading/initializing required datasets. It coordinates data lookup from
various sources and handles dataset management.
"""

import os
from typing import Optional, Dict, Any, List

from fastapi import Request
from src.utils import download_file
from src.ip_address import (
    is_valid_and_routable_ip,
    get_ip_address_type,
    extract_ipv4_from_ipv6,
)
from src.geo_lookup import (
    process_country_states_cities_database,
    process_zip_codes_database,
    get_currency_from_country,
    is_country_in_european_union,
    get_geocoder_data,
    get_us_state_name_and_code,
    get_timezone_and_offset_from_us_state_code,
    get_country_states_cities_data,
    get_continent_code_from_name,
    find_zip_code,
    get_geo_from_maxmind,
)
from src.asn_lookup import lookup_asn_from_ip, get_asn_from_maxmind
from src.dns_lookup import get_dns_info, get_ipv4_from_ipv6


DATASETS_DIR = "assets"
DATASETS = {
    "GeoLite2-ASN": ("https://git.io/GeoLite2-ASN.mmdb", "GeoLite2-ASN.mmdb"),
    "GeoLite2-City": ("https://git.io/GeoLite2-City.mmdb", "GeoLite2-City.mmdb"),
    "Country-States-Cities": (
        (
            "https://raw.githubusercontent.com/dr5hn/"
            "countries-states-cities-database/refs/heads/master/"
            "json/countries%2Bstates%2Bcities.json"
        ),
        "countries_states_cities.json",
    ),
    "Zip-Codes": (
        (
            "https://raw.githubusercontent.com/wouterdebie/"
            "zip_codes_plus/refs/heads/main/data/zip_codes.csv"
        ),
        "zip_codes.csv",
    ),
}


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

    if not client_ip or not is_valid_and_routable_ip(client_ip):
        return None

    return client_ip


GEO_FIELDS = [
    "continent",
    "continent_code",
    "country",
    "country_code",
    "region",
    "region_code",
    "city",
    "postal_code",
    "latitude",
    "longitude",
    "timezone",
    "accuracy_radius",
]

ASN_FIELDS = [
    "asn",
    "organization",
]

ASN_LOOKUP_FIELDS = [
    "asn",
    "asn_name",
    "organization",
    "net",
    "country",
    "region",
    "city",
    "latitude",
    "longitude",
]


GEOCODER_FIELDS = ["country", "region", "county", "city"]

COUNTRY_STATES_CITIES_FIELDS = [
    "continent",
    "country",
    "timezone",
    "offset",
    "region",
    "region_code",
    "city",
    "county",
]


def check_missing_information(
    information: Dict[str, Any], list1: List[str], list2: List[str]
) -> bool:
    """
    Check if any keys from list1 that are also in list2 have
    missing or None values in the information dict.

    Args:
        information: Dictionary with information data
        list1: First list of keys to check
        list2: Second list of keys to check against

    Returns:
        True if any common key is missing or None in the information
        dict, False otherwise
    """

    common_keys = set(list1) & set(list2)

    if not common_keys:
        return False

    return any(
        key not in information or information[key] is None for key in common_keys
    )


def get_ip_information(ip_address: str, fields: List[str]) -> Dict[str, Any]:
    """
    Get the information for the given IP address.

    Args:
        ip_address: The IP address to get information for
        fields: The fields to get information for

    Returns:
        A dictionary with the information for the given IP address
    """
    information: Dict[str, Any] = {}
    ip_address_type = get_ip_address_type(ip_address)

    if "ip" in fields:
        information["ip"] = ip_address

    if ip_address_type == "ipv6":
        ipv4_from_ipv6 = extract_ipv4_from_ipv6(ip_address)
        if ipv4_from_ipv6 and ipv4_from_ipv6 != ip_address:
            information["ipv4"] = ipv4_from_ipv6
            ip_address = ipv4_from_ipv6
        else:
            information["ipv4"] = None

    if check_missing_information(information, ["ipv4"], fields):
        if ip_address_type == "ipv6":
            ipv4_from_ipv6 = get_ipv4_from_ipv6(ip_address)
            if ipv4_from_ipv6 and ipv4_from_ipv6 != ip_address:
                information["ipv4"] = ipv4_from_ipv6
                ip_address = ipv4_from_ipv6
            else:
                information["ipv4"] = None
        else:
            information["ipv4"] = ip_address

    if "hostname" in fields:
        information["hostname"] = get_dns_info(ip_address)

    if "type" in fields:
        information["type"] = ip_address_type

    if check_missing_information(information, GEO_FIELDS, fields):
        maxmind_path = os.path.join(DATASETS_DIR, DATASETS["GeoLite2-City"][1])
        information.update(get_geo_from_maxmind(ip_address, maxmind_path))

    if check_missing_information(information, ASN_FIELDS, fields):
        maxmind_path = os.path.join(DATASETS_DIR, DATASETS["GeoLite2-ASN"][1])
        asn_info = get_asn_from_maxmind(ip_address, maxmind_path)
        if asn_info:
            information.update(asn_info)

    if check_missing_information(information, ASN_LOOKUP_FIELDS, fields):
        lookup_result = lookup_asn_from_ip(ip_address)
        if lookup_result:
            if not information.get("latitude") or not information.get("longitude"):
                information["accuracy_radius"] = 1000
            information.update(lookup_result)

    if (
        information.get("latitude")
        and information.get("longitude")
        and check_missing_information(information, GEOCODER_FIELDS, fields)
    ):
        information.update(
            get_geocoder_data((information["latitude"], information["longitude"]))
        )

    def fill_in_region_postal_timezone(
        information: Dict[str, Any], fields: List[str]
    ) -> None:
        if check_missing_information(information, ["region", "region_code"], fields):
            information["region"], information["region_code"] = (
                get_us_state_name_and_code(
                    information.get("region"), information.get("region_code")
                )
            )
        if check_missing_information(information, ["postal_code"], fields):
            zip_codes_path = os.path.join(
                DATASETS_DIR, DATASETS["Zip-Codes"][1].replace(".csv", ".json")
            )
            information["postal_code"] = find_zip_code(
                information.get("city"), information.get("region_code"), zip_codes_path
            )

        timezone, offset = get_timezone_and_offset_from_us_state_code(
            information.get("region_code")
        )
        if timezone and offset:
            information["timezone"] = timezone
            information["offset"] = offset

    if information.get("country_code"):
        if "currency" in fields:
            information["currency"] = get_currency_from_country(
                information["country_code"]
            )
        if "is_in_european_union" in fields:
            information["is_in_european_union"] = is_country_in_european_union(
                information["country_code"]
            )
        if check_missing_information(information, COUNTRY_STATES_CITIES_FIELDS, fields):
            country_states_cities_path = os.path.join(
                DATASETS_DIR, DATASETS["Country-States-Cities"][1]
            )
            information.update(
                get_country_states_cities_data(
                    information["country_code"],
                    country_states_cities_path,
                    information.get("city"),
                    information.get("region"),
                    information.get("region_code"),
                )
            )
        if information.get("country_code") == "US":
            fill_in_region_postal_timezone(information, fields)
    else:
        fill_in_region_postal_timezone(information, fields)

    if information.get("continent") and check_missing_information(
        information, ["continent_code"], fields
    ):
        information["continent_code"] = get_continent_code_from_name(
            information["continent"]
        )

    information = {field: information.get(field) for field in fields}

    return information


def download_and_process_datasets() -> None:
    """
    Download and process the datasets.
    """
    country_states_cities_path = os.path.join(
        DATASETS_DIR, DATASETS["Country-States-Cities"][1]
    )
    does_country_states_cities_database_exist = os.path.exists(
        country_states_cities_path
    )

    zip_codes_path = os.path.join(DATASETS_DIR, DATASETS["Zip-Codes"][1])
    zip_codes_json_path = zip_codes_path.replace(".csv", ".json")
    does_zip_codes_database_exist = os.path.exists(zip_codes_json_path)

    for dataset_name, (dataset_url, dataset_filename) in DATASETS.items():
        if dataset_name == "Zip-Codes" and does_zip_codes_database_exist:
            continue

        download_file(
            dataset_url, os.path.join(DATASETS_DIR, dataset_filename), dataset_name
        )

    if not does_country_states_cities_database_exist:
        print("Processing country states cities database...")
        process_country_states_cities_database(country_states_cities_path)

    if not does_zip_codes_database_exist:
        print("Processing zip codes database...")
        process_zip_codes_database(zip_codes_path, zip_codes_json_path)
