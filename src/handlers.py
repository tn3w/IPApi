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
import json
import urllib.request
import urllib.error
from functools import lru_cache
from typing import Optional, Dict, Any, List, Union, Tuple

from fastapi import Request
from redis import Redis
from netaddr import IPNetwork, IPAddress, AddrFormatError
from src.ip_address import (
    is_valid_and_routable_ip,
    get_ip_address_type,
    extract_ipv4_from_ipv6,
)
from src.geo_lookup import (
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
from src.asn_lookup import (
    get_abuse_contact,
    get_rpki_validity,
    get_asn_from_maxmind,
)
from src.ip_whois import ip_whois_pwhois, ip_whois
from src.dns_lookup import get_hostname_from_ip, get_ipv4_from_ipv6


DATASETS_DIR = "assets"
DATASETS: Dict[str, Union[str, Tuple[Union[str, list[str]], str]]] = {
    # Geolocation
    "GeoLite2-ASN": ("https://git.io/GeoLite2-ASN.mmdb", "GeoLite2-ASN.mmdb"),
    "GeoLite2-City": ("https://git.io/GeoLite2-City.mmdb", "GeoLite2-City.mmdb"),
    "Countries-States-Cities": (
        (
            "https://raw.githubusercontent.com/tn3w/IPSet/"
            "refs/heads/master/countries_states_cities.json"
        ),
        "countries_states_cities.json",
    ),
    "Zip-Codes": (
        "https://raw.githubusercontent.com/tn3w/IPSet/refs/heads/master/zip_codes.json",
        "zip_codes.json",
    ),
    # Abuse: VPNs / Proxies / Spam
    "IPSet": (
        "https://raw.githubusercontent.com/tn3w/IPSet/refs/heads/master/iplookup.json",
        "ipset.json",
    ),
    # Abuse: Data Center
    "Data-Center-ASNS": (
        "https://raw.githubusercontent.com/tn3w/IPSet/refs/heads/master/datacenter_asns.json",
        "data-center-asns.json",
    ),
    # Abuse: Firehol Level 1
    "Firehol-Level-1": (
        "https://raw.githubusercontent.com/tn3w/IPSet/refs/heads/master/firehol_level1.json",
        "firehol_level1.json",
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
    "asn_name",
]

ASN_LOOKUP_FIELDS = [
    "asn",
    "asn_name",
    "org",
    "net",
    "prefix",
    "country",
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


LOADED_IPSET_DATA: Dict[str, Any] = {}


def load_ipset_data() -> None:
    """
    Load the IPSet data from the file.
    """
    ipset_path = os.path.join(DATASETS_DIR, DATASETS["IPSet"][1])
    with open(ipset_path, "r", encoding="utf-8") as file:
        ipset_data = json.load(file)
    LOADED_IPSET_DATA.update(ipset_data)


load_ipset_data()


@lru_cache(maxsize=1000)
def get_ip_groups(ip_address: str) -> List[str]:
    """
    Get the groups for the given IP address.
    """
    if not LOADED_IPSET_DATA:
        load_ipset_data()
    return LOADED_IPSET_DATA.get(ip_address, [])


LOADED_DATA_CENTER_ASNS_DATA: List[str] = []


def load_data_center_asns_data() -> None:
    """
    Load the data center ASNs data from the file.
    """
    data_center_asns_path = os.path.join(DATASETS_DIR, DATASETS["Data-Center-ASNS"][1])
    with open(data_center_asns_path, "r", encoding="utf-8") as file:
        data_center_asns_data = json.load(file)
    LOADED_DATA_CENTER_ASNS_DATA.extend(data_center_asns_data)


load_data_center_asns_data()


@lru_cache(maxsize=1000)
def is_data_center_asn(asn: str) -> bool:
    """
    Check if the given ASN is a data center ASN.
    """
    if not LOADED_DATA_CENTER_ASNS_DATA:
        load_data_center_asns_data()
    return asn in LOADED_DATA_CENTER_ASNS_DATA


LOADED_FIREHOL_LEVEL1_DATA: List[IPNetwork] = []


def load_firehol_level1_data() -> None:
    """
    Load the firehol level 1 data from the file.
    """
    firehol_level1_path = os.path.join(DATASETS_DIR, DATASETS["Firehol-Level-1"][1])
    with open(firehol_level1_path, "r", encoding="utf-8") as file:
        firehol_data = json.load(file)

    LOADED_FIREHOL_LEVEL1_DATA.extend([IPNetwork(cidr) for cidr in firehol_data])


load_firehol_level1_data()


@lru_cache(maxsize=1000)
def is_firehol_level1_ip(ip_address: str) -> bool:
    """
    Check if the given IPv4 address is contained in any CIDR range from the Firehol Level 1 dataset.

    Args:
        ip_address: The IPv4 address to check
        firehol_level1_path: Path to the Firehol Level 1 dataset

    Returns:
        True if the IP is in any CIDR range, False otherwise
    """
    if not LOADED_FIREHOL_LEVEL1_DATA:
        load_firehol_level1_data()

    try:
        ip_obj = IPAddress(ip_address)
        return any(ip_obj in network for network in LOADED_FIREHOL_LEVEL1_DATA)
    except (ValueError, AddrFormatError):
        return False


def get_ip_information(
    ip_address: str, fields: List[str], redis: Redis
) -> Dict[str, Any]:
    """
    Get the information for the given IP address.

    Args:
        ip_address: The IP address to get information for
        fields: The fields to get information for
        redis: The Redis client to use for caching

    Returns:
        A dictionary with the information for the given IP address
    """
    information: Dict[str, Any] = {}
    ip_address_type = get_ip_address_type(ip_address)

    if "ip" in fields:
        information["ip"] = ip_address

    if "type" in fields:
        information["type"] = ip_address_type

    groups = get_ip_groups(ip_address)

    if "tor_exit_node" in fields:
        information["tor_exit_node"] = "TorExitNodes" in groups

    if check_missing_information(information, ["vpn", "vpn_name"], fields):
        vpn_providers = [
            "NordVPN",
            "ProtonVPN",
            "ExpressVPN",
            "Surfshark",
            "PrivateInternetAccess",
            "CyberGhost",
            "TunnelBear",
            "Mullvad",
        ]
        vpn_name = next((name for name in vpn_providers if name in groups), None)
        information["vpn"] = bool(vpn_name)
        information["vpn_name"] = vpn_name

    if "forum_spammer" in fields:
        information["forum_spammer"] = "StopForumSpam" in groups

    if "proxy" in fields:
        information["proxy"] = "FireholProxies" in groups or "AwesomeProxies" in groups

    if ip_address_type == "ipv6":
        ipv4_from_ipv6 = extract_ipv4_from_ipv6(ip_address)
        if ipv4_from_ipv6 and ipv4_from_ipv6 != ip_address:
            information["ipv4"] = ipv4_from_ipv6
            ip_address = ipv4_from_ipv6
            ip_address_type = "ipv4"
        else:
            information["ipv4"] = None

    if check_missing_information(information, ["ipv4"], fields):
        if ip_address_type == "ipv6":
            ipv4_from_ipv6 = get_ipv4_from_ipv6(ip_address)
            if ipv4_from_ipv6 and ipv4_from_ipv6 != ip_address:
                information["ipv4"] = ipv4_from_ipv6
                ip_address = ipv4_from_ipv6
                ip_address_type = "ipv4"
            else:
                information["ipv4"] = None
        else:
            information["ipv4"] = ip_address

    if "hostname" in fields:
        hostname = get_hostname_from_ip(ip_address)
        if hostname and hostname != ip_address:
            information["hostname"] = hostname

    if check_missing_information(information, GEO_FIELDS, fields):
        maxmind_path = os.path.join(DATASETS_DIR, DATASETS["GeoLite2-City"][1])
        information.update(get_geo_from_maxmind(ip_address, maxmind_path))

    if check_missing_information(information, ASN_FIELDS, fields):
        maxmind_path = os.path.join(DATASETS_DIR, DATASETS["GeoLite2-ASN"][1])
        asn_info = get_asn_from_maxmind(ip_address, maxmind_path)
        if asn_info:
            information.update(asn_info)

    if (
        information.get("latitude")
        and information.get("longitude")
        and check_missing_information(information, GEOCODER_FIELDS, fields)
    ):
        information.update(
            get_geocoder_data(
                (information["latitude"], information["longitude"]), redis
            )
        )

    if check_missing_information(information, ["abuse_contact"], fields):
        country_code = information.get("country_code")
        if isinstance(country_code, str):
            try:
                lookup_result = ip_whois(ip_address, country_code.upper(), redis)
                if lookup_result:
                    information.update(lookup_result)
            except ValueError:
                pass

    if check_missing_information(information, ASN_LOOKUP_FIELDS, fields):
        lookup_result = ip_whois_pwhois(ip_address, redis)
        if lookup_result:
            if information.get("latitude") or information.get("longitude"):
                information["accuracy_radius"] = 100
            information.update(lookup_result)

    if check_missing_information(information, ["abuse_contact"], fields):
        information["abuse_contact"] = get_abuse_contact(ip_address, redis)

    if check_missing_information(information, ["rpki", "rpki_count"], fields):
        asn, prefix = information.get("asn"), information.get("prefix")
        if isinstance(asn, str) and isinstance(prefix, str):
            information["rpki"], information["rpki_count"] = get_rpki_validity(
                asn,
                prefix,
                redis,
            )

    if "data_center" in fields:
        if information.get("asn"):
            information["data_center"] = is_data_center_asn(str(information["asn"]))
        else:
            information["data_center"] = False

    if "firehol_level1" in fields:
        if ip_address_type == "ipv4":
            information["firehol_level1"] = is_firehol_level1_ip(ip_address)
        else:
            information["firehol_level1"] = False

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
            zip_codes_path = os.path.join(DATASETS_DIR, DATASETS["Zip-Codes"][1])
            information["postal_code"] = find_zip_code(
                information.get("city"),
                information.get("region_code"),
                zip_codes_path,
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
                DATASETS_DIR, DATASETS["Countries-States-Cities"][1]
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

    if check_missing_information(
        information, ["accuracy_radius"], fields
    ) and not check_missing_information(information, ["latitude", "longitude"], fields):
        information["accuracy_radius"] = 1000

    information = {field: information.get(field) for field in fields}

    return information


def download_datasets() -> None:
    """
    Download the datasets from the URLs in the DATASETS dictionary.
    """
    if not os.path.exists(DATASETS_DIR):
        os.makedirs(DATASETS_DIR)

    for dataset_name, (url, file_name) in DATASETS.items():
        file_path = os.path.join(DATASETS_DIR, file_name)
        if not os.path.exists(file_path):
            print(f"Downloading {dataset_name}...")

            try:
                print(f"Downloading {dataset_name} from {url}...")
                urllib.request.urlretrieve(str(url), file_path)
                print(f"Successfully downloaded {dataset_name} to {file_path}")
            except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
                print(f"Error downloading {dataset_name}: {e}")
