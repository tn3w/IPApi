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
from typing import Optional, Dict, Any, List, Union, Tuple

from fastapi import Request
from redis import Redis
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
from src.asn_lookup import (
    get_abuse_contact,
    get_rpki_validity,
    get_asn_from_maxmind,
)
from src.ip_whois import ip_whois_pwhois, ip_whois
from src.dns_lookup import get_dns_info, get_ipv4_from_ipv6
from src.abuse_lookup import (
    process_tor_exit_nodes_database,
    is_tor_exit_node,
    process_nordvpn_servers_database,
    process_sudesh0sudesh_servers_database,
    process_pia_servers_database,
    process_cyberghost_servers_database,
    process_mullvad_servers_database,
    is_vpn_server,
    download_surfshark_hostnames_database,
    process_firehol_proxies_database,
    is_proxy_server,
    # process_awesome_lists_proxies_database,
    process_data_center_asns_database,
    is_data_center_asn,
)


DATASETS_DIR = "assets"
DATASETS: Dict[str, Union[str, Tuple[Union[str, list[str]], str]]] = {
    # Geolocation
    "GeoLite2-ASN": ("https://git.io/GeoLite2-ASN.mmdb", "GeoLite2-ASN.mmdb"),
    "GeoLite2-City": ("https://git.io/GeoLite2-City.mmdb", "GeoLite2-City.mmdb"),
    "Country-States-Cities": (
        (
            "https://raw.githubusercontent.com/dr5hn/"
            "countries-states-cities-database/refs/heads/master/"
            "json/countries%2Bstates%2Bcities.json"
        ),
        "countries-states-cities.json",
    ),
    "Zip-Codes": (
        (
            "https://raw.githubusercontent.com/wouterdebie/"
            "zip_codes_plus/refs/heads/main/data/zip_codes.csv"
        ),
        "zip-codes.json",
    ),
    "Tor-Exit-Nodes": (
        "https://onionoo.torproject.org/details?flag=exit",
        "tor-exit-nodes.json",
    ),
    # Abuse: VPN Servers
    "NordVPN-Servers": (
        "https://api.nordvpn.com/v1/servers?limit=10000",
        "nordvpn-servers.json",
    ),
    "ProtonVPN-Servers": (
        (
            "https://raw.githubusercontent.com/tn3w/ProtonVPN-IPs/"
            "refs/heads/master/protonvpn_ips.json"
        ),
        "protonvpn-servers.json",
    ),
    "ExpressVPN-Servers": (
        (
            "https://raw.githubusercontent.com/sudesh0sudesh/ExpressVPN-IPs/"
            "refs/heads/main/express_ips.csv"
        ),
        "expressvpn-servers.json",
    ),
    "Surfshark-Servers": (
        (
            "https://raw.githubusercontent.com/sudesh0sudesh/surfshark-IPs/"
            "refs/heads/main/surfshark_ips.csv"
        ),
        "surfshark-servers.json",
    ),
    "Surfshark-Hostnames": (
        "https://surfshark.com/api/v1/server/configurations",
        "surfshark-by-hostname.json",
    ),
    "Private-Internet-Access-Servers": (
        "https://serverlist.piaservers.net/vpninfo/servers/v6",
        "pia-servers.json",
    ),
    "CyberGhost-Servers": (
        (
            "https://gist.githubusercontent.com/Windows81/17e75698d4fe349bcfb71d1c1ca537d4/"
            "raw/88713feecd901acaa03b3805b7ac1ab19ada73b2/.txt"
        ),
        "cyberghost-servers.json",
    ),
    "TunnelBear-Servers": (
        (
            "https://raw.githubusercontent.com/tn3w/TunnelBear-IPs/"
            "refs/heads/master/tunnelbear_ips.json"
        ),
        "tunnelbear-servers.json",
    ),
    "Mullvad": (
        "https://api.mullvad.net/www/relays/all",
        "mullvad-servers.json",
    ),
    # Abuse: Proxy Servers
    "Firehol-Proxies": (
        "https://iplists.firehol.org/files/firehol_proxies.netset",
        "firehol_proxies.json",
    ),
    # "Awesome-Lists-Proxies": (
    #     (
    #         "https://raw.githubusercontent.com/mthcht/awesome-lists/"
    #         "refs/heads/main/Lists/PROXY/ALL_PROXY_Lists.csv"
    #     ),
    #     "awesome-lists-proxies.json",
    # )
    # Abuse: Data Center
    "Data-Center-ASNS": (
        (
            "https://raw.githubusercontent.com/brianhama/bad-asn-list/"
            "refs/heads/master/bad-asn-list.csv"
        ),
        "data-center-asns.json",
    ),
}


def get_parsed_file_path(file_path: str) -> str:
    """
    Get the parsed file path for the given file path.
    """
    return file_path.replace(".json", ".parsed.json").replace(".csv", ".parsed.csv")


VPN_SERVERS_FILES = (
    (
        "NordVPN",
        get_parsed_file_path(
            os.path.join(DATASETS_DIR, DATASETS["NordVPN-Servers"][1])
        ),
    ),
    (
        "ProtonVPN",
        os.path.join(DATASETS_DIR, DATASETS["ProtonVPN-Servers"][1]),
    ),
    (
        "TunnelBear",
        os.path.join(DATASETS_DIR, DATASETS["TunnelBear-Servers"][1]),
    ),
    (
        "ExpressVPN",
        get_parsed_file_path(
            os.path.join(DATASETS_DIR, DATASETS["ExpressVPN-Servers"][1])
        ),
    ),
    (
        "Surfshark",
        get_parsed_file_path(
            os.path.join(DATASETS_DIR, DATASETS["Surfshark-Servers"][1])
        ),
    ),
    (
        "Surfshark",
        os.path.join(DATASETS_DIR, DATASETS["Surfshark-Hostnames"][1]),
    ),
    (
        "Private Internet Access",
        get_parsed_file_path(
            os.path.join(DATASETS_DIR, DATASETS["Private-Internet-Access-Servers"][1])
        ),
    ),
    (
        "CyberGhost",
        get_parsed_file_path(
            os.path.join(DATASETS_DIR, DATASETS["CyberGhost-Servers"][1])
        ),
    ),
    (
        "Mullvad",
        get_parsed_file_path(os.path.join(DATASETS_DIR, DATASETS["Mullvad"][1])),
    ),
)


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

    if "tor_exit_node" in fields:
        tor_nodes_file = os.path.join(DATASETS_DIR, DATASETS["Tor-Exit-Nodes"][1])
        information["tor_exit_node"] = is_tor_exit_node(
            ip_address, get_parsed_file_path(tor_nodes_file)
        )

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

    if check_missing_information(information, ["vpn", "vpn_name"], fields):
        vpn_name = is_vpn_server(ip_address, VPN_SERVERS_FILES)

        information["vpn"] = bool(vpn_name)
        information["vpn_name"] = vpn_name

    if "proxy" in fields:
        information["proxy"] = is_proxy_server(
            ip_address,
            (
                get_parsed_file_path(
                    os.path.join(DATASETS_DIR, DATASETS["Firehol-Proxies"][1])
                ),
            ),
        )

    if "hostname" in fields:
        hostname = get_dns_info(ip_address)
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
            information["data_center"] = is_data_center_asn(
                str(information["asn"]),
                get_parsed_file_path(
                    os.path.join(DATASETS_DIR, DATASETS["Data-Center-ASNS"][1])
                ),
            )
        else:
            information["data_center"] = False

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
                information.get("city"),
                information.get("region_code"),
                get_parsed_file_path(zip_codes_path),
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
                    get_parsed_file_path(country_states_cities_path),
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

    if check_missing_information(information, ["accuracy_radius"], fields):
        information["accuracy_radius"] = 1000

    information = {field: information.get(field) for field in fields}

    return information


def download_and_process_datasets() -> None:
    """
    Download and process the datasets.
    """
    for dataset_name, (dataset_url, dataset_filename) in DATASETS.items():
        file_path = os.path.join(DATASETS_DIR, dataset_filename)
        if (
            not os.path.exists(get_parsed_file_path(file_path))
            and not "Surfshark-Hostnames" in dataset_name
        ):
            download_file(dataset_url, file_path, dataset_name)

    standard_processors = {
        "Country-States-Cities": process_country_states_cities_database,
        "Zip-Codes": process_zip_codes_database,
        "Tor-Exit-Nodes": process_tor_exit_nodes_database,
        "NordVPN-Servers": process_nordvpn_servers_database,
        "ExpressVPN-Servers": process_sudesh0sudesh_servers_database,
        "Surfshark-Servers": process_sudesh0sudesh_servers_database,
        "Private-Internet-Access-Servers": process_pia_servers_database,
        "CyberGhost-Servers": process_cyberghost_servers_database,
        "Mullvad": process_mullvad_servers_database,
        "Firehol-Proxies": process_firehol_proxies_database,
        # "Awesome-Lists-Proxies": process_awesome_lists_proxies_database,
        "Data-Center-ASNS": process_data_center_asns_database,
    }

    for dataset_key, processor_func in standard_processors.items():
        file_path = os.path.join(DATASETS_DIR, DATASETS[dataset_key][1])
        if not os.path.exists(get_parsed_file_path(file_path)):
            print(f"Processing {dataset_key.lower()} database...")
            processor_func(file_path)
            os.rename(file_path, get_parsed_file_path(file_path))

    file_path = os.path.join(DATASETS_DIR, DATASETS["Surfshark-Hostnames"][1])
    if not os.path.exists(file_path):
        print("Processing surfshark by hostname database...")
        if not isinstance(DATASETS["Surfshark-Hostnames"][0], list):
            download_surfshark_hostnames_database(
                DATASETS["Surfshark-Hostnames"][0], file_path
            )
