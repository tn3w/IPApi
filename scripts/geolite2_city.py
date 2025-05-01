#!/usr/bin/env python3
#
# Requirements:
#   pip install "maxminddb>=2.6.3" "reverse-geocode>=1.6.5"
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
import json
import argparse
import urllib.request
from typing import Optional, Dict, Any, cast, TypedDict
from dataclasses import dataclass

import maxminddb
import reverse_geocode  # type: ignore


GEOLITE2_URL = "https://git.io/GeoLite2-City.mmdb"
DATABASE_DIR = "test"
DATABASE_PATH = os.path.join(DATABASE_DIR, "GeoLite2-City.mmdb")
COUNTRIES_DATA_URL = (
    "https://raw.githubusercontent.com/dr5hn/"
    "countries-states-cities-database/refs/heads/master/"
    "json/countries%2Bstates%2Bcities.json"
)
COUNTRIES_DATA_PATH = os.path.join(DATABASE_DIR, "countries_states_cities.json")

COUNTRY_TO_CURRENCY_MAP: Dict[str, str] = {
    "AF": "AFN",
    "AL": "ALL",
    "DZ": "DZD",
    "AS": "USD",
    "AD": "EUR",
    "AO": "AOA",
    "AI": "XCD",
    "AQ": "USD",
    "AG": "XCD",
    "AR": "ARS",
    "AM": "AMD",
    "AW": "AWG",
    "AU": "AUD",
    "AT": "EUR",
    "AZ": "AZN",
    "BS": "BSD",
    "BH": "BHD",
    "BD": "BDT",
    "BB": "BBD",
    "BY": "BYR",
    "BE": "EUR",
    "BZ": "BZD",
    "BJ": "XOF",
    "BM": "BMD",
    "BT": "BTN",
    "BO": "BOB",
    "BA": "BAM",
    "BW": "BWP",
    "BV": "NOK",
    "BR": "BRL",
    "IO": "USD",
    "VG": "USD",
    "BN": "BND",
    "BG": "BGN",
    "BF": "XOF",
    "BI": "BIF",
    "KH": "KHR",
    "CM": "XAF",
    "CA": "CAD",
    "CV": "CVE",
    "KY": "KYD",
    "CF": "XAF",
    "TD": "XAF",
    "CL": "CLP",
    "CN": "CNY",
    "CX": "AUD",
    "CC": "AUD",
    "CO": "COP",
    "KM": "KMF",
    "CK": "NZD",
    "CR": "CRC",
    "HR": "HRK",
    "CU": "CUP",
    "CY": "CYP",
    "CZ": "CZK",
    "CD": "CDF",
    "DK": "DKK",
    "DJ": "DJF",
    "DM": "XCD",
    "DO": "DOP",
    "TL": "USD",
    "EC": "USD",
    "EG": "EGP",
    "SV": "SVC",
    "GQ": "XAF",
    "ER": "ERN",
    "EE": "EEK",
    "ET": "ETB",
    "FK": "FKP",
    "FO": "DKK",
    "FJ": "FJD",
    "FI": "EUR",
    "FR": "EUR",
    "GF": "EUR",
    "PF": "XPF",
    "TF": "EUR",
    "GA": "XAF",
    "GM": "GMD",
    "GE": "GEL",
    "DE": "EUR",
    "GH": "GHC",
    "GI": "GIP",
    "GR": "EUR",
    "GL": "DKK",
    "GD": "XCD",
    "GP": "EUR",
    "GU": "USD",
    "GT": "GTQ",
    "GN": "GNF",
    "GW": "XOF",
    "GY": "GYD",
    "HT": "HTG",
    "HM": "AUD",
    "HN": "HNL",
    "HK": "HKD",
    "HU": "HUF",
    "IS": "ISK",
    "IN": "INR",
    "ID": "IDR",
    "IR": "IRR",
    "IQ": "IQD",
    "IE": "EUR",
    "IL": "ILS",
    "IT": "EUR",
    "CI": "XOF",
    "JM": "JMD",
    "JP": "JPY",
    "JO": "JOD",
    "KZ": "KZT",
    "KE": "KES",
    "KI": "AUD",
    "KW": "KWD",
    "KG": "KGS",
    "LA": "LAK",
    "LV": "LVL",
    "LB": "LBP",
    "LS": "LSL",
    "LR": "LRD",
    "LY": "LYD",
    "LI": "CHF",
    "LT": "LTL",
    "LU": "EUR",
    "MO": "MOP",
    "MK": "MKD",
    "MG": "MGA",
    "MW": "MWK",
    "MY": "MYR",
    "MV": "MVR",
    "ML": "XOF",
    "MT": "MTL",
    "MH": "USD",
    "MQ": "EUR",
    "MR": "MRO",
    "MU": "MUR",
    "YT": "EUR",
    "MX": "MXN",
    "FM": "USD",
    "MD": "MDL",
    "MC": "EUR",
    "MN": "MNT",
    "MS": "XCD",
    "MA": "MAD",
    "MZ": "MZN",
    "MM": "MMK",
    "NA": "NAD",
    "NR": "AUD",
    "NP": "NPR",
    "NL": "EUR",
    "AN": "ANG",
    "NC": "XPF",
    "NZ": "NZD",
    "NI": "NIO",
    "NE": "XOF",
    "NG": "NGN",
    "NU": "NZD",
    "NF": "AUD",
    "KP": "KPW",
    "MP": "USD",
    "NO": "NOK",
    "OM": "OMR",
    "PK": "PKR",
    "PW": "USD",
    "PS": "ILS",
    "PA": "PAB",
    "PG": "PGK",
    "PY": "PYG",
    "PE": "PEN",
    "PH": "PHP",
    "PN": "NZD",
    "PL": "PLN",
    "PT": "EUR",
    "PR": "USD",
    "QA": "QAR",
    "CG": "XAF",
    "RE": "EUR",
    "RO": "RON",
    "RU": "RUB",
    "RW": "RWF",
    "SH": "SHP",
    "KN": "XCD",
    "LC": "XCD",
    "PM": "EUR",
    "VC": "XCD",
    "WS": "WST",
    "SM": "EUR",
    "ST": "STD",
    "SA": "SAR",
    "SN": "XOF",
    "CS": "RSD",
    "SC": "SCR",
    "SL": "SLL",
    "SG": "SGD",
    "SK": "SKK",
    "SI": "EUR",
    "SB": "SBD",
    "SO": "SOS",
    "ZA": "ZAR",
    "GS": "GBP",
    "KR": "KRW",
    "ES": "EUR",
    "LK": "LKR",
    "SD": "SDD",
    "SR": "SRD",
    "SJ": "NOK",
    "SZ": "SZL",
    "SE": "SEK",
    "CH": "CHF",
    "SY": "SYP",
    "TW": "TWD",
    "TJ": "TJS",
    "TZ": "TZS",
    "TH": "THB",
    "TG": "XOF",
    "TK": "NZD",
    "TO": "TOP",
    "TT": "TTD",
    "TN": "TND",
    "TR": "TRY",
    "TM": "TMM",
    "TC": "USD",
    "TV": "AUD",
    "VI": "USD",
    "UG": "UGX",
    "UA": "UAH",
    "AE": "AED",
    "GB": "GBP",
    "US": "USD",
    "UM": "USD",
    "UY": "UYU",
    "UZ": "UZS",
    "VU": "VUV",
    "VA": "EUR",
    "VE": "VEF",
    "VN": "VND",
    "WF": "XPF",
    "EH": "MAD",
    "YE": "YER",
    "ZM": "ZMK",
    "ZW": "ZWD",
}

EU_COUNTRY_CODES: set[str] = {
    "AT",  # Austria
    "BE",  # Belgium
    "BG",  # Bulgaria
    "HR",  # Croatia
    "CY",  # Cyprus
    "CZ",  # Czech Republic
    "DK",  # Denmark
    "EE",  # Estonia
    "FI",  # Finland
    "FR",  # France
    "DE",  # Germany
    "GR",  # Greece
    "HU",  # Hungary
    "IE",  # Ireland
    "IT",  # Italy
    "LV",  # Latvia
    "LT",  # Lithuania
    "LU",  # Luxembourg
    "MT",  # Malta
    "NL",  # Netherlands
    "PL",  # Poland
    "PT",  # Portugal
    "RO",  # Romania
    "SK",  # Slovakia
    "SI",  # Slovenia
    "ES",  # Spain
    "SE",  # Sweden
}

CONTINENT_NAME_TO_CODE: Dict[str, str] = {
    "Africa": "AF",
    "Antarctica": "AN",
    "Asia": "AS",
    "Europe": "EU",
    "North America": "NA",
    "Oceania": "OC",
    "South America": "SA",
}


@dataclass
class GeoIPInformation:
    """Class to store GeoIP information."""

    ip: str
    continent: Optional[str] = None
    continent_code: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    is_in_european_union: Optional[bool] = None
    currency: Optional[str] = None
    region: Optional[str] = None
    region_code: Optional[str] = None
    city: Optional[str] = None
    postal_code: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    accuracy_radius: Optional[int] = None
    response_time_ms: Optional[float] = None


class RegionData(TypedDict):
    """Class to store region data."""

    name: str
    code: str
    latitude: str
    longitude: str
    cities: Dict[str, Dict[str, Any]]


@dataclass
class CountryData:
    """Class to store country data."""

    name: str
    iso2: str
    iso3: str
    region: str
    subregion: str
    currency: str
    regions: Dict[str, RegionData]


RecordDict = Dict[str, Any]


def download_database() -> bool:
    """Download the GeoLite2 City database."""
    if os.path.exists(DATABASE_PATH):
        return True

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


def get_currency_from_country(country_code: str) -> Optional[str]:
    """Get the currency from the country code."""
    if not country_code:
        return None

    return COUNTRY_TO_CURRENCY_MAP.get(country_code)


def is_country_in_european_union(country_code: str) -> bool:
    """Check if a country is in the European Union based on its ISO code."""
    if not country_code:
        return False

    return country_code.upper() in EU_COUNTRY_CODES


def download_countries_data() -> bool:
    """Download countries, states, and cities data."""
    if os.path.exists(COUNTRIES_DATA_PATH):
        return True

    if not os.path.exists(DATABASE_DIR):
        os.makedirs(DATABASE_DIR)

    try:
        print(f"Downloading countries data from {COUNTRIES_DATA_URL}...")
        urllib.request.urlretrieve(COUNTRIES_DATA_URL, COUNTRIES_DATA_PATH)
        print(f"Successfully downloaded countries data to {COUNTRIES_DATA_PATH}")
        return True
    except Exception as e:
        print(f"Error downloading countries data: {e}")
        return False


def load_countries_data() -> Dict[str, CountryData]:
    """Load countries data from file or download if not exists."""
    if not os.path.exists(COUNTRIES_DATA_PATH):
        print("Countries data not found. Downloading it now...")
        if not download_countries_data():
            print("Failed to download countries data.")
            return {}

    try:
        with open(COUNTRIES_DATA_PATH, "r", encoding="utf-8") as f:
            countries_json = json.load(f)

        countries_data: Dict[str, CountryData] = {}
        for country in countries_json:
            country_code = country.get("iso2", "")
            if not country_code:
                continue

            regions_data: Dict[str, RegionData] = {}
            for region in country.get("states", []):
                region_code = region.get("state_code", "")
                if not region_code:
                    continue

                regions_data[region_code] = {
                    "name": region.get("name", ""),
                    "code": region_code,
                    "latitude": region.get("latitude", ""),
                    "longitude": region.get("longitude", ""),
                    "cities": {
                        city.get("name", ""): city for city in region.get("cities", [])
                    },
                }

            countries_data[country_code] = CountryData(
                name=country.get("name", ""),
                iso2=country_code,
                iso3=country.get("iso3", ""),
                region=country.get("region", ""),
                subregion=country.get("subregion", ""),
                currency=country.get("currency", ""),
                regions=regions_data,
            )

        return countries_data
    except Exception as e:
        print(f"Error loading countries data: {e}")
        return {}


def get_countries_data() -> Dict[str, CountryData]:
    """Get countries data with caching using closure instead of global variable."""
    cache: Dict[str, Optional[Dict[str, CountryData]]] = {"data": None}

    def get_data() -> Dict[str, CountryData]:
        if cache["data"] is None:
            cache["data"] = load_countries_data()
        return cache["data"] or {}

    return get_data()


def fill_country_continent_data(geoip_info: GeoIPInformation) -> None:
    """Fill country, continent, and region data using the downloaded dataset."""
    if not geoip_info.country_code:
        return

    countries_data = get_countries_data()
    country_code = geoip_info.country_code

    if country_code not in countries_data:
        return

    country_data = countries_data[country_code]

    if not geoip_info.country:
        geoip_info.country = country_data.name

    if not geoip_info.continent:
        geoip_info.continent = country_data.region

    # Set continent code if we have the continent name but not the code
    if geoip_info.continent and not geoip_info.continent_code:
        geoip_info.continent_code = CONTINENT_NAME_TO_CODE.get(geoip_info.continent)

    if not geoip_info.currency:
        geoip_info.currency = country_data.currency

    if geoip_info.city and not geoip_info.region:
        city_name = geoip_info.city

        for region_code, region_data in country_data.regions.items():
            for city_key in region_data["cities"]:
                if city_name.lower() in city_key.lower():
                    geoip_info.region = region_data["name"]
                    geoip_info.region_code = region_code
                    break

            if geoip_info.region:
                break


def get_geoip_information(ip_address: str) -> GeoIPInformation:
    """Get detailed geolocation information for an IP address."""
    if not database_exists():
        print("Database not found. Please run with -d option to download it first.")
        return GeoIPInformation(ip=ip_address)

    start_time = time.time()

    try:
        with maxminddb.open_database(DATABASE_PATH) as reader:  # type: ignore
            result = reader.get(ip_address)  # type: ignore
            if not result:
                return GeoIPInformation(ip=ip_address)

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

            geoip_info.is_in_european_union = get_nested(
                record, "country", "is_in_european_union"
            )
            if not geoip_info.is_in_european_union and geoip_info.country_code:
                geoip_info.is_in_european_union = is_country_in_european_union(
                    geoip_info.country_code
                )

            if geoip_info.country_code:
                geoip_info.currency = get_currency_from_country(geoip_info.country_code)

            subdivisions = get_nested(record, "subdivisions")
            if subdivisions and len(subdivisions) > 0:
                geoip_info.region = get_nested(subdivisions[0], "names", "en")
                region_code = get_nested(subdivisions[0], "iso_code")
                if region_code and region_code != "0":
                    geoip_info.region_code = region_code

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
        return GeoIPInformation(ip=ip_address)


def fill_empty_fields_with_geocoder(geoip_info: GeoIPInformation) -> None:
    """Fill in empty fields in the GeoIP information using reverse geocoding."""
    try:
        if not (geoip_info.latitude and geoip_info.longitude):
            return

        coordinates = [(geoip_info.latitude, geoip_info.longitude)]
        result: Dict[str, str] = reverse_geocode.search(coordinates)[0]  # type: ignore

        if not geoip_info.country:
            country = result.get("country", "")  # type: ignore
            geoip_info.country = country

        if not geoip_info.country_code:
            country_code: str | None = result.get("country_code", "")  # type: ignore
            if isinstance(country_code, str):
                geoip_info.country_code = country_code

            if geoip_info.country_code:
                if geoip_info.is_in_european_union is None:
                    geoip_info.is_in_european_union = is_country_in_european_union(
                        geoip_info.country_code
                    )
                    if not geoip_info.currency:
                        geoip_info.currency = get_currency_from_country(
                            geoip_info.country_code
                        )

        if not geoip_info.city:
            city = result.get("city", "")  # type: ignore
            geoip_info.city = city

    except ImportError:
        print("Warning: reverse_geocode package not found.")
    except Exception as e:
        print(f"Error during reverse geocoding: {e}")


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
    group.add_argument(
        "-c",
        "--download-countries",
        action="store_true",
        help="Download/update the countries data",
    )

    args = parser.parse_args()

    if args.download:
        download_database()
        return

    if args.download_countries:
        download_countries_data()
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
            print("\n~-~ GeoIP Information: ~-~")
            for key, value in geoip_info.__dict__.items():
                key = key.replace("_", " ").capitalize()
                if value is None:
                    value = "N/A"
                print(f"{key}: {value}")
        else:
            print("Failed to retrieve GeoIP information")


if __name__ == "__main__":
    main()
