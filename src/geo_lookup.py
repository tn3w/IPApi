#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Geolocation data lookup and processing module.

This module handles geolocation data retrieval and processing for IP addresses,
providing country, region, city, timezone, and other geographic information.
It supports multiple data sources including MaxMind GeoIP databases and
supplementary data for enhanced location details like currencies and timezones.
"""

import json
import csv
import unicodedata
from functools import lru_cache
from typing import Dict, List, Optional, Any, cast, Iterator, Tuple, Union

from redis import Redis
import maxminddb
import maxminddb.errors
import reverse_geocode  # type: ignore


RecordDict = Dict[str, Any]
RecordList = List[Any]
RecordValue = Union[RecordDict, RecordList, str, int, float, bool, None]


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

CONTINENT_NAME_TO_NORMALIZED_NAME: Dict[str, str] = {
    "Northern America": "North America",
    "Southern America": "South America",
}

UNITED_STATES_STATES_TO_CODES: Dict[str, str] = {
    "Alabama": "AL",
    "Alaska": "AK",
    "Arizona": "AZ",
    "Arkansas": "AR",
    "California": "CA",
    "Colorado": "CO",
    "Connecticut": "CT",
    "Delaware": "DE",
    "Florida": "FL",
    "Georgia": "GA",
    "Hawaii": "HI",
    "Idaho": "ID",
    "Illinois": "IL",
    "Indiana": "IN",
    "Iowa": "IA",
    "Kansas": "KS",
    "Kentucky": "KY",
    "Louisiana": "LA",
    "Maine": "ME",
    "Maryland": "MD",
    "Massachusetts": "MA",
    "Michigan": "MI",
    "Minnesota": "MN",
    "Mississippi": "MS",
    "Missouri": "MO",
    "Montana": "MT",
    "Nebraska": "NE",
    "Nevada": "NV",
    "New Hampshire": "NH",
    "New Jersey": "NJ",
    "New Mexico": "NM",
    "New York": "NY",
    "North Carolina": "NC",
    "North Dakota": "ND",
    "Ohio": "OH",
    "Oklahoma": "OK",
    "Oregon": "OR",
    "Pennsylvania": "PA",
    "Rhode Island": "RI",
    "South Carolina": "SC",
    "South Dakota": "SD",
    "Tennessee": "TN",
    "Texas": "TX",
    "Utah": "UT",
    "Vermont": "VT",
    "Virginia": "VA",
    "Washington": "WA",
    "West Virginia": "WV",
    "Wisconsin": "WI",
    "Wyoming": "WY",
}

UNITED_STATES_STATES_TO_TIMEZONE_AND_OFFSET = {
    "AL": ("America/Chicago", -21600),  # Alabama
    "AK": ("America/Anchorage", -32400),  # Alaska
    "AZ": ("America/Phoenix", -25200),  # Arizona
    "AR": ("America/Chicago", -21600),  # Arkansas
    "CA": ("America/Los_Angeles", -28800),  # California
    "CO": ("America/Denver", -25200),  # Colorado
    "CT": ("America/New_York", -18000),  # Connecticut
    "DE": ("America/New_York", -18000),  # Delaware
    "FL": ("America/New_York", -18000),  # Florida
    "GA": ("America/New_York", -18000),  # Georgia
    "HI": ("Pacific/Honolulu", -36000),  # Hawaii
    "ID": ("America/Denver", -25200),  # Idaho
    "IL": ("America/Chicago", -21600),  # Illinois
    "IN": ("America/New_York", -18000),  # Indiana
    "IA": ("America/Chicago", -21600),  # Iowa
    "KS": ("America/Chicago", -21600),  # Kansas
    "KY": ("America/New_York", -18000),  # Kentucky
    "LA": ("America/Chicago", -21600),  # Louisiana
    "ME": ("America/New_York", -18000),  # Maine
    "MD": ("America/New_York", -18000),  # Maryland
    "MA": ("America/New_York", -18000),  # Massachusetts
    "MI": ("America/New_York", -18000),  # Michigan
    "MN": ("America/Chicago", -21600),  # Minnesota
    "MS": ("America/Chicago", -21600),  # Mississippi
    "MO": ("America/Chicago", -21600),  # Missouri
    "MT": ("America/Denver", -25200),  # Montana
    "NE": ("America/Chicago", -21600),  # Nebraska
    "NV": ("America/Los_Angeles", -28800),  # Nevada
    "NH": ("America/New_York", -18000),  # New Hampshire
    "NJ": ("America/New_York", -18000),  # New Jersey
    "NM": ("America/Denver", -25200),  # New Mexico
    "NY": ("America/New_York", -18000),  # New York
    "NC": ("America/New_York", -18000),  # North Carolina
    "ND": ("America/Chicago", -21600),  # North Dakota
    "OH": ("America/New_York", -18000),  # Ohio
    "OK": ("America/Chicago", -21600),  # Oklahoma
    "OR": ("America/Los_Angeles", -28800),  # Oregon
    "PA": ("America/New_York", -18000),  # Pennsylvania
    "RI": ("America/New_York", -18000),  # Rhode Island
    "SC": ("America/New_York", -18000),  # South Carolina
    "SD": ("America/Chicago", -21600),  # South Dakota
    "TN": ("America/Chicago", -21600),  # Tennessee
    "TX": ("America/Chicago", -21600),  # Texas
    "UT": ("America/Denver", -25200),  # Utah
    "VT": ("America/New_York", -18000),  # Vermont
    "VA": ("America/New_York", -18000),  # Virginia
    "WA": ("America/Los_Angeles", -28800),  # Washington
    "WV": ("America/New_York", -18000),  # West Virginia
    "WI": ("America/Chicago", -21600),  # Wisconsin
    "WY": ("America/Denver", -25200),  # Wyoming
}


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


def get_continent_code_from_name(continent_name: str) -> Optional[str]:
    """Get the continent code from the continent name."""
    if not continent_name:
        return None

    return CONTINENT_NAME_TO_CODE.get(continent_name)


def get_normalized_continent_name(continent_name: str) -> Optional[str]:
    """Get the normalized continent name from the continent name."""
    if not continent_name:
        return None

    return CONTINENT_NAME_TO_NORMALIZED_NAME.get(continent_name, continent_name)


def get_us_state_name_and_code(
    state_name: Optional[str], state_code: Optional[str]
) -> Tuple[Optional[str], Optional[str]]:
    """Get the state name and code from the state name or code."""
    if not state_name and not state_code:
        return None, None

    if state_name:
        return (state_name, UNITED_STATES_STATES_TO_CODES.get(state_name))

    if state_code:
        state_name = None
        for name, code in UNITED_STATES_STATES_TO_CODES.items():
            if code == state_code:
                state_name = name
                break
        if state_name:
            return (state_name, state_code)
        return None, None

    return None, None


def get_timezone_and_offset_from_us_state_code(
    state_code: Optional[str],
) -> Tuple[Optional[str], Optional[int]]:
    """
    Get the timezone name and GMT offset for a US state code.

    Args:
        state_code: Two-letter US state code (e.g., 'CA', 'NY')

    Returns:
        Tuple containing (timezone_name, gmt_offset_in_seconds) or (None, None) if not found
    """
    if not state_code:
        return None, None

    state_code = state_code.upper()
    return UNITED_STATES_STATES_TO_TIMEZONE_AND_OFFSET.get(state_code, (None, None))


def process_country_states_cities_database(file_path: str) -> None:
    """
    Process the country-states-cities database from a JSON file.

    Args:
        file_path: Path to the JSON file containing the country-states-cities data
    """

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error loading country database: {e}")
        return

    result: Dict[str, Dict[str, Any]] = {}

    for country in data:
        iso2 = country.get("iso2")
        if not iso2:
            continue

        region = country.get("region", "")
        subregion = country.get("subregion", "")

        if region and region in CONTINENT_NAME_TO_CODE:
            processed_region = region
        elif subregion in CONTINENT_NAME_TO_NORMALIZED_NAME:
            processed_region = get_normalized_continent_name(subregion)
        else:
            processed_region = region

        timezones = country.get("timezones", [])
        timezone: Dict[str, Any] = {}
        if timezones and len(timezones) > 0:
            first_timezone = timezones[0]
            timezone = {
                "name": first_timezone.get("zoneName", ""),
                "offset": first_timezone.get("gmtOffset", 0),
            }

        processed_states: List[Dict[str, Any]] = []
        for state in country.get("states", []):
            processed_cities: List[str] = []

            for city in state.get("cities", []):
                city_name = city.get("name", "")
                if city_name:
                    normalized_name = unicodedata.normalize("NFKD", city_name)  # type: ignore
                    normalized_name = "".join(
                        [c for c in normalized_name if not unicodedata.combining(c)]
                    )  # type: ignore
                    processed_cities.append(normalized_name)

            processed_states.append(
                {
                    "name": state.get("name", ""),
                    "state_code": state.get("state_code", ""),
                    "cities": processed_cities,
                }
            )

        result[iso2] = {
            "name": country.get("name", ""),
            "region": processed_region,
            "timezone": timezone,
            "states": processed_states,
        }

    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(result, file, ensure_ascii=False)


@lru_cache(maxsize=1000)
def get_country_states_cities_data(
    country_code: Optional[str],
    country_data_path: str,
    city: Optional[str] = None,
    region: Optional[str] = None,
    region_code: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Get additional country, region, and timezone data based on country code.

    Args:
        country_code: ISO country code
        country_data_path: Path to the processed country-states-cities JSON file
        city: City name (optional)
        region: Region name (optional)
        region_code: Region code (optional)

    Returns:
        Dictionary with geographic information
    """
    country_info: Dict[str, Any] = {}

    if not country_code:
        return country_info

    try:
        with open(country_data_path, "r", encoding="utf-8") as file:
            countries_data = json.load(file)
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error loading country database: {e}")
        return country_info

    country_data = countries_data.get(country_code)

    if not country_data:
        return country_info

    country_info["country"] = country_data.get("name", "")
    country_info["country_code"] = country_code
    country_info["continent"] = country_data.get("region", "")

    timezone_info = country_data.get("timezone", {})
    if timezone_info:
        country_info["timezone"] = timezone_info.get("name", "")
        country_info["offset"] = timezone_info.get("offset", 0)

    states = country_data.get("states", [])

    if city and not region and not region_code:
        for state in states:
            if state.get("name") == city:
                country_info["region"] = state.get("name", "")
                country_info["region_code"] = state.get("state_code", "")
                break

            cities = state.get("cities", [])
            if any(c.lower() == city.lower() for c in cities):
                country_info["region"] = state.get("name", "")
                country_info["region_code"] = state.get("state_code", "")
                break

    elif region_code and not region:
        for state in states:
            if state.get("state_code") == region_code:
                country_info["region"] = state.get("name", "")
                break

    elif region and not region_code and not city:
        for state in states:
            if state.get("name") == region:
                country_info["region_code"] = state.get("state_code", "")
                break

    return country_info


def process_zip_codes_database(file_path: str) -> None:
    """
    Process ZIP codes CSV data and convert it to a more efficient JSON format for lookups.

    Args:
        file_path: Path to save the processed JSON data
    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            csv_reader: Iterator[List[str]] = csv.reader(file)  # type: ignore
            csv_reader = cast(Iterator[List[str]], csv_reader)

            next(csv_reader, None)

            zip_codes_data: Dict[str, str] = {}

            for row in csv_reader:
                if len(row) < 4:
                    continue

                zip_code = row[0].strip()
                city = row[2].strip()
                state = row[3].strip()

                if not city or not state:
                    continue

                city_upper = city.upper()
                state_upper = state.upper()
                key = f"{city_upper}|{state_upper}"

                if key not in zip_codes_data or (
                    len(zip_code) < len(zip_codes_data[key])
                ):
                    zip_codes_data[key] = zip_code

        with open(file_path, "w", encoding="utf-8") as json_file:
            json.dump(zip_codes_data, json_file, ensure_ascii=False)

        print(f"Successfully processed ZIP codes data to {file_path}")

    except (IOError, json.JSONDecodeError, csv.Error, OSError) as e:
        print(f"Error processing ZIP codes data: {e}")


@lru_cache(maxsize=1000)
def find_zip_code(
    city: str, state_code: str, zip_codes_data_path: str
) -> Optional[str]:
    """
    Find a ZIP code for a given city and state using the processed ZIP codes data.

    Args:
        city: Name of the city
        state_code: State code (2-letter abbreviation like CA, NY)
        zip_codes_data_path: Path to the processed ZIP codes JSON file

    Returns:
        ZIP code as a string, or None if not found
    """
    if not city:
        return None

    try:
        with open(zip_codes_data_path, "r", encoding="utf-8") as file:
            zip_codes_data = json.load(file)
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error loading ZIP codes data: {e}")
        return None

    city_upper = city.strip().upper()

    if state_code:
        state_upper = state_code.strip().upper()
        key = f"{city_upper}|{state_upper}"

        if key in zip_codes_data:
            return zip_codes_data[key]

    for key, zip_code in zip_codes_data.items():
        city_part = key.split("|")[0]
        if city_part == city_upper:
            return zip_code

    for key, zip_code in zip_codes_data.items():
        city_part, state_part = key.split("|")
        if city_upper in city_part:
            if state_code and state_code.strip().upper() != state_part:
                continue

            return zip_code

    return None


def get_geocoder_data(
    coordinates: Tuple[float, float], redis: Optional[Redis] = None
) -> Dict[str, str]:
    """
    Get geocoder data for a given set of coordinates.
    """

    if redis:
        cache_key = f"geocoder:{coordinates}"
        cached_data = redis.get(cache_key)
        if cached_data:
            return json.loads(cached_data)  # type: ignore

    result = reverse_geocode.search([coordinates])[0]  # type: ignore
    result = cast(Dict[str, str], result)

    result["region"] = result.get("state", "")
    for key in ["state", "population", "latitude", "longitude"]:
        try:
            result.pop(key)
        except KeyError:
            pass

    if redis:
        cache_key = f"geocoder:{coordinates}"
        redis.set(cache_key, json.dumps(result), ex=86400)

    return result


def get_geo_from_maxmind(ip_address: str, database_path: str) -> Dict[str, Any]:
    """Get detailed geolocation information for an IP address.

    Args:
        ip_address: The IP address to look up

    Returns:
        Dictionary with geolocation information
    """

    geo_info: Dict[str, Any] = {}

    try:
        with maxminddb.open_database(database_path) as reader:  # type: ignore
            result = reader.get(ip_address)  # type: ignore
            if not result:
                return geo_info

            record = cast(RecordDict, result)

            def get_nested(d: RecordValue, *keys: str, default: Any = None) -> Any:
                """Safely get a nested value from a dictionary."""
                current = d
                for key in keys:
                    if not isinstance(current, dict) or key not in current:
                        return default
                    current = current[key]
                return current

            country = get_nested(record, "country", "names", "en")
            if country:
                geo_info["country"] = country
                geo_info["country_code"] = get_nested(record, "country", "iso_code")
            else:
                registered_country = get_nested(
                    record, "registered_country", "names", "en"
                )
                if registered_country:
                    geo_info["country"] = registered_country
                    geo_info["country_code"] = get_nested(
                        record, "registered_country", "iso_code"
                    )

            geo_info["continent"] = get_nested(record, "continent", "names", "en")
            geo_info["continent_code"] = get_nested(record, "continent", "code")

            subdivisions = get_nested(record, "subdivisions")
            if isinstance(subdivisions, list) and subdivisions:
                subdivision = cast(RecordDict, subdivisions[0])
                geo_info["region"] = get_nested(subdivision, "names", "en")
                region_code = get_nested(subdivision, "iso_code")
                if region_code and region_code != "0":
                    geo_info["region_code"] = region_code

            geo_info["city"] = get_nested(record, "city", "names", "en")
            geo_info["postal_code"] = get_nested(record, "postal", "code")

            location = get_nested(record, "location")
            if location:
                geo_info["latitude"] = get_nested(location, "latitude")
                geo_info["longitude"] = get_nested(location, "longitude")
                geo_info["timezone"] = get_nested(location, "time_zone")
                geo_info["accuracy_radius"] = get_nested(location, "accuracy_radius")

            return geo_info

    except (
        maxminddb.errors.InvalidDatabaseError,
        FileNotFoundError,
        PermissionError,
        ValueError,
    ) as exc:
        print(f"Error looking up geo information: {exc}")
        return geo_info
