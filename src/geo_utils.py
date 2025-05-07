import json
import os
import unicodedata
from typing import Dict, List, Optional, Any, cast, Iterator, Tuple

import csv

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


# Country-States-Cities database
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


def enhance_with_country_data(
    data_dict: Dict[str, Any], country_data_path: str
) -> Dict[str, Any]:
    """
    Enhance the provided dictionary with country, region, and timezone data based on country code.

    Args:
        data_dict: Dictionary containing at least a country_code key
        country_data_path: Path to the processed country-states-cities JSON file

    Returns:
        Enhanced dictionary with additional geographic information
    """
    if not data_dict.get("country_code"):
        return data_dict

    result = data_dict.copy()

    try:
        with open(country_data_path, "r", encoding="utf-8") as file:
            countries_data = json.load(file)
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error loading country database: {e}")
        return result

    country_code = result.get("country_code", "")
    country_info = countries_data.get(country_code)

    if not country_info:
        return result

    if not result.get("country"):
        result["country"] = country_info.get("name", "")

    if not result.get("continent"):
        result["continent"] = country_info.get("region", "")

    timezone_info = country_info.get("timezone", {})
    if timezone_info:
        if not result.get("timezone"):
            result["timezone"] = timezone_info.get("name", "")
        if not result.get("offset"):
            result["offset"] = timezone_info.get("offset", 0)

    states = country_info.get("states", [])

    if (
        result.get("city")
        and not result.get("region")
        and not result.get("region_code")
    ):
        city_name = result.get("city", "")
        for state in states:
            if state.get("name") == city_name:
                result["region"] = state.get("name", "")
                result["region_code"] = state.get("state_code", "")
                break

            cities = state.get("cities", [])
            if any(city.lower() == city_name.lower() for city in cities):
                result["region"] = state.get("name", "")
                result["region_code"] = state.get("state_code", "")
                break

    elif result.get("region_code") and not result.get("region"):
        region_code = result.get("region_code", "")
        for state in states:
            if state.get("state_code") == region_code:
                result["region"] = state.get("name", "")
                break

    elif (
        result.get("region")
        and not result.get("region_code")
        and not result.get("city")
    ):
        region_name = result.get("region", "")
        for state in states:
            if state.get("name") == region_name:
                result["region_code"] = state.get("state_code", "")
                break

    if result.get("country_code") == "US":
        result["region"], result["region_code"] = get_us_state_name_and_code(
            result.get("region"), result.get("region_code")
        )

    return result


def process_zip_codes_database(csv_file_path: str, json_file_path: str) -> None:
    """
    Process ZIP codes CSV data and convert it to a more efficient JSON format for lookups.

    Args:
        csv_file_path: Path to the ZIP codes CSV file
        json_file_path: Path to save the processed JSON data
    """
    try:
        with open(csv_file_path, "r", encoding="utf-8") as file:
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

        with open(json_file_path, "w", encoding="utf-8") as json_file:
            json.dump(zip_codes_data, json_file, ensure_ascii=False)

        os.remove(csv_file_path)

        print(f"Successfully processed ZIP codes data to {json_file_path}")

    except Exception as e:
        print(f"Error processing ZIP codes data: {e}")


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
