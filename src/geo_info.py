import math
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Final, Dict, Any, List, Optional
import logging

import pytz
from timezonefinder import TimezoneFinder
import pgeocode
import pandas as pd
import numpy as np

from src.utils import key_or_value_search

logger = logging.getLogger(__name__)


TIMEZONE_FINDER: Final[TimezoneFinder] = TimezoneFinder()

COUNTRY_CODE_TO_NAME: Final[Dict[str, str]] = {
    "AF": "Afghanistan", "AL": "Albania", "DZ": "Algeria",
    "AS": "American Samoa", "AD": "Andorra", "AO": "Angola", "AI": "Anguilla",
    "AQ": "Antarctica", "AG": "Antigua and Barbuda", "AR": "Argentina",
    "AM": "Armenia", "AW": "Aruba", "AU": "Australia", "AT": "Austria",
    "AZ": "Azerbaijan", "BS": "Bahamas", "BH": "Bahrain", "BD": "Bangladesh",
    "BB": "Barbados", "BY": "Belarus", "BE": "Belgium", "BZ": "Belize",
    "BJ": "Benin", "BM": "Bermuda", "BT": "Bhutan", "BO": "Bolivia",
    "BA": "Bosnia and Herzegovina", "BW": "Botswana", "BV": "Bouvet Island",
    "BR": "Brazil", "IO": "British Indian Ocean Territory",
    "VG": "British Virgin Islands", "BN": "Brunei", "BG": "Bulgaria",
    "BF": "Burkina Faso", "BI": "Burundi", "KH": "Cambodia", "CM": "Cameroon",
    "CA": "Canada", "CV": "Cape Verde", "KY": "Cayman Islands",
    "CF": "Central African Republic", "TD": "Chad", "CL": "Chile",
    "CN": "China", "CX": "Christmas Island", "CC": "Cocos (Keeling) Islands",
    "CO": "Colombia", "KM": "Comoros", "CK": "Cook Islands", "CR": "Costa Rica",
    "HR": "Croatia", "CU": "Cuba", "CY": "Cyprus", "CZ": "Czech Republic",
    "CD": "Democratic Republic of the Congo", "DK": "Denmark", "DJ": "Djibouti",
    "DM": "Dominica", "DO": "Dominican Republic", "TL": "East Timor",
    "EC": "Ecuador", "EG": "Egypt", "SV": "El Salvador",
    "GQ": "Equatorial Guinea", "ER": "Eritrea", "EE": "Estonia",
    "ET": "Ethiopia", "FK": "Falkland Islands", "FO": "Faroe Islands",
    "FJ": "Fiji", "FI": "Finland", "FR": "France", "GF": "French Guiana",
    "PF": "French Polynesia", "TF": "French Southern Territories",
    "GA": "Gabon", "GM": "Gambia", "GE": "Georgia", "DE": "Germany",
    "GH": "Ghana", "GI": "Gibraltar", "GR": "Greece", "GL": "Greenland",
    "GD": "Grenada", "GP": "Guadeloupe", "GU": "Guam", "GT": "Guatemala",
    "GN": "Guinea", "GW": "Guinea-Bissau", "GY": "Guyana", "HT": "Haiti",
    "HM": "Heard Island and McDonald Islands", "HN": "Honduras",
    "HK": "Hong Kong", "HU": "Hungary", "IS": "Iceland", "IN": "India",
    "ID": "Indonesia", "IR": "Iran", "IQ": "Iraq", "IE": "Ireland",
    "IL": "Israel", "IT": "Italy", "CI": "Ivory Coast", "JM": "Jamaica",
    "JP": "Japan", "JO": "Jordan", "KZ": "Kazakhstan", "KE": "Kenya",
    "KI": "Kiribati", "KW": "Kuwait", "KG": "Kyrgyzstan", "LA": "Laos",
    "LV": "Latvia", "LB": "Lebanon", "LS": "Lesotho", "LR": "Liberia",
    "LY": "Libya", "LI": "Liechtenstein", "LT": "Lithuania", "LU": "Luxembourg",
    "MO": "Macau", "MK": "Macedonia", "MG": "Madagascar", "MW": "Malawi",
    "MY": "Malaysia", "MV": "Maldives", "ML": "Mali", "MT": "Malta",
    "MH": "Marshall Islands", "MQ": "Martinique", "MR": "Mauritania",
    "MU": "Mauritius", "YT": "Mayotte", "MX": "Mexico", "FM": "Micronesia",
    "MD": "Moldova", "MC": "Monaco", "MN": "Mongolia", "ME": "Montenegro",
    "MS": "Montserrat", "MA": "Morocco", "MZ": "Mozambique", "MM": "Myanmar",
    "NA": "Namibia", "NR": "Nauru", "NP": "Nepal", "NL": "Netherlands",
    "AN": "Netherlands Antilles", "NC": "New Caledonia", "NZ": "New Zealand",
    "NI": "Nicaragua", "NE": "Niger", "NG": "Nigeria", "NU": "Niue",
    "NF": "Norfolk Island", "KP": "North Korea",
    "MP": "Northern Mariana Islands", "NO": "Norway", "OM": "Oman",
    "PK": "Pakistan", "PW": "Palau", "PS": "Palestinian Territory",
    "PA": "Panama", "PG": "Papua New Guinea", "PY": "Paraguay", "PE": "Peru",
    "PH": "Philippines", "PN": "Pitcairn", "PL": "Poland", "PT": "Portugal",
    "PR": "Puerto Rico", "QA": "Qatar", "CG": "Republic of the Congo",
    "RE": "Reunion", "RO": "Romania", "RU": "Russia", "RW": "Rwanda",
    "SH": "Saint Helena", "KN": "Saint Kitts and Nevis", "LC": "Saint Lucia",
    "PM": "Saint Pierre and Miquelon", "VC": "Saint Vincent and the Grenadines",
    "WS": "Samoa", "SM": "San Marino", "ST": "São Tomé and Príncipe",
    "SA": "Saudi Arabia", "SN": "Senegal", "RS": "Serbia",
    "CS": "Serbia and Montenegro", "SC": "Seychelles", "SL": "Sierra Leone",
    "SG": "Singapore", "SK": "Slovakia", "SI": "Slovenia",
    "SB": "Solomon Islands", "SO": "Somalia", "ZA": "South Africa",
    "GS": "South Georgia and the South Sandwich Islands", "KR": "South Korea",
    "ES": "Spain", "LK": "Sri Lanka", "SD": "Sudan", "SR": "Suriname",
    "SJ": "Svalbard and Jan Mayen", "SZ": "Swaziland", "SE": "Sweden",
    "CH": "Switzerland", "SY": "Syria", "TW": "Taiwan", "TJ": "Tajikistan",
    "TZ": "Tanzania", "TH": "Thailand", "TG": "Togo", "TK": "Tokelau",
    "TO": "Tonga", "TT": "Trinidad and Tobago", "TN": "Tunisia", "TR": "Turkey",
    "TM": "Turkmenistan", "TC": "Turks and Caicos Islands", "TV": "Tuvalu",
    "VI": "U.S. Virgin Islands", "UG": "Uganda", "UA": "Ukraine",
    "AE": "United Arab Emirates", "GB": "United Kingdom", "US": "United States",
    "UM": "United States Minor Outlying Islands", "UY": "Uruguay",
    "UZ": "Uzbekistan", "VU": "Vanuatu", "VA": "Vatican City",
    "VE": "Venezuela", "VN": "Vietnam", "WF": "Wallis and Futuna",
    "EH": "Western Sahara", "YE": "Yemen", "ZM": "Zambia", "ZW": "Zimbabwe",
}

COUNTRY_TO_CURRENCY_MAP: Final[Dict[str, str]] = {
    "AF": "AFN", "AL": "ALL", "DZ": "DZD", "AS": "USD", "AD": "EUR",
    "AO": "AOA", "AI": "XCD", "AQ": "USD", "AG": "XCD", "AR": "ARS",
    "AM": "AMD", "AW": "AWG", "AU": "AUD", "AT": "EUR", "AZ": "AZN",
    "BS": "BSD", "BH": "BHD", "BD": "BDT", "BB": "BBD", "BY": "BYR",
    "BE": "EUR", "BZ": "BZD", "BJ": "XOF", "BM": "BMD", "BT": "BTN",
    "BO": "BOB", "BA": "BAM", "BW": "BWP", "BV": "NOK", "BR": "BRL",
    "IO": "USD", "VG": "USD", "BN": "BND", "BG": "BGN", "BF": "XOF",
    "BI": "BIF", "KH": "KHR", "CM": "XAF", "CA": "CAD", "CV": "CVE",
    "KY": "KYD", "CF": "XAF", "TD": "XAF", "CL": "CLP", "CN": "CNY",
    "CX": "AUD", "CC": "AUD", "CO": "COP", "KM": "KMF", "CK": "NZD",
    "CR": "CRC", "HR": "HRK", "CU": "CUP", "CY": "CYP", "CZ": "CZK",
    "CD": "CDF", "DK": "DKK", "DJ": "DJF", "DM": "XCD", "DO": "DOP",
    "TL": "USD", "EC": "USD", "EG": "EGP", "SV": "SVC", "GQ": "XAF",
    "ER": "ERN", "EE": "EEK", "ET": "ETB", "FK": "FKP", "FO": "DKK",
    "FJ": "FJD", "FI": "EUR", "FR": "EUR", "GF": "EUR", "PF": "XPF",
    "TF": "EUR", "GA": "XAF", "GM": "GMD", "GE": "GEL", "DE": "EUR",
    "GH": "GHC", "GI": "GIP", "GR": "EUR", "GL": "DKK", "GD": "XCD",
    "GP": "EUR", "GU": "USD", "GT": "GTQ", "GN": "GNF", "GW": "XOF",
    "GY": "GYD", "HT": "HTG", "HM": "AUD", "HN": "HNL", "HK": "HKD",
    "HU": "HUF", "IS": "ISK", "IN": "INR", "ID": "IDR", "IR": "IRR",
    "IQ": "IQD", "IE": "EUR", "IL": "ILS", "IT": "EUR", "CI": "XOF",
    "JM": "JMD", "JP": "JPY", "JO": "JOD", "KZ": "KZT", "KE": "KES",
    "KI": "AUD", "KW": "KWD", "KG": "KGS", "LA": "LAK", "LV": "LVL",
    "LB": "LBP", "LS": "LSL", "LR": "LRD", "LY": "LYD", "LI": "CHF",
    "LT": "LTL", "LU": "EUR", "MO": "MOP", "MK": "MKD", "MG": "MGA",
    "MW": "MWK", "MY": "MYR", "MV": "MVR", "ML": "XOF", "MT": "MTL",
    "MH": "USD", "MQ": "EUR", "MR": "MRO", "MU": "MUR", "YT": "EUR",
    "MX": "MXN", "FM": "USD", "MD": "MDL", "MC": "EUR", "MN": "MNT",
    "MS": "XCD", "MA": "MAD", "MZ": "MZN", "MM": "MMK", "NA": "NAD",
    "NR": "AUD", "NP": "NPR", "NL": "EUR", "AN": "ANG", "NC": "XPF",
    "NZ": "NZD", "NI": "NIO", "NE": "XOF", "NG": "NGN", "NU": "NZD",
    "NF": "AUD", "KP": "KPW", "MP": "USD", "NO": "NOK", "OM": "OMR",
    "PK": "PKR", "PW": "USD", "PS": "ILS", "PA": "PAB", "PG": "PGK",
    "PY": "PYG", "PE": "PEN", "PH": "PHP", "PN": "NZD", "PL": "PLN",
    "PT": "EUR", "PR": "USD", "QA": "QAR", "CG": "XAF", "RE": "EUR",
    "RO": "RON", "RU": "RUB", "RW": "RWF", "SH": "SHP", "KN": "XCD",
    "LC": "XCD", "PM": "EUR", "VC": "XCD", "WS": "WST", "SM": "EUR",
    "ST": "STD", "SA": "SAR", "SN": "XOF", "CS": "RSD", "SC": "SCR",
    "SL": "SLL", "SG": "SGD", "SK": "SKK", "SI": "EUR", "SB": "SBD",
    "SO": "SOS", "ZA": "ZAR", "GS": "GBP", "KR": "KRW", "ES": "EUR",
    "LK": "LKR", "SD": "SDD", "SR": "SRD", "SJ": "NOK", "SZ": "SZL",
    "SE": "SEK", "CH": "CHF", "SY": "SYP", "TW": "TWD", "TJ": "TJS",
    "TZ": "TZS", "TH": "THB", "TG": "XOF", "TK": "NZD", "TO": "TOP",
    "TT": "TTD", "TN": "TND", "TR": "TRY", "TM": "TMM", "TC": "USD",
    "TV": "AUD", "VI": "USD", "UG": "UGX", "UA": "UAH", "AE": "AED",
    "GB": "GBP", "US": "USD", "UM": "USD", "UY": "UYU", "UZ": "UZS",
    "VU": "VUV", "VA": "EUR", "VE": "VEF", "VN": "VND", "WF": "XPF",
    "EH": "MAD", "YE": "YER", "ZM": "ZMK", "ZW": "ZWD",
}

EU_COUNTRY_CODES: Final[set[str]] = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR",
    "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK",
    "SI", "ES", "SE",
}

COUNTRY_TO_CONTINENT_CODE: Final[Dict[str, str]] = {
    "AF": "AS", "DZ": "AF", "AO": "AF", "BJ": "AF", "BW": "AF", "BF": "AF",
    "BI": "AF", "CM": "AF", "CV": "AF", "CF": "AF", "TD": "AF", "KM": "AF",
    "CD": "AF", "DJ": "AF", "EG": "AF", "GQ": "AF", "ER": "AF", "ET": "AF",
    "GA": "AF", "GM": "AF", "GH": "AF", "GN": "AF", "GW": "AF", "CI": "AF",
    "KE": "AF", "LS": "AF", "LR": "AF", "LY": "AF", "MG": "AF", "MW": "AF",
    "ML": "AF", "MR": "AF", "MU": "AF", "MA": "AF", "MZ": "AF", "NA": "AF",
    "NE": "AF", "NG": "AF", "CG": "AF", "RW": "AF", "ST": "AF", "SN": "AF",
    "SC": "AF", "SL": "AF", "SO": "AF", "ZA": "AF", "SD": "AF", "SZ": "AF",
    "TZ": "AF", "TG": "AF", "TN": "AF", "UG": "AF", "EH": "AF", "ZM": "AF",
    "ZW": "AF", "AQ": "AN", "BV": "AN", "TF": "AN", "HM": "AN", "GS": "AN",
    "AM": "AS", "AZ": "AS", "BH": "AS", "BD": "AS", "BT": "AS", "IO": "AS",
    "BN": "AS", "KH": "AS", "CN": "AS", "CX": "AS", "CC": "AS", "GE": "AS",
    "HK": "AS", "IN": "AS", "ID": "AS", "IR": "AS", "IQ": "AS", "IL": "AS",
    "JP": "AS", "JO": "AS", "KZ": "AS", "KW": "AS", "KG": "AS", "LA": "AS",
    "LB": "AS", "MO": "AS", "MY": "AS", "MV": "AS", "MN": "AS", "MM": "AS",
    "NP": "AS", "KP": "AS", "OM": "AS", "PK": "AS", "PS": "AS", "PH": "AS",
    "QA": "AS", "RU": "EU", "SA": "AS", "SG": "AS", "KR": "AS", "LK": "AS",
    "SY": "AS", "TW": "AS", "TJ": "AS", "TH": "AS", "TL": "AS", "TR": "AS",
    "TM": "AS", "AE": "AS", "UZ": "AS", "VN": "AS", "YE": "AS", "AL": "EU",
    "AD": "EU", "AT": "EU", "BY": "EU", "BE": "EU", "BA": "EU", "BG": "EU",
    "HR": "EU", "CY": "EU", "CZ": "EU", "DK": "EU", "EE": "EU", "FI": "EU",
    "FR": "EU", "DE": "EU", "GI": "EU", "GR": "EU", "HU": "EU", "IS": "EU",
    "IE": "EU", "IT": "EU", "LV": "EU", "LI": "EU", "LT": "EU", "LU": "EU",
    "MK": "EU", "MT": "EU", "MD": "EU", "MC": "EU", "ME": "EU", "NL": "EU",
    "NO": "EU", "PL": "EU", "PT": "EU", "RO": "EU", "SM": "EU", "RS": "EU",
    "CS": "EU", "SK": "EU", "SI": "EU", "ES": "EU", "SJ": "EU", "SE": "EU",
    "CH": "EU", "UA": "EU", "GB": "EU", "VA": "EU", "AI": "NA", "AG": "NA",
    "BS": "NA", "BB": "NA", "BZ": "NA", "BM": "NA", "CA": "NA", "KY": "NA",
    "CR": "NA", "CU": "NA", "DM": "NA", "DO": "NA", "SV": "NA", "GL": "NA",
    "GD": "NA", "GP": "NA", "GT": "NA", "HT": "NA", "HN": "NA", "JM": "NA",
    "MQ": "NA", "MX": "NA", "MS": "NA", "AN": "NA", "NI": "NA", "PA": "NA",
    "PR": "NA", "KN": "NA", "LC": "NA", "PM": "NA", "VC": "NA", "TC": "NA",
    "US": "NA", "UM": "NA", "VI": "NA", "AS": "OC", "AU": "OC", "CK": "OC",
    "FJ": "OC", "PF": "OC", "GU": "OC", "KI": "OC", "MH": "OC", "FM": "OC",
    "NR": "OC", "NC": "OC", "NZ": "OC", "NU": "OC", "NF": "OC", "MP": "OC",
    "PW": "OC", "PG": "OC", "PN": "OC", "WS": "OC", "SB": "OC", "TK": "OC",
    "TO": "OC", "TV": "OC", "VU": "OC", "WF": "OC", "AR": "SA", "BO": "SA",
    "BR": "SA", "CL": "SA", "CO": "SA", "EC": "SA", "FK": "SA", "GF": "SA",
    "GY": "SA", "PY": "SA", "PE": "SA", "SR": "SA", "UY": "SA", "VE": "SA",
}

COUNTRY_TO_RIR: Final[Dict[str, str]] = {
    country: (
        "ripe" if continent == "EU"
        else "apnic" if continent in ["AS", "OC"]
        else "lacnic" if continent == "SA"
        else "afrinic" if continent == "AF"
        else "arin"
    )
    for country, continent in COUNTRY_TO_CONTINENT_CODE.items()
}

CONTINENT_NAME_TO_CODE: Final[Dict[str, str]] = {
    "Africa": "AF", "Antarctica": "AN", "Asia": "AS", "Europe": "EU",
    "North America": "NA", "Oceania": "OC", "South America": "SA",
}

PGEOCODE_SUPPORTED_COUNTRY_CODES: Final[List[str]] = [
    "AD", "AR", "AS", "AT", "AU", "AX", "AZ", "BD", "BE", "BG", "BM", "BR",
    "BY", "CA", "CH", "CL", "CO", "CR", "CY", "CZ", "DE", "DK", "DO", "DZ",
    "EE", "ES", "FI", "FM", "FO", "FR", "GB", "GF", "GG", "GL", "GP", "GT",
    "GU", "HR", "HT", "HU", "IE", "IM", "IN", "IS", "IT", "JE", "JP", "KR",
    "LI", "LK", "LT", "LU", "LV", "MC", "MD", "MH", "MK", "MP", "MQ", "MT",
    "MW", "MX", "MY", "NC", "NL", "NO", "NZ", "PE", "PH", "PK", "PL", "PM",
    "PR", "PT", "PW", "RE", "RO", "RS", "RU", "SE", "SG", "SI", "SJ", "SK",
    "SM", "TH", "TR", "UA", "US", "UY", "VA", "VI", "WF", "YT", "ZA",
]


@lru_cache(maxsize=1000)
def get_geo_country(
    country_code: Optional[str], country_name: Optional[str]
) -> Dict[str, Any]:
    """Get the geo information for a country code or name."""
    if country_code and country_name:
        country_name = None

    enriched_data: Dict[str, Any] = {
        "country_code": country_code,
        "country": country_name,
    }

    country_code, country_name = key_or_value_search(
        enriched_data.get("country_code"),
        enriched_data.get("country"),
        COUNTRY_CODE_TO_NAME,
    )

    if country_name:
        enriched_data["country"] = country_name
    if country_code:
        enriched_data["country_code"] = country_code

    country_code = enriched_data.get("country_code")
    if not enriched_data.get("continent_code") and country_code:
        country_code = country_code.upper()
        continent_code = COUNTRY_TO_CONTINENT_CODE.get(country_code)
        if continent_code:
            enriched_data["continent_code"] = continent_code

    continent_name, continent_code = key_or_value_search(
        enriched_data.get("continent"),
        enriched_data.get("continent_code"),
        CONTINENT_NAME_TO_CODE,
    )

    if continent_name:
        enriched_data["continent"] = continent_name
    if continent_code:
        enriched_data["continent_code"] = continent_code

    country_code = enriched_data.get("country_code")
    if country_code:
        if not enriched_data.get("currency"):
            currency_code = COUNTRY_TO_CURRENCY_MAP.get(
                country_code.upper()
            )
            if currency_code:
                enriched_data["currency"] = currency_code

        if not enriched_data.get("is_eu"):
            is_eu = country_code.upper() in EU_COUNTRY_CODES
            enriched_data["is_eu"] = is_eu

    return enriched_data


@lru_cache(maxsize=1000)
def get_timezone_info(latitude: float, longitude: float) -> Optional[Dict[str, Any]]:
    """Get the timezone info for a given latitude and longitude."""

    timezone_data = {}
    timezone_name = TIMEZONE_FINDER.timezone_at(lat=latitude, lng=longitude)
    if not timezone_name:
        return None

    timezone_data["timezone_name"] = timezone_name

    timezone = pytz.timezone(timezone_name)
    now = datetime.now(timezone)
    timezone_data["timezone_abbreviation"] = now.strftime("%Z")

    utc_offset = now.utcoffset()
    if utc_offset:
        total_seconds = int(utc_offset.total_seconds())
        hours, remainder = divmod(abs(total_seconds), 3600)
        minutes = remainder // 60

        sign = "+" if total_seconds >= 0 else "-"
        timezone_data["utc_offset"] = total_seconds
        timezone_data["utc_offset_str"] = f"UTC{sign}{hours:02d}:{minutes:02d}"

    timezone_data["dst_active"] = now.dst() != timedelta(0)

    return timezone_data


def _get_postal_data(
    postal_data: pd.Series, existing_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Update enriched data with postal data."""
    field_mapping = {
        "place_name": "city",
        "state_name": "region",
        "state_code": "region_code",
        "county_name": "district",
        "latitude": "latitude",
        "longitude": "longitude",
        "postal_code": "postal_code",
    }

    return_data = {}
    for pg_field, our_field in field_mapping.items():
        if pg_field in postal_data.index:
            value = postal_data[pg_field]
            is_not_na = bool(pd.notna(value))
            if is_not_na and not existing_data.get(our_field):
                data = value
                if isinstance(data, np.float64):
                    data = float(data)
                return_data[our_field] = data

    return return_data


@lru_cache(maxsize=50)
def _get_nominatim(country_code: str) -> Optional[pgeocode.Nominatim]:
    """Get a cached Nominatim instance for the given country code."""
    try:
        return pgeocode.Nominatim(country_code)
    except Exception as e:
        logger.error("Error getting Nominatim instance: %s", e)
        return None


@lru_cache(maxsize=50)
def _get_country_locations(country_code: str) -> Optional[pd.DataFrame]:
    """Get and cache all location data for a country."""
    nomi = _get_nominatim(country_code)
    if nomi is None:
        return None

    try:
        df = nomi.query_location("")
        if df is None or len(df) == 0:
            return None
        return df
    except Exception as e:
        logger.error("Error getting country locations: %s", e)
        return None


def _find_nearest_postal_code(
    country_code: str, lat: float, lon: float
) -> Optional[pd.Series]:
    """Find the nearest postal code to a given lat/lon coordinate"""
    try:
        df = _get_country_locations(country_code)
        if df is None:
            return None

        df = df.dropna(subset=["latitude", "longitude"])
        if len(df) == 0:
            return None

        lat_margin = 0.5
        lon_margin = 0.5 / math.cos(math.radians(lat))

        mask = (
            (df["latitude"] >= lat - lat_margin)
            & (df["latitude"] <= lat + lat_margin)
            & (df["longitude"] >= lon - lon_margin)
            & (df["longitude"] <= lon + lon_margin)
        )
        df_filtered = df[mask].copy()

        if len(df_filtered) == 0:
            return None

        lat1_rad = math.radians(lat)
        lon1_rad = math.radians(lon)
        lat2_rad = np.radians(df_filtered["latitude"].astype(float))
        lon2_rad = np.radians(df_filtered["longitude"].astype(float))

        dlon = lon2_rad - lon1_rad
        dlat = lat2_rad - lat1_rad
        a = (
            np.sin(dlat / 2) ** 2
            + np.cos(lat1_rad) * np.cos(lat2_rad) * np.sin(dlon / 2) ** 2
        )
        c = 2 * np.arcsin(np.sqrt(a))
        distances = 6371 * c

        df_filtered.loc[:, "distance"] = distances

        min_idx = distances.argmin()
        closest_idx = df_filtered.index[min_idx]
        closest = df_filtered.loc[closest_idx]
        return closest if closest["distance"] < 50 else None
    except Exception as e:
        logger.error("Error finding nearest postal code: %s", e)
        return None


def _find_by_city(
    country_code: str, city: str, district: Optional[str] = None
) -> pd.DataFrame:
    """Find postal codes by city name and optionally district"""
    try:
        nomi = _get_nominatim(country_code)
        if nomi is None:
            return pd.DataFrame()

        results = nomi.query_location(city)

        if results is None or results.empty:
            return pd.DataFrame()

        if district and not results.empty:
            filter_fields = ["place_name", "community_name", "county_name"]
            mask = pd.Series(False, index=results.index)

            for field in filter_fields:
                if field in results.columns:
                    valid_data = results[field].notna()
                    if bool(valid_data.any()):
                        field_mask = (
                            results.loc[valid_data, field]
                            .str.lower()
                            .str.contains(district.lower(), na=False)
                        )
                        mask.loc[field_mask.index] = (
                            mask.loc[field_mask.index] | field_mask
                        )

            filtered = results[mask]
            if not filtered.empty:
                return pd.DataFrame(filtered) if not isinstance(filtered, pd.DataFrame) else filtered

        return pd.DataFrame(results) if not isinstance(results, pd.DataFrame) else results
    except Exception as e:
        logger.error("Error finding by city: %s", e)
        return pd.DataFrame()


def _find_by_district(country_code: str, district: str) -> pd.DataFrame:
    """Find postal codes by district name"""
    try:
        all_data = _get_country_locations(country_code)
        if all_data is None or all_data.empty:
            return pd.DataFrame()

        filter_fields = ["county_name", "community_name", "place_name"]
        mask = pd.Series(False, index=all_data.index)

        district_lower = district.lower()
        for field in filter_fields:
            if field in all_data.columns:
                valid_data = all_data[field].notna() & all_data[field].apply(
                    lambda x: isinstance(x, str)
                )
                if valid_data.any():
                    field_mask = (
                        all_data.loc[valid_data, field]
                        .str.lower()
                        .str.contains(district_lower, na=False)
                    )
                    mask.loc[field_mask.index] = mask.loc[field_mask.index] | field_mask

        result = all_data[mask]
        return pd.DataFrame(result) if not isinstance(result, pd.DataFrame) else result
    except Exception as e:
        logger.error("Error finding by district: %s", e)
        return pd.DataFrame()


@lru_cache(maxsize=1000)
def enrich_location_data(
    country_code: str,
    postal_code: Optional[str] = None,
    latitude: Optional[float] = None,
    longitude: Optional[float] = None,
    city: Optional[str] = None,
    region: Optional[str] = None,
    district: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Enrich location data by filling in missing fields based on available information."""

    if country_code.upper() not in PGEOCODE_SUPPORTED_COUNTRY_CODES:
        return None

    nomi = _get_nominatim(country_code)
    if nomi is None:
        return None

    data = {
        "country_code": country_code,
        "postal_code": postal_code,
        "latitude": latitude,
        "longitude": longitude,
        "city": city,
        "region": region,
        "district": district,
    }

    if postal_code:
        postal_data = nomi.query_postal_code(postal_code)
        if not postal_data.empty and isinstance(postal_data, pd.Series):
            return _get_postal_data(postal_data, data)

    if latitude is not None and longitude is not None:
        postal_data = _find_nearest_postal_code(country_code, latitude, longitude)
        if postal_data is not None:
            return _get_postal_data(postal_data, data)

    if city:
        search_query = f"{city} {region}" if region else city

        city_data = _find_by_city(country_code, search_query, district)

        if city_data.empty and region:
            city_data = _find_by_city(country_code, city, district)

        if not city_data.empty:
            if region and "state_name" in city_data.columns:
                region_lower = region.lower()
                mask = pd.Series(False, index=city_data.index)

                if "state_name" in city_data.columns:
                    valid_strings = city_data["state_name"].notna() & city_data[
                        "state_name"
                    ].apply(lambda x: isinstance(x, str))
                    if valid_strings.any():
                        string_mask = (
                            city_data.loc[valid_strings, "state_name"]
                            .str.lower()
                            .str.contains(region_lower, na=False)
                        )
                        mask.loc[string_mask.index] = string_mask

                region_match = city_data[mask]
                if not region_match.empty:
                    city_data = region_match

            return _get_postal_data(city_data.iloc[0], data)

    if district:
        district_data = _find_by_district(country_code, district)
        if not district_data.empty:
            return _get_postal_data(district_data.iloc[0], data)

    return {}


def get_rir_for_country(country_code: str) -> Optional[str]:
    """Get the RIR for a given country code."""
    if not country_code:
        return None
    return COUNTRY_TO_RIR.get(country_code.upper())
