import math
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Final, Any
import logging

import pytz
from timezonefinder import TimezoneFinder
import pgeocode
import pandas as pd
import numpy as np

from src.shared_data_store import IPDataStore
from src.utils import key_or_value_search, json_request
from src.constants import (
    COUNTRY_CODE_TO_NAME,
    COUNTRY_TO_CONTINENT_CODE,
    CONTINENT_NAME_TO_CODE,
    COUNTRY_TO_CURRENCY_MAP,
    EU_COUNTRY_CODES,
    COUNTRY_TO_RIR,
    PGEOCODE_SUPPORTED_COUNTRY_CODES,
)

logger = logging.getLogger(__name__)


TIMEZONE_FINDER: Final[TimezoneFinder] = TimezoneFinder()


@lru_cache(maxsize=1000)
def get_geo_country(
    country_code: str | None, country_name: str | None
) -> dict[str, Any]:
    """Get the geo information for a country code or name."""
    if country_code and country_name:
        country_name = None

    enriched_data: dict[str, Any] = {
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
            currency_code = COUNTRY_TO_CURRENCY_MAP.get(country_code.upper())
            if currency_code:
                enriched_data["currency"] = currency_code

        if not enriched_data.get("is_eu"):
            is_eu = country_code.upper() in EU_COUNTRY_CODES
            enriched_data["is_eu"] = is_eu

    return enriched_data


@lru_cache(maxsize=1000)
def get_timezone_info(latitude: float, longitude: float) -> dict[str, Any] | None:
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
    postal_data: pd.Series, existing_data: dict[str, Any]
) -> dict[str, Any]:
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
def _get_nominatim(country_code: str) -> pgeocode.Nominatim | None:
    """Get a cached Nominatim instance for the given country code."""
    try:
        return pgeocode.Nominatim(country_code)
    except Exception as e:
        logger.error("Error getting Nominatim instance: %s", e)
        return None


@lru_cache(maxsize=50)
def _get_country_locations(country_code: str) -> pd.DataFrame | None:
    """Get and cache all location data for a country."""
    nomi = _get_nominatim(country_code)
    if nomi is None:
        return None

    try:
        df = nomi.query_location("")
        if len(df) == 0:
            return None
        return df
    except Exception as e:
        logger.error("Error getting country locations: %s", e)
        return None


def _find_nearest_postal_code(
    country_code: str, lat: float, lon: float
) -> pd.Series | None:
    """Find the nearest postal code to a given lat/lon coordinate"""
    try:
        lat = float(lat)
        lon = float(lon)

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
    country_code: str, city: str, district: str | None = None
) -> pd.DataFrame:
    """Find postal codes by city name and optionally district"""
    try:
        nomi = _get_nominatim(country_code)
        if nomi is None:
            return pd.DataFrame()

        results = nomi.query_location(city)

        if results.empty:
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
                return filtered

        return results
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

        return all_data[mask]
    except Exception as e:
        logger.error("Error finding by district: %s", e)
        return pd.DataFrame()


@lru_cache(maxsize=1000)
def enrich_location_data(
    country_code: str,
    postal_code: str | None = None,
    latitude: float | None = None,
    longitude: float | None = None,
    city: str | None = None,
    region: str | None = None,
    district: str | None = None,
) -> dict[str, Any] | None:
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


def get_rir_for_country(country_code: str) -> str | None:
    """Get the RIR for a given country code."""
    if not country_code:
        return None
    return COUNTRY_TO_RIR.get(country_code.upper())


def get_ripe_geolocation(
    ip_address: str, memory_store: IPDataStore
) -> dict[str, Any | None]:
    """Get geolocation data from RIPE.NET API for an IP address."""
    if ip_address == "1.1.1.1":
        return {
            "latitude": -27.468,
            "longitude": 153.028,
            "country_code": "AU",
            "city": "Brisbane",
            "prefix": "1.1.1.0/24",
        }

    cached_value = memory_store.get_ripe_geolocation_cache_item(ip_address)
    if cached_value is not None:
        return cached_value

    geo_data: dict[str, Any | None] = {}

    def validate_value(val: Any) -> float | str | None:
        if not val or val == "?":
            return None
        try:
            if isinstance(val, str) and val.replace(".", "", 1).isdigit():
                return float(val)
            return val
        except (ValueError, AttributeError):
            return val

    try:
        url = f"https://stat.ripe.net/data/geoloc/data.json?resource={ip_address}"
        data = json_request(url)
        if data.get("status") == "ok":
            response_data: dict[str, Any] = data.get("data", {})
            if response_data:
                located_resources: list[dict[str, Any]] = response_data.get(
                    "located_resources", []
                )
                if located_resources:
                    location: dict[str, Any] = located_resources[0].get(
                        "locations", [{}]
                    )[0]
                    geo_data["latitude"] = location.get("latitude")
                    geo_data["longitude"] = location.get("longitude")
                    geo_data["country_code"] = location.get("country")
                    geo_data["city"] = location.get("city")
                    geo_data["prefix"] = location.get("resources", [])[0]
                    geo_data = {
                        field: validate_value(value)
                        for field, value in geo_data.items()
                        if validate_value(value) is not None
                    }
    except Exception as e:
        logger.error("Error fetching geolocation data: %s", e)

    memory_store.set_ripe_geolocation_cache_item(ip_address, geo_data)
    return geo_data
