#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Pydantic model schemas for API responses.

This module defines the data structures and schemas used for API responses,
including IP geolocation data, error responses, and field management endpoints.
It provides models for standardized JSON responses with proper field typing and documentation.
"""

from typing import Optional, Final, List, Dict, Any
from pydantic import BaseModel, Field


DEFAULT_FIELDS: Final[List[str]] = [
    "ip",
    "hostname",
    "type",
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
    "currency",
    "accuracy_radius",
    "asn",
    "asn_name",
    "vpn",
    "vpn_name",
    "proxy",
    "data_center",
    "forum_spammer",
    "firehol_level1",
    "tor_exit_node",
]

ALL_FIELDS: Final[List[str]] = [
    "ip",
    "ipv4",
    "hostname",
    "type",
    "continent",
    "continent_code",
    "country",
    "country_code",
    "region",
    "region_code",
    "city",
    "county",
    "postal_code",
    "latitude",
    "longitude",
    "timezone",
    "offset",
    "currency",
    "accuracy_radius",
    "asn",
    "asn_name",
    "org",
    "net",
    "prefix",
    "abuse_contact",
    "rpki",
    "rpki_count",
    "vpn",
    "vpn_name",
    "proxy",
    "data_center",
    "forum_spammer",
    "firehol_level1",
    "tor_exit_node",
    "all",
]

FIELDS_FOR_ALL: Final[List[str]] = [
    field for field in ALL_FIELDS if field not in ("all", "rpki", "rpki_count")
]

FIELD_BITS: Final[Dict[str, int]] = {
    field: 1 << i for i, field in enumerate(ALL_FIELDS)
}
ALL_FIELDS_MASK: Final[int] = (1 << len(ALL_FIELDS)) - 1


def fields_to_number(fields: List[str]) -> int:
    """
    Convert a list of field names to a unique number.

    Each field has a bit position, and the number has those bits set.
    For example:
    - "ip" -> 1 (binary: 0001)
    - "ip,continent" -> 3 (binary: 0011)
    - "ip,continent,country" -> 7 (binary: 0111)

    Args:
        fields: List of field names

    Returns:
        Integer representing the selected fields
    """
    if not fields:
        return 0

    number = 0
    for field in fields:
        if field in FIELD_BITS:
            number |= FIELD_BITS[field]

    return number


def number_to_fields(number: int) -> List[str]:
    """
    Convert a number back to the list of field names it represents.

    Args:
        number: Integer representing selected fields

    Returns:
        List of field names
    """
    if number <= 0:
        return []

    if number >= ALL_FIELDS_MASK:
        return ALL_FIELDS.copy()

    result: List[str] = []
    for field, bit in FIELD_BITS.items():
        if number & bit:
            result.append(field)

    if "all" in result:
        try:
            result.remove("all")
            result.extend(FIELDS_FOR_ALL)
        except ValueError:
            pass

    return result


def parse_fields_param(fields_param: Optional[str] = None) -> List[str]:
    """
    Parse the fields parameter from the request.

    Args:
        fields_param: String parameter, either a number or comma-separated fields

    Returns:
        List of field names
    """
    if not fields_param:
        return DEFAULT_FIELDS.copy()

    try:
        number = int(fields_param)
        return number_to_fields(number)
    except ValueError:
        fields = [f.strip() for f in fields_param.split(",") if f.strip() in ALL_FIELDS]
        if not fields:
            return DEFAULT_FIELDS.copy()
        if "all" in fields:
            try:
                fields.remove("all")
                fields.extend(FIELDS_FOR_ALL)
            except ValueError:
                pass
        return fields


class ErrorResponse(BaseModel):
    """Error response model."""

    detail: str = Field(..., description="Error description")


class IPAPIResponse(BaseModel):
    """IP API response model."""

    # Geographic information
    ip: Optional[str] = Field(None, description="IP address")
    ipv4: Optional[str] = Field(
        None, description="IPv4 address from DNS lookup for IPv6 input"
    )
    hostname: Optional[str] = Field(None, description="Hostname")
    type: Optional[str] = Field(None, description="IP address type")
    continent: Optional[str] = Field(None, description="Continent name")
    continent_code: Optional[str] = Field(None, description="Continent code")
    is_in_european_union: Optional[bool] = Field(
        None, description="If the country is in the European Union"
    )
    country: Optional[str] = Field(None, description="Country name")
    country_code: Optional[str] = Field(
        None, description="Country code (ISO 3166-1 alpha-2)"
    )
    region: Optional[str] = Field(None, description="Region/state name")
    region_code: Optional[str] = Field(None, description="Region/state code")
    city: Optional[str] = Field(None, description="City name")
    county: Optional[str] = Field(None, description="County name")
    postal_code: Optional[str] = Field(None, description="Postal/ZIP code")
    latitude: Optional[float] = Field(None, description="Latitude coordinate")
    longitude: Optional[float] = Field(None, description="Longitude coordinate")
    timezone: Optional[str] = Field(None, description="Timezone")
    currency: Optional[str] = Field(None, description="Currency code")
    accuracy_radius: Optional[int] = Field(
        None, description="Accuracy radius in kilometers"
    )

    # ASN information
    asn: Optional[str] = Field(None, description="Autonomous System Number")
    asn_name: Optional[str] = Field(None, description="Autonomous System name")
    org: Optional[str] = Field(None, description="Organization name")
    net: Optional[str] = Field(None, description="Network range")
    prefix: Optional[str] = Field(None, description="Prefix")
    abuse_contact: Optional[str] = Field(None, description="Abuse contact email")
    rpki: Optional[str] = Field(None, description="RPKI validity status")
    rpki_count: Optional[int] = Field(
        None, description="Number of ROAs existing for the prefix"
    )

    # Abuse information
    vpn: Optional[bool] = Field(None, description="If the IP is a VPN server")
    vpn_name: Optional[str] = Field(None, description="Name of the VPN server")
    proxy: Optional[bool] = Field(None, description="If the IP is a proxy server")
    data_center: Optional[bool] = Field(None, description="If the IP is a data center")
    forum_spammer: Optional[bool] = Field(
        None, description="If the IP is a forum spammer"
    )
    firehol_level1: Optional[bool] = Field(
        None, description="If the IP is in the Firehol Level 1 dataset"
    )
    tor_exit_node: Optional[bool] = Field(
        None, description="If the IP is a Tor exit node"
    )

    class Config:
        """Config for the IPAPIResponse model."""

        json_schema_extra = {
            "example": {
                "ip": "1.1.1.1",
                "hostname": "one.one.one.one",
                "type": "ipv4",
                "continent": "North America",
                "continent_code": "NA",
                "country": "United States",
                "country_code": "US",
                "region": "California",
                "region_code": "CA",
                "city": "Los Angeles",
                "postal_code": "90001",
                "latitude": 34.052571,
                "longitude": -118.243907,
                "timezone": "America/Adak",
                "currency": "USD",
                "accuracy_radius": 1000,
                "asn": 13335,
                "asn_name": "Cloudflare, Inc.",
                "vpn": False,
                "vpn_name": None,
                "proxy": False,
                "data_center": False,
                "forum_spammer": False,
                "firehol_level1": False,
                "tor_exit_node": False,
            }
        }


class FieldsListResponse(BaseModel):
    """Response model for the field list endpoint."""

    fields: List[str] = Field(..., description="List of all available fields")

    class Config:
        """Config for the FieldsListResponse model."""

        json_schema_extra = {"example": {"fields": ALL_FIELDS}}


class FieldToNumberResponse(BaseModel):
    """Response model for converting field names to a number."""

    fields: List[str] = Field(..., description="List of field names")
    number: int = Field(..., description="Numeric representation of the fields")

    class Config:
        """Config for the FieldToNumberResponse model."""

        json_schema_extra = {
            "example": {
                "fields": ["ip", "country", "city"],
                "number": fields_to_number(["ip", "country", "city"]),
            }
        }


class NumberToFieldsResponse(BaseModel):
    """Response model for converting a number to field names."""

    number: int = Field(..., description="Numeric representation of the fields")
    fields: List[str] = Field(..., description="List of field names")
    fields_str: str = Field(..., description="Comma-separated list of field names")

    class Config:
        """Config for the NumberToFieldsResponse model."""

        @staticmethod
        def json_schema_extra(schema: Dict[str, Any], _model: type) -> None:
            """Dynamically calculate the example values based on current FIELDS."""
            all_fields_mask = (1 << len(ALL_FIELDS)) - 1

            all_fields_str = ",".join(ALL_FIELDS)

            if "example" not in schema:
                schema["example"] = {}

            schema["example"] = {
                "number": all_fields_mask,
                "fields": ALL_FIELDS,
                "fields_str": all_fields_str,
            }
