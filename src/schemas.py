#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Pydantic model schemas for API responses.

This module defines the data structures and schemas used for API responses,
including IP geolocation data, error responses, and field management endpoints.
It provides models for standardized JSON responses with proper field typing and documentation.
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

from src.field_utils import ALL_FIELDS


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
                "number": 293,
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
