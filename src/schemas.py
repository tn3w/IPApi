"""
Pydantic models for API request and response schemas.
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
    country: Optional[str] = Field(None, description="Country name")
    country_code: Optional[str] = Field(
        None, description="Country code (ISO 3166-1 alpha-2)"
    )
    region: Optional[str] = Field(None, description="Region/state name")
    region_code: Optional[str] = Field(None, description="Region/state code")
    city: Optional[str] = Field(None, description="City name")
    postal_code: Optional[str] = Field(None, description="Postal/ZIP code")
    latitude: Optional[float] = Field(None, description="Latitude coordinate")
    longitude: Optional[float] = Field(None, description="Longitude coordinate")
    timezone: Optional[str] = Field(None, description="Timezone")
    currency: Optional[str] = Field(None, description="Currency code")
    accuracy_radius: Optional[int] = Field(
        None, description="Accuracy radius in kilometers"
    )

    # ASN information
    asn: Optional[int] = Field(None, description="Autonomous System Number")
    asn_name: Optional[str] = Field(None, description="Autonomous System name")
    organization: Optional[str] = Field(None, description="Organization name")
    net: Optional[str] = Field(None, description="Network range")

    class Config:
        json_schema_extra = {
            "example": {
                "ip": "8.8.8.8",
                "hostname": "dns.google",
                "type": "ipv4",
                "continent": "North America",
                "continent_code": "NA",
                "country": "United States",
                "country_code": "US",
                "region": "Kansas",
                "region_code": "KS",
                "city": "Cheney",
                "latitude": 37.751,
                "longitude": -97.822,
                "timezone": "America/Chicago",
                "currency": "USD",
                "asn": 15169,
                "asn_name": "GOOGLE",
                "organization": "GOOGLE",
            }
        }


# Models for Fields-tagged endpoints


class FieldsListResponse(BaseModel):
    """Response model for the field list endpoint."""

    fields: List[str] = Field(..., description="List of all available fields")

    class Config:
        json_schema_extra = {"example": {"fields": ALL_FIELDS}}


class FieldToNumberResponse(BaseModel):
    """Response model for converting field names to a number."""

    fields: List[str] = Field(..., description="List of field names")
    number: int = Field(..., description="Numeric representation of the fields")

    class Config:
        json_schema_extra = {
            "example": {
                "fields": ["ip", "country", "city"],
                "number": 293,  # Example number that represents these fields
            }
        }


class NumberToFieldsResponse(BaseModel):
    """Response model for converting a number to field names."""

    number: int = Field(..., description="Numeric representation of the fields")
    fields: List[str] = Field(..., description="List of field names")
    fields_str: str = Field(..., description="Comma-separated list of field names")

    class Config:
        @staticmethod
        def json_schema_extra(schema: Dict[str, Any], model: type) -> None:
            """Dynamically calculate the example values based on current FIELDS."""
            # Calculate all fields bitmask dynamically: 2^len(FIELDS) - 1
            all_fields_mask = (1 << len(ALL_FIELDS)) - 1

            # Generate a comma-separated string of all fields
            all_fields_str = ",".join(ALL_FIELDS)

            # Set the example
            if "example" not in schema:
                schema["example"] = {}

            schema["example"] = {
                "number": all_fields_mask,
                "fields": ALL_FIELDS,
                "fields_str": all_fields_str,
            }
