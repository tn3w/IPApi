"""
Pydantic models for API request and response schemas.
"""

from typing import Optional
from pydantic import BaseModel, Field


class ErrorResponse(BaseModel):
    """Error response model."""

    detail: str = Field(..., description="Error description")


class IPGeolocationResponse(BaseModel):
    """IP geolocation response model."""

    # Geographic information
    ip: Optional[str] = Field(None, description="IP address")
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
        schema_extra = {
            "example": {
                "ip": "8.8.8.8",
                "continent": "North America",
                "continent_code": "NA",
                "country": "United States",
                "country_code": "US",
                "region": "Kansas",
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
