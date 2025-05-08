"""
Utilities for handling field selection in API responses.
"""

from typing import List, Optional

# List of fields that are related to the location of the IP address
GEO_FIELDS: List[str] = [
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
]

# List of fields that are related to the ASN of the IP address
ASN_FIELDS: List[str] = [
    "asn",
    "organization",
]

# List of fields that are related to the ASN of the IP address
EXTENDED_ASN_FIELDS: List[str] = [
    "asn_name",
    "net",
]

# Default fields to return
DEFAULT_FIELDS: List[str] = [
    "ip",
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
    "organization",
]

# List of all possible response fields
ALL_FIELDS: List[str] = [
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
    "postal_code",
    "latitude",
    "longitude",
    "timezone",
    "currency",
    "accuracy_radius",
    "asn",
    "asn_name",
    "organization",
    "net",
]

# Each field is assigned a power of 2 (a bit position)
# This allows any combination of fields to be represented by a unique number
FIELD_BITS = {field: 1 << i for i, field in enumerate(ALL_FIELDS)}

# All fields mask - has all bits set for all fields
ALL_FIELDS_MASK = (1 << len(ALL_FIELDS)) - 1


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
    # If empty or invalid, return 0
    if not fields:
        return 0

    # Calculate number by adding powers of 2 for each field
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
    # If 0 or invalid, return empty list
    if number <= 0:
        return []

    # If number represents ALL_FIELDS_MASK or is larger, return all fields
    if number >= ALL_FIELDS_MASK:
        return ALL_FIELDS.copy()

    # Check each bit position and include corresponding field if set
    result: List[str] = []
    for field, bit in FIELD_BITS.items():
        if number & bit:
            result.append(field)

    return result


def parse_fields_param(fields_param: Optional[str] = None) -> List[str]:
    """
    Parse the fields parameter from the request.

    Args:
        fields_param: String parameter, either a number or comma-separated fields

    Returns:
        List of field names
    """
    # Default: all fields
    if not fields_param:
        return DEFAULT_FIELDS.copy()

    # Try parsing as number first
    try:
        number = int(fields_param)
        return number_to_fields(number)
    except ValueError:
        # Parse as comma-separated list
        fields = [f.strip() for f in fields_param.split(",") if f.strip() in ALL_FIELDS]
        if not fields:
            return DEFAULT_FIELDS.copy()
        return fields
