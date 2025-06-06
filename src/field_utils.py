#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Field management utilities for API responses.

This module provides functionality for handling response field selection,
including field definitions, conversion between field names and numeric representations,
and parsing of field parameters from API requests. It supports selective field inclusion
in responses through bitwise operations and query parameter parsing.
"""

from typing import Final, List, Dict, Optional

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

FIELDS_FOR_ALL: Final[List[str]] = [field for field in ALL_FIELDS if field != "all"]

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
