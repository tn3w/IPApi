from typing import Dict, Any, cast, Union, List

import maxminddb


RecordDict = Dict[str, Any]
RecordList = List[Any]
RecordValue = Union[RecordDict, RecordList, str, int, float, bool, None]


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

    except Exception as exc:
        print(f"Error looking up geo information: {exc}")
        return geo_info
