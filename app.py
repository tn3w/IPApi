import os
from typing import Optional, Dict, Any, List

import uvicorn
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from src.ip_address import is_valid_and_routable_ip, get_ip_address_type
from src.schemas import (
    IPAPIResponse,
    ErrorResponse,
    FieldsListResponse,
    FieldToNumberResponse,
    NumberToFieldsResponse,
)
from src.field_utils import (
    parse_fields_param,
    fields_to_number,
    ALL_FIELDS,
    number_to_fields,
)
from src.geo_utils import (
    process_country_states_cities_database,
    process_zip_codes_database,
    get_currency_from_country,
    is_country_in_european_union,
    get_geocoder_data,
    get_us_state_name_and_code,
    get_country_states_cities_data,
    get_continent_code_from_name,
    find_zip_code,
)
from src.asn_lookup import lookup_asn_from_ip, get_asn_from_maxmind
from src.utils import download_file
from src.dns_lookup import get_dns_info, get_ipv4_from_ipv6
from src.geo_lookup import get_geo_from_maxmind

DATASETS_DIR = "assets"
DATASETS = {
    "GeoLite2-ASN": ("https://git.io/GeoLite2-ASN.mmdb", "GeoLite2-ASN.mmdb"),
    "GeoLite2-City": ("https://git.io/GeoLite2-City.mmdb", "GeoLite2-City.mmdb"),
    "Country-States-Cities": (
        (
            "https://raw.githubusercontent.com/dr5hn/"
            "countries-states-cities-database/refs/heads/master/"
            "json/countries%2Bstates%2Bcities.json"
        ),
        "countries_states_cities.json",
    ),
    "Zip-Codes": (
        (
            "https://raw.githubusercontent.com/wouterdebie/"
            "zip_codes_plus/refs/heads/main/data/zip_codes.csv"
        ),
        "zip_codes.csv",
    ),
}

templates = Jinja2Templates(directory="templates")

app = FastAPI(
    title="IP Geolocation API",
    description="API that returns GeoIP and ASN information for IP addresses",
    version="1.0.0",
)


def get_ip_address(request: Request) -> Optional[str]:
    """
    Extract and validate the client IP address from the request.

    First checks the client.host attribute. If that's missing or localhost,
    falls back to the X-Forwarded-For header. Returns None if no valid
    routable IP address is found.

    Args:
        request: The FastAPI request object

    Returns:
        A valid routable IP address or None
    """
    client_ip = request.client.host if request.client else None

    if not client_ip or not is_valid_and_routable_ip(client_ip):
        return None

    return client_ip


GEO_FIELDS = [
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
    "accuracy_radius",
]

ASN_FIELDS = [
    "asn",
    "organization",
]

ASN_LOOKUP_FIELDS = [
    "asn",
    "asn_name",
    "organization",
    "net",
    "country",
    "country_code",
    "state",
    "city",
    "latitude",
    "longitude",
]


GEOCODER_FIELDS = ["country", "country_code", "region", "county", "city"]

COUNTRY_STATES_CITIES_FIELDS = [
    "continent",
    "country",
    "timezone",
    "offset",
    "region",
    "region_code",
    "city",
    "county",
]


def check_missing_information(
    information: Dict[str, Any], list1: List[str], list2: List[str]
) -> bool:
    """
    Check if any keys from list1 that are also in list2 have
    missing or None values in the information dict.

    Args:
        information: Dictionary with information data
        list1: First list of keys to check
        list2: Second list of keys to check against

    Returns:
        True if any common key is missing or None in the information
        dict, False otherwise
    """

    common_keys = set(list1) & set(list2)

    if not common_keys:
        return False

    return any(
        key not in information or information[key] is None for key in common_keys
    )


def get_ip_information(ip_address: str, fields: List[str]) -> Dict[str, Any]:
    information: Dict[str, Any] = {}
    ip_address_type = get_ip_address_type(ip_address)

    if "ip" in fields:
        information["ip"] = ip_address

    if "ipv4" in fields:
        ipv4_from_ipv6 = get_ipv4_from_ipv6(ip_address)
        if ipv4_from_ipv6 and ipv4_from_ipv6 != ip_address:
            information["ipv4"] = ipv4_from_ipv6
        else:
            information["ipv4"] = None

    if "hostname" in fields:
        information["hostname"] = get_dns_info(ip_address)

    if "type" in fields:
        information["type"] = ip_address_type

    if check_missing_information(information, GEO_FIELDS, fields):
        maxmind_path = os.path.join(DATASETS_DIR, DATASETS["GeoLite2-City"][1])
        information.update(get_geo_from_maxmind(ip_address, maxmind_path))

    if check_missing_information(information, ASN_FIELDS, fields):
        maxmind_path = os.path.join(DATASETS_DIR, DATASETS["GeoLite2-ASN"][1])
        asn_info = get_asn_from_maxmind(ip_address, maxmind_path)
        if asn_info:
            information.update(asn_info)

    if check_missing_information(information, ASN_LOOKUP_FIELDS, fields):
        lookup_result = lookup_asn_from_ip(ip_address)
        if lookup_result:
            if not information.get("latitude") or not information.get("longitude"):
                information["accuracy_radius"] = 1000
            information.update(lookup_result)

    if (
        information.get("latitude")
        and information.get("longitude")
        and check_missing_information(information, GEOCODER_FIELDS, fields)
    ):
        information.update(
            get_geocoder_data((information["latitude"], information["longitude"]))
        )

    def fill_in_region_and_postal_code(
        information: Dict[str, Any], fields: List[str]
    ) -> None:
        if check_missing_information(information, ["region", "region_code"], fields):
            information["region"], information["region_code"] = (
                get_us_state_name_and_code(
                    information.get("region"), information.get("region_code")
                )
            )
        if check_missing_information(information, ["postal_code"], fields):
            zip_codes_path = os.path.join(
                DATASETS_DIR, DATASETS["Zip-Codes"][1].replace(".csv", ".json")
            )
            information["postal_code"] = find_zip_code(
                information.get("city"), information.get("region_code"), zip_codes_path
            )

    if information.get("country_code"):
        if "currency" in fields:
            information["currency"] = get_currency_from_country(
                information["country_code"]
            )
        if "is_in_european_union" in fields:
            information["is_in_european_union"] = is_country_in_european_union(
                information["country_code"]
            )
        if information.get("country_code") == "US":
            fill_in_region_and_postal_code(information, fields)
        if check_missing_information(information, COUNTRY_STATES_CITIES_FIELDS, fields):
            country_states_cities_path = os.path.join(
                DATASETS_DIR, DATASETS["Country-States-Cities"][1]
            )
            information.update(
                get_country_states_cities_data(
                    information["country_code"],
                    country_states_cities_path,
                    information.get("city"),
                    information.get("region"),
                    information.get("region_code"),
                )
            )
    else:
        fill_in_region_and_postal_code(information, fields)

    if information.get("continent") and check_missing_information(
        information, ["continent_code"], fields
    ):
        information["continent_code"] = get_continent_code_from_name(
            information["continent"]
        )

    if information.get("postal_code"):
        if isinstance(information["postal_code"], str) and information["postal_code"].isdigit():
            information["postal_code"] = int(information["postal_code"])

    information = {field: information.get(field) for field in fields}

    return information


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index(request: Request):
    """
    Return the index HTML page.
    """
    api_url = str(request.base_url).rstrip("/")
    return templates.TemplateResponse(
        "index.html", {"request": request, "api_url": api_url}
    )


@app.get(
    "/self",
    response_model=IPAPIResponse,
    responses={
        status.HTTP_400_BAD_REQUEST: {
            "model": ErrorResponse,
            "description": "Invalid IP address",
        }
    },
    summary="Get current IP geolocation",
    description="Returns geolocation and ASN information for the current client IP address",
    tags=["IP"],
)
def self(request: Request):
    """
    Return the GeoIP and ASN information for the current IP address.
    """
    ip_address = get_ip_address(request)
    if not ip_address:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid IP address",
        )

    fields_param = request.query_params.get("fields", "")
    fields = parse_fields_param(fields_param)

    return JSONResponse(content=get_ip_information(ip_address, fields))


@app.get(
    "/{ip_address}",
    response_model=IPAPIResponse,
    responses={
        status.HTTP_400_BAD_REQUEST: {
            "model": ErrorResponse,
            "description": "Invalid IP address",
        }
    },
    summary="Get specific IP geolocation",
    description="Returns geolocation and ASN information for the specified IP address",
    tags=["IP"],
)
def ip(ip_address: str, request: Request):
    """
    Return the GeoIP and ASN information for the given IP address.
    """
    if not is_valid_and_routable_ip(ip_address):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid IP address",
        )

    fields_param = request.query_params.get("fields", "")
    fields = parse_fields_param(fields_param)

    return JSONResponse(content=get_ip_information(ip_address, fields))


@app.get(
    "/fields/list",
    response_model=FieldsListResponse,
    summary="Get all available fields",
    description="Returns a list of all available fields that can be requested",
    tags=["Fields"],
)
async def available_fields():
    """
    Return a list of all available fields.
    """
    return {"fields": ALL_FIELDS}


@app.get(
    "/fields/{field_name}/number",
    response_model=FieldToNumberResponse,
    summary="Get number for a field",
    description="Returns the number representing a single field or comma-separated list of fields",
    tags=["Fields"],
)
async def field_number(field_name: str):
    """
    Return the number representing a field or comma-separated field list.
    """
    fields = [f.strip() for f in field_name.split(",") if f.strip() in ALL_FIELDS]

    number = fields_to_number(fields)

    return {
        "fields": fields,
        "number": number,
    }


@app.get(
    "/numbers/{number}/fields",
    response_model=NumberToFieldsResponse,
    summary="Get fields for a number",
    description="Returns the list of field names represented by the given number",
    tags=["Fields"],
)
async def number_to_field_names(number: int):
    """
    Return the field names corresponding to the given number.
    """
    field_names = number_to_fields(number)

    return {
        "number": number,
        "fields": field_names,
        "fields_str": ",".join(field_names),
    }


def main() -> None:
    """
    Main function to run the app.
    """

    country_states_cities_path = os.path.join(
        DATASETS_DIR, DATASETS["Country-States-Cities"][1]
    )
    does_country_states_cities_database_exist = os.path.exists(
        country_states_cities_path
    )

    zip_codes_path = os.path.join(DATASETS_DIR, DATASETS["Zip-Codes"][1])
    zip_codes_json_path = zip_codes_path.replace(".csv", ".json")
    does_zip_codes_database_exist = os.path.exists(zip_codes_json_path)

    for dataset_name, (dataset_url, dataset_filename) in DATASETS.items():
        if dataset_name == "Zip-Codes" and does_zip_codes_database_exist:
            continue

        download_file(
            dataset_url, os.path.join(DATASETS_DIR, dataset_filename), dataset_name
        )

    if not does_country_states_cities_database_exist:
        print("Processing country states cities database...")
        process_country_states_cities_database(country_states_cities_path)

    if not does_zip_codes_database_exist:
        print("Processing zip codes database...")
        process_zip_codes_database(zip_codes_path, zip_codes_json_path)

    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=5000,
        workers=16,
        server_header=False,
    )


if __name__ == "__main__":
    main()
