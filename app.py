import os
from typing import Optional, Dict, Any, List

import uvicorn
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from src.ip_address import is_valid_and_routable_ip, get_ip_address_type
from src.schemas import (
    IPAPIResponse,
    ErrorResponse,
    FieldsListResponse,
    FieldToNumberResponse,
    NumberToFieldsResponse,
    IPAddressResponse,
)
from src.field_utils import (
    parse_fields_param,
    fields_to_number,
    FIELDS,
    number_to_fields,
)
from src.geo_utils import (
    process_country_states_cities_database,
    process_zip_codes_database,
)
from src.utils import download_file
from src.dns_lookup import get_dns_info

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

    if not client_ip or client_ip == "127.0.0.1":
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()

    if not client_ip or not is_valid_and_routable_ip(client_ip):
        return None

    return client_ip


def get_ip_information(ip_address: str, fields: List[str]) -> Dict[str, Any]:
    information: Dict[str, Any] = {}

    if "ip" in fields:
        information["ip"] = ip_address

    if "hostname" in fields:
        information["hostname"] = get_dns_info(ip_address)

    if "type" in fields:
        information["type"] = get_ip_address_type(ip_address)

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

    return get_ip_information(ip_address, fields)


@app.get(
    "/onlyip",
    response_model=IPAddressResponse,
    summary="Get current IP address",
    description="Returns the current IP address",
    tags=["IP"],
)
def onlyip(request: Request):
    """
    Return the current IP address.
    """
    ip_address = get_ip_address(request)
    if not ip_address:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid IP address",
        )
    return {"ip": ip_address}


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

    return get_ip_information(ip_address, fields)


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
    return {"fields": FIELDS}


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
    fields = [f.strip() for f in field_name.split(",") if f.strip() in FIELDS]

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
