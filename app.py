import os
from typing import Optional, Dict, Any

import uvicorn
from fastapi import FastAPI, Request, HTTPException, status, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from src.ip_address import is_valid_and_routable_ip
from src.schemas import (
    IPGeolocationResponse,
    ErrorResponse,
    FieldsListResponse,
    FieldToNumberResponse,
    NumberToFieldsResponse,
)
from src.field_utils import (
    parse_fields_param,
    filter_response,
    fields_to_number,
    FIELDS,
    number_to_fields,
)
from src.utils import download_file

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


def get_ip_information(ip_address: str) -> Dict[str, Any]:
    """
    Get the GeoIP and ASN information for the given IP address.
    """
    return {"ip": ip_address}


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index(request: Request):
    """
    Return the index HTML page.
    """
    return templates.TemplateResponse("index.html", {"request": request})


@app.get(
    "/self",
    response_model=IPGeolocationResponse,
    responses={
        status.HTTP_400_BAD_REQUEST: {
            "model": ErrorResponse,
            "description": "Invalid IP address",
        }
    },
    summary="Get current IP geolocation",
    description="Returns geolocation and ASN information for the current client IP address",
    tags=["API"],
)
async def self(
    request: Request,
    fields: Optional[str] = Query(
        None, description="Comma-separated list of fields to include or field number"
    ),
):
    """
    Return the GeoIP and ASN information for the current IP address.
    """
    ip_address = get_ip_address(request)
    if not ip_address:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid IP address",
        )

    # Get the IP information
    ip_info = get_ip_information(ip_address)

    # Parse the fields parameter
    _, field_number = parse_fields_param(fields)

    # Filter the response based on the requested fields
    filtered_data = filter_response(ip_info, field_number)

    return JSONResponse(filtered_data)


@app.get(
    "/{ip_address}",
    response_model=IPGeolocationResponse,
    responses={
        status.HTTP_400_BAD_REQUEST: {
            "model": ErrorResponse,
            "description": "Invalid IP address",
        }
    },
    summary="Get specific IP geolocation",
    description="Returns geolocation and ASN information for the specified IP address",
    tags=["API"],
)
async def ip(
    ip_address: str,
    fields: Optional[str] = Query(
        None, description="Comma-separated list of fields to include or field number"
    ),
):
    """
    Return the GeoIP and ASN information for the given IP address.
    """
    if not is_valid_and_routable_ip(ip_address):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid IP address",
        )

    # Get the IP information
    ip_info = get_ip_information(ip_address)

    # Parse the fields parameter
    _, field_number = parse_fields_param(fields)

    # Filter the response based on the requested fields
    filtered_data = filter_response(ip_info, field_number)

    return JSONResponse(filtered_data)


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
    # Parse the field_name as a comma-separated list
    fields = [f.strip() for f in field_name.split(",") if f.strip() in FIELDS]

    # Get the number
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
    # Convert the number to field names
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

    # Download all datasets
    for dataset_name, (dataset_url, dataset_filename) in DATASETS.items():
        download_file(
            dataset_url, os.path.join(DATASETS_DIR, dataset_filename), dataset_name
        )

    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=5000,
        workers=16,
        server_header=False,
    )


if __name__ == "__main__":
    main()
