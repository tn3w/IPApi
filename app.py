#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Main FastAPI application for IPApi service.

This module sets up the FastAPI server with routes to provide geolocation and ASN information
for IP addresses. It includes endpoints for current client IP lookup, specific IP address lookup,
field management, and serves a web interface.
"""

from typing import Optional

import uvicorn
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.exception_handlers import http_exception_handler
from starlette.exceptions import HTTPException as StarletteHTTPException
from src.ip_address import is_valid_and_routable_ip
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
from src.handlers import (
    get_ip_address,
    get_ip_information,
    download_and_process_datasets,
)

templates = Jinja2Templates(directory="templates")

app = FastAPI(
    title="IPApi",
    description="API that returns GeoIP and ASN information for IP addresses",
    version="1.0.0",
)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index(request: Request):
    """
    Return the index HTML page.
    """
    return templates.TemplateResponse("index.html", {"request": request})


@app.get(
    "/json/self",
    response_model=IPAPIResponse,
    responses={
        status.HTTP_400_BAD_REQUEST: {
            "model": ErrorResponse,
            "description": "Invalid IP address",
        }
    },
    summary="Get current IP geolocation",
    description="Returns geolocation and ASN information for the current client IP address",
    tags=["JSON"],
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
    "/json/",
    response_model=IPAPIResponse,
    include_in_schema=False,
)
@app.get(
    "/json/{ip_address}",
    response_model=IPAPIResponse,
    responses={
        status.HTTP_400_BAD_REQUEST: {
            "model": ErrorResponse,
            "description": "Invalid IP address",
        }
    },
    summary="Get specific IP geolocation",
    description="Returns geolocation and ASN information for the specified IP address",
    tags=["JSON"],
)
def ip(request: Request,ip_address: Optional[str] = None):
    """
    Return the GeoIP and ASN information for the given IP address.
    """

    if not ip_address:
        ip_address = request.query_params.get("ip")

    if not ip_address or not is_valid_and_routable_ip(ip_address):
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


@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    """
    Custom handler for HTTP exceptions.
    For 404 errors, render the custom 404.html template.
    For other HTTP exceptions, use the default handler.
    """
    if exc.status_code == 404:
        return templates.TemplateResponse("404.html", {"request": request})
    return await http_exception_handler(request, exc)


def main() -> None:
    """
    Main function to run the app.
    """

    download_and_process_datasets()

    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=5000,
        workers=16,
        server_header=False,
    )


if __name__ == "__main__":
    main()
