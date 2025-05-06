"""
This is a simple API that returns the GeoIP and ASN information for the given IP address.
"""

from typing import Optional
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from src.ip_address import is_valid_and_routable_ip
from src.schemas import IPGeolocationResponse, ErrorResponse

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
)
def self(request: Request):
    """
    Return the GeoIP and ASN information for the current IP address.
    """
    ip_address = get_ip_address(request)
    if not ip_address:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Not a valid IP address"
        )

    ip_information = get_ip_information(ip_address)
    return ip_information


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
)
def ip(ip_address: str):
    """
    Return the GeoIP and ASN information for the given IP address.
    """
    if not is_valid_and_routable_ip(ip_address):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Not a valid IP address"
        )

    return get_ip_information(ip_address)
