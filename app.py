import logging
from pathlib import Path
from typing import Final, Dict
import os

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, Response, JSONResponse

from src.memory_server import MemoryServer, MemoryDataStore
from src.ip_address import get_ip_info
from src.utils import (
    IPAPIResponse,
    FieldsListResponse,
    FieldToNumberResponse,
    FIELDS_INCLUDING_ALL,
    fields_to_number,
    load_dotenv,
    load_templates,
)

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

MEMORY_SERVER: Final[MemoryServer] = MemoryServer.get_instance()
MEMORY_SERVER.start()


def get_memory_store() -> MemoryDataStore:
    """Dependency to get the memory data store client."""
    client = MEMORY_SERVER.get_client()
    return client.get_data_store()


MEMORY_STORE = get_memory_store()
MEMORY_STORE.load_datasets()

TEMPLATES: Final[Dict[str, str]] = load_templates()

STATIC_DIR = Path("static")
ROBOTS_TXT = (
    (STATIC_DIR / "robots.txt").read_text()
    if (STATIC_DIR / "robots.txt").exists()
    else ""
)
SECURITY_TXT = (
    (STATIC_DIR / "security.txt").read_text()
    if (STATIC_DIR / "security.txt").exists()
    else ""
)
FAVICON = (
    (STATIC_DIR / "favicon.ico").read_bytes()
    if (STATIC_DIR / "favicon.ico").exists()
    else None
)

app = FastAPI(
    title="IPApi",
    description="API that returns information about IP addresses and hostnames",
    version="1.0.0",
)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def index(request: Request):
    """
    Return the index template.

    Args:
        request: The request object

    Returns:
        The index template
    """
    index_template = TEMPLATES.get("index.html")
    if not index_template:
        raise HTTPException(status_code=404, detail="Index template not found")

    content = index_template.replace("BASE_URL", str(request.base_url))
    response = HTMLResponse(content=content)

    response.headers["Cache-Control"] = "public, max-age=31536000, immutable"

    return response


@app.post("/", response_class=HTMLResponse, include_in_schema=False)
def index_post(request: Request):
    """
    Return the index template.
    """
    ip_address = request.form.get("ip")
    if not ip_address:
        raise HTTPException(status_code=400, detail="IP address is required")
    return get_ip_address_info(ip_address, request)


@app.exception_handler(404)
async def not_found_exception_handler(request: Request, exc: HTTPException):
    """
    Handle 404 not found exceptions.

    Args:
        request: The request object
        exc: The exception

    Returns:
        The 404 template
    """
    not_found_template = TEMPLATES.get("404.html")
    if not not_found_template:
        raise HTTPException(status_code=404, detail="404 - Not found.")

    response = HTMLResponse(
        content=not_found_template.replace("BASE_URL", str(request.base_url)),
        status_code=404,
    )

    if hasattr(exc, "detail") and exc.detail:
        response.headers["X-Error"] = exc.detail

    return response


@app.get("/robots.txt", include_in_schema=False)
def robots_txt():
    """
    Return the robots.txt file.
    """
    if not ROBOTS_TXT:
        raise HTTPException(status_code=404, detail="Robots.txt not found")

    response = Response(content=ROBOTS_TXT, media_type="text/plain")
    response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return response


@app.get("/.well-known/security.txt", include_in_schema=False)
def security_txt():
    """
    Return the security.txt file.
    """
    if not SECURITY_TXT:
        raise HTTPException(status_code=404, detail="Security.txt not found")

    response = Response(content=SECURITY_TXT, media_type="text/plain")
    response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return response


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    """
    Return the favicon.ico file.
    """
    if not FAVICON:
        raise HTTPException(status_code=404, detail="Favicon not found")

    response = Response(content=FAVICON, media_type="image/x-icon")
    response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return response


# ------------------------------------------------------------
# API Routes
# ------------------------------------------------------------


@app.get(
    "/self",
    response_model=IPAPIResponse,
    summary="Get information about the current IP address",
    description=(
        "Return detailed information about your own IP address,"
        " working like /{ip_address} but for your own IP address."
    ),
    tags=["JSON"],
)
def get_self_ip_address_info(request: Request):
    """
    Return information about the current IP address.
    """
    if not request.client:
        raise HTTPException(status_code=404, detail="Client IP address not found")
    ip_info = get_ip_info(request.client.host, request, MEMORY_STORE)
    if not ip_info:
        raise HTTPException(status_code=404, detail="Invalid IP address")
    return JSONResponse(content=ip_info)


@app.get(
    "/fields",
    response_model=FieldsListResponse,
    summary="Get a list of all available fields",
    description=(
        "Returns a list of all available fields that can be used in the /{ip_address} endpoint."
    ),
    tags=["FIELDS"],
)
def get_fields_list():
    """
    Return a list of all available fields.
    """
    return FieldsListResponse(fields=FIELDS_INCLUDING_ALL)


@app.get(
    "/fields/number/{fields}",
    response_model=FieldToNumberResponse,
    summary="Get the number representation of a list of fields",
    description=(
        "Returns the number representation of a list of fields."
        " This is useful for requests with low payload size."
    ),
    tags=["FIELDS"],
)
def get_fields_number(fields: str):
    """
    Return the number representation of a list of fields.
    """
    fields = fields.split(",")
    return FieldToNumberResponse(fields=fields, number=fields_to_number(fields))


@app.get(
    "/{ip_address}",
    response_model=IPAPIResponse,
    summary="Get information about a specific IP address",
    description=(
        "Returns comprehensive data about the specified IP address, including geographic details"
        " (continent, country, region, city, coordinates), network information"
        " (ASN, ISP, organization), and security assessment (proxy/VPN detection, threat scoring)."
        " Supports both IPv4 and IPv6 addresses as well as hostnames."
    ),
    tags=["JSON"],
)
def get_ip_address_info(ip_address: str, request: Request):
    """
    Return information about an IP address.

    Args:
        ip_address: The IP address to get information about

    Returns:
        Information about the IP address
    """
    ip_info = get_ip_info(ip_address, request, MEMORY_STORE)
    if not ip_info:
        raise HTTPException(status_code=404, detail="Invalid IP address")
    return JSONResponse(content=ip_info)


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------


def main() -> None:
    """
    Run the application.
    """
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "5000"))
    workers = int(os.getenv("WORKERS", "16"))
    logger.info(
        "Starting API server at http://%s:%d with %d workers", host, port, workers
    )
    uvicorn.run(
        "app:app",
        host=host,
        port=port,
        workers=workers,
        server_header=False,
    )


if __name__ == "__main__":
    main()
