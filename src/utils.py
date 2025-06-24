import os
import re
import glob
import json
import logging
import urllib.request
import urllib.error
from typing import Optional, Final, Tuple, List, Dict, Any

import htmlmin
from csscompressor import compress as compress_css
from jsmin import jsmin
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


ALL_FIELDS: Final[List[str]] = [
    # General information
    "ip_address",
    "version",
    "classification",
    "hostname",
    "ipv4_address",
    "ipv6_address",
    # Geographic information
    "continent",
    "continent_code",
    "country",
    "country_code",
    "is_eu",
    "region",
    "region_code",
    "city",
    "district",
    "postal_code",
    "latitude",
    "longitude",
    "timezone_name",
    "timezone_abbreviation",
    "utc_offset",
    "utc_offset_str",
    "dst_active",
    "currency",
    # Network information
    "asn",
    "as_name",
    "org",
    "isp",
    "domain",
    "prefix",
    "date_allocated",
    "rir",
    "abuse_contact",
    "rpki_status",
    "rpki_roa_count",
    # Abuse information
    "is_vpn",
    "vpn_provider",
    "is_proxy",
    "is_firehol",
    "is_datacenter",
    "is_forum_spammer",
    "is_tor_exit_node",
    "fraud_score",
    "threat_type",
]

FIELDS_INCLUDING_ALL: Final[List[str]] = ALL_FIELDS + ["all"]

FIELD_BITS: Final[Dict[str, int]] = {
    field: 1 << i for i, field in enumerate(FIELDS_INCLUDING_ALL)
}
ALL_FIELDS_MASK: Final[int] = (1 << len(FIELDS_INCLUDING_ALL)) - 1


def key_or_value_search(
    key: Optional[str], value: Optional[str], mapping: Dict[str, str]
) -> Tuple[Optional[str], Optional[str]]:
    """Look up a key or value in a mapping."""
    if not key and not value:
        return None, None

    if key:
        return key, mapping.get(key)
    if value:
        return next((k for k, v in mapping.items() if v == value), None), value
    return None, None


def get_nested(record_value: Any, *keys: str, default: Any = None) -> Any:
    """Safely get a nested value from a dictionary."""
    current = record_value
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def load_dotenv(env_file=".env"):
    """Load environment variables from a .env file into os.environ."""

    if not os.path.exists(env_file):
        return

    with open(env_file, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = [part.strip() for part in line.split("=", 1)]
                if (value.startswith('"') and value.endswith('"')) or (
                    value.startswith("'") and value.endswith("'")
                ):
                    value = value[1:-1]
                os.environ[key] = value


def extract_external_scripts(
    html_content: str, base_path: str, scripts_dir: str = "scripts"
) -> Tuple[str, Dict[str, str]]:
    """Extract and process external script references."""
    script_pattern = re.compile(
        r'<script\s+src=["\']([^"\']+)["\'][^>]*></script>', re.DOTALL
    )
    matches = script_pattern.findall(html_content)

    scripts = {}
    modified_html = html_content

    for src in matches:
        try:
            if src.startswith(("http:", "https:")):
                continue

            script_path = os.path.join(scripts_dir, os.path.basename(src))
            if not os.path.exists(script_path):
                script_path = os.path.join(base_path, src)

            if os.path.exists(script_path):
                with open(script_path, "r", encoding="utf-8") as f:
                    script_content = f.read()
                    scripts[src] = script_content

                placeholder = f"<!-- EXTERNAL_SCRIPT_PLACEHOLDER_{src} -->"
                original_tag = f'<script src="{src}"></script>'
                modified_html = modified_html.replace(original_tag, placeholder)
        except Exception as e:
            logger.error("Error processing script %s: %s", src, e)

    return modified_html, scripts


def extract_external_styles(
    html_content: str, base_path: str, styles_dir: str = "styles"
) -> Tuple[str, Dict[str, str]]:
    """Extract and process external stylesheet references."""
    link_pattern = re.compile(
        r'<link\s+[^>]*href=["\']([^"\']+)["\'][^>]*rel=["\']stylesheet["\'][^>]*>',
        re.DOTALL,
    )
    link_pattern_alt = re.compile(
        r'<link\s+[^>]*rel=["\']stylesheet["\'][^>]*href=["\']([^"\']+)["\'][^>]*>',
        re.DOTALL,
    )

    matches = link_pattern.findall(html_content) + link_pattern_alt.findall(
        html_content
    )

    styles = {}
    modified_html = html_content

    for href in matches:
        try:
            if href.startswith(("http:", "https:")):
                continue

            style_path = os.path.join(styles_dir, os.path.basename(href))
            if not os.path.exists(style_path):
                style_path = os.path.join(base_path, href)

            if os.path.exists(style_path):
                with open(style_path, "r", encoding="utf-8") as f:
                    style_content = f.read()
                    styles[href] = style_content

                placeholder = f"<!-- EXTERNAL_STYLE_PLACEHOLDER_{href} -->"

                pattern1 = f'<link\\s+href="{href}"\\s+rel="stylesheet"[^>]*>'
                pattern2 = f'<link\\s+rel="stylesheet"\\s+href="{href}"[^>]*>'

                link_tags = re.findall(pattern1, html_content) + re.findall(
                    pattern2, html_content
                )

                for tag in link_tags:
                    modified_html = modified_html.replace(tag, placeholder)
        except Exception as e:
            logger.error("Error processing stylesheet %s: %s", href, e)

    return modified_html, styles


def inline_external_resources(
    html_content: str,
    external_scripts: Dict[str, str],
    external_styles: Dict[str, str],
) -> str:
    """Replace external resource references with inlined minified content."""
    result = html_content

    for src, content in external_scripts.items():
        placeholder = f"<!-- EXTERNAL_SCRIPT_PLACEHOLDER_{src} -->"
        if placeholder in result:
            result = result.replace(placeholder, f"<script>{content}</script>")

    for href, content in external_styles.items():
        placeholder = f"<!-- EXTERNAL_STYLE_PLACEHOLDER_{href} -->"
        if placeholder in result:
            result = result.replace(placeholder, f"<style>{content}</style>")

    return result


def minify_inline_resources(html_content: str) -> str:
    """Minify inline CSS and JavaScript within style and script tags."""
    script_pattern = re.compile(r"<script[^>]*>(.*?)</script>", re.DOTALL)

    def minify_script(match):
        script_content = match.group(1).strip()
        if not script_content or "src=" in match.group(0):
            return match.group(0)
        minified_js = jsmin(script_content).replace("\n", "")
        return f"<script>{minified_js}</script>"

    style_pattern = re.compile(r"<style[^>]*>(.*?)</style>", re.DOTALL)

    def minify_style(match):
        style_content = match.group(1).strip()
        if not style_content:
            return match.group(0)
        minified_css = compress_css(style_content)
        return f"<style>{minified_css}</style>"

    result = script_pattern.sub(minify_script, html_content)
    result = style_pattern.sub(minify_style, result)

    return result


def minify_html_content(
    content: str,
    base_path: str,
    styles_dir: str = "styles",
    scripts_dir: str = "scripts",
) -> str:
    """Minify HTML content with special handling for external CSS/JS."""
    content_with_minified_inline = minify_inline_resources(content)

    content_with_external_script_placeholders, external_scripts = (
        extract_external_scripts(content_with_minified_inline, base_path, scripts_dir)
    )

    content_with_all_placeholders, external_styles = extract_external_styles(
        content_with_external_script_placeholders, base_path, styles_dir
    )

    minified_html = htmlmin.minify(
        content_with_all_placeholders,
        remove_comments=False,
        remove_empty_space=True,
        reduce_boolean_attributes=True,
    )

    minified_external_scripts = {
        src: jsmin(script).replace("\n", "") for src, script in external_scripts.items()
    }
    minified_external_styles = {
        href: compress_css(style) for href, style in external_styles.items()
    }

    result_with_all = inline_external_resources(
        minified_html, minified_external_scripts, minified_external_styles
    )

    final_result = htmlmin.minify(
        result_with_all,
        remove_comments=True,
        remove_empty_space=True,
        reduce_boolean_attributes=True,
    )

    return final_result


def load_templates(
    templates_dir: str = "templates",
    styles_dir: str = "styles",
    scripts_dir: str = "scripts",
) -> Dict[str, str]:
    """
    Load and minify all HTML templates.

    Returns:
        Dictionary mapping template filenames to minified HTML content
    """
    template_files = glob.glob(os.path.join(templates_dir, "*.html"))
    minified_templates = {}

    for file_path in template_files:
        filename = os.path.basename(file_path)
        base_path = os.path.dirname(file_path)

        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        minified_content = minify_html_content(
            content, base_path, styles_dir, scripts_dir
        )
        minified_templates[filename] = minified_content

    return minified_templates


def json_request(url: str) -> Dict[str, Any]:
    """Make a JSON request to a URL."""
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(request, timeout=1) as response:
            return json.loads(response.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        logger.error("Error making JSON request to %s: %s", url, e)
        return {}


def any_field_in_list(fields: list[str], field_list: list[str]) -> bool:
    """Check if any field in the list is in the field list."""
    return any(field in field_list for field in fields)


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
        return FIELDS_INCLUDING_ALL.copy()

    result: List[str] = []
    for field, bit in FIELD_BITS.items():
        if number & bit:
            result.append(field)

    if "all" in result:
        try:
            result.remove("all")
            result.extend(ALL_FIELDS)
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
        return ALL_FIELDS.copy()

    try:
        number = int(fields_param)
        return number_to_fields(number)
    except ValueError:
        fields = [
            f.strip()
            for f in fields_param.split(",")
            if f.strip() in FIELDS_INCLUDING_ALL
        ]
        if not fields:
            return ALL_FIELDS.copy()
        if "all" in fields:
            try:
                fields.remove("all")
                fields.extend(ALL_FIELDS)
            except ValueError:
                pass
        return fields


class ErrorResponse(BaseModel):
    """Error response model."""

    detail: str = Field(..., description="Error description")


class IPAPIResponse(BaseModel):
    """IP API response model."""

    # General information
    ip_address: Optional[str] = Field(None, description="IP address")
    version: Optional[int] = Field(None, description="IP address version")
    classification: Optional[str] = Field(None, description="IP address classification")
    ipv4_address: Optional[str] = Field(
        None,
        description="IPv4 address from DNS lookup or IPv4-mapped IPv6 address",
    )
    ipv6_address: Optional[str] = Field(
        None,
        description="IPv6 address from DNS lookup",
    )
    hostname: Optional[str] = Field(None, description="Hostname from DNS lookup")

    # Geographic information
    continent: Optional[str] = Field(None, description="Continent name")
    continent_code: Optional[str] = Field(None, description="Continent code")
    is_eu: Optional[bool] = Field(
        None, description="If the country is in the European Union"
    )
    country: Optional[str] = Field(None, description="Country name")
    country_code: Optional[str] = Field(
        None, description="Country code (ISO 3166-1 alpha-2)"
    )
    region: Optional[str] = Field(None, description="Region/state name")
    region_code: Optional[str] = Field(None, description="Region/state code")
    city: Optional[str] = Field(None, description="City name")
    district: Optional[str] = Field(None, description="District name")
    postal_code: Optional[str] = Field(None, description="Postal/ZIP code")
    latitude: Optional[float] = Field(None, description="Latitude coordinate")
    longitude: Optional[float] = Field(None, description="Longitude coordinate")
    timezone_name: Optional[str] = Field(None, description="Timezone name")
    timezone_abbreviation: Optional[str] = Field(
        None, description="Timezone abbreviation"
    )
    utc_offset: Optional[int] = Field(None, description="Timezone offset")
    utc_offset_str: Optional[str] = Field(
        None, description="Timezone offset in string format"
    )
    dst_active: Optional[bool] = Field(None, description="If the timezone is in DST")
    currency: Optional[str] = Field(None, description="Currency code")

    # ASN information
    asn: Optional[str] = Field(None, description="Autonomous System Number")
    as_name: Optional[str] = Field(None, description="Autonomous System name")
    org: Optional[str] = Field(None, description="Organization name")
    isp: Optional[str] = Field(None, description="Internet Service Provider name")
    domain: Optional[str] = Field(None, description="Domain name")
    prefix: Optional[str] = Field(None, description="Prefix")
    date_allocated: Optional[str] = Field(None, description="Date allocated")
    rir: Optional[str] = Field(None, description="RIR")
    abuse_contact: Optional[str] = Field(None, description="Abuse contact email")
    rpki_status: Optional[str] = Field(None, description="RPKI validity status")
    rpki_roa_count: Optional[int] = Field(
        None, description="Number of ROAs existing for the prefix"
    )

    # Abuse information
    is_vpn: Optional[bool] = Field(None, description="If the IP is a VPN server")
    vpn_provider: Optional[str] = Field(None, description="Name of the VPN server")
    is_proxy: Optional[bool] = Field(None, description="If the IP is a proxy server")
    is_datacenter: Optional[bool] = Field(
        None, description="If the IP is a data center"
    )
    is_forum_spammer: Optional[bool] = Field(
        None, description="If the IP is a forum spammer"
    )
    is_firehol: Optional[bool] = Field(
        None, description="If the IP is in the Firehol Level 1 dataset"
    )
    is_tor_exit_node: Optional[bool] = Field(
        None, description="If the IP is a Tor exit node"
    )
    fraud_score: Optional[float] = Field(None, description="Fraud score")
    threat_type: Optional[str] = Field(None, description="Threat type")

    class Config:
        """Config for the IPAPIResponse model."""

        json_schema_extra = {
            "example": {
                "ip_address": "1.1.1.1",
                "version": 4,
                "classification": "public",
                "ipv4_address": "1.1.1.1",
                "ipv6_address": "2606:4700:4700::1001",
                "hostname": "one.one.one.one",
                "continent": "Oceania",
                "continent_code": "OC",
                "is_eu": False,
                "country": "Australia",
                "country_code": "AU",
                "region": "Queensland",
                "region_code": "QLD",
                "city": "Brisbane",
                "district": None,
                "postal_code": "4007",
                "latitude": -27.467541,
                "longitude": 153.028091,
                "timezone_name": "Australia/Brisbane",
                "timezone_abbreviation": "AEST",
                "utc_offset": 36000,
                "utc_offset_str": "UTC+10:00",
                "dst_active": False,
                "currency": "AUD",
                "asn": "13335",
                "as_name": "CLOUDFLARENET",
                "org": "Cloudflare, Inc.",
                "isp": "Cloudflare",
                "domain": "cloudflare.com",
                "prefix": "1.1.1.0/24",
                "date_allocated": "2018-04-01",
                "rir": "apnic",
                "abuse_contact": "abuse@cloudflare.com",
                "rpki_status": "valid",
                "rpki_roa_count": 1,
                "is_vpn": False,
                "vpn_provider": None,
                "is_proxy": False,
                "is_datacenter": False,
                "is_forum_spammer": False,
                "is_firehol": False,
                "is_tor_exit_node": False,
                "fraud_score": 0.0,
                "threat_type": None,
            }
        }


class FieldsListResponse(BaseModel):
    """Response model for the field list endpoint."""

    fields: List[str] = Field(..., description="List of all available fields")

    class Config:
        """Config for the FieldsListResponse model."""

        json_schema_extra = {"example": {"fields": FIELDS_INCLUDING_ALL}}


class FieldToNumberResponse(BaseModel):
    """Response model for converting field names to a number."""

    fields: List[str] = Field(..., description="List of field names")
    number: int = Field(..., description="Numeric representation of the fields")

    class Config:
        """Config for the FieldToNumberResponse model."""

        json_schema_extra = {
            "example": {
                "fields": ["ip", "country", "city"],
                "number": fields_to_number(["ip", "country", "city"]),
            }
        }
