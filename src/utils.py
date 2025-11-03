import os
import re
import glob
import json
import logging
import xml.etree.ElementTree as ET
import urllib.request
import urllib.error
from typing import Final, Any

import htmlmin
from csscompressor import compress as compress_css
from jsmin import jsmin
from pydantic import BaseModel, Field
from tld import get_fld

logger = logging.getLogger(__name__)


ALL_FIELDS: Final[list[str]] = [
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
    "is_anycast",
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

FIELDS_INCLUDING_ALL: Final[list[str]] = ALL_FIELDS + ["all"]

FIELD_BITS: Final[dict[str, int]] = {
    field: 1 << i for i, field in enumerate(FIELDS_INCLUDING_ALL)
}
ALL_FIELDS_MASK: Final[int] = (1 << len(FIELDS_INCLUDING_ALL)) - 1


def key_or_value_search(
    key: str | None, value: str | None, mapping: dict[str, str]
) -> tuple[str | None, str | None]:
    """Look up a key or value in a mapping."""
    if not key and not value:
        return None, None

    if key:
        return key, mapping.get(key)
    if value:
        return next((k for k, v in mapping.items() if v == value), None), value
    return None, None


def get_nested(record_value: dict[str, Any], *keys: str, default: Any = None) -> Any:
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
) -> tuple[str, dict[str, str]]:
    """Extract and process external script references."""
    script_pattern = re.compile(
        r'<script\s+src=["\']([^"\']+)["\'][^>]*></script>', re.DOTALL
    )
    matches: list[str] = script_pattern.findall(html_content)

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
) -> tuple[str, dict[str, str]]:
    """Extract and process external stylesheet references."""
    link_pattern = re.compile(
        r'<link\s+[^>]*href=["\']([^"\']+)["\'][^>]*rel=["\']stylesheet["\'][^>]*>',
        re.DOTALL,
    )
    link_pattern_alt = re.compile(
        r'<link\s+[^>]*rel=["\']stylesheet["\'][^>]*href=["\']([^"\']+)["\'][^>]*>',
        re.DOTALL,
    )

    matches: list[str] = link_pattern.findall(html_content) + link_pattern_alt.findall(
        html_content
    )

    styles: dict[str, str] = {}
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
    external_scripts: dict[str, str],
    external_styles: dict[str, str],
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

    def minify_script(match: re.Match[str]) -> str:
        script_content = match.group(1).strip()
        if not script_content or "src=" in match.group(0):
            return match.group(0)
        minified_js = jsmin(script_content).replace("\n", "")
        return f"<script>{minified_js}</script>"

    style_pattern = re.compile(r"<style[^>]*>(.*?)</style>", re.DOTALL)

    def minify_style(match: re.Match[str]) -> str:
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
) -> dict[str, str]:
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


def json_request(url: str) -> dict[str, Any]:
    """Make a JSON request to a URL."""
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(request, timeout=1) as response:
            return json.loads(response.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        logger.error("Error making JSON request to %s: %s", url, e)
        return {}


def xml_request(url: str) -> ET.Element | None:
    """Make an HTTP request and parse XML response."""
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(request, timeout=1) as response:
            xml_data = response.read().decode("utf-8")
            return ET.fromstring(xml_data)
    except Exception as e:
        logger.warning(f"XML request failed for {url}: {e}")
        return None


def any_field_in_list(fields: list[str], field_list: list[str]) -> bool:
    """Check if any field in the list is in the field list."""
    return any(field in field_list for field in fields)


def fields_to_number(fields: list[str]) -> int:
    """
    Convert a list of field names to a unique number.

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


def number_to_fields(number: int) -> list[str]:
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

    result: list[str] = []
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


def parse_fields_param(fields_param: str | None = None) -> list[str]:
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
    ip_address: str | None = Field(None, description="IP address")
    version: int | None = Field(None, description="IP address version")
    classification: str | None = Field(None, description="IP address classification")
    ipv4_address: str | None = Field(
        None,
        description="IPv4 address from DNS lookup or IPv4-mapped IPv6 address",
    )
    ipv6_address: str | None = Field(
        None,
        description="IPv6 address from DNS lookup",
    )
    hostname: str | None = Field(None, description="Hostname from DNS lookup")

    # Geographic information
    continent: str | None = Field(None, description="Continent name")
    continent_code: str | None = Field(None, description="Continent code")
    is_eu: bool | None = Field(
        None, description="If the country is in the European Union"
    )
    country: str | None = Field(None, description="Country name")
    country_code: str | None = Field(
        None, description="Country code (ISO 3166-1 alpha-2)"
    )
    region: str | None = Field(None, description="Region/state name")
    region_code: str | None = Field(None, description="Region/state code")
    city: str | None = Field(None, description="City name")
    district: str | None = Field(None, description="District name")
    postal_code: str | None = Field(None, description="Postal/ZIP code")
    latitude: float | None = Field(None, description="Latitude coordinate")
    longitude: float | None = Field(None, description="Longitude coordinate")
    timezone_name: str | None = Field(None, description="Timezone name")
    timezone_abbreviation: str | None = Field(None, description="Timezone abbreviation")
    utc_offset: int | None = Field(None, description="Timezone offset")
    utc_offset_str: str | None = Field(
        None, description="Timezone offset in string format"
    )
    dst_active: bool | None = Field(None, description="If the timezone is in DST")
    currency: str | None = Field(None, description="Currency code")

    # ASN information
    asn: str | None = Field(None, description="Autonomous System Number")
    as_name: str | None = Field(None, description="Autonomous System name")
    org: str | None = Field(None, description="Organization name")
    isp: str | None = Field(None, description="Internet Service Provider name")
    domain: str | None = Field(None, description="Domain name")
    prefix: str | None = Field(None, description="Prefix")
    date_allocated: str | None = Field(None, description="Date allocated")
    rir: str | None = Field(None, description="RIR")
    abuse_contact: str | None = Field(None, description="Abuse contact email")
    rpki_status: str | None = Field(None, description="RPKI validity status")
    rpki_roa_count: int | None = Field(
        None, description="Number of ROAs existing for the prefix"
    )
    is_anycast: bool | None = Field(None, description="If the IP is an anycast IP")

    # Abuse information
    is_vpn: bool | None = Field(None, description="If the IP is a VPN server")
    vpn_provider: str | None = Field(None, description="Name of the VPN server")
    is_proxy: bool | None = Field(None, description="If the IP is a proxy server")
    is_datacenter: bool | None = Field(None, description="If the IP is a data center")
    is_forum_spammer: bool | None = Field(
        None, description="If the IP is a forum spammer"
    )
    is_firehol: bool | None = Field(
        None, description="If the IP is in the Firehol Level 1 dataset"
    )
    is_tor_exit_node: bool | None = Field(
        None, description="If the IP is a Tor exit node"
    )
    fraud_score: float | None = Field(None, description="Fraud score")
    threat_type: str | None = Field(None, description="Threat type")

    class Config:
        """Config for the IPAPIResponse model."""

        json_schema_extra: dict[str, Any] = {
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
                "is_anycast": True,
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

    fields: list[str] = Field(..., description="List of all available fields")

    class Config:
        """Config for the FieldsListResponse model."""

        json_schema_extra: dict[str, Any] = {
            "example": {"fields": FIELDS_INCLUDING_ALL}
        }


class FieldToNumberResponse(BaseModel):
    """Response model for converting field names to a number."""

    fields: list[str] = Field(..., description="List of field names")
    number: int = Field(..., description="Numeric representation of the fields")

    class Config:
        """Config for the FieldToNumberResponse model."""

        json_schema_extra: dict[str, Any] = {
            "example": {
                "fields": ["ip", "country", "city"],
                "number": fields_to_number(["ip", "country", "city"]),
            }
        }


GENERAL_EMAIL_PROVIDERS = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "aol.com",
    "icloud.com",
    "protonmail.com",
    "mail.com",
    "yandex.com",
    "zoho.com",
    "fastmail.com",
    "tutanota.com",
    "gmx.com",
    "web.de",
    "mail.ru",
    "qq.com",
    "163.com",
    "126.com",
    "sina.com",
    "sohu.com",
    "mail.mil",
}


def extract_domain_from_email_or_hostname(input_string: str) -> str | None:
    """
    Extract the proper domain from an email address or hostname using the tld library.

    This function handles:
    - Multi-part TLDs like co.uk, com.au, etc.
    - Excludes general email providers (gmail.com, yahoo.com, etc.)

    Args:
        input_string: Email address or hostname to extract domain from

    Returns:
        The extracted domain or None if extraction fails or domain should be excluded
    """
    if not input_string:
        return None

    if "@" in input_string:
        domain_part = input_string.split("@")[-1].strip()
    else:
        domain_part = input_string.strip()

    if not domain_part:
        return None

    try:
        fld = get_fld(domain_part, fix_protocol=True, fail_silently=True)

        if fld and fld.lower() not in GENERAL_EMAIL_PROVIDERS:
            return fld.lower()
    except Exception:
        if "." in domain_part:
            parts = domain_part.lower().split(".")
            if len(parts) >= 2:
                fallback_domain = ".".join(parts[-2:])
                if fallback_domain not in GENERAL_EMAIL_PROVIDERS:
                    return fallback_domain

    return None
