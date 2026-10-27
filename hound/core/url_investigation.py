"""Passive URL threat intelligence for Hound Sniffer."""

import asyncio
import base64
import ipaddress
import time

from urllib.parse import urlsplit

import httpx

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from hound.core.domains import is_domain
from hound.providers.virustotal import get_api_key as vt_key
from hound.providers.abusech import get_key as abusech_key


def validate_url(url):
    """Accept public HTTP(S) URLs without credentials."""

    if len(url) > 2048:
        raise ValueError("URL exceeds 2048 characters")

    parsed = urlsplit(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported")

    if not parsed.hostname:
        raise ValueError("URL hostname missing")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not supported")

    host = parsed.hostname

    try:
        address = ipaddress.ip_address(host)

        if not address.is_global:
            raise ValueError("Non-global IP addresses are not supported")

    except ValueError as error:
        if "Non-global" in str(error):
            raise

        if not is_domain(host):
            raise ValueError("Invalid public hostname") from error

    try:
        parsed.port
    except ValueError as error:
        raise ValueError("Invalid URL port") from error

    return url


async def check_virustotal(url):
    """Retrieve an existing VirusTotal URL report."""

    key = vt_key()

    if not key:
        return {"success": False, "error": "API key missing"}

    url_id = base64.urlsafe_b64encode(
        url.encode("utf-8")
    ).decode("ascii").rstrip("=")

    endpoint = (
        "https://www.virustotal.com/api/v3/urls/"
        + url_id
    )

    try:
        async with httpx.AsyncClient(timeout=8) as client:
            response = await client.get(
                endpoint,
                headers={"x-apikey": key},
            )

        if response.status_code == 404:
            return {
                "success": False,
                "error": "No existing URL report",
            }

        response.raise_for_status()

        attributes = response.json()["data"]["attributes"]
        stats = attributes.get("last_analysis_stats") or {}

        return {
            "success": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation"),
            "categories": attributes.get("categories") or {},
        }

    except httpx.HTTPStatusError as error:
        return {
            "success": False,
            "error": f"HTTP {error.response.status_code}",
        }

    except (httpx.RequestError, ValueError, KeyError, TypeError):
        return {
            "success": False,
            "error": "VirusTotal lookup unavailable",
        }


async def check_urlhaus(url):
    """Check whether URLhaus tracks the exact URL."""

    key = abusech_key()

    if not key:
        return {"success": False, "error": "Auth-Key missing"}

    try:
        async with httpx.AsyncClient(timeout=8) as client:
            response = await client.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                headers={"Auth-Key": key},
                data={"url": url},
            )

        response.raise_for_status()
        data = response.json()

        status = data.get("query_status")

        if status == "no_results":
            return {"success": True, "found": False}

        if status != "ok":
            return {
                "success": False,
                "error": f"URLhaus status: {str(status)[:60]}",
            }

        return {
            "success": True,
            "found": True,
            "url_status": data.get("url_status"),
            "threat": data.get("threat"),
            "date_added": data.get("date_added"),
            "reference": data.get("urlhaus_reference"),
        }

    except httpx.HTTPStatusError as error:
        return {
            "success": False,
            "error": f"HTTP {error.response.status_code}",
        }

    except (httpx.RequestError, ValueError, TypeError):
        return {
            "success": False,
            "error": "URLhaus lookup unavailable",
        }


async def investigate_url(url):
    """Investigate URL against both providers concurrently."""

    validate_url(url)

    start = time.perf_counter()

    vt, uh = await asyncio.gather(
        check_virustotal(url),
        check_urlhaus(url),
        return_exceptions=True,
    )

    if isinstance(vt, BaseException):
        vt = {"success": False, "error": "Provider failure"}

    if isinstance(uh, BaseException):
        uh = {"success": False, "error": "Provider failure"}

    malicious = vt.get("malicious") or 0
    suspicious = vt.get("suspicious") or 0

    if uh.get("found") is True:
        verdict = "URLHAUS IOC MATCH - INVESTIGATE"
    elif malicious >= 3:
        verdict = "MULTIPLE VT DETECTIONS - INVESTIGATE"
    elif malicious or suspicious:
        verdict = "VT DETECTION - REVIEW"
    elif vt.get("success") and uh.get("success"):
        verdict = "NO POSITIVE SIGNALS IN QUERIED SOURCES"
    else:
        verdict = "UNKNOWN - PARTIAL INTELLIGENCE"

    return {
        "url": url,
        "virustotal": vt,
        "urlhaus": uh,
        "verdict": verdict,
        "elapsed": round(time.perf_counter() - start, 2),
    }


def build_url_report(report):
    """Render URL investigation as a Rich report."""

    table = Table(
        show_header=False,
        expand=True,
    )

    table.add_column("Field", style="cyan")
    table.add_column("Result")

    vt = report["virustotal"]
    uh = report["urlhaus"]

    table.add_row("URL", Text(report["url"]))
    table.add_row("Verdict", report["verdict"])

    if vt.get("success"):
        for field in (
            "malicious",
            "suspicious",
            "harmless",
            "undetected",
            "reputation",
        ):
            value = vt.get(field)
            table.add_row(
                "VirusTotal " + field.title(),
                "Unknown" if value is None else str(value),
            )
    else:
        table.add_row(
            "VirusTotal",
            vt.get("error", "Unavailable"),
        )

    if uh.get("success"):
        table.add_row(
            "URLhaus Match",
            "YES" if uh.get("found") else "No match",
        )

        if uh.get("found"):
            for field in (
                "threat",
                "url_status",
                "date_added",
                "reference",
            ):
                value = uh.get(field)
                table.add_row(
                    "URLhaus " + field.replace("_", " ").title(),
                    "Unknown" if value is None else str(value),
                )
    else:
        table.add_row(
            "URLhaus",
            uh.get("error", "Unavailable"),
        )

    table.add_row(
        "Investigation Time",
        f"{report['elapsed']}s",
    )

    return Group(
        Panel(
            table,
            title="HOUND URL INTELLIGENCE",
            border_style="cyan",
        ),
        Panel(
            Text(
                "URL reputation is preliminary. "
                "A single detection can be a false positive. "
                "No matches do not prove safety.\n"
                "Hound has not visited the target URL."
            ),
            title="ANALYST NOTES",
            border_style="yellow",
        ),
    )
