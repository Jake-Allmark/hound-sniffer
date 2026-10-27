"""Passive file hash intelligence for Hound Sniffer."""

import asyncio
import re
import time
from datetime import datetime, timezone

import httpx

from rich.console import Group
from rich.panel import Panel
from rich.table import Table

from hound.providers.virustotal import get_api_key as vt_key
from hound.providers.abusech import get_key as abusech_key


def classify_hash(value):
    """Validate and classify a file hash."""

    value = value.strip()

    if not re.fullmatch(r"[a-fA-F0-9]+", value):
        raise ValueError("Hash must contain hexadecimal characters")

    types = {
        32: "MD5",
        40: "SHA-1",
        64: "SHA-256",
    }

    if len(value) not in types:
        raise ValueError("Unsupported hash length")

    return types[len(value)]


def format_date(value):
    if not isinstance(value, (int, float)):
        return "Unknown"

    try:
        return datetime.fromtimestamp(
            value, timezone.utc
        ).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, OverflowError, OSError):
        return "Unknown"


def number(value):
    """Accept only valid non-negative integer counts."""

    if isinstance(value, bool) or not isinstance(value, int):
        return None

    return value if value >= 0 else None


async def check_virustotal(file_hash):
    """Look up an existing VirusTotal file report."""

    key = vt_key()

    if not key:
        return {
            "success": False,
            "error": "VirusTotal API key missing",
        }

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(
                "https://www.virustotal.com/api/v3/files/"
                + file_hash,
                headers={"x-apikey": key},
            )

        if response.status_code == 404:
            return {
                "success": True,
                "found": False,
            }

        response.raise_for_status()

        attributes = response.json()["data"]["attributes"]
        stats = attributes.get("last_analysis_stats") or {}

        malicious = number(stats.get("malicious"))
        suspicious = number(stats.get("suspicious"))

        if malicious is None or suspicious is None:
            raise ValueError("Missing detection statistics")

        return {
            "success": True,
            "found": True,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": number(stats.get("harmless")),
            "undetected": number(stats.get("undetected")),
            "reputation": attributes.get("reputation"),
            "file_type": attributes.get("type_description"),
            "file_size": attributes.get("size"),
            "sha256": attributes.get("sha256"),
            "meaningful_name": attributes.get("meaningful_name"),
            "first_seen": format_date(
                attributes.get("first_submission_date")
            ),
            "last_analysis": format_date(
                attributes.get("last_analysis_date")
            ),
        }

    except httpx.HTTPStatusError as error:
        status = error.response.status_code

        if status == 429:
            message = "API rate limit exceeded"
        elif status in (401, 403):
            message = "API authentication or access failed"
        else:
            message = f"HTTP {status}"

        return {"success": False, "error": message}

    except (httpx.RequestError, ValueError, KeyError, TypeError):
        return {
            "success": False,
            "error": "VirusTotal lookup unavailable",
        }


async def check_malwarebazaar(file_hash):
    """Search known malware samples by hash."""

    key = abusech_key()

    if not key:
        return {
            "success": False,
            "error": "abuse.ch Auth-Key missing",
        }

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.post(
                "https://mb-api.abuse.ch/api/v1/",
                headers={"Auth-Key": key},
                data={
                    "query": "get_info",
                    "hash": file_hash,
                },
            )

        response.raise_for_status()

        data = response.json()
        status = data.get("query_status")

        if status == "hash_not_found":
            return {
                "success": True,
                "found": False,
            }

        if status != "ok":
            return {
                "success": False,
                "error": f"MalwareBazaar status: {str(status)[:60]}",
            }

        records = data.get("data")

        if not isinstance(records, list) or not records:
            raise ValueError("Missing malware records")

        sample = records[0]

        if not isinstance(sample, dict):
            raise ValueError("Invalid malware record")

        return {
            "success": True,
            "found": True,
            "sha256": sample.get("sha256_hash"),
            "malware_family": sample.get("signature"),
            "file_type": sample.get("file_type"),
            "file_size": sample.get("file_size"),
            "first_seen": sample.get("first_seen"),
            "last_seen": sample.get("last_seen"),
            "tags": sample.get("tags") or [],
        }

    except httpx.HTTPStatusError as error:
        return {
            "success": False,
            "error": f"HTTP {error.response.status_code}",
        }

    except (httpx.RequestError, ValueError, TypeError):
        return {
            "success": False,
            "error": "MalwareBazaar lookup unavailable",
        }


def assess_hash(vt, bazaar):
    """Calculate a provisional detection-evidence score."""

    vt_found = vt.get("success") and vt.get("found")
    mb_found = bazaar.get("success") and bazaar.get("found")

    malicious = vt.get("malicious") if vt_found else 0
    suspicious = vt.get("suspicious") if vt_found else 0

    score = (
        min(malicious, 6) * 10
        + min(suspicious, 5) * 3
        + (45 if mb_found else 0)
    )

    score = min(100, score)

    sources_available = sum((
        vt.get("success") is True,
        bazaar.get("success") is True,
    ))

    evidence_found = (
        (vt_found and (malicious > 0 or suspicious > 0))
        or mb_found
    )

    if sources_available == 0:
        return {
            "score": None,
            "verdict": "INSUFFICIENT INTELLIGENCE",
            "confidence": "UNKNOWN",
        }

    if not evidence_found:
        verdict = (
            "NO POSITIVE SIGNALS IN QUERIED SOURCES"
            if sources_available == 2
            else "UNKNOWN - PARTIAL COVERAGE"
        )
        score = None

    elif mb_found and malicious >= 3:
        verdict = "CORROBORATED MALWARE INTELLIGENCE"

    elif mb_found:
        verdict = "KNOWN MALWARE SAMPLE MATCH"

    elif malicious >= 3:
        verdict = "MULTIPLE MALICIOUS DETECTIONS"

    else:
        verdict = "DETECTION REQUIRES REVIEW"

    confidence = (
        "MULTI-SOURCE COVERAGE"
        if sources_available == 2
        else "LIMITED - SINGLE SOURCE"
    )

    return {
        "score": score,
        "verdict": verdict,
        "confidence": confidence,
    }


async def investigate_hash(file_hash):
    """Query VirusTotal and MalwareBazaar concurrently."""

    hash_type = classify_hash(file_hash)
    file_hash = file_hash.lower()

    start = time.perf_counter()

    vt, bazaar = await asyncio.gather(
        check_virustotal(file_hash),
        check_malwarebazaar(file_hash),
        return_exceptions=True,
    )

    if isinstance(vt, BaseException):
        vt = {"success": False, "error": "Provider failure"}

    if isinstance(bazaar, BaseException):
        bazaar = {"success": False, "error": "Provider failure"}

    return {
        "hash": file_hash,
        "hash_type": hash_type,
        "virustotal": vt,
        "malwarebazaar": bazaar,
        "assessment": assess_hash(vt, bazaar),
        "elapsed": round(time.perf_counter() - start, 2),
    }


def build_hash_report(report):
    """Build a Rich report for file hash intelligence."""

    vt = report["virustotal"]
    mb = report["malwarebazaar"]
    assessment = report["assessment"]

    def show(value):
        return "Unknown" if value is None else str(value)

    overview = Table(show_header=False, expand=True)
    overview.add_column("Field", style="cyan")
    overview.add_column("Value")

    overview.add_row("Hash", report["hash"])
    overview.add_row("Type", report["hash_type"])
    overview.add_row("Verdict", assessment["verdict"])

    overview.add_row(
        "Threat Score (experimental)",
        (
            f"{assessment['score']}/100"
            if assessment["score"] is not None
            else "N/A"
        ),
    )

    overview.add_row(
        "Evidence Coverage",
        assessment["confidence"],
    )

    overview.add_row(
        "Investigation Time",
        f"{report['elapsed']}s",
    )

    vt_table = Table(show_header=False, expand=True)
    vt_table.add_column("Field", style="magenta")
    vt_table.add_column("Value")

    if vt.get("success") and vt.get("found"):
        fields = {
            "Malicious": vt.get("malicious"),
            "Suspicious": vt.get("suspicious"),
            "Harmless": vt.get("harmless"),
            "Undetected": vt.get("undetected"),
            "Community Reputation": vt.get("reputation"),
            "File Type": vt.get("file_type"),
            "File Size": vt.get("file_size"),
            "First Submission": vt.get("first_seen"),
            "Last Analysis": vt.get("last_analysis"),
        }

        for field, value in fields.items():
            vt_table.add_row(field, show(value))

    elif vt.get("success"):
        vt_table.add_row("Status", "No existing report")

    else:
        vt_table.add_row(
            "Status",
            vt.get("error", "Unavailable"),
        )

    mb_table = Table(show_header=False, expand=True)
    mb_table.add_column("Field", style="yellow")
    mb_table.add_column("Value")

    if mb.get("success") and mb.get("found"):
        fields = {
            "Known Malware Sample": "YES",
            "Malware Family": mb.get("malware_family"),
            "File Type": mb.get("file_type"),
            "First Seen": mb.get("first_seen"),
            "Last Seen": mb.get("last_seen"),
            "Tags": ", ".join(map(str, mb.get("tags") or [])),
        }

        for field, value in fields.items():
            mb_table.add_row(field, show(value))

    elif mb.get("success"):
        mb_table.add_row("Status", "No matching sample")

    else:
        mb_table.add_row(
            "Status",
            mb.get("error", "Unavailable"),
        )

    return Group(
        Panel(
            overview,
            title="HOUND FILE INVESTIGATION",
            border_style="cyan",
        ),
        Panel(
            vt_table,
            title="VIRUSTOTAL FILE INTELLIGENCE",
            border_style="magenta",
        ),
        Panel(
            mb_table,
            title="MALWAREBAZAAR INTELLIGENCE",
            border_style="yellow",
        ),
        Panel(
            "Scores are experimental detection indicators, "
            "not calibrated malware probabilities. "
            "A detection may concern a harmless test file. "
            "No matches do not prove a file is safe. "
            "No file was downloaded or executed.",
            title="ANALYST NOTES",
            border_style="yellow",
        ),
    )
