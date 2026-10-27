"""Domain intelligence engine for Hound Sniffer."""

import asyncio
import re
import time
from datetime import datetime, timezone
from urllib.parse import quote

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from hound.providers.virustotal import get_api_key


DOMAIN_PATTERN = re.compile(
    r"(?=.{1,253}$)"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)


def is_domain(value):
    """Validate an ASCII domain name."""
    return bool(DOMAIN_PATTERN.fullmatch(value))


def timestamp(value):
    if value is None:
        return None

    try:
        return datetime.fromtimestamp(
            value,
            tz=timezone.utc
        ).strftime("%Y-%m-%d")
    except (ValueError, TypeError, OverflowError):
        return None


async def virustotal_domain(domain):
    """Retrieve VirusTotal domain reputation."""

    key = get_api_key()

    if not key:
        return {
            "success": False,
            "error": "VirusTotal API key missing",
        }

    url = (
        "https://www.virustotal.com/api/v3/domains/"
        + quote(domain, safe="")
    )

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(
                url,
                headers={
                    "x-apikey": key,
                    "Accept": "application/json",
                },
            )

        if response.status_code == 429:
            return {
                "success": False,
                "error": "VirusTotal rate limit reached",
            }

        if response.status_code in (401, 403):
            return {
                "success": False,
                "error": "VirusTotal authentication failed",
            }

        if response.status_code == 404:
            return {
                "success": False,
                "error": "Domain not found in VirusTotal",
            }

        response.raise_for_status()

        data = response.json()["data"]["attributes"]
        stats = data.get("last_analysis_stats") or {}

        return {
            "success": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0),
            "reputation": data.get("reputation"),
            "registrar": data.get("registrar"),
            "created": timestamp(data.get("creation_date")),
            "first_seen": timestamp(data.get("first_seen_date")),
            "last_analysis": timestamp(
                data.get("last_analysis_date")
            ),
            "categories": data.get("categories") or {},
            "tags": data.get("tags") or [],
        }

    except httpx.HTTPStatusError as error:
        return {
            "success": False,
            "error": f"VirusTotal HTTP {error.response.status_code}",
        }

    except httpx.RequestError:
        return {
            "success": False,
            "error": "VirusTotal connection failed or timed out",
        }

    except (ValueError, KeyError, TypeError):
        return {
            "success": False,
            "error": "Invalid VirusTotal domain response",
        }


async def lookup_dns(domain):
    """Retrieve live public DNS records."""

    record_types = ["A", "AAAA", "MX", "NS"]

    async def query(record_type):
        try:
            answers = await dns.asyncresolver.resolve(
                domain,
                record_type,
                lifetime=3.0,
                raise_on_no_answer=False,
            )

            if answers.rrset is None:
                return record_type, [], None

            records = [
                record.to_text()
                for record in answers
            ]

            return record_type, records[:10], None

        except dns.resolver.NXDOMAIN:
            return record_type, [], "Domain does not exist"

        except (
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            dns.resolver.YXDOMAIN,
        ):
            return record_type, [], "DNS lookup unavailable"

        except Exception:
            return record_type, [], "DNS lookup failed"

    results = await asyncio.gather(
        *[query(t) for t in record_types]
    )

    records = {}
    errors = {}

    for record_type, values, error in results:
        records[record_type] = values

        if error:
            errors[record_type] = error

    return {
        "success": not bool(errors),
        "records": records,
        "errors": errors,
    }


def score_domain(vt):
    """Provisional single-provider domain scoring."""

    if not vt.get("success"):
        return {
            "score": None,
            "verdict": "INSUFFICIENT DATA",
            "confidence": "UNKNOWN",
        }

    malicious = max(0, int(vt.get("malicious") or 0))
    suspicious = max(0, int(vt.get("suspicious") or 0))
    harmless = max(0, int(vt.get("harmless") or 0))
    undetected = max(0, int(vt.get("undetected") or 0))

    total = malicious + suspicious + harmless + undetected

    if total == 0:
        return {
            "score": None,
            "verdict": "INSUFFICIENT DATA",
            "confidence": "UNKNOWN",
        }

    score = min(
        100,
        malicious * 12 + suspicious * 4
    )

    if score >= 60:
        verdict = "HIGH DETECTION SIGNAL"
    elif score >= 25:
        verdict = "SUSPICIOUS"
    elif score > 0:
        verdict = "REVIEW"
    else:
        verdict = "NO VT DETECTIONS"

    return {
        "score": score,
        "verdict": verdict,
        "confidence": "LIMITED - SINGLE REPUTATION SOURCE",
    }


async def investigate_domain(domain):
    """Investigate a domain using VT and live DNS."""

    domain = domain.lower()

    if not is_domain(domain):
        raise ValueError("Invalid domain name")

    start = time.perf_counter()

    vt, dns_data = await asyncio.gather(
        virustotal_domain(domain),
        lookup_dns(domain),
    )

    return {
        "domain": domain,
        "virustotal": vt,
        "dns": dns_data,
        "assessment": score_domain(vt),
        "elapsed": round(
            time.perf_counter() - start,
            2
        ),
    }
