"""URLhaus and ThreatFox passive intelligence lookups."""

import os
from pathlib import Path

import httpx


KEY_FILE = (
    Path.home() / ".config/hound-sniffer/abusech.key"
)

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/host/"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"


def get_key():
    key = os.getenv("ABUSECH_API_KEY", "").strip()

    if key:
        return key

    if KEY_FILE.exists():
        return KEY_FILE.read_text().strip()

    return None


def failure(message):
    return {
        "success": False,
        "error": message,
    }


async def urlhaus_host(domain):
    """Look up malware-distribution URLs linked to a host."""

    key = get_key()

    if not key:
        return failure("abuse.ch Auth-Key not configured")

    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            response = await client.post(
                URLHAUS_API,
                headers={"Auth-Key": key},
                data={"host": domain},
            )

        response.raise_for_status()
        data = response.json()
        status = data.get("query_status")

        if status == "no_results":
            return {
                "success": True,
                "found": False,
                "url_count": 0,
                "active_in_sample": 0,
                "first_seen": None,
                "reference": None,
                "sample_urls": [],
            }

        if status != "ok":
            return failure(
                f"URLhaus returned: {str(status)[:80]}"
            )

        urls = data.get("urls") or []

        if not isinstance(urls, list):
            return failure("Invalid URLhaus URL list")

        sample = [
            item for item in urls
            if isinstance(item, dict)
        ]

        try:
            total = int(data.get("url_count") or 0)
        except (ValueError, TypeError):
            total = len(sample)

        active = sum(
            item.get("url_status") == "online"
            for item in sample
        )

        return {
            "success": True,
            "found": True,
            "url_count": total,
            "active_in_sample": active,
            "first_seen": data.get("firstseen"),
            "reference": data.get("urlhaus_reference"),
            "sample_urls": [
                {
                    "status": item.get("url_status"),
                    "date": item.get("date_added"),
                    "reference": item.get("urlhaus_reference"),
                }
                for item in sample[:5]
            ],
        }

    except httpx.HTTPStatusError as exc:
        return failure(
            f"URLhaus HTTP {exc.response.status_code}"
        )

    except httpx.RequestError:
        return failure("URLhaus connection failed or timed out")

    except (ValueError, TypeError, AttributeError):
        return failure("Invalid URLhaus response")


async def threatfox_domain(domain):
    """Search exact domain IOCs in ThreatFox."""

    key = get_key()

    if not key:
        return failure("abuse.ch Auth-Key not configured")

    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            response = await client.post(
                THREATFOX_API,
                headers={
                    "Auth-Key": key,
                    "Accept": "application/json",
                },
                json={
                    "query": "search_ioc",
                    "search_term": domain,
                    "exact_match": True,
                },
            )

        response.raise_for_status()

        data = response.json()
        status = data.get("query_status")

        if status in ("no_result", "no_results"):
            return {
                "success": True,
                "found": False,
                "matches": 0,
                "indicators": [],
            }

        if status != "ok":
            return failure(
                f"ThreatFox returned: {str(status)[:80]}"
            )

        records = data.get("data") or []

        if not isinstance(records, list):
            return failure("Invalid ThreatFox IOC list")

        # Only count exact domain IOCs.
        matches = [
            item for item in records
            if (
                isinstance(item, dict)
                and item.get("ioc_type") == "domain"
                and str(item.get("ioc", "")).lower()
                == domain.lower()
            )
        ]

        return {
            "success": True,
            "found": bool(matches),
            "matches": len(matches),
            "indicators": [
                {
                    "ioc": item.get("ioc"),
                    "threat_type": item.get("threat_type"),
                    "malware": item.get("malware_printable")
                        or item.get("malware"),
                    "confidence": item.get("confidence_level"),
                    "first_seen": item.get("first_seen"),
                    "last_seen": item.get("last_seen"),
                    "reference": item.get("reference"),
                }
                for item in matches[:5]
            ],
        }

    except httpx.HTTPStatusError as exc:
        return failure(
            f"ThreatFox HTTP {exc.response.status_code}"
        )

    except httpx.RequestError:
        return failure("ThreatFox connection failed or timed out")

    except (ValueError, TypeError, AttributeError):
        return failure("Invalid ThreatFox response")
