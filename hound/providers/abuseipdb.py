import os
from pathlib import Path

import httpx


API_URL = "https://api.abuseipdb.com/api/v2/check"

KEY_FILE = (
    Path.home()
    / ".config"
    / "hound-sniffer"
    / "abuseipdb.key"
)


def get_api_key():
    """Read the API key from the environment or local config."""

    key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()

    if key:
        return key

    if KEY_FILE.exists():
        return KEY_FILE.read_text().strip()

    return None


async def lookup_ip(ip: str) -> dict:
    """Query AbuseIPDB for an IPv4 or IPv6 address."""

    api_key = get_api_key()

    if not api_key:
        return {
            "success": False,
            "error": "AbuseIPDB API key not configured",
        }

    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
    }

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(
                API_URL,
                headers=headers,
                params=params,
            )

        response.raise_for_status()

        data = response.json()["data"]

        return {
            "success": True,
            "provider": "AbuseIPDB",
            "ip": data.get("ipAddress"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "domain": data.get("domain"),
            "country": data.get("countryCode"),
            "tor": data.get("isTor"),
            "whitelisted": data.get("isWhitelisted"),
            "abuse_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "distinct_reporters": data.get("numDistinctUsers"),
            "last_reported": data.get("lastReportedAt"),
        }

    except httpx.HTTPStatusError as error:
        status = error.response.status_code

        if status == 401:
            message = "Invalid or missing API key"
        elif status == 403:
            message = "Access forbidden - check API permissions"
        elif status == 429:
            message = "API rate limit exceeded"
        else:
            message = f"API returned HTTP {status}"

        return {
            "success": False,
            "error": message,
        }

    except httpx.RequestError:
        return {
            "success": False,
            "error": "API connection failed or timed out",
        }

    except (ValueError, KeyError, TypeError):
        return {
            "success": False,
            "error": "Invalid response received from AbuseIPDB",
        }
