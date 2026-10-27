import os
from pathlib import Path

import httpx


API_URL = "https://www.virustotal.com/api/v3/ip_addresses"

KEY_FILE = (
    Path.home()
    / ".config/hound-sniffer/virustotal.key"
)


def get_api_key():
    key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()

    if key:
        return key

    if KEY_FILE.exists():
        return KEY_FILE.read_text().strip()

    return None


async def lookup_ip(ip):
    key = get_api_key()

    if not key:
        return {
            "success": False,
            "error": "VirusTotal API key missing"
        }

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(
                f"{API_URL}/{ip}",
                headers={
                    "x-apikey": key,
                    "Accept": "application/json"
                }
            )

        if response.status_code == 401:
            raise ValueError("Invalid VirusTotal API key")

        if response.status_code == 403:
            raise ValueError("VirusTotal access forbidden")

        if response.status_code == 404:
            raise ValueError("IP not found in VirusTotal")

        if response.status_code == 429:
            raise ValueError("VirusTotal API rate limit exceeded")

        response.raise_for_status()

        data = response.json()["data"]["attributes"]

        stats = data.get("last_analysis_stats") or {}

        return {
            "success": True,
            "provider": "VirusTotal",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": sum(
                value for value in stats.values()
                if isinstance(value, int)
            ),
            "reputation": data.get("reputation"),
            "asn": data.get("asn"),
            "as_owner": data.get("as_owner"),
            "country": data.get("country"),
            "network": data.get("network"),
        }

    except ValueError as error:
        return {"success": False, "error": str(error)}

    except httpx.HTTPStatusError as error:
        return {
            "success": False,
            "error": f"HTTP {error.response.status_code}"
        }

    except httpx.RequestError:
        return {
            "success": False,
            "error": "VirusTotal connection failed or timed out"
        }

    except (KeyError, TypeError):
        return {
            "success": False,
            "error": "Unexpected VirusTotal response"
        }
