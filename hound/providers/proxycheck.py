import os
from pathlib import Path

import httpx


API_URL = "https://proxycheck.io/v3"

KEY_FILE = (
    Path.home()
    / ".config/hound-sniffer/proxycheck.key"
)


def get_api_key():
    key = os.environ.get("PROXYCHECK_API_KEY", "").strip()

    if key:
        return key

    if KEY_FILE.exists():
        return KEY_FILE.read_text().strip()

    return None


async def lookup_ip(ip: str) -> dict:
    """Get VPN, proxy, Tor and network intelligence."""

    params = {}
    key = get_api_key()

    if key:
        params["key"] = key

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(
                f"{API_URL}/{ip}",
                params=params,
            )

        response.raise_for_status()
        data = response.json()

        if data.get("status") not in ("ok", "warning"):
            return {
                "success": False,
                "error": "ProxyCheck rejected the request",
            }

        result = data.get(ip)

        if not isinstance(result, dict):
            return {
                "success": False,
                "error": "No IP intelligence returned",
            }

        detections = result.get("detections") or {}
        network = result.get("network") or {}
        location = result.get("location") or {}
        operator = result.get("operator") or {}

        return {
            "success": True,
            "provider": "ProxyCheck",
            "ip": ip,

            # Network
            "isp": network.get("provider"),
            "organization": network.get("organisation"),
            "asn": network.get("asn"),
            "network_type": network.get("type"),
            "hostname": network.get("hostname"),
            "network_range": network.get("range"),

            # Location
            "country": location.get("country_name"),
            "city": location.get("city_name"),

            # Detection
            "vpn": detections.get("vpn"),
            "proxy": detections.get("proxy"),
            "tor": detections.get("tor"),
            "hosting": detections.get("hosting"),
            "anonymous": detections.get("anonymous"),
            "compromised": detections.get("compromised"),

            # VPN / Proxy Operator
            "vpn_provider": operator.get("name"),
            "operator_url": operator.get("url"),
            "operator_services": operator.get("services"),

            # Provider-specific metrics
            "risk": detections.get("risk"),
            "detection_confidence": detections.get("confidence"),
            "attack_history": result.get("attack_history") or {},
            "last_updated": result.get("last_updated"),
        }

    except httpx.HTTPStatusError as error:
        return {
            "success": False,
            "error": f"ProxyCheck HTTP {error.response.status_code}",
        }

    except httpx.RequestError:
        return {
            "success": False,
            "error": "ProxyCheck connection failed or timed out",
        }

    except (ValueError, TypeError, AttributeError):
        return {
            "success": False,
            "error": "Invalid ProxyCheck response",
        }
