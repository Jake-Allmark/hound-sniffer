import asyncio
import time

from hound.providers.abuseipdb import lookup_ip as abuse_lookup
from hound.providers.virustotal import lookup_ip as vt_lookup
from hound.providers.proxycheck import lookup_ip as proxy_lookup


async def investigate_ip(ip: str) -> dict:
    """Query all configured providers concurrently."""

    start = time.perf_counter()

    providers = {
        "AbuseIPDB": abuse_lookup,
        "VirusTotal": vt_lookup,
        "ProxyCheck": proxy_lookup,
    }

    tasks = [
        lookup(ip)
        for lookup in providers.values()
    ]

    results = await asyncio.gather(
        *tasks,
        return_exceptions=True,
    )

    intelligence = {}

    for name, result in zip(providers, results):

        if isinstance(result, BaseException):
            intelligence[name] = {
                "success": False,
                "error": "Unexpected provider failure",
            }
        else:
            intelligence[name] = result

    intelligence["elapsed"] = round(
        time.perf_counter() - start,
        2,
    )

    return intelligence
