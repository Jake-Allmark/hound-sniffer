from hound.core.domain_scoring import score_enriched_domain
"""Combine existing domain intelligence with abuse.ch."""

import asyncio
import time

from hound.core.domains import investigate_domain
from hound.providers.abusech import (
    urlhaus_host,
    threatfox_domain,
)


async def investigate_enriched_domain(domain):
    """Run VT, DNS, URLhaus and ThreatFox concurrently."""

    start = time.perf_counter()

    results = await asyncio.gather(
        investigate_domain(domain),
        urlhaus_host(domain),
        threatfox_domain(domain),
        return_exceptions=True,
    )

    # Preserve the original domain investigation.
    if isinstance(results[0], BaseException):
        raise RuntimeError(
            "Core domain investigation failed"
        ) from results[0]

    report = results[0]

    def normalise(result, provider):
        if isinstance(result, BaseException):
            return {
                "success": False,
                "error": f"{provider} lookup failed",
            }
        return result

    urlhaus = normalise(results[1], "URLhaus")
    threatfox = normalise(results[2], "ThreatFox")

    report["urlhaus"] = urlhaus
    report["threatfox"] = threatfox

    urlhaus_hit = (
        urlhaus.get("success") is True
        and urlhaus.get("found") is True
    )

    threatfox_hit = (
        threatfox.get("success") is True
        and threatfox.get("found") is True
    )

    if urlhaus_hit and threatfox_hit:
        status = "MULTIPLE MALWARE INTELLIGENCE HITS"
    elif urlhaus_hit or threatfox_hit:
        status = "MALWARE INTELLIGENCE HIT - REVIEW"
    elif not urlhaus.get("success") and not threatfox.get("success"):
        status = "ADDITIONAL INTELLIGENCE UNAVAILABLE"
    else:
        status = "NO HITS IN RESPONDING SOURCES"

    report["correlation"] = {
        "status": status,
        "urlhaus_hit": urlhaus_hit,
        "threatfox_hit": threatfox_hit,
    }

    report["elapsed"] = round(
        time.perf_counter() - start,
        2,
    )

    report['assessment'] = score_enriched_domain(report)

    return report
