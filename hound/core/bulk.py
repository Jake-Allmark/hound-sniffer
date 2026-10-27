"""Bulk investigation engine for Hound Sniffer."""

import asyncio
import ipaddress
import json
import os
import re
import time

from pathlib import Path

from hound.core.investigation import investigate_ip
from hound.core.scoring import calculate_scores
from hound.core.domain_enrichment import investigate_enriched_domain
from hound.core.domains import is_domain
from hound.core.url_investigation import investigate_url, validate_url
from hound.core.hash_investigation import investigate_hash
from hound.providers.virustotal import get_api_key


def classify(value):
    """Validate and identify an investigation target."""

    value = value.strip()

    if not value:
        raise ValueError("Empty indicator")

    try:
        ip = ipaddress.ip_address(value)

        if not ip.is_global:
            raise ValueError("Non-global IP address")

        return "IP", str(ip)
    except ValueError as exc:
        if str(exc) == "Non-global IP address":
            raise

    if value.startswith(("http://", "https://")):
        validate_url(value)
        return "URL", value

    if re.fullmatch(r"[a-fA-F0-9]{32}", value):
        return "MD5", value.lower()

    if re.fullmatch(r"[a-fA-F0-9]{40}", value):
        return "SHA1", value.lower()

    if re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return "SHA256", value.lower()

    if is_domain(value.lower()):
        return "DOMAIN", value.lower()

    raise ValueError("Unsupported indicator")


def read_targets(filename):
    """Load, deduplicate and limit batch input."""

    path = Path(filename)

    if path.stat().st_size > 65536:
        raise ValueError("Input file exceeds 64 KiB")

    values = []

    for line in path.read_text(encoding="utf-8-sig").splitlines():
        value = line.strip()

        if not value or value.startswith("#"):
            continue

        if len(value) > 2048:
            raise ValueError("Indicator exceeds 2048 characters")

        if value not in values:
            values.append(value)

    if not values:
        raise ValueError("Input file contains no indicators")

    if len(values) > 25:
        raise ValueError(
            "Alpha batch limit is 25 unique indicators"
        )

    return values


def provider_status(data):
    """Return provider availability without exposing secrets."""

    return {
        name: item.get("success") is True
        for name, item in data.items()
        if isinstance(item, dict) and "success" in item
    }


async def investigate_target(target):
    """Run the appropriate Hound investigation engine."""

    start = time.perf_counter()

    try:
        kind, target = classify(target)

        if kind == "IP":
            raw = await investigate_ip(target)
            assessment = calculate_scores(raw)

            score = assessment["threat_score"]
            verdict = assessment["verdict"]
            confidence = assessment["confidence_score"]

            providers = provider_status(raw)

            if verdict in (
                "INSUFFICIENT DATA",
                "LIMITED EVIDENCE",
            ):
                score = None

        elif kind == "DOMAIN":
            raw = await investigate_enriched_domain(target)
            assessment = raw["assessment"]

            score = assessment["score"]
            verdict = assessment["verdict"]
            confidence = assessment["confidence"]

            providers = provider_status({
                "VirusTotal": raw["virustotal"],
                "URLhaus": raw["urlhaus"],
                "ThreatFox": raw["threatfox"],
                "DNS": raw["dns"],
            })

        elif kind == "URL":
            raw = await investigate_url(target)

            score = None
            verdict = raw["verdict"]
            confidence = "NOT CALIBRATED"

            providers = provider_status({
                "VirusTotal": raw["virustotal"],
                "URLhaus": raw["urlhaus"],
            })

        else:
            raw = await investigate_hash(target)
            assessment = raw["assessment"]

            score = assessment["score"]
            verdict = assessment["verdict"]
            confidence = assessment["confidence"]

            providers = provider_status({
                "VirusTotal": raw["virustotal"],
                "MalwareBazaar": raw["malwarebazaar"],
            })

        available = sum(providers.values())

        if available == 0:
            status = "NO DATA"
        elif available < len(providers):
            status = "PARTIAL"
        else:
            status = "COMPLETE"

        return {
            "indicator": target,
            "type": kind,
            "status": status,
            "threat_score": score,
            "confidence": confidence,
            "verdict": verdict,
            "providers": providers,
            "elapsed": round(
                time.perf_counter() - start, 2
            ),
            "intelligence": raw,
        }

    except ValueError as exc:
        return {
            "indicator": target,
            "type": "INVALID",
            "status": "INVALID",
            "threat_score": None,
            "confidence": "UNKNOWN",
            "verdict": str(exc),
            "providers": {},
            "elapsed": 0,
            "intelligence": {},
        }

    except Exception as exc:
        return {
            "indicator": target,
            "type": "ERROR",
            "status": "FAILED",
            "threat_score": None,
            "confidence": "UNKNOWN",
            "verdict": f"Investigation failed: {type(exc).__name__}",
            "providers": {},
            "elapsed": 0,
            "intelligence": {},
        }


async def run_bulk(
    targets,
    workers=3,
    dispatcher=None,
    interval_seconds=None,
):
    """Run bounded investigations with conservative VT pacing."""

    if dispatcher is None:
        dispatcher = investigate_target

    if not 1 <= workers <= 3:
        raise ValueError("Workers must be between 1 and 3")

    if interval_seconds is None:
        interval_seconds = 16.0 if get_api_key() else 0.0

    if interval_seconds < 0:
        raise ValueError("Invalid interval")

    semaphore = asyncio.Semaphore(workers)
    pacing_lock = asyncio.Lock()

    loop = asyncio.get_running_loop()
    next_start = loop.time()

    async def worker(target):
        nonlocal next_start

        # Reject invalid indicators without API requests.
        try:
            classify(target)
        except ValueError:
            return await dispatcher(target)

        async with semaphore:

            # Space batch requests when VT is configured.
            async with pacing_lock:
                now = loop.time()

                if now < next_start:
                    await asyncio.sleep(next_start - now)

                next_start = loop.time() + interval_seconds

            return await dispatcher(target)

    tasks = [
        asyncio.create_task(worker(target))
        for target in targets
    ]

    return await asyncio.gather(*tasks)


def save_json(path, results):
    """Write a private JSON report without overwriting files."""

    path = Path(path).expanduser()

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL

    fd = os.open(path, flags, 0o600)

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(
                {
                    "tool": "Hound Sniffer",
                    "version": "0.1-alpha",
                    "results": results,
                },
                output,
                indent=2,
                default=str,
            )
    except BaseException:
        path.unlink(missing_ok=True)
        raise
