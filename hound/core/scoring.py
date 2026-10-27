"""Hound Sniffer - provisional IP scoring v0.2."""


def valid_number(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
    )


def clamp(value):
    return max(0, min(100, value))


def calculate_scores(results):
    """Score maliciousness evidence separately from coverage."""

    abuse = results.get("AbuseIPDB") or {}
    vt = results.get("VirusTotal") or {}
    proxy = results.get("ProxyCheck") or {}

    abuse_score = abuse.get("abuse_score")
    malicious = vt.get("malicious")
    suspicious = vt.get("suspicious")

    abuse_ok = (
        abuse.get("success") is True
        and valid_number(abuse_score)
    )

    vt_ok = (
        vt.get("success") is True
        and valid_number(malicious)
        and valid_number(suspicious)
    )

    proxy_ok = proxy.get("success") is True

    score = 0.0
    coverage = 0

    evidence = []
    warnings = []

    # AbuseIPDB: maximum 30 points.
    if abuse_ok:
        abuse_score = clamp(abuse_score)
        score += abuse_score * 0.30
        coverage += 25

        evidence.append(
            f"AbuseIPDB confidence: {abuse_score}/100"
        )

        reports = abuse.get("total_reports")

        if reports is not None:
            evidence.append(
                f"AbuseIPDB reports: {reports}"
            )

        if abuse.get("whitelisted") is True:
            evidence.append(
                "AbuseIPDB whitelist flag: YES"
            )

    else:
        warnings.append("AbuseIPDB unavailable")

    # VirusTotal: maximum 60 points.
    if vt_ok:
        malicious = max(0, int(malicious))
        suspicious = max(0, int(suspicious))

        vt_points = min(
            60,
            min(55, malicious * 10)
            + min(12, suspicious * 3)
        )

        score += vt_points
        coverage += 30

        evidence.append(
            f"VirusTotal malicious detections: {malicious}"
        )

        evidence.append(
            f"VirusTotal suspicious detections: {suspicious}"
        )

    else:
        warnings.append("VirusTotal unavailable")

    # ProxyCheck: confirmed compromise only.
    if proxy_ok:
        coverage += 10

        if proxy.get("compromised") is True:
            score += 15
            evidence.append(
                "ProxyCheck compromised classification detected"
            )

        for field, label in (
            ("vpn", "VPN"),
            ("proxy", "Proxy"),
            ("anonymous", "Anonymous"),
            ("tor", "Tor"),
        ):
            if proxy.get(field) is True:
                evidence.append(
                    f"ProxyCheck {label} classification detected"
                )

        risk = proxy.get("risk")

        if valid_number(risk):
            evidence.append(
                f"ProxyCheck provider-specific risk: {risk}/100"
            )

            if risk >= 75:
                warnings.append(
                    "Elevated ProxyCheck risk requires "
                    "contextual investigation"
                )
    else:
        warnings.append("ProxyCheck unavailable")

    # Coverage and agreement.
    if abuse_ok and vt_ok:
        coverage += 10

        abuse_positive = abuse_score >= 50
        vt_positive = malicious >= 3

        if abuse_positive and vt_positive:
            score += 5
            coverage += 10
            evidence.append(
                "AbuseIPDB and VirusTotal both report "
                "positive maliciousness signals"
            )

        elif abuse_positive != vt_positive:
            coverage = max(0, coverage - 10)
            warnings.append(
                "AbuseIPDB and VirusTotal disagree "
                "on maliciousness signals"
            )

    score = round(clamp(score))
    coverage = round(clamp(coverage))

    # Verdicts.
    if not abuse_ok and not vt_ok:
        verdict = "INSUFFICIENT DATA"

    elif not abuse_ok or not vt_ok:
        verdict = "LIMITED EVIDENCE"

    elif score >= 70:
        verdict = "HIGH RISK"

    elif score >= 35:
        verdict = "SUSPICIOUS"

    elif score > 0:
        verdict = "REVIEW"

    elif (
        proxy_ok
        and valid_number(proxy.get("risk"))
        and proxy["risk"] >= 75
    ):
        verdict = "CONTEXT REVIEW"

    else:
        verdict = "NO POSITIVE MALICIOUSNESS SIGNALS"

    warnings.append(
        "Threat and coverage scores are experimental "
        "heuristics, not calibrated probabilities"
    )

    return {
        "threat_score": score,
        "confidence_score": coverage,
        "verdict": verdict,
        "evidence": evidence,
        "warnings": warnings,
        "scoring_version": "0.2",
    }
