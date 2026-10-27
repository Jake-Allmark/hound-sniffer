"""Multi-source domain threat scoring v0.2."""


def valid_count(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
    )


def score_enriched_domain(report):
    """Combine available VT, URLhaus and ThreatFox evidence."""

    vt = report.get("virustotal") or {}
    uh = report.get("urlhaus") or {}
    tf = report.get("threatfox") or {}

    vt_ok = (
        vt.get("success") is True
        and valid_count(vt.get("malicious"))
        and valid_count(vt.get("suspicious"))
    )

    uh_ok = uh.get("success") is True
    tf_ok = tf.get("success") is True

    available = sum((vt_ok, uh_ok, tf_ok))

    if available == 0:
        return {
            "score": None,
            "verdict": "INSUFFICIENT DATA",
            "confidence": "UNKNOWN",
            "scoring_version": "0.2",
        }

    score = 0

    # VT detections: maximum 40 points.
    if vt_ok:
        score += min(
            40,
            vt["malicious"] * 8
            + vt["suspicious"] * 3
        )

    # URLhaus host association: 30 points.
    # A historical host match does not establish that
    # every URL or service is currently malicious.
    uh_hit = uh_ok and uh.get("found") is True

    if uh_hit:
        score += 30

    # Exact ThreatFox domain IOC: 40 points.
    tf_hit = tf_ok and tf.get("found") is True

    if tf_hit:
        score += 40

    score = min(100, score)

    # Prevent a missing source from appearing clean.
    if available < 3:
        confidence = f"PARTIAL COVERAGE ({available}/3)"
    else:
        confidence = "THREE SOURCES QUERIED"

    if score >= 70:
        verdict = "HIGH RISK"

    elif score >= 30:
        verdict = "SUSPICIOUS"

    elif score > 0:
        verdict = "REVIEW"

    elif available < 3:
        verdict = "NO HITS - PARTIAL COVERAGE"

    else:
        verdict = "NO POSITIVE SIGNALS IN QUERIED SOURCES"

    return {
        "score": score,
        "verdict": verdict,
        "confidence": confidence,
        "scoring_version": "0.2",
    }
