"""Terminal and dashboard rendering for domain investigations."""

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


def value(item):
    if item is None:
        return "Unknown"
    return str(item)


def build_domain_report(report):
    """Create reusable Rich output for CLI and TUI."""

    domain = report["domain"]
    vt = report["virustotal"]
    dns_data = report["dns"]
    assessment = report["assessment"]

    # ----------------------------------
    # Assessment
    # ----------------------------------

    threat = Table(
        show_header=False,
        expand=True,
    )

    threat.add_column("Field", style="bold cyan")
    threat.add_column("Value")

    score = assessment["score"]

    threat.add_row(
        "Threat Score",
        f"{score}/100" if score is not None else "N/A",
    )

    threat.add_row(
        "Verdict",
        assessment["verdict"],
    )

    threat.add_row(
        "Confidence",
        assessment["confidence"],
    )

    threat.add_row(
        "Investigation Time",
        f"{report['elapsed']} seconds",
    )

    # ----------------------------------
    # VirusTotal
    # ----------------------------------

    reputation = Table(
        show_header=False,
        expand=True,
    )

    reputation.add_column("Field", style="bold magenta")
    reputation.add_column("Value")

    if vt.get("success"):

        fields = {
            "Malicious": vt.get("malicious"),
            "Suspicious": vt.get("suspicious"),
            "Harmless": vt.get("harmless"),
            "Undetected": vt.get("undetected"),
            "Community Reputation": vt.get("reputation"),
            "Registrar": vt.get("registrar"),
            "Created": vt.get("created"),
            "First Seen": vt.get("first_seen"),
            "Last Analysis": vt.get("last_analysis"),
        }

        for name, result in fields.items():
            reputation.add_row(
                name,
                Text(value(result)),
            )

        categories = vt.get("categories") or {}

        for provider, category in list(categories.items())[:6]:
            reputation.add_row(
                f"Category ({provider})",
                Text(value(category)),
            )

    else:
        reputation.add_row(
            "Status",
            Text(vt.get("error", "Unavailable")),
        )

    # ----------------------------------
    # DNS
    # ----------------------------------

    dns_table = Table(
        show_header=False,
        expand=True,
    )

    dns_table.add_column("Record", style="bold green")
    dns_table.add_column("Value")

    records = dns_data.get("records") or {}

    for record_type in ("A", "AAAA", "MX", "NS"):

        items = records.get(record_type) or []

        if items:
            for item in items:
                dns_table.add_row(
                    record_type,
                    Text(item),
                )
        else:
            error = dns_data.get("errors", {}).get(
                record_type
            )

            dns_table.add_row(
                record_type,
                Text(error or "No records returned"),
            )

    # ----------------------------------
    # Return complete dashboard
    # ----------------------------------

    return Group(
        Panel(
            Text(domain, style="bold cyan"),
            title="DOMAIN INVESTIGATION",
            border_style="cyan",
        ),

        Panel(
            threat,
            title="HOUND DOMAIN ASSESSMENT",
            border_style="yellow",
        ),

        Panel(
            reputation,
            title="VIRUSTOTAL DOMAIN INTELLIGENCE",
            border_style="magenta",
        ),

        Panel(
            dns_table,
            title="LIVE DNS INTELLIGENCE",
            border_style="green",
        ),

        Panel(
            Text(
                "Experimental domain scoring combines VirusTotal, "
                "URLhaus and ThreatFox findings. "
                "Source findings require analyst review.\n\n"
                "No detections does not prove a domain is safe. "
                "DNS records do not establish maliciousness."
            ),
            title="ANALYST NOTES",
            border_style="yellow",
        ),
    )


def display_domain_investigation(console, report):
    console.print()
    console.print(build_domain_report(report))
