"""Rich output for enriched domain investigations."""

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from hound.core.domain_output import build_domain_report


def display_value(value):
    return "Unknown" if value is None else str(value)


def build_enriched_domain_report(report):
    """Render core domain results and malware intelligence."""

    correlation = report.get("correlation") or {}
    status = correlation.get("status", "UNKNOWN")

    urlhaus = report.get("urlhaus") or {}
    threatfox = report.get("threatfox") or {}

    warning = Panel(
        Text(
            status
            + "\nExperimental scoring incorporates available "
            "VirusTotal, URLhaus and ThreatFox findings. Review IOC evidence "
            "separately before taking action."
        ),
        title="MULTI-SOURCE INTELLIGENCE",
        border_style="yellow",
    )

    uh_table = Table(show_header=False, expand=True)
    uh_table.add_column("Field", style="cyan")
    uh_table.add_column("Value")

    if urlhaus.get("success"):
        uh_table.add_row(
            "Host match",
            "YES" if urlhaus.get("found") else "No match",
        )

        uh_table.add_row(
            "Reported malware URLs",
            display_value(urlhaus.get("url_count")),
        )

        uh_table.add_row(
            "Online URLs in returned sample",
            display_value(urlhaus.get("active_in_sample")),
        )

        uh_table.add_row(
            "First Seen",
            display_value(urlhaus.get("first_seen")),
        )

        uh_table.add_row(
            "Source",
            display_value(urlhaus.get("reference")),
        )

    else:
        uh_table.add_row(
            "Status",
            display_value(urlhaus.get("error", "Unavailable")),
        )

    tf_table = Table(show_header=False, expand=True)
    tf_table.add_column("Field", style="magenta")
    tf_table.add_column("Value")

    if threatfox.get("success"):

        tf_table.add_row(
            "Exact domain matches",
            str(threatfox.get("matches", 0)),
        )

        for index, item in enumerate(
            threatfox.get("indicators") or [],
            start=1,
        ):
            tf_table.add_row(
                f"IOC {index}",
                display_value(item.get("ioc")),
            )

            tf_table.add_row(
                "Threat Type",
                display_value(item.get("threat_type")),
            )

            tf_table.add_row(
                "Malware",
                display_value(item.get("malware")),
            )

            tf_table.add_row(
                "Confidence (ThreatFox)",
                display_value(item.get("confidence")),
            )

            tf_table.add_row(
                "Last Seen",
                display_value(item.get("last_seen")),
            )

            tf_table.add_row(
                "Reference",
                display_value(item.get("reference")),
            )

    else:
        tf_table.add_row(
            "Status",
            display_value(threatfox.get("error", "Unavailable")),
        )

    return Group(
        warning,
        build_domain_report(report),
        Panel(
            uh_table,
            title="URLHAUS MALWARE INTELLIGENCE",
            border_style="red",
        ),
        Panel(
            tf_table,
            title="THREATFOX IOC INTELLIGENCE",
            border_style="magenta",
        ),
    )
