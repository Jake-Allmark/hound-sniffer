from pathlib import Path
from hound.core.hash_investigation import investigate_hash, build_hash_report
from hound.core.url_investigation import investigate_url, build_url_report
from hound.ai.analyzer import analyze
import asyncio
import ipaddress
import re

from urllib.parse import urlparse

import typer

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from hound.core.investigation import investigate_ip
from hound.core.domain_enrichment import investigate_enriched_domain
from hound.core.enriched_output import build_enriched_domain_report
from hound.ai.domain_analyzer import analyze_domain
from hound.core.scoring import calculate_scores


app = typer.Typer(
    help="Hound Sniffer - SOC Threat Intelligence Platform",
    no_args_is_help=True,
)

console = Console()


def classify_indicator(target: str) -> str:
    """Identify the indicator type."""

    try:
        ip = ipaddress.ip_address(target)
        return f"IPv{ip.version}"
    except ValueError:
        pass

    if re.fullmatch(r"[a-fA-F0-9]{32}", target):
        return "MD5 Hash"

    if re.fullmatch(r"[a-fA-F0-9]{40}", target):
        return "SHA1 Hash"

    if re.fullmatch(r"[a-fA-F0-9]{64}", target):
        return "SHA256 Hash"

    if target.startswith(("http://", "https://")):
        if urlparse(target).hostname:
            return "URL"

    domain_pattern = (
        r"(?=.{1,253}$)"
        r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z]{2,63}"
    )

    if re.fullmatch(domain_pattern, target):
        return "Domain"

    return "Unknown"


def display_results(target: str, indicator_type: str, data: dict):
    """Render intelligence results in the terminal."""

    table = Table(
        title="NETWORK INTELLIGENCE",
        show_header=False,
        border_style="cyan",
    )

    table.add_column("Field", style="bold cyan")
    table.add_column("Value", style="white")

    def value(item):
        if item is None:
            return "Unknown"
        if isinstance(item, bool):
            return "YES" if item else "NO"
        return str(item)

    table.add_row("IP Address", target)
    table.add_row("Type", indicator_type)

    table.add_row("ISP", value(data.get("isp")))
    table.add_row("Usage Type", value(data.get("usage_type")))
    table.add_row("Domain", value(data.get("domain")))
    table.add_row("Country", value(data.get("country")))
    table.add_row("TOR Exit Node", value(data.get("tor")))
    table.add_row("Whitelisted", value(data.get("whitelisted")))

    console.print(table)

    threat = Table(
        title="THREAT INTELLIGENCE",
        show_header=False,
        border_style="yellow",
    )

    threat.add_column("Field", style="bold yellow")
    threat.add_column("Value")

    score = data.get("abuse_score")

    if score is None:
        score_text = "Unknown"
    elif score >= 75:
        score_text = f"[red]{score}/100[/red]"
    elif score >= 25:
        score_text = f"[yellow]{score}/100[/yellow]"
    else:
        score_text = f"[green]{score}/100[/green]"

    threat.add_row("Provider", "AbuseIPDB")
    threat.add_row("Abuse Confidence", score_text)
    threat.add_row("Total Reports", value(data.get("total_reports")))
    threat.add_row("Distinct Reporters", value(data.get("distinct_reporters")))
    threat.add_row("Last Reported", value(data.get("last_reported")))

    console.print(threat)

    console.print(
        "[dim]AbuseIPDB confidence is a provider-specific metric.[/dim]"
    )


@app.callback()
def main():
    """Hound Sniffer - SOC Threat Intelligence Platform."""
    pass


@app.command()
def sniff(
    target: str = typer.Argument(
        ...,
        help="IP, domain, URL or hash",
    ),
    ai: bool = typer.Option(
        False,
        "--ai",
        help="Run local AI threat analysis",
    ),
):
    """Investigate an indicator."""

    console.print()

    console.print(
        Panel.fit(
            "[bold cyan]🐕 HOUND SNIFFER[/bold cyan]\n"
            "[dim]SOC Threat Intelligence Platform[/dim]",
            border_style="cyan",
        )
    )

    indicator_type = classify_indicator(target)

    if indicator_type == "Unknown":
        console.print("[red]Invalid indicator.[/red]")
        raise typer.Exit(code=1)

    console.print(f"\n[cyan]TARGET:[/cyan] {target}")
    console.print(f"[cyan]TYPE:[/cyan] {indicator_type}")

    if indicator_type == "Domain":

        console.print(
            "\n[cyan]Investigating domain intelligence...[/cyan]"
        )

        report = asyncio.run(
            investigate_enriched_domain(target)
        )

        console.print(build_enriched_domain_report(report))

        if ai:
            console.print(
                "\n[cyan]Hound AI is analysing domain evidence...[/cyan]"
            )

            analysis = asyncio.run(analyze_domain(report))

            console.print(
                Panel(
                    analysis["summary"],
                    title="HOUND AI - DOMAIN ANALYSIS",
                    border_style="cyan",
                )
            )

            console.print(
                "\n[bold green]RECOMMENDED ACTIONS[/bold green]"
            )

            console.print(analysis["recommendation"])

            if analysis["ai_used"]:
                console.print(
                    f"[dim]Local AI: {analysis['model']}[/dim]"
                )
            else:
                console.print(
                    "[yellow]Local AI unavailable; "
                    "showing rule-based recommendations.[/yellow]"
                )

        return

    if indicator_type in (
        "MD5 Hash",
        "SHA1 Hash",
        "SHA256 Hash",
    ):
        console.print(
            "\n[cyan]Investigating file hash intelligence...[/cyan]"
        )

        report = asyncio.run(
            investigate_hash(target)
        )

        console.print(
            build_hash_report(report)
        )

        if ai:
            console.print(
                "[yellow]File hash AI analysis is not enabled yet.[/yellow]"
            )

        return

    if indicator_type == "URL":
        console.print(
            "\n[cyan]Investigating URL intelligence...[/cyan]"
        )

        try:
            report = asyncio.run(investigate_url(target))
        except ValueError as error:
            console.print(f"[red]{error}[/red]")
            raise typer.Exit(code=1)

        console.print(build_url_report(report))

        if ai:
            console.print(
                "[yellow]URL AI analysis is not yet enabled.[/yellow]"
            )

        return

    if indicator_type not in ("IPv4", "IPv6"):
        console.print(
            "[yellow]URL and hash investigations "
            "are not implemented yet.[/yellow]"
        )
        return

    ip = ipaddress.ip_address(target)

    if not ip.is_global:
        console.print(
            "\n[yellow]Non-global IP detected.[/yellow]"
        )
        console.print(
            "[dim]Skipping external reputation lookup.[/dim]"
        )
        return

    console.print("\n[cyan]Querying threat intelligence providers...[/cyan]\n")

    results = asyncio.run(investigate_ip(target))

    console.print(
        f"Investigation completed in {results['elapsed']}s"
    )

    abuse = results["AbuseIPDB"]
    vt = results["VirusTotal"]

    if abuse.get("success"):
        display_results(target, indicator_type, abuse)
    else:
        console.print(
            f"[yellow]AbuseIPDB: {abuse.get('error')}[/yellow]"
        )

    if vt.get("success"):
        table = Table(
            title="VIRUSTOTAL INTELLIGENCE",
            show_header=False,
            border_style="magenta"
        )

        table.add_column("Field", style="bold magenta")
        table.add_column("Value")

        fields = {
            "Malicious": vt.get("malicious"),
            "Suspicious": vt.get("suspicious"),
            "Harmless": vt.get("harmless"),
            "Undetected": vt.get("undetected"),
            "Total Engines": vt.get("total_engines"),
            "Reputation": vt.get("reputation"),
            "ASN": vt.get("asn"),
            "AS Owner": vt.get("as_owner"),
            "Country": vt.get("country"),
            "Network": vt.get("network")
        }

        for field, value in fields.items():
            table.add_row(
                field,
                "Unknown" if value is None else str(value)
            )

        console.print()
        console.print(table)

    else:
        console.print(
            f"[yellow]VirusTotal: {vt.get('error')}[/yellow]"
        )

    proxycheck = results["ProxyCheck"]

    if proxycheck.get("success"):

        table = Table(
            title="VPN & PROXY INTELLIGENCE",
            show_header=False,
            border_style="green",
        )

        table.add_column("Field", style="bold green")
        table.add_column("Value")

        def show(value):
            if value is None:
                return "Unknown"

            if isinstance(value, bool):
                return "Detected" if value else "Not detected"

            if isinstance(value, list):
                return ", ".join(map(str, value)) or "Unknown"

            if isinstance(value, dict):
                return ", ".join(
                    f"{k}: {v}" for k, v in value.items()
                ) or "None reported"

            return str(value)

        fields = {
            "VPN": proxycheck.get("vpn"),
            "VPN / Proxy Operator": proxycheck.get("vpn_provider"),
            "Operator Services": proxycheck.get("operator_services"),
            "Proxy": proxycheck.get("proxy"),
            "TOR": proxycheck.get("tor"),
            "Hosting": proxycheck.get("hosting"),
            "Anonymous": proxycheck.get("anonymous"),
            "Compromised": proxycheck.get("compromised"),
            "ISP": proxycheck.get("isp"),
            "Organization": proxycheck.get("organization"),
            "ASN": proxycheck.get("asn"),
            "Network Type": proxycheck.get("network_type"),
            "Hostname": proxycheck.get("hostname"),
            "Country": proxycheck.get("country"),
            "City": proxycheck.get("city"),
            "ProxyCheck Risk": proxycheck.get("risk"),
            "Detection Confidence": proxycheck.get("detection_confidence"),
            "Attack History": proxycheck.get("attack_history"),
            "Last Updated": proxycheck.get("last_updated"),
        }

        for field, value in fields.items():
            table.add_row(field, show(value))

        console.print()
        console.print(table)

        console.print(
            "[dim]ProxyCheck risk measures provider-specific "
            "abuse/anonymization risk, not Hound's malware score.[/dim]"
        )

    else:
        console.print(
            f"\n[yellow]ProxyCheck: "
            f"{proxycheck.get('error', 'Unavailable')}[/yellow]"
        )


    # -----------------------------------
    # Hound Threat Assessment
    # -----------------------------------

    assessment = calculate_scores(results)

    threat_score = assessment["threat_score"]
    confidence = assessment["confidence_score"]
    verdict = assessment["verdict"]

    if verdict == "HIGH RISK":
        color = "red"
    elif verdict in ("SUSPICIOUS", "LOW MALICIOUSNESS SIGNAL"):
        color = "yellow"
    elif verdict == "NO MALICIOUS SIGNALS DETECTED":
        color = "green"
    else:
        color = "yellow"

    assessed = verdict not in (
        "INSUFFICIENT DATA",
        "LIMITED EVIDENCE",
    )

    score_text = (
        f"{threat_score}/100" if assessed
        else "N/A - insufficient coverage"
    )

    assessment_table = Table(
        show_header=False,
        border_style=color,
    )

    assessment_table.add_column(
        "Field",
        style="bold cyan",
    )
    assessment_table.add_column("Value")

    assessment_table.add_row(
        "Threat Score",
        score_text,
    )

    assessment_table.add_row(
        "Confidence",
        f"{confidence}/100",
    )

    assessment_table.add_row(
        "Verdict",
        f"[bold {color}]{verdict}[/bold {color}]",
    )

    assessment_table.add_row(
        "Scoring Version",
        assessment["scoring_version"],
    )

    console.print()
    console.print(
        Panel(
            assessment_table,
            title="HOUND THREAT ASSESSMENT",
            border_style=color,
        )
    )

    console.print(
        "\n[bold cyan]EVIDENCE[/bold cyan]"
    )

    for item in assessment["evidence"]:
        console.print(f"  • {item}")

    if assessment["warnings"]:
        console.print(
            "\n[bold yellow]ANALYST WARNINGS[/bold yellow]"
        )

        for warning in assessment["warnings"]:
            console.print(
                f"  [yellow]⚠ {warning}[/yellow]"
            )

    console.print(
        "\n[dim]Scores are provisional heuristics, "
        "not calibrated probabilities. "
        "No detections does not prove safety.[/dim]"
    )


    if ai:
        console.print()
        console.print(
            "[cyan]Hound AI is analysing intelligence...[/cyan]"
        )

        ai_result = asyncio.run(
            analyze(target, results, assessment)
        )

        if ai_result["success"]:
            console.print(
                Panel(
                    ai_result["summary"],
                    title="HOUND AI - SOC ANALYSIS",
                    border_style="cyan",
                )
            )

            console.print(
                "\n[bold green]RECOMMENDED ACTION[/bold green]"
            )

            console.print(
                ai_result["recommendation"]
            )

            console.print(
                "\n[dim]Local model: qwen3:4b-instruct[/dim]"
            )

        else:
            console.print(
                "[yellow]Local AI unavailable: "
                + ai_result["error"]
                + "[/yellow]"
            )





@app.command()
def batch(
    file: Path = typer.Argument(
        ...,
        help="Text file containing one indicator per line",
    ),
    workers: int = typer.Option(
        3,
        "--workers",
        min=1,
        max=3,
        help="Maximum concurrent investigations",
    ),
    json_out: Path = typer.Option(
        None,
        "--json",
        help="Export detailed intelligence as JSON",
    ),
):
    """Investigate multiple indicators."""

    from hound.core.bulk import (
        read_targets,
        run_bulk,
        save_json,
    )

    try:
        targets = read_targets(file)
    except (OSError, UnicodeError, ValueError) as error:
        console.print(f"[red]Input error: {error}[/red]")
        raise typer.Exit(code=1)

    console.print()
    console.print(
        Panel.fit(
            "[bold cyan]HOUND BATCH INVESTIGATION[/bold cyan]",
            border_style="cyan",
        )
    )

    console.print(
        f"Indicators: {len(targets)} | Workers: {workers}"
    )

    console.print(
        "[dim]VirusTotal batch requests are conservatively "
        "paced when an API key is configured.[/dim]"
    )

    results = asyncio.run(
        run_bulk(targets, workers=workers)
    )

    table = Table(
        title="SOC INVESTIGATION RESULTS",
        border_style="cyan",
    )

    table.add_column("Indicator", style="cyan")
    table.add_column("Type")
    table.add_column("Status")
    table.add_column("Score")
    table.add_column("Verdict")
    table.add_column("Time", justify="right")

    for item in results:

        score = item["threat_score"]

        score_text = (
            f"{score}/100"
            if score is not None
            else "N/A"
        )

        table.add_row(
            item["indicator"],
            item["type"],
            item["status"],
            score_text,
            item["verdict"],
            f"{item['elapsed']}s",
        )

    console.print(table)

    if json_out is not None:
        try:
            save_json(json_out, results)
            console.print(
                f"[green]JSON report saved: {json_out}[/green]"
            )
        except OSError as error:
            console.print(
                f"[red]Export failed: {error}[/red]"
            )
            raise typer.Exit(code=1)

    console.print(
        "\n[dim]Scores are experimental triage indicators. "
        "Review the underlying evidence before acting.[/dim]"
    )


if __name__ == "__main__":
    app()
