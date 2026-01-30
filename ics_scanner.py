#!/usr/bin/env python3
"""
MottaSec ICS Ninja Scanner - A multi-protocol Industrial Control System security scanner.

Developed by MottaSec Ghost Team - The unseen guardians of industrial systems.
"""

import os
import sys
import time
import click
import yaml
import json
import csv
import ipaddress
import logging
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel
from rich.logging import RichHandler

# Import scanner modules (graceful fallback)
from scanners import AVAILABLE_SCANNERS, UNAVAILABLE_SCANNERS, ALL_SCANNER_NAMES

# Import utilities
from utils.network import parse_target_input, port_scan
from utils.reporting import generate_report
from utils.config import load_config
from utils.cve_lookup import enrich_scan_results, get_database_stats
from utils.compliance import map_finding_to_compliance, generate_compliance_report, get_compliance_summary
from utils.diff import load_scan_result, compare_scans, generate_diff_report, find_latest_scan, risk_trend
from utils.profiles import get_profile, list_profiles, apply_profile, format_profiles_table, PROFILE_NAMES

# Initialize console
console = Console()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, console=console)]
)
logger = logging.getLogger("ICSNinja")

# Version
VERSION = "1.0.0"
CODENAME = "MottaSec-Fox"

# Protocol to scanner class mapping (only available scanners)
PROTOCOL_SCANNERS = AVAILABLE_SCANNERS


def _analyze_cross_protocol(target_results):
    """Analyze results across protocols for a single target to find cross-protocol issues."""
    cross_protocol_issues = []
    active_protocols = set(target_results.keys())

    # Skip if only one or zero protocols found
    if len(active_protocols) <= 1:
        return cross_protocol_issues

    # Modbus + S7 = Siemens PLC with Modbus gateway
    if "modbus" in active_protocols and "s7" in active_protocols:
        cross_protocol_issues.append({
            "severity": "medium",
            "description": "Siemens PLC with Modbus gateway enabled — additional attack surface",
            "details": "Both S7comm and Modbus are active on this host. The Modbus interface may "
                       "bypass S7-specific access controls, providing an alternative path to device registers.",
            "remediation": "Disable Modbus if not required. If needed, apply network segmentation "
                           "to restrict access to both protocols independently."
        })

    # MQTT + OPC-UA = IIoT gateway
    if "mqtt" in active_protocols and "opcua" in active_protocols:
        cross_protocol_issues.append({
            "severity": "medium",
            "description": "IIoT gateway detected — bridge between IT and OT networks",
            "details": "MQTT (IT/cloud protocol) and OPC-UA (OT protocol) on the same host suggests "
                       "an IIoT gateway bridging IT and OT networks.",
            "remediation": "Ensure strict network segmentation between IT and OT sides. "
                           "Apply authentication and encryption on both protocols. "
                           "Monitor gateway for anomalous cross-network traffic."
        })

    # SNMP + any ICS protocol
    ics_protocols = {"modbus", "dnp3", "bacnet", "s7", "ethernet-ip", "opcua",
                     "profinet", "iec104", "hart"}
    if "snmp" in active_protocols and active_protocols & ics_protocols:
        cross_protocol_issues.append({
            "severity": "high",
            "description": "SNMP exposed on ICS device — management interface accessible",
            "details": "SNMP management interface is accessible alongside ICS protocols. "
                       "SNMP can leak device information and may allow configuration changes.",
            "remediation": "Restrict SNMP access via ACLs. Use SNMPv3 with authentication and encryption. "
                           "Change default community strings. Consider disabling SNMP if not required."
        })

    # Multiple protocols = larger attack surface
    if len(active_protocols) >= 3:
        cross_protocol_issues.append({
            "severity": "medium",
            "description": f"Multi-protocol device — larger attack surface ({len(active_protocols)} protocols active)",
            "details": f"Active protocols: {', '.join(sorted(active_protocols))}. "
                       "Each additional protocol increases the number of potential attack vectors.",
            "remediation": "Disable protocols that are not operationally required. "
                           "Apply defense-in-depth with per-protocol access controls."
        })

    # Check for unencrypted + auth weakness combination
    unencrypted_protocols = set()
    auth_issue_protocols = set()
    for protocol, findings in target_results.items():
        if protocol.startswith("_"):
            continue
        for issue in findings.get("issues", []):
            desc_lower = issue.get("description", "").lower()
            details_lower = issue.get("details", "").lower()
            combined = desc_lower + " " + details_lower
            if any(kw in combined for kw in ["unencrypted", "no encryption", "cleartext",
                                              "plain text", "no tls", "no ssl"]):
                unencrypted_protocols.add(protocol)
            if any(kw in combined for kw in ["no authentication", "unauthenticated",
                                              "default credential", "default password",
                                              "auth", "anonymous access"]):
                auth_issue_protocols.add(protocol)

    if unencrypted_protocols and auth_issue_protocols:
        cross_protocol_issues.append({
            "severity": "critical",
            "description": "Device has both unencrypted communications and authentication weaknesses",
            "details": f"Unencrypted: {', '.join(sorted(unencrypted_protocols))}. "
                       f"Auth issues: {', '.join(sorted(auth_issue_protocols))}. "
                       "An attacker can intercept traffic AND access the device without proper credentials.",
            "remediation": "Enable encryption on all supported protocols. "
                           "Enforce authentication with strong, unique credentials. "
                           "Prioritize fixing authentication on unencrypted channels."
        })

    return cross_protocol_issues


def validate_protocols(ctx, param, value):
    """Validate the protocols parameter."""
    if not value:
        return []
    
    if value.lower() == 'all':
        # Return all available protocols
        if not AVAILABLE_SCANNERS:
            raise click.BadParameter("No protocol scanners are available. Install required dependencies.")
        return list(AVAILABLE_SCANNERS.keys())
    
    protocols = [p.strip().lower() for p in value.split(',')]
    invalid_protocols = [p for p in protocols if p not in ALL_SCANNER_NAMES]
    
    if invalid_protocols:
        raise click.BadParameter(
            f"Invalid protocols: {', '.join(invalid_protocols)}. "
            f"Known protocols: {', '.join(ALL_SCANNER_NAMES)}"
        )
    
    # Warn about unavailable protocols and filter them out
    unavailable = [p for p in protocols if p not in AVAILABLE_SCANNERS]
    if unavailable:
        for p in unavailable:
            reason = UNAVAILABLE_SCANNERS.get(p, "unknown")
            console.print(f"[yellow]Warning: '{p}' scanner unavailable ({reason}). Skipping.[/yellow]")
        protocols = [p for p in protocols if p in AVAILABLE_SCANNERS]
        if not protocols:
            raise click.BadParameter("No requested protocols are available. Install missing dependencies.")
    
    return protocols

def print_mottasec_banner():
    """Print the MottaSec ICS Ninja Scanner banner."""
    banner = f"""
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                                                                              ║
    ║  [bold blue]MottaSec ICS Ninja Scanner v{VERSION}[/bold blue] - [bold yellow]"{CODENAME}"[/bold yellow]                         ║
    ║                                                                              ║
    ║  [cyan]Developed by the MottaSec Ghost Team[/cyan]                                   ║
    ║  [cyan]The unseen guardians of industrial systems[/cyan]                             ║
    ║                                                                              ║
    ║  [green]"We find what others miss"[/green]                                           ║
    ║                                                                              ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    """
    console.print(Panel(banner, border_style="blue"))

@click.group()
def cli():
    """MottaSec ICS Ninja Scanner - A multi-protocol Industrial Control System security scanner."""
    pass

@cli.command()
@click.option('--target', required=True, help='Target IP, IP range, or subnet')
@click.option('--protocols', required=True, callback=validate_protocols, 
              help='Comma-separated list of protocols or \'all\'')
@click.option('--intensity', type=click.Choice(['low', 'medium', 'high']), default='low',
              help='Scan intensity level')
@click.option('--output-format', type=click.Choice(['txt', 'json', 'csv', 'html', 'all']), default='txt',
              help='Output format')
@click.option('--output-file', help='Output file name (without extension)')
@click.option('--port-range', help='Custom port range to scan (default: protocol standard ports)')
@click.option('--timeout', default=5, help='Connection timeout in seconds')
@click.option('--threads', default=10, help='Number of threads for parallel scanning')
@click.option('--no-verify', is_flag=True, help='Disable SSL/TLS verification for protocols that support it')
@click.option('--rate-limit', default=0.0, type=float,
              help='Delay between operations in seconds (protects fragile ICS devices)')
@click.option('--yes', '-y', is_flag=True, help='Skip confirmation for high intensity scans')
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.option('--profile', type=click.Choice(PROFILE_NAMES), default=None,
              help='Apply a pre-built scan profile (overrides --protocols, --intensity)')
@click.option('--cve-check', is_flag=True, help='Enable CVE correlation against embedded ICS CVE database')
@click.option('--compliance', type=click.Choice(['iec62443', 'nist80082', 'nerccip', 'all']), default=None,
              help='Run compliance mapping against ICS security frameworks')
@click.option('--diff-baseline', is_flag=True,
              help='Auto-compare results with most recent previous scan for the same target')
def scan(target, protocols, intensity, output_format, output_file, port_range, timeout, threads,
         no_verify, rate_limit, yes, debug, profile, cve_check, compliance, diff_baseline):
    """Run a security scan against ICS targets."""
    # Set debug logging if requested
    if debug:
        logging.getLogger("ICSNinja").setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    start_time = time.time()
    
    # Print banner
    print_mottasec_banner()
    
    # Apply scan profile if specified (overrides protocols and intensity)
    if profile:
        profile_protocols, profile_intensity, extra_ports = apply_profile(profile)
        protocols = validate_protocols(None, None, ','.join(profile_protocols))
        intensity = profile_intensity
        if extra_ports and not port_range:
            from utils.profiles import ports_to_range_string
            port_range = ports_to_range_string(extra_ports)
        profile_info = get_profile(profile)
        console.print(f"[bold cyan]📋 Profile: {profile_info['name']}[/bold cyan]")
        console.print(f"[cyan]   {profile_info['description']}[/cyan]")
        if profile_info.get('notes'):
            console.print(f"[yellow]   ⚠ {profile_info['notes']}[/yellow]")
    
    # High intensity confirmation
    if intensity == 'high' and not yes:
        if not click.confirm("⚠️  High intensity scan may affect device operation. Continue?"):
            console.print("[yellow]Scan aborted.[/yellow]")
            return
    
    logger.info(f"Starting scan with intensity: {intensity}")
    logger.info(f"Target: {target}")
    logger.info(f"Protocols: {', '.join(protocols)}")
    if rate_limit > 0:
        logger.info(f"Rate limit: {rate_limit}s delay between operations")
    
    # Parse target input
    try:
        targets = parse_target_input(target)
        console.print(f"[green]Resolved {len(targets)} target(s) from input: {target}[/green]")
    except Exception as e:
        console.print(f"[bold red]Error parsing target: {str(e)}[/bold red]")
        sys.exit(1)
    
    # Load configuration
    config = load_config()
    
    # Initialize scan results
    scan_results = {
        "metadata": {
            "scan_time": datetime.now().isoformat(),
            "target": target,
            "protocols": protocols,
            "intensity": intensity,
            "version": VERSION,
            "codename": CODENAME,
            "scanner": "MottaSec ICS Ninja Scanner"
        },
        "results": {}
    }
    
    # Create scanners for each protocol
    active_scanners = {}
    for protocol in protocols:
        scanner_class = PROTOCOL_SCANNERS[protocol]
        try:
            scanner_instance = scanner_class(
                intensity=intensity, timeout=timeout,
                verify=not no_verify, request_delay=rate_limit
            )
        except TypeError:
            # Fallback if scanner doesn't support request_delay parameter
            scanner_instance = scanner_class(intensity=intensity, timeout=timeout, verify=not no_verify)
            logger.debug(f"Scanner {protocol} does not support request_delay parameter")
        active_scanners[protocol] = scanner_instance
        logger.debug(f"Initialized {protocol} scanner with intensity {intensity}")
    
    # Function to scan a single target
    def scan_target(ip):
        target_results = {}
        
        # First perform port scan if port range is specified
        open_ports = []
        if port_range:
            logger.debug(f"Scanning ports {port_range} on {ip}")
            open_ports = port_scan(str(ip), port_range, timeout)
            if open_ports:
                logger.debug(f"Found open ports on {ip}: {open_ports}")
        
        # Run each protocol scanner against the target
        for protocol, scanner in active_scanners.items():
            try:
                logger.debug(f"Running {protocol} scan on {ip}")
                scanner.start_scan_timer()
                protocol_result = scanner.scan(str(ip), open_ports)
                scan_duration = scanner.stop_scan_timer()
                
                if protocol_result:
                    # Add scan duration to results
                    if 'scan_info' not in protocol_result:
                        protocol_result['scan_info'] = {}
                    protocol_result['scan_info']['duration_seconds'] = scan_duration
                    protocol_result['scan_info']['scanner'] = scanner.name
                    target_results[protocol] = protocol_result
                    
                    logger.debug(f"Found {len(protocol_result.get('issues', []))} issues with {protocol} on {ip}")
            except Exception as e:
                logger.error(f"Error scanning {ip} with {protocol}: {str(e)}")
                console.print(f"[bold red]Error scanning {ip} with {protocol}: {str(e)}[/bold red]")
        
        # Cross-protocol intelligence analysis
        if len(target_results) > 1:
            cross_issues = _analyze_cross_protocol(target_results)
            if cross_issues:
                target_results["_cross_protocol"] = {
                    "issues": cross_issues,
                    "scan_info": {
                        "scanner": "Cross-Protocol Analyzer",
                        "protocols_analyzed": list(target_results.keys())
                    }
                }
        
        return str(ip), target_results
    
    # Scan all targets in parallel
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TextColumn("[cyan]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        scan_task = progress.add_task("[bold blue]Scanning targets...", total=len(targets))
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for ip in targets:
                future = executor.submit(scan_target, ip)
                futures.append(future)
            
            for future in futures:
                ip, target_results = future.result()
                if target_results:
                    scan_results["results"][ip] = target_results
                progress.update(scan_task, advance=1)
    
    # CVE enrichment
    if cve_check:
        console.print("\n[bold cyan]🔍 Running CVE correlation...[/bold cyan]")
        cve_stats_before = get_database_stats()
        console.print(f"[cyan]   CVE database: {cve_stats_before['total_cves']} CVEs across "
                      f"{cve_stats_before['vendor_count']} vendors[/cyan]")
        enriched = enrich_scan_results(scan_results)
        cve_meta = enriched.get("metadata", {}).get("cve_correlation", {})
        total_cves_found = cve_meta.get("total_cves_found", 0)
        if total_cves_found > 0:
            console.print(f"[bold red]   ⚠ {total_cves_found} CVE(s) matched against discovered devices![/bold red]")
        else:
            console.print(f"[green]   No known CVEs matched.[/green]")
        scan_results = enriched
    
    # Compliance mapping
    if compliance:
        console.print(f"\n[bold cyan]📋 Running compliance mapping ({compliance})...[/bold cyan]")
        comp_summary = get_compliance_summary(scan_results)
        # Map CLI keys to actual framework names used in compliance.py
        _fw_label_map = {
            'iec62443': 'IEC 62443',
            'nist80082': 'NIST SP 800-82',
            'nerccip': 'NERC CIP',
        }
        frameworks_to_show = ['iec62443', 'nist80082', 'nerccip'] if compliance == 'all' else [compliance]
        for fw in frameworks_to_show:
            label = _fw_label_map.get(fw, fw)
            # by_framework uses full framework names as keys, values are int counts
            total_v = comp_summary.get('by_framework', {}).get(label, 0)
            if total_v > 0:
                console.print(f"[yellow]   {label}: {total_v} violation(s)[/yellow]")
            else:
                console.print(f"[green]   {label}: No violations[/green]")
        # Attach compliance data to scan results for reporting
        scan_results["compliance"] = generate_compliance_report(scan_results)
        scan_results["compliance"]["requested_frameworks"] = frameworks_to_show
    
    # Processing finished
    elapsed_time = time.time() - start_time
    console.print(f"\n[bold green]Scan completed in {elapsed_time:.2f} seconds[/bold green]")
    
    # Generate summary
    total_issues = 0
    critical_issues = 0
    high_issues = 0
    medium_issues = 0
    low_issues = 0
    info_issues = 0
    cross_protocol_count = 0
    
    for ip, protocols_data in scan_results["results"].items():
        for protocol, findings in protocols_data.items():
            if 'issues' in findings:
                for issue in findings['issues']:
                    total_issues += 1
                    if protocol == "_cross_protocol":
                        cross_protocol_count += 1
                    severity = issue.get('severity', '').lower()
                    if severity == 'critical':
                        critical_issues += 1
                    elif severity == 'high':
                        high_issues += 1
                    elif severity == 'medium':
                        medium_issues += 1
                    elif severity == 'low':
                        low_issues += 1
                    elif severity == 'info':
                        info_issues += 1
    
    # Display summary table
    table = Table(title="MottaSec ICS Ninja Scanner - Scan Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Total targets", str(len(targets)))
    table.add_row("Targets with findings", str(len(scan_results["results"])))
    table.add_row("Total issues found", str(total_issues))
    table.add_row("Critical issues", f"[bold red]{critical_issues}[/bold red]")
    table.add_row("High issues", f"[red]{high_issues}[/red]")
    table.add_row("Medium issues", f"[yellow]{medium_issues}[/yellow]")
    table.add_row("Low issues", f"[blue]{low_issues}[/blue]")
    table.add_row("Info issues", f"[cyan]{info_issues}[/cyan]")
    if cross_protocol_count > 0:
        table.add_row("Cross-protocol insights", f"[magenta]{cross_protocol_count}[/magenta]")
    table.add_row("Protocols scanned", ", ".join(protocols))
    table.add_row("Scan intensity", intensity)
    if rate_limit > 0:
        table.add_row("Rate limit", f"{rate_limit}s")
    table.add_row("Scan duration", f"{elapsed_time:.2f} seconds")
    
    console.print(table)
    
    # Generate reports
    if output_file:
        output_formats = [output_format] if output_format != 'all' else ['txt', 'json', 'csv', 'html']
        for format_type in output_formats:
            report_path = generate_report(scan_results, format_type, output_file)
            console.print(f"[bold green]Report saved to: {report_path}[/bold green]")
    else:
        # Print results to console
        for ip, protocols_data in scan_results["results"].items():
            console.print(f"\n[bold blue]Results for target: {ip}[/bold blue]")
            for protocol, findings in protocols_data.items():
                if protocol == "_cross_protocol":
                    console.print(f"\n[bold magenta]🔗 Cross-Protocol Intelligence[/bold magenta]")
                else:
                    console.print(f"\n[bold cyan]Protocol: {protocol.upper()}[/bold cyan]")
                
                if 'device_info' in findings:
                    console.print("[green]Device Information:[/green]")
                    for key, value in findings['device_info'].items():
                        console.print(f"  [cyan]{key}:[/cyan] {value}")
                
                if 'issues' in findings:
                    if protocol == "_cross_protocol":
                        console.print("[magenta]Cross-Protocol Insights:[/magenta]")
                    else:
                        console.print("\n[yellow]Issues Found:[/yellow]")
                    for issue in findings['issues']:
                        severity = issue.get('severity', 'unknown')
                        severity_color = {
                            'critical': 'red',
                            'high': 'red',
                            'medium': 'yellow',
                            'low': 'cyan',
                            'info': 'blue'
                        }.get(severity.lower(), 'white')
                        
                        console.print(f"  [[{severity_color}]{severity}[/{severity_color}]] {issue['description']}")
                        if 'details' in issue:
                            console.print(f"    Details: {issue['details']}")
                        if 'remediation' in issue:
                            console.print(f"    Remediation: {issue['remediation']}")
                
                if not findings.get('issues') and protocol != "_cross_protocol":
                    console.print("[green]  No issues detected[/green]")
    
    # Diff baseline comparison
    if diff_baseline and output_file:
        console.print("\n[bold cyan]🔄 Comparing with previous scan...[/bold cyan]")
        baseline_path = find_latest_scan(target)
        if baseline_path:
            try:
                old_result = load_scan_result(baseline_path)
                diff_result = compare_scans(old_result, scan_results)
                changes = diff_result['summary']['changes']
                trend = changes['risk_trend'].upper()
                trend_color = {'IMPROVED': 'green', 'DEGRADED': 'red', 'UNCHANGED': 'yellow'}.get(trend, 'white')
                console.print(f"[cyan]   Baseline: {baseline_path}[/cyan]")
                console.print(f"[{trend_color}]   Risk trend: {trend} ({changes['net_risk_change']:+.1f})[/{trend_color}]")
                console.print(f"[green]   New issues: {changes['new_issues']}[/green]")
                console.print(f"[cyan]   Resolved: {changes['resolved_issues']}[/cyan]")
                console.print(f"[yellow]   Persistent: {changes['persistent_issues']}[/yellow]")
                # Save diff report
                diff_report_path = Path("reports") / f"{output_file}_diff.txt"
                diff_report_path.parent.mkdir(exist_ok=True)
                diff_report_content = generate_diff_report(diff_result, 'txt')
                with open(diff_report_path, 'w') as f:
                    f.write(diff_report_content)
                console.print(f"[bold green]   Diff report saved to: {diff_report_path}[/bold green]")
            except Exception as e:
                console.print(f"[yellow]   Could not compare: {str(e)}[/yellow]")
        else:
            console.print("[yellow]   No previous scan found for this target.[/yellow]")
    
    # Final message
    console.print(f"\n[bold green]MottaSec ICS Ninja Scanner completed successfully![/bold green]")
    console.print("[yellow]If you found this tool useful, contact us at ghost@mottasec.com[/yellow]")

@cli.command()
def list():
    """List available protocols and scan options."""
    print_mottasec_banner()
    
    console.print("[bold blue]Available Protocols[/bold blue]")
    for protocol in sorted(ALL_SCANNER_NAMES):
        if protocol in AVAILABLE_SCANNERS:
            console.print(f"  ✅ [cyan]{protocol}[/cyan]")
        else:
            reason = UNAVAILABLE_SCANNERS.get(protocol, "unknown error")
            console.print(f"  ❌ [dim]{protocol}[/dim] — [red]{reason}[/red]")
    
    console.print(f"\n  [green]{len(AVAILABLE_SCANNERS)}/{len(ALL_SCANNER_NAMES)} scanners available[/green]")
    
    console.print("\n[bold blue]Intensity Levels[/bold blue]")
    console.print("  - [green]low[/green]: Passive scan (device discovery, version detection)")
    console.print("  - [yellow]medium[/yellow]: Query system state (read registers, security settings)")
    console.print("  - [red]high[/red]: Simulated attack vectors (unauthenticated control attempts, write tests)")
    
    console.print("\n[yellow]Developed by MottaSec Ghost Team - The unseen guardians of industrial systems.[/yellow]")
    console.print("[yellow]Contact us at ghost@mottasec.com[/yellow]")

@cli.command()
def version():
    """Show the version of the tool."""
    print_mottasec_banner()
    console.print(f"MottaSec ICS Ninja Scanner v{VERSION} - Codename: '{CODENAME}'")
    console.print("[yellow]Developed by MottaSec Ghost Team - The unseen guardians of industrial systems.[/yellow]")


@cli.command()
def profiles():
    """List available scan profiles."""
    print_mottasec_banner()
    console.print("[bold blue]Available Scan Profiles[/bold blue]\n")
    console.print(format_profiles_table())
    console.print("[cyan]Usage: ics_scanner.py scan --target <IP> --protocols all --profile <name>[/cyan]")


@cli.command('cve-db')
def cve_db():
    """Show CVE database statistics."""
    print_mottasec_banner()
    stats = get_database_stats()
    console.print("[bold blue]CVE Database Statistics[/bold blue]\n")
    
    table = Table(title="Embedded ICS CVE Database")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Total CVEs", str(stats['total_cves']))
    table.add_row("Vendors", str(stats['vendors']))
    table.add_row("Last updated", stats.get('last_updated', 'unknown'))
    
    if 'severity_distribution' in stats:
        for sev, count in stats['severity_distribution'].items():
            color = {'critical': 'red', 'high': 'red', 'medium': 'yellow', 'low': 'blue'}.get(sev.lower(), 'white')
            table.add_row(f"  {sev}", f"[{color}]{count}[/{color}]")
    
    console.print(table)
    console.print("\n[cyan]Use --cve-check with the scan command to correlate findings.[/cyan]")


@cli.command()
@click.argument('old_report', type=click.Path(exists=True))
@click.argument('new_report', type=click.Path(exists=True))
@click.option('--format', 'fmt', type=click.Choice(['txt', 'json', 'html']), default='txt',
              help='Diff report format')
@click.option('--output', help='Save diff report to file')
def diff(old_report, new_report, fmt, output):
    """Compare two scan reports and show changes.
    
    Usage: ics_scanner.py diff <old_report.json> <new_report.json>
    """
    print_mottasec_banner()
    console.print("[bold blue]Scan Comparison Report[/bold blue]\n")
    
    try:
        old_result = load_scan_result(old_report)
        new_result = load_scan_result(new_report)
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        console.print(f"[bold red]Error loading reports: {str(e)}[/bold red]")
        sys.exit(1)
    
    diff_result = compare_scans(old_result, new_result)
    changes = diff_result['summary']['changes']
    
    # Console summary
    trend = changes['risk_trend'].upper()
    trend_color = {'IMPROVED': 'green', 'DEGRADED': 'red', 'UNCHANGED': 'yellow'}.get(trend, 'white')
    
    table = Table(title="Scan Comparison Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Risk trend", f"[{trend_color}]{trend}[/{trend_color}]")
    table.add_row("Risk change", f"[{trend_color}]{changes['net_risk_change']:+.1f}[/{trend_color}]")
    table.add_row("New issues", f"[red]{changes['new_issues']}[/red]")
    table.add_row("Resolved issues", f"[green]{changes['resolved_issues']}[/green]")
    table.add_row("Persistent issues", str(changes['persistent_issues']))
    table.add_row("Severity changes", str(changes['changed_severity']))
    table.add_row("New hosts", str(len(diff_result.get('new_hosts', []))))
    table.add_row("Removed hosts", str(len(diff_result.get('removed_hosts', []))))
    console.print(table)
    
    # Show most improved/degraded
    risk_analysis = diff_result.get('host_risk_analysis', {})
    if risk_analysis.get('most_improved'):
        h = risk_analysis['most_improved']
        console.print(f"\n[green]Most improved host: {h['host']} (risk -{h['improvement']:.1f})[/green]")
    if risk_analysis.get('most_degraded'):
        h = risk_analysis['most_degraded']
        console.print(f"[red]Most degraded host: {h['host']} (risk +{h['degradation']:.1f})[/red]")
    
    # Save or print full report
    report_content = generate_diff_report(diff_result, fmt)
    if output:
        with open(output, 'w', encoding='utf-8') as f:
            f.write(report_content)
        console.print(f"\n[bold green]Diff report saved to: {output}[/bold green]")
    elif fmt == 'txt':
        console.print(f"\n{report_content}")


@cli.command()
@click.argument('scan_files', nargs=-1, type=click.Path(exists=True))
@click.option('--output', help='Save trend report to file')
def trend(scan_files, output):
    """Analyze risk trend across multiple scans (oldest first).
    
    Usage: ics_scanner.py trend report1.json report2.json report3.json
    """
    print_mottasec_banner()
    
    if len(scan_files) < 2:
        console.print("[bold red]At least 2 scan reports required for trend analysis.[/bold red]")
        sys.exit(1)
    
    console.print(f"[bold blue]Risk Trend Analysis ({len(scan_files)} scans)[/bold blue]\n")
    
    scan_history = []
    for filepath in scan_files:
        try:
            scan_history.append(load_scan_result(filepath))
        except Exception as e:
            console.print(f"[red]Error loading {filepath}: {str(e)}[/red]")
            sys.exit(1)
    
    trend_result = risk_trend(scan_history)
    
    if 'error' in trend_result:
        console.print(f"[red]{trend_result['error']}[/red]")
        sys.exit(1)
    
    scores = trend_result['risk_scores']
    analysis = trend_result['trend_analysis']
    
    table = Table(title="Risk Trend Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    direction = analysis['overall_direction'].upper()
    dir_color = {'IMPROVING': 'green', 'DEGRADING': 'red', 'STABLE': 'yellow'}.get(direction, 'white')
    
    table.add_row("Overall trend", f"[{dir_color}]{direction}[/{dir_color}]")
    table.add_row("Initial risk score", f"{scores['initial']:.1f}")
    table.add_row("Final risk score", f"{scores['final']:.1f}")
    table.add_row("Total change", f"{scores['total_change']:+.1f}")
    table.add_row("Peak risk", f"{scores['peak']['score']:.1f} ({scores['peak']['time']})")
    table.add_row("Lowest risk", f"{scores['lowest']['score']:.1f} ({scores['lowest']['time']})")
    table.add_row("Improving periods", str(analysis['improving_periods']))
    table.add_row("Degrading periods", str(analysis['degrading_periods']))
    table.add_row("Volatility", f"{analysis['volatility']:.2f}")
    
    console.print(table)
    
    # Timeline
    console.print("\n[bold cyan]Risk Score Timeline:[/bold cyan]")
    for ts, score in scores['timeline']:
        bar_len = int(score)
        bar_color = 'green' if score <= 30 else 'yellow' if score <= 60 else 'red'
        console.print(f"  {ts[:19]:20s} [{bar_color}]{'█' * bar_len}[/{bar_color}] {score:.1f}")
    
    if output:
        import json as _json
        with open(output, 'w', encoding='utf-8') as f:
            _json.dump(trend_result, f, indent=2, ensure_ascii=False)
        console.print(f"\n[bold green]Trend report saved to: {output}[/bold green]")


if __name__ == "__main__":
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan aborted by user[/bold red]")
        sys.exit(1)
    except Exception as e:
        logger.exception("An unexpected error occurred")
        console.print(f"\n[bold red]An error occurred: {str(e)}[/bold red]")
        sys.exit(1)
