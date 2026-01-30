#!/usr/bin/env python3
"""
Scan comparison (diff) utilities for the ICS Ninja Scanner.

Provides functions to compare scan results over time, track changes in security posture,
and generate trend analysis for Industrial Control Systems.

Developed by MottaSec Ghost Team - The unseen guardians of industrial systems.
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict

from utils.cvss import calculate_risk_score, get_cvss_for_issue


@dataclass
class ScanSummary:
    """Summary statistics for a scan."""
    total_hosts: int
    hosts_with_issues: int
    total_issues: int
    issues_by_severity: Dict[str, int]
    risk_score: float
    protocols: List[str]
    scan_time: str


def normalize_description(description: str) -> str:
    """
    Normalize issue descriptions for comparison by removing variable parts.
    
    Args:
        description (str): Original issue description
        
    Returns:
        str: Normalized description for matching
    """
    normalized = description.lower().strip()
    
    # Remove timestamps (various formats)
    normalized = re.sub(r'\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(\.\d+)?[Z]?\b', '[TIMESTAMP]', normalized)
    normalized = re.sub(r'\b\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}\b', '[TIMESTAMP]', normalized)
    normalized = re.sub(r'\b\d{1,2}:\d{2}:\d{2}\b', '[TIME]', normalized)
    
    # Remove version numbers (e.g., "v1.2.3", "version 4.5.6")
    normalized = re.sub(r'\bv?\d+\.\d+(\.\d+)*\b', '[VERSION]', normalized)
    normalized = re.sub(r'\bversion\s+\d+\.\d+(\.\d+)*\b', 'version [VERSION]', normalized)
    normalized = re.sub(r'\bfirmware\s+\d+\.\d+(\.\d+)*\b', 'firmware [VERSION]', normalized)
    
    # Remove specific IP addresses and ports
    normalized = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b', '[IP_ADDRESS]', normalized)
    normalized = re.sub(r'\bport\s+\d+\b', 'port [PORT]', normalized)
    
    # Remove specific numbers that might vary (IDs, counts, etc.)
    normalized = re.sub(r'\bid\s*[:=]?\s*\d+\b', 'id [ID]', normalized)
    normalized = re.sub(r'\bunit\s+id\s*[:=]?\s*\d+\b', 'unit id [ID]', normalized)
    normalized = re.sub(r'\b\d+\s+objects?\s+(found|detected|enumerated)\b', '[COUNT] objects [ACTION]', normalized)
    normalized = re.sub(r'\b\d+\s+devices?\s+(found|detected)\b', '[COUNT] devices [ACTION]', normalized)
    
    # Remove specific register/memory addresses  
    normalized = re.sub(r'\b0x[0-9a-f]+\b', '[ADDRESS]', normalized)
    normalized = re.sub(r'\baddress\s+\d+\b', 'address [ADDRESS]', normalized)
    normalized = re.sub(r'\bregister\s+\d+\b', 'register [ADDRESS]', normalized)
    
    # Remove specific measurements/values
    normalized = re.sub(r'\b\d+(\.\d+)?\s*(ms|seconds?|minutes?|hours?|days?)\b', '[TIME_VALUE]', normalized)
    normalized = re.sub(r'\b\d+(\.\d+)?\s*(bytes?|kb|mb|gb)\b', '[SIZE]', normalized)
    normalized = re.sub(r'\b\d+(\.\d+)?\s*%\b', '[PERCENTAGE]', normalized)
    
    # Normalize spacing and punctuation
    normalized = re.sub(r'\s+', ' ', normalized)
    normalized = normalized.strip(' .,;:')
    
    return normalized


def create_issue_key(host: str, protocol: str, issue: Dict[str, Any]) -> str:
    """
    Create a unique key for issue matching across scans.
    
    Args:
        host (str): IP address or hostname
        protocol (str): Protocol name
        issue (Dict): Issue dictionary
        
    Returns:
        str: Unique key for the issue
    """
    description = issue.get('description', '')
    normalized_desc = normalize_description(description)
    return f"{host}|{protocol}|{normalized_desc}"


def extract_scan_summary(scan_result: Dict[str, Any]) -> ScanSummary:
    """
    Extract summary statistics from a scan result.
    
    Args:
        scan_result (Dict): Complete scan result dictionary
        
    Returns:
        ScanSummary: Summary statistics
    """
    metadata = scan_result.get('metadata', {})
    results = scan_result.get('results', {})
    
    total_hosts = len(results)
    hosts_with_issues = 0
    total_issues = 0
    issues_by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    protocols = metadata.get('protocols', [])
    scan_time = metadata.get('scan_time', '')
    
    # Count issues and hosts with issues
    for host, protocols_data in results.items():
        host_has_issues = False
        for protocol, findings in protocols_data.items():
            if protocol.startswith('_'):  # Skip meta-protocols like _cross_protocol
                continue
            issues = findings.get('issues', [])
            if issues:
                host_has_issues = True
                total_issues += len(issues)
                
            for issue in issues:
                severity = issue.get('severity', 'unknown').lower()
                if severity in issues_by_severity:
                    issues_by_severity[severity] += 1
        
        if host_has_issues:
            hosts_with_issues += 1
    
    # Calculate risk score using existing CVSS function
    try:
        risk_data = calculate_risk_score(results)
        risk_score = risk_data.get('score', 0.0)
    except Exception:
        risk_score = 0.0
    
    return ScanSummary(
        total_hosts=total_hosts,
        hosts_with_issues=hosts_with_issues,
        total_issues=total_issues,
        issues_by_severity=issues_by_severity,
        risk_score=float(risk_score),
        protocols=protocols,
        scan_time=scan_time
    )


def load_scan_result(filepath: str) -> Dict[str, Any]:
    """
    Load a JSON scan result file from reports directory.
    
    Args:
        filepath (str): Path to the JSON scan result file
        
    Returns:
        Dict[str, Any]: Scan result dictionary
        
    Raises:
        FileNotFoundError: If the file doesn't exist
        json.JSONDecodeError: If the file is not valid JSON
        ValueError: If the file doesn't contain valid scan results
    """
    file_path = Path(filepath)
    
    # If path is relative, check in reports directory
    if not file_path.is_absolute():
        reports_dir = Path("reports")
        file_path = reports_dir / filepath
    
    if not file_path.exists():
        raise FileNotFoundError(f"Scan result file not found: {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            scan_data = json.load(f)
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Invalid JSON in {file_path}: {e}")
    
    # Validate basic scan result structure
    if not isinstance(scan_data, dict):
        raise ValueError(f"Scan result must be a dictionary, got {type(scan_data)}")
    
    if 'metadata' not in scan_data or 'results' not in scan_data:
        raise ValueError(f"Invalid scan result format: missing 'metadata' or 'results' keys")
    
    return scan_data


def compare_scans(old_result: Dict[str, Any], new_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare two scan results and identify changes.
    
    Args:
        old_result (Dict): Older scan result
        new_result (Dict): Newer scan result
        
    Returns:
        Dict[str, Any]: Diff result containing all changes
    """
    old_summary = extract_scan_summary(old_result)
    new_summary = extract_scan_summary(new_result)
    
    # Build issue mappings for comparison
    old_issues = {}  # key -> (host, protocol, issue_dict)
    new_issues = {}
    
    # Extract issues from old scan
    for host, protocols_data in old_result.get('results', {}).items():
        for protocol, findings in protocols_data.items():
            if protocol.startswith('_'):
                continue
            for issue in findings.get('issues', []):
                key = create_issue_key(host, protocol, issue)
                old_issues[key] = (host, protocol, issue)
    
    # Extract issues from new scan  
    for host, protocols_data in new_result.get('results', {}).items():
        for protocol, findings in protocols_data.items():
            if protocol.startswith('_'):
                continue
            for issue in findings.get('issues', []):
                key = create_issue_key(host, protocol, issue)
                new_issues[key] = (host, protocol, issue)
    
    # Find differences
    old_keys = set(old_issues.keys())
    new_keys = set(new_issues.keys())
    
    new_issue_keys = new_keys - old_keys
    resolved_issue_keys = old_keys - new_keys
    persistent_issue_keys = old_keys & new_keys
    
    # Organize by host and protocol
    new_issues_organized = {}
    resolved_issues_organized = {}
    persistent_issues_organized = {}
    changed_severity_issues = {}
    
    def add_to_organized(organized_dict, issue_key, issue_tuple):
        host, protocol, issue = issue_tuple
        if host not in organized_dict:
            organized_dict[host] = {}
        if protocol not in organized_dict[host]:
            organized_dict[host][protocol] = []
        organized_dict[host][protocol].append(issue)
    
    # Organize new issues
    for key in new_issue_keys:
        add_to_organized(new_issues_organized, key, new_issues[key])
    
    # Organize resolved issues
    for key in resolved_issue_keys:
        add_to_organized(resolved_issues_organized, key, old_issues[key])
    
    # Check for severity changes in persistent issues
    for key in persistent_issue_keys:
        old_host, old_protocol, old_issue = old_issues[key]
        new_host, new_protocol, new_issue = new_issues[key]
        
        old_severity = old_issue.get('severity', '').lower()
        new_severity = new_issue.get('severity', '').lower()
        
        if old_severity != new_severity:
            # Severity changed
            change_info = {
                'old_issue': old_issue,
                'new_issue': new_issue,
                'old_severity': old_severity,
                'new_severity': new_severity
            }
            add_to_organized(changed_severity_issues, key, (old_host, old_protocol, change_info))
        else:
            # No change in severity
            add_to_organized(persistent_issues_organized, key, new_issues[key])
    
    # Identify host and device changes
    old_hosts = set(old_result.get('results', {}).keys())
    new_hosts = set(new_result.get('results', {}).keys())
    
    new_hosts_found = new_hosts - old_hosts
    removed_hosts = old_hosts - new_hosts
    
    # Check for device/firmware changes on persistent hosts
    device_changes = {}
    common_hosts = old_hosts & new_hosts
    
    for host in common_hosts:
        old_host_data = old_result['results'][host]
        new_host_data = new_result['results'][host]
        host_changes = {}
        
        # Check protocols
        old_protocols = set(old_host_data.keys())
        new_protocols = set(new_host_data.keys())
        
        if old_protocols != new_protocols:
            host_changes['protocols'] = {
                'added': list(new_protocols - old_protocols),
                'removed': list(old_protocols - new_protocols)
            }
        
        # Check device info changes
        for protocol in old_protocols & new_protocols:
            if protocol.startswith('_'):
                continue
                
            old_device_info = old_host_data[protocol].get('device_info', {})
            new_device_info = new_host_data[protocol].get('device_info', {})
            
            info_changes = {}
            for key in set(old_device_info.keys()) | set(new_device_info.keys()):
                old_val = old_device_info.get(key, '')
                new_val = new_device_info.get(key, '')
                if old_val != new_val:
                    info_changes[key] = {'old': old_val, 'new': new_val}
            
            if info_changes:
                if protocol not in host_changes:
                    host_changes[protocol] = {}
                host_changes[protocol]['device_info'] = info_changes
        
        if host_changes:
            device_changes[host] = host_changes
    
    # Calculate risk score changes
    old_risk = old_summary.risk_score
    new_risk = new_summary.risk_score
    risk_change = new_risk - old_risk
    
    # Find most improved/degraded hosts
    host_risk_changes = {}
    for host in common_hosts:
        # Calculate risk for individual hosts
        old_host_issues = []
        new_host_issues = []
        
        for protocol, findings in old_result['results'][host].items():
            if protocol.startswith('_'):
                continue
            old_host_issues.extend(findings.get('issues', []))
            
        for protocol, findings in new_result['results'][host].items():
            if protocol.startswith('_'):
                continue
            new_host_issues.extend(findings.get('issues', []))
        
        # Simple risk calculation based on severity counts
        def calc_host_risk(issues):
            severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 1}
            return sum(severity_weights.get(issue.get('severity', '').lower(), 0) for issue in issues)
        
        old_host_risk = calc_host_risk(old_host_issues)
        new_host_risk = calc_host_risk(new_host_issues)
        host_risk_changes[host] = new_host_risk - old_host_risk
    
    # Find most improved and degraded hosts
    most_improved = None
    most_degraded = None
    
    if host_risk_changes:
        most_improved_host = min(host_risk_changes, key=host_risk_changes.get)
        most_degraded_host = max(host_risk_changes, key=host_risk_changes.get)
        
        if host_risk_changes[most_improved_host] < 0:
            most_improved = {
                'host': most_improved_host,
                'improvement': abs(host_risk_changes[most_improved_host])
            }
        
        if host_risk_changes[most_degraded_host] > 0:
            most_degraded = {
                'host': most_degraded_host,
                'degradation': host_risk_changes[most_degraded_host]
            }
    
    # Compile results
    diff_result = {
        'metadata': {
            'comparison_time': datetime.now().isoformat(),
            'old_scan': {
                'time': old_summary.scan_time,
                'target': old_result.get('metadata', {}).get('target', 'unknown')
            },
            'new_scan': {
                'time': new_summary.scan_time, 
                'target': new_result.get('metadata', {}).get('target', 'unknown')
            }
        },
        'summary': {
            'old_summary': asdict(old_summary),
            'new_summary': asdict(new_summary),
            'changes': {
                'new_issues': len(new_issue_keys),
                'resolved_issues': len(resolved_issue_keys),
                'persistent_issues': len(persistent_issue_keys),
                'changed_severity': len(changed_severity_issues),
                'net_risk_change': risk_change,
                'risk_trend': 'improved' if risk_change < 0 else 'degraded' if risk_change > 0 else 'unchanged'
            }
        },
        'new_hosts': list(new_hosts_found),
        'removed_hosts': list(removed_hosts),
        'new_issues': new_issues_organized,
        'resolved_issues': resolved_issues_organized,
        'persistent_issues': persistent_issues_organized,
        'changed_severity': changed_severity_issues,
        'device_changes': device_changes,
        'host_risk_analysis': {
            'most_improved': most_improved,
            'most_degraded': most_degraded,
            'risk_changes': host_risk_changes
        }
    }
    
    return diff_result


def risk_trend(scan_history: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze risk trend over a series of scans.
    
    Args:
        scan_history (List[Dict]): List of scan results (oldest first)
        
    Returns:
        Dict[str, Any]: Risk trend analysis
    """
    if not scan_history:
        return {'error': 'No scan history provided'}
    
    if len(scan_history) < 2:
        return {'error': 'At least 2 scans required for trend analysis'}
    
    # Extract summaries and risk scores over time
    summaries = []
    risk_scores = []
    timestamps = []
    
    for scan in scan_history:
        summary = extract_scan_summary(scan)
        summaries.append(summary)
        risk_scores.append(summary.risk_score)
        timestamps.append(summary.scan_time)
    
    # Calculate trend metrics
    initial_risk = risk_scores[0]
    final_risk = risk_scores[-1]
    total_change = final_risk - initial_risk
    
    # Calculate average change per scan
    changes = [risk_scores[i+1] - risk_scores[i] for i in range(len(risk_scores)-1)]
    avg_change = sum(changes) / len(changes) if changes else 0
    
    # Detect trend direction
    improving_count = sum(1 for change in changes if change < 0)
    degrading_count = sum(1 for change in changes if change > 0)
    stable_count = sum(1 for change in changes if change == 0)
    
    if improving_count > degrading_count:
        overall_trend = 'improving'
    elif degrading_count > improving_count:
        overall_trend = 'degrading'  
    else:
        overall_trend = 'stable'
    
    # Calculate volatility (standard deviation of changes)
    if len(changes) > 1:
        mean_change = sum(changes) / len(changes)
        volatility = (sum((x - mean_change) ** 2 for x in changes) / len(changes)) ** 0.5
    else:
        volatility = 0
    
    # Find peak and lowest risk
    max_risk = max(risk_scores)
    min_risk = min(risk_scores)
    max_risk_idx = risk_scores.index(max_risk)
    min_risk_idx = risk_scores.index(min_risk)
    
    # Issue trend analysis
    total_issues_over_time = [summary.total_issues for summary in summaries]
    critical_issues_over_time = [summary.issues_by_severity.get('critical', 0) for summary in summaries]
    
    return {
        'time_period': {
            'start': timestamps[0],
            'end': timestamps[-1],
            'total_scans': len(scan_history)
        },
        'risk_scores': {
            'timeline': list(zip(timestamps, risk_scores)),
            'initial': initial_risk,
            'final': final_risk,
            'total_change': total_change,
            'average_change_per_scan': avg_change,
            'peak': {'score': max_risk, 'time': timestamps[max_risk_idx]},
            'lowest': {'score': min_risk, 'time': timestamps[min_risk_idx]}
        },
        'trend_analysis': {
            'overall_direction': overall_trend,
            'volatility': volatility,
            'improving_periods': improving_count,
            'degrading_periods': degrading_count,
            'stable_periods': stable_count
        },
        'issue_trends': {
            'total_issues_timeline': list(zip(timestamps, total_issues_over_time)),
            'critical_issues_timeline': list(zip(timestamps, critical_issues_over_time))
        }
    }


def generate_diff_report(diff_result: Dict[str, Any], format_type: str = 'txt') -> str:
    """
    Generate a human-readable diff report.
    
    Args:
        diff_result (Dict): Result from compare_scans()
        format_type (str): Output format ('txt', 'json', 'html')
        
    Returns:
        str: Formatted report content
    """
    if format_type == 'json':
        return json.dumps(diff_result, indent=2, ensure_ascii=False)
    
    if format_type == 'html':
        return _generate_html_diff_report(diff_result)
    
    # Default to text format
    return _generate_text_diff_report(diff_result)


def _generate_text_diff_report(diff_result: Dict[str, Any]) -> str:
    """Generate a text-format diff report."""
    lines = []
    
    # Header
    lines.append("ICS NINJA SCANNER - SCAN COMPARISON REPORT")
    lines.append("=" * 50)
    lines.append("")
    
    # Metadata
    metadata = diff_result['metadata']
    lines.append("COMPARISON DETAILS")
    lines.append("-" * 20)
    lines.append(f"Comparison time: {metadata['comparison_time']}")
    lines.append(f"Old scan: {metadata['old_scan']['time']} ({metadata['old_scan']['target']})")
    lines.append(f"New scan: {metadata['new_scan']['time']} ({metadata['new_scan']['target']})")
    lines.append("")
    
    # Summary
    summary = diff_result['summary']
    old_sum = summary['old_summary']
    new_sum = summary['new_summary']
    changes = summary['changes']
    
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 17)
    lines.append(f"Risk Score Change: {old_sum['risk_score']:.1f} → {new_sum['risk_score']:.1f} "
                 f"({changes['net_risk_change']:+.1f}) [{changes['risk_trend'].upper()}]")
    lines.append(f"Total Issues: {old_sum['total_issues']} → {new_sum['total_issues']} "
                 f"({new_sum['total_issues'] - old_sum['total_issues']:+d})")
    lines.append(f"Affected Hosts: {old_sum['hosts_with_issues']} → {new_sum['hosts_with_issues']} "
                 f"({new_sum['hosts_with_issues'] - old_sum['hosts_with_issues']:+d})")
    lines.append("")
    lines.append("Issue Changes:")
    lines.append(f"  • New issues found: {changes['new_issues']}")
    lines.append(f"  • Issues resolved: {changes['resolved_issues']}")
    lines.append(f"  • Persistent issues: {changes['persistent_issues']}")
    lines.append(f"  • Severity changes: {changes['changed_severity']}")
    lines.append("")
    
    # Host changes
    if diff_result['new_hosts'] or diff_result['removed_hosts']:
        lines.append("HOST CHANGES")
        lines.append("-" * 12)
        if diff_result['new_hosts']:
            lines.append(f"New hosts discovered ({len(diff_result['new_hosts'])}):")
            for host in diff_result['new_hosts']:
                lines.append(f"  + {host}")
        if diff_result['removed_hosts']:
            lines.append(f"Hosts no longer accessible ({len(diff_result['removed_hosts'])}):")
            for host in diff_result['removed_hosts']:
                lines.append(f"  - {host}")
        lines.append("")
    
    # Most significant changes
    risk_analysis = diff_result.get('host_risk_analysis', {})
    most_improved = risk_analysis.get('most_improved')
    most_degraded = risk_analysis.get('most_degraded')
    
    if most_improved or most_degraded:
        lines.append("SIGNIFICANT HOST CHANGES")
        lines.append("-" * 23)
        if most_improved:
            lines.append(f"Most improved: {most_improved['host']} "
                         f"(risk reduction: {most_improved['improvement']:.1f})")
        if most_degraded:
            lines.append(f"Most degraded: {most_degraded['host']} "
                         f"(risk increase: {most_degraded['degradation']:.1f})")
        lines.append("")
    
    # New issues detail
    if diff_result['new_issues']:
        lines.append("NEW ISSUES DETECTED")
        lines.append("-" * 19)
        for host, protocols in diff_result['new_issues'].items():
            lines.append(f"Host: {host}")
            for protocol, issues in protocols.items():
                lines.append(f"  Protocol: {protocol.upper()}")
                for issue in issues:
                    severity = issue.get('severity', 'unknown').upper()
                    lines.append(f"    [{severity}] {issue['description']}")
                    if issue.get('details'):
                        lines.append(f"      Details: {issue['details']}")
        lines.append("")
    
    # Resolved issues
    if diff_result['resolved_issues']:
        lines.append("RESOLVED ISSUES")
        lines.append("-" * 15)
        for host, protocols in diff_result['resolved_issues'].items():
            lines.append(f"Host: {host}")
            for protocol, issues in protocols.items():
                lines.append(f"  Protocol: {protocol.upper()}")
                for issue in issues:
                    severity = issue.get('severity', 'unknown').upper()
                    lines.append(f"    ✓ [{severity}] {issue['description']}")
        lines.append("")
    
    # Severity changes
    if diff_result['changed_severity']:
        lines.append("SEVERITY CHANGES")
        lines.append("-" * 16)
        for host, protocols in diff_result['changed_severity'].items():
            lines.append(f"Host: {host}")
            for protocol, changes in protocols.items():
                lines.append(f"  Protocol: {protocol.upper()}")
                for change in changes:
                    old_sev = change['old_severity'].upper()
                    new_sev = change['new_severity'].upper()
                    desc = change['new_issue']['description']
                    lines.append(f"    {old_sev} → {new_sev}: {desc}")
        lines.append("")
    
    # Device/firmware changes
    if diff_result['device_changes']:
        lines.append("DEVICE & FIRMWARE CHANGES")
        lines.append("-" * 25)
        for host, changes in diff_result['device_changes'].items():
            lines.append(f"Host: {host}")
            if 'protocols' in changes:
                if changes['protocols'].get('added'):
                    lines.append(f"  + New protocols: {', '.join(changes['protocols']['added'])}")
                if changes['protocols'].get('removed'):
                    lines.append(f"  - Removed protocols: {', '.join(changes['protocols']['removed'])}")
            
            for protocol, protocol_changes in changes.items():
                if protocol == 'protocols':
                    continue
                lines.append(f"  Protocol: {protocol.upper()}")
                if 'device_info' in protocol_changes:
                    for key, change in protocol_changes['device_info'].items():
                        lines.append(f"    {key}: {change['old']} → {change['new']}")
        lines.append("")
    
    lines.append("END OF COMPARISON REPORT")
    lines.append("=" * 50)
    
    return '\n'.join(lines)


def _generate_html_diff_report(diff_result: Dict[str, Any]) -> str:
    """Generate an HTML-format diff report."""
    # This is a simplified HTML report - could be enhanced with CSS styling
    html = []
    html.append('<!DOCTYPE html>')
    html.append('<html><head><title>ICS Ninja Scanner - Scan Comparison Report</title>')
    html.append('<style>')
    html.append('body { font-family: Arial, sans-serif; margin: 20px; }')
    html.append('h1, h2 { color: #2E86C1; }')
    html.append('.summary { background-color: #F8F9FA; padding: 15px; border-radius: 5px; }')
    html.append('.new { color: #E74C3C; }')
    html.append('.resolved { color: #27AE60; }')
    html.append('.changed { color: #F39C12; }')
    html.append('table { border-collapse: collapse; width: 100%; margin: 10px 0; }')
    html.append('th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }')
    html.append('th { background-color: #f2f2f2; }')
    html.append('</style></head><body>')
    
    # Title and metadata
    html.append('<h1>ICS Ninja Scanner - Scan Comparison Report</h1>')
    metadata = diff_result['metadata']
    html.append(f'<p><strong>Comparison time:</strong> {metadata["comparison_time"]}</p>')
    html.append(f'<p><strong>Old scan:</strong> {metadata["old_scan"]["time"]} ({metadata["old_scan"]["target"]})</p>')
    html.append(f'<p><strong>New scan:</strong> {metadata["new_scan"]["time"]} ({metadata["new_scan"]["target"]})</p>')
    
    # Summary
    summary = diff_result['summary']
    changes = summary['changes']
    html.append('<div class="summary">')
    html.append('<h2>Executive Summary</h2>')
    html.append(f'<p><strong>Risk Trend:</strong> {changes["risk_trend"].upper()}</p>')
    html.append(f'<p><strong>Net Risk Change:</strong> {changes["net_risk_change"]:+.1f}</p>')
    html.append(f'<p><strong>New Issues:</strong> <span class="new">{changes["new_issues"]}</span></p>')
    html.append(f'<p><strong>Resolved Issues:</strong> <span class="resolved">{changes["resolved_issues"]}</span></p>')
    html.append(f'<p><strong>Changed Severity:</strong> <span class="changed">{changes["changed_severity"]}</span></p>')
    html.append('</div>')
    
    # Add more detailed sections as needed...
    html.append('</body></html>')
    
    return '\n'.join(html)


def find_latest_scan(target_pattern: str, reports_dir: str = "reports") -> Optional[str]:
    """
    Find the most recent scan file for a given target pattern.
    
    Args:
        target_pattern (str): Target pattern to match in filename
        reports_dir (str): Directory to search in
        
    Returns:
        Optional[str]: Path to the most recent scan file, or None if not found
    """
    reports_path = Path(reports_dir)
    if not reports_path.exists():
        return None
    
    # Clean up the target pattern for filename matching
    safe_target = target_pattern.replace('/', '_').replace(':', '_').replace(' ', '_')
    
    # Find matching JSON files
    matching_files = []
    for file_path in reports_path.glob("*.json"):
        filename = file_path.name.lower()
        # Match files that contain the target pattern
        if safe_target.lower() in filename or target_pattern.lower() in filename:
            try:
                # Extract timestamp from filename if possible
                timestamp_match = re.search(r'(\d{8}_\d{6})', filename)
                if timestamp_match:
                    timestamp_str = timestamp_match.group(1)
                    timestamp = datetime.strptime(timestamp_str, '%Y%m%d_%H%M%S')
                    matching_files.append((timestamp, str(file_path)))
            except ValueError:
                # If we can't parse timestamp, use file modification time
                mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                matching_files.append((mtime, str(file_path)))
    
    if not matching_files:
        return None
    
    # Return the most recent file
    matching_files.sort(key=lambda x: x[0], reverse=True)
    return matching_files[0][1]