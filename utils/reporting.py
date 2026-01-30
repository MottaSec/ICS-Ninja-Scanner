#!/usr/bin/env python3
"""
Reporting utilities for the ICS Scanner.
Provides functions for generating reports in various formats.
"""

import os
import json
import csv
from datetime import datetime
from pathlib import Path

def ensure_reports_dir():
    """
    Ensure the reports directory exists.
    
    Returns:
        Path: Path to the reports directory
    """
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    return reports_dir

def generate_timestamp():
    """
    Generate a timestamp string for report filenames.
    
    Returns:
        str: Timestamp string in format YYYYMMDD_HHMMSS
    """
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def generate_report(scan_results, format_type, output_file=None):
    """
    Generate a report from scan results.
    
    Args:
        scan_results (dict): Scan results to report
        format_type (str): Report format ('txt', 'json', 'csv')
        output_file (str): Base name for the output file (without extension)
        
    Returns:
        str: Path to the generated report
    """
    reports_dir = ensure_reports_dir()
    
    if not output_file:
        timestamp = generate_timestamp()
        target = scan_results['metadata']['target']
        safe_target = target.replace('/', '_').replace(':', '_')
        output_file = f"ics_scan_{safe_target}_{timestamp}"
    
    if format_type == 'txt':
        return generate_txt_report(scan_results, reports_dir / f"{output_file}.txt")
    elif format_type == 'json':
        return generate_json_report(scan_results, reports_dir / f"{output_file}.json")
    elif format_type == 'csv':
        return generate_csv_report(scan_results, reports_dir / f"{output_file}.csv")
    elif format_type == 'html':
        from utils.html_report import generate_html_report
        return generate_html_report(scan_results, reports_dir / f"{output_file}.html")
    else:
        raise ValueError(f"Unsupported report format: {format_type}")

def generate_txt_report(scan_results, output_path):
    """
    Generate a text report.
    
    Args:
        scan_results (dict): Scan results to report
        output_path (Path): Path to the output file
        
    Returns:
        str: Path to the generated report
    """
    with open(output_path, 'w') as f:
        f.write("ICS SECURITY SCAN REPORT\n")
        f.write("======================\n\n")
        
        # Metadata
        f.write("SCAN INFO\n")
        f.write("---------\n")
        metadata = scan_results['metadata']
        f.write(f"Scan Time: {metadata['scan_time']}\n")
        f.write(f"Target: {metadata['target']}\n")
        f.write(f"Protocols: {', '.join(metadata['protocols'])}\n")
        f.write(f"Intensity: {metadata['intensity']}\n")
        f.write(f"Tool Version: {metadata['version']}\n\n")
        
        # Results summary
        total_issues = 0
        issues_by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for ip, protocols in scan_results['results'].items():
            for protocol, findings in protocols.items():
                if 'issues' in findings:
                    for issue in findings['issues']:
                        total_issues += 1
                        severity = issue.get('severity', 'unknown').lower()
                        if severity in issues_by_severity:
                            issues_by_severity[severity] += 1
        
        f.write("SUMMARY\n")
        f.write("-------\n")
        f.write(f"Total targets scanned: {len(scan_results['results'])}\n")
        f.write(f"Total issues found: {total_issues}\n")
        f.write("Issues by severity:\n")
        for severity, count in issues_by_severity.items():
            f.write(f"  {severity.capitalize()}: {count}\n")
        f.write("\n")
        
        # Detailed results
        f.write("DETAILED FINDINGS\n")
        f.write("----------------\n\n")
        
        for ip, protocols in scan_results['results'].items():
            f.write(f"HOST: {ip}\n")
            f.write(f"{'-' * (len(ip) + 6)}\n")
            
            for protocol, findings in protocols.items():
                f.write(f"\nProtocol: {protocol.upper()}\n")
                
                if 'device_info' in findings:
                    f.write("Device Information:\n")
                    for key, value in findings['device_info'].items():
                        f.write(f"  {key}: {value}\n")
                
                if 'issues' in findings:
                    f.write("\nIssues Found:\n")
                    for issue in findings['issues']:
                        severity = issue.get('severity', 'unknown')
                        f.write(f"  [{severity.upper()}] {issue['description']}\n")
                        if 'details' in issue:
                            f.write(f"    Details: {issue['details']}\n")
                        if 'remediation' in issue:
                            f.write(f"    Remediation: {issue['remediation']}\n")
                
                if not findings.get('issues'):
                    f.write("  No issues detected\n")
            
            f.write("\n")
        
        f.write("\nEND OF REPORT\n")
    
    return str(output_path)

def generate_json_report(scan_results, output_path):
    """
    Generate a JSON report.
    
    Args:
        scan_results (dict): Scan results to report
        output_path (Path): Path to the output file
        
    Returns:
        str: Path to the generated report
    """
    with open(output_path, 'w') as f:
        json.dump(scan_results, f, indent=2)
    
    return str(output_path)

def generate_csv_report(scan_results, output_path):
    """
    Generate a CSV report.
    
    Args:
        scan_results (dict): Scan results to report
        output_path (Path): Path to the output file
        
    Returns:
        str: Path to the generated report
    """
    with open(output_path, 'w', newline='') as f:
        fieldnames = ['IP', 'Protocol', 'Severity', 'Description', 'Details', 'Remediation']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for ip, protocols in scan_results['results'].items():
            for protocol, findings in protocols.items():
                if 'issues' in findings:
                    for issue in findings['issues']:
                        writer.writerow({
                            'IP': ip,
                            'Protocol': protocol,
                            'Severity': issue.get('severity', 'unknown'),
                            'Description': issue['description'],
                            'Details': issue.get('details', ''),
                            'Remediation': issue.get('remediation', '')
                        })
                else:
                    # Write a row even if no issues were found
                    writer.writerow({
                        'IP': ip,
                        'Protocol': protocol,
                        'Severity': 'info',
                        'Description': 'No issues detected',
                        'Details': '',
                        'Remediation': ''
                    })
    
    return str(output_path) 