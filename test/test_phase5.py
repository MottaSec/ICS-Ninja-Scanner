#!/usr/bin/env python3
"""
Phase 5 tests for MottaSec ICS Ninja Scanner.
Tests CVE correlation, compliance mapping, scan diff, and scan profiles.
"""

import sys
import os
import json
import tempfile
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================================
# Test Data
# ============================================================================

SAMPLE_SCAN_RESULTS = {
    "metadata": {
        "scan_time": "2026-01-29T12:00:00",
        "target": "192.168.1.0/24",
        "protocols": ["modbus", "s7", "opcua"],
        "intensity": "medium",
        "version": "1.0.0",
        "codename": "MottaSec-Fox",
        "scanner": "MottaSec ICS Ninja Scanner"
    },
    "results": {
        "192.168.1.10": {
            "s7": {
                "device_info": {
                    "device_name": "S7-1200",
                    "firmware_version": "4.2.1",
                    "module_type": "CPU 1214C",
                    "vendor": "Siemens",
                    "order_code": "6ES7 214-1AG40-0XB0"
                },
                "issues": [
                    {
                        "severity": "critical",
                        "description": "Unauthenticated access to PLC — no password protection",
                        "details": "S7comm connection established without authentication",
                        "remediation": "Enable S7 access protection level"
                    },
                    {
                        "severity": "high",
                        "description": "CPU state can be changed remotely",
                        "details": "PLC can be stopped/started without authorization",
                        "remediation": "Set access protection to full access with password"
                    },
                    {
                        "severity": "medium",
                        "description": "Firmware version disclosed via S7comm",
                        "details": "Device firmware V4.2.1 disclosed",
                        "remediation": "Restrict S7comm access"
                    }
                ]
            },
            "modbus": {
                "device_info": {
                    "device_name": "Modbus TCP Gateway"
                },
                "issues": [
                    {
                        "severity": "high",
                        "description": "Writable holding registers — no authentication required",
                        "details": "Registers 0-100 writable without authentication",
                        "remediation": "Implement Modbus access controls"
                    },
                    {
                        "severity": "medium",
                        "description": "Unencrypted Modbus/TCP communications",
                        "details": "Modbus/TLS not available on this device",
                        "remediation": "Use Modbus/TLS or VPN for encrypted transport"
                    }
                ]
            }
        },
        "192.168.1.20": {
            "opcua": {
                "device_info": {
                    "device_name": "OPC UA Server",
                    "vendor": "Unified Automation"
                },
                "issues": [
                    {
                        "severity": "critical",
                        "description": "OPC UA SecurityMode 'None' allowed — no encryption or signing",
                        "details": "Server endpoint accepts SecurityMode None",
                        "remediation": "Disable SecurityMode None; require Sign or SignAndEncrypt"
                    },
                    {
                        "severity": "low",
                        "description": "OPC UA address space browsable without authentication",
                        "details": "Anonymous browsing of namespace tree allowed",
                        "remediation": "Require authentication for browsing"
                    }
                ]
            }
        }
    }
}

SAMPLE_SCAN_RESULTS_V2 = {
    "metadata": {
        "scan_time": "2026-02-05T12:00:00",
        "target": "192.168.1.0/24",
        "protocols": ["modbus", "s7", "opcua"],
        "intensity": "medium",
        "version": "1.0.0",
        "codename": "MottaSec-Fox",
        "scanner": "MottaSec ICS Ninja Scanner"
    },
    "results": {
        "192.168.1.10": {
            "s7": {
                "device_info": {
                    "device_name": "S7-1200",
                    "firmware_version": "4.3.0",
                    "module_type": "CPU 1214C",
                    "vendor": "Siemens",
                    "order_code": "6ES7 214-1AG40-0XB0"
                },
                "issues": [
                    {
                        "severity": "medium",
                        "description": "Firmware version disclosed via S7comm",
                        "details": "Device firmware V4.3.0 disclosed",
                        "remediation": "Restrict S7comm access"
                    }
                ]
            }
        },
        "192.168.1.20": {
            "opcua": {
                "device_info": {
                    "device_name": "OPC UA Server",
                    "vendor": "Unified Automation"
                },
                "issues": [
                    {
                        "severity": "critical",
                        "description": "OPC UA SecurityMode 'None' allowed — no encryption or signing",
                        "details": "Server endpoint accepts SecurityMode None",
                        "remediation": "Disable SecurityMode None; require Sign or SignAndEncrypt"
                    }
                ]
            }
        },
        "192.168.1.30": {
            "modbus": {
                "device_info": {
                    "device_name": "New Modbus Device"
                },
                "issues": [
                    {
                        "severity": "high",
                        "description": "Default credentials detected on web interface",
                        "details": "admin/admin login accepted",
                        "remediation": "Change default credentials immediately"
                    }
                ]
            }
        }
    }
}


# ============================================================================
# CVE Lookup Tests
# ============================================================================

def test_cve_lookup_import():
    """Test that cve_lookup module imports correctly."""
    from utils.cve_lookup import lookup_cves, enrich_scan_results, get_database_stats, fetch_from_nvd
    print("  ✅ cve_lookup imports OK")


def test_cve_database_stats():
    """Test CVE database has expected structure and count."""
    from utils.cve_lookup import get_database_stats
    stats = get_database_stats()
    assert isinstance(stats, dict), "get_database_stats should return a dict"
    assert 'total_cves' in stats, "Stats should have total_cves"
    assert stats['total_cves'] >= 50, f"Expected 50+ CVEs, got {stats['total_cves']}"
    assert 'vendors' in stats, "Stats should have vendors count"
    print(f"  ✅ CVE database: {stats['total_cves']} CVEs, {stats['vendors']} vendors")


def test_cve_lookup_siemens():
    """Test CVE lookup with Siemens S7 device info."""
    from utils.cve_lookup import lookup_cves
    device_info = {
        "device_name": "S7-1200",
        "firmware_version": "4.2.1",
        "vendor": "Siemens",
        "module_type": "CPU 1214C",
        "order_code": "6ES7 214-1AG40-0XB0"
    }
    results = lookup_cves(device_info)
    assert isinstance(results, list), "lookup_cves should return a list"
    print(f"  ✅ CVE lookup for S7-1200: {len(results)} CVEs matched")


def test_cve_enrich_scan_results():
    """Test CVE enrichment of full scan results."""
    from utils.cve_lookup import enrich_scan_results
    enriched = enrich_scan_results(SAMPLE_SCAN_RESULTS)
    assert isinstance(enriched, dict), "enrich_scan_results should return a dict"
    assert 'results' in enriched, "Enriched results should have 'results' key"
    assert 'metadata' in enriched, "Enriched results should have 'metadata' key"
    print(f"  ✅ CVE enrichment completed successfully")


def test_cve_fetch_from_nvd_stub():
    """Test that NVD fetch stub exists and returns a list."""
    from utils.cve_lookup import fetch_from_nvd
    result = fetch_from_nvd("cpe:2.3:h:siemens:s7-1200:-:*:*:*:*:*:*:*")
    assert isinstance(result, list), "fetch_from_nvd should return a list"
    print(f"  ✅ NVD fetch stub works (returns {len(result)} results)")


# ============================================================================
# Compliance Tests
# ============================================================================

def test_compliance_import():
    """Test that compliance module imports correctly."""
    from utils.compliance import map_finding_to_compliance, generate_compliance_report, get_compliance_summary
    print("  ✅ compliance imports OK")


def test_compliance_map_finding_unauth():
    """Test compliance mapping for unauthenticated access finding."""
    from utils.compliance import map_finding_to_compliance
    finding = {
        "severity": "critical",
        "description": "Unauthenticated access to PLC — no password protection",
        "details": "S7comm connection established without authentication"
    }
    violations = map_finding_to_compliance(finding)
    assert isinstance(violations, list), "Should return a list"
    assert len(violations) > 0, "Unauthenticated access should map to at least one violation"
    # Should map to IEC 62443 and others
    frameworks = set(v.get('framework', '') for v in violations)
    print(f"  ✅ Auth violation mapped to {len(violations)} violations across {frameworks}")


def test_compliance_map_finding_encryption():
    """Test compliance mapping for encryption finding."""
    from utils.compliance import map_finding_to_compliance
    finding = {
        "severity": "medium",
        "description": "Unencrypted Modbus/TCP communications",
        "details": "Modbus/TLS not available"
    }
    violations = map_finding_to_compliance(finding)
    assert isinstance(violations, list), "Should return a list"
    assert len(violations) > 0, "Unencrypted comms should map to violations"
    print(f"  ✅ Encryption violation mapped to {len(violations)} violations")


def test_compliance_generate_report():
    """Test compliance report generation."""
    from utils.compliance import generate_compliance_report
    report = generate_compliance_report(SAMPLE_SCAN_RESULTS)
    assert isinstance(report, dict), "Should return a dict"
    print(f"  ✅ Compliance report generated: {list(report.keys())}")


def test_compliance_summary():
    """Test compliance summary."""
    from utils.compliance import get_compliance_summary
    summary = get_compliance_summary(SAMPLE_SCAN_RESULTS)
    assert isinstance(summary, dict), "Should return a dict"
    print(f"  ✅ Compliance summary: {summary.get('total_violations', '?')} total violations")


# ============================================================================
# Diff Tests
# ============================================================================

def test_diff_import():
    """Test that diff module imports correctly."""
    from utils.diff import load_scan_result, compare_scans, risk_trend, generate_diff_report, find_latest_scan
    print("  ✅ diff imports OK")


def test_diff_normalize_description():
    """Test description normalization for fuzzy matching."""
    from utils.diff import normalize_description
    # Test IP normalization
    desc1 = "Device found at 192.168.1.10 on port 502"
    desc2 = "Device found at 10.0.0.5 on port 502"
    norm1 = normalize_description(desc1)
    norm2 = normalize_description(desc2)
    assert norm1 == norm2, f"IP-normalized descriptions should match:\n  '{norm1}'\n  '{norm2}'"
    # Test version normalization
    desc3 = "Firmware version 4.2.1 disclosed"
    desc4 = "Firmware version 5.0.3 disclosed"
    norm3 = normalize_description(desc3)
    norm4 = normalize_description(desc4)
    assert norm3 == norm4, f"Version-normalized descriptions should match:\n  '{norm3}'\n  '{norm4}'"
    print(f"  ✅ Description normalization works correctly")


def test_diff_compare_scans():
    """Test scan comparison with two different results."""
    from utils.diff import compare_scans
    diff = compare_scans(SAMPLE_SCAN_RESULTS, SAMPLE_SCAN_RESULTS_V2)
    assert isinstance(diff, dict), "compare_scans should return a dict"
    assert 'new_hosts' in diff, "Should have new_hosts"
    assert 'removed_hosts' in diff, "Should have removed_hosts"
    assert 'new_issues' in diff, "Should have new_issues"
    assert 'resolved_issues' in diff, "Should have resolved_issues"
    assert 'summary' in diff, "Should have summary"
    
    changes = diff['summary']['changes']
    print(f"  ✅ Scan diff: +{changes['new_issues']} new, -{changes['resolved_issues']} resolved, "
          f"{changes['persistent_issues']} persistent")
    
    # V2 has 192.168.1.30 which is new
    assert '192.168.1.30' in diff['new_hosts'], "192.168.1.30 should be a new host"
    print(f"  ✅ New host 192.168.1.30 detected correctly")


def test_diff_generate_report():
    """Test diff report generation."""
    from utils.diff import compare_scans, generate_diff_report
    diff = compare_scans(SAMPLE_SCAN_RESULTS, SAMPLE_SCAN_RESULTS_V2)
    
    # Text format
    txt_report = generate_diff_report(diff, 'txt')
    assert isinstance(txt_report, str), "Text report should be a string"
    assert "SCAN COMPARISON" in txt_report, "Should contain header"
    
    # JSON format
    json_report = generate_diff_report(diff, 'json')
    parsed = json.loads(json_report)
    assert isinstance(parsed, dict), "JSON report should parse to dict"
    
    print(f"  ✅ Diff reports generated (txt: {len(txt_report)} chars, json: {len(json_report)} chars)")


def test_diff_load_scan_result():
    """Test loading scan results from JSON file."""
    from utils.diff import load_scan_result
    
    # Write a temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, dir='.') as f:
        json.dump(SAMPLE_SCAN_RESULTS, f)
        temp_path = f.name
    
    try:
        loaded = load_scan_result(temp_path)
        assert loaded['metadata']['target'] == '192.168.1.0/24', "Should load correctly"
        print(f"  ✅ load_scan_result works with JSON file")
    finally:
        os.unlink(temp_path)


def test_diff_risk_trend():
    """Test risk trend analysis."""
    from utils.diff import risk_trend
    result = risk_trend([SAMPLE_SCAN_RESULTS, SAMPLE_SCAN_RESULTS_V2])
    assert isinstance(result, dict), "Should return a dict"
    assert 'trend_analysis' in result, "Should have trend_analysis"
    assert 'risk_scores' in result, "Should have risk_scores"
    direction = result['trend_analysis']['overall_direction']
    print(f"  ✅ Risk trend: {direction}")


# ============================================================================
# Profiles Tests
# ============================================================================

def test_profiles_import():
    """Test that profiles module imports correctly."""
    from utils.profiles import get_profile, list_profiles, apply_profile, format_profiles_table, PROFILE_NAMES
    print("  ✅ profiles imports OK")


def test_profiles_list():
    """Test listing all profiles."""
    from utils.profiles import list_profiles, PROFILE_NAMES
    profiles = list_profiles()
    assert isinstance(profiles, list), "Should return a list"
    assert len(profiles) == 8, f"Expected 8 profiles, got {len(profiles)}"
    assert len(PROFILE_NAMES) == 8, f"Expected 8 profile names, got {len(PROFILE_NAMES)}"
    profile_keys = [p['key'] for p in profiles]
    assert 'siemens-plant' in profile_keys, "Should have siemens-plant"
    assert 'substation' in profile_keys, "Should have substation"
    assert 'bms' in profile_keys, "Should have bms"
    print(f"  ✅ 8 profiles listed: {', '.join(PROFILE_NAMES)}")


def test_profiles_get():
    """Test getting a specific profile."""
    from utils.profiles import get_profile
    profile = get_profile('siemens-plant')
    assert profile is not None, "siemens-plant should exist"
    assert 's7' in profile['protocols'], "Siemens profile should include s7"
    assert 'profinet' in profile['protocols'], "Siemens profile should include profinet"
    
    none_profile = get_profile('nonexistent')
    assert none_profile is None, "Nonexistent profile should return None"
    print(f"  ✅ get_profile works (siemens-plant has {len(profile['protocols'])} protocols)")


def test_profiles_apply():
    """Test applying a profile."""
    from utils.profiles import apply_profile
    protocols, intensity, ports = apply_profile('substation')
    assert isinstance(protocols, list), "Protocols should be a list"
    assert intensity == 'low', "Substation should be low intensity"
    assert len(ports) > 0, "Substation should have extra ports"
    print(f"  ✅ apply_profile: substation → {intensity} intensity, {len(protocols)} protocols, {len(ports)} ports")
    
    # Test invalid profile
    try:
        apply_profile('nonexistent')
        assert False, "Should raise KeyError"
    except KeyError:
        pass
    print(f"  ✅ apply_profile raises KeyError for invalid profile")


def test_profiles_format_table():
    """Test profile table formatting."""
    from utils.profiles import format_profiles_table
    table = format_profiles_table()
    assert isinstance(table, str), "Should return a string"
    assert 'siemens-plant' in table, "Table should contain siemens-plant"
    assert len(table) > 200, "Table should be substantial"
    print(f"  ✅ format_profiles_table: {len(table)} chars")


# ============================================================================
# CLI Integration Tests (structure only — no Click runner)
# ============================================================================

def test_cli_imports():
    """Test that ics_scanner.py can parse without errors."""
    import ast
    scanner_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'ics_scanner.py')
    with open(scanner_path, 'r', encoding='utf-8') as f:
        source = f.read()
    try:
        ast.parse(source)
        print(f"  ✅ ics_scanner.py syntax is valid ({len(source.splitlines())} lines)")
    except SyntaxError as e:
        print(f"  ❌ ics_scanner.py has syntax error: {e}")
        raise


def test_cli_has_commands():
    """Verify CLI commands are defined."""
    scanner_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'ics_scanner.py')
    with open(scanner_path, 'r', encoding='utf-8') as f:
        source = f.read()
    
    expected_commands = ['def scan(', 'def profiles(', 'def cve_db(', 'def diff(', 'def trend(', 'def list(', 'def version(']
    for cmd in expected_commands:
        assert cmd in source, f"Missing CLI command: {cmd}"
    
    expected_options = ['--profile', '--cve-check', '--compliance', '--diff-baseline']
    for opt in expected_options:
        assert opt in source, f"Missing CLI option: {opt}"
    
    print(f"  ✅ All CLI commands and Phase 5 options present")


# ============================================================================
# Runner
# ============================================================================

def run_all_tests():
    """Run all Phase 5 tests."""
    tests = [
        # CVE Lookup
        ("CVE Lookup", [
            test_cve_lookup_import,
            test_cve_database_stats,
            test_cve_lookup_siemens,
            test_cve_enrich_scan_results,
            test_cve_fetch_from_nvd_stub,
        ]),
        # Compliance
        ("Compliance Mapping", [
            test_compliance_import,
            test_compliance_map_finding_unauth,
            test_compliance_map_finding_encryption,
            test_compliance_generate_report,
            test_compliance_summary,
        ]),
        # Diff
        ("Scan Comparison (Diff)", [
            test_diff_import,
            test_diff_normalize_description,
            test_diff_compare_scans,
            test_diff_generate_report,
            test_diff_load_scan_result,
            test_diff_risk_trend,
        ]),
        # Profiles
        ("Scan Profiles", [
            test_profiles_import,
            test_profiles_list,
            test_profiles_get,
            test_profiles_apply,
            test_profiles_format_table,
        ]),
        # CLI
        ("CLI Integration", [
            test_cli_imports,
            test_cli_has_commands,
        ]),
    ]
    
    total = 0
    passed = 0
    failed = 0
    errors = []
    
    print("=" * 60)
    print("MottaSec ICS Ninja Scanner — Phase 5 Test Suite")
    print("=" * 60)
    
    for section_name, section_tests in tests:
        print(f"\n{'─' * 40}")
        print(f"📋 {section_name}")
        print(f"{'─' * 40}")
        
        for test_fn in section_tests:
            total += 1
            try:
                test_fn()
                passed += 1
            except Exception as e:
                failed += 1
                errors.append((test_fn.__name__, str(e)))
                print(f"  ❌ {test_fn.__name__}: {e}")
    
    print(f"\n{'=' * 60}")
    print(f"RESULTS: {passed}/{total} passed, {failed} failed")
    print(f"{'=' * 60}")
    
    if errors:
        print("\nFailed tests:")
        for name, err in errors:
            print(f"  ❌ {name}: {err}")
        return False
    else:
        print("\n🥷 All Phase 5 tests passed! Ready to ship.")
        return True


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
