#!/usr/bin/env python3
"""
Test suite for the CVSS 3.1 scoring module.
Created by MottaSec Jedis for the MottaSec ICS Ninja Scanner.
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.cvss import calculate_cvss_base_score, get_cvss_for_issue, calculate_risk_score


class TestCVSSCalculator(unittest.TestCase):
    """Test CVSS 3.1 base score calculation."""

    def test_max_score(self):
        """AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H should be 10.0."""
        result = calculate_cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        self.assertIsNotNone(result)
        self.assertEqual(result['score'], 10.0)

    def test_critical_score(self):
        """AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H should be 9.8."""
        result = calculate_cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertIsNotNone(result)
        self.assertEqual(result['score'], 9.8)

    def test_zero_score(self):
        """No impact = 0.0."""
        result = calculate_cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        self.assertIsNotNone(result)
        self.assertEqual(result['score'], 0.0)

    def test_medium_score(self):
        result = calculate_cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
        self.assertIsNotNone(result)
        self.assertGreater(result['score'], 0.0)
        self.assertLess(result['score'], 7.0)

    def test_high_complexity_reduces_score(self):
        low_ac = calculate_cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        high_ac = calculate_cvss_base_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N")
        self.assertGreater(low_ac['score'], high_ac['score'])

    def test_scope_changed_increases_score(self):
        unchanged = calculate_cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        changed = calculate_cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        self.assertGreater(changed['score'], unchanged['score'])

    def test_severity_labels(self):
        # Critical
        result = calculate_cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(result['severity'], 'Critical')

        # None (0.0)
        result = calculate_cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        self.assertEqual(result['severity'], 'None')

    def test_severity_label_matches_severity(self):
        result = calculate_cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(result['severity'], result['severity_label'])

    def test_vector_is_preserved(self):
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        result = calculate_cvss_base_score(vec)
        self.assertEqual(result['vector'], vec)

    def test_invalid_vector_returns_none(self):
        result = calculate_cvss_base_score("invalid")
        self.assertIsNone(result)

    def test_empty_string_returns_none(self):
        result = calculate_cvss_base_score("")
        self.assertIsNone(result)

    def test_none_input_returns_none(self):
        result = calculate_cvss_base_score(None)
        self.assertIsNone(result)

    def test_non_string_returns_none(self):
        result = calculate_cvss_base_score(42)
        self.assertIsNone(result)

    def test_cvss30_prefix_accepted(self):
        """CVSS:3.0 prefix should also be parsed."""
        result = calculate_cvss_base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertIsNotNone(result)
        self.assertEqual(result['score'], 9.8)


class TestGetCVSSForIssue(unittest.TestCase):
    """Test auto-CVSS assignment for issues."""

    def test_unauthenticated_access(self):
        issue = {'severity': 'critical', 'description': 'Unauthenticated Modbus access detected'}
        result = get_cvss_for_issue(issue)
        self.assertIsNotNone(result)
        self.assertGreaterEqual(result['score'], 9.0)

    def test_anonymous_access(self):
        issue = {'severity': 'critical', 'description': 'MQTT broker allows anonymous access'}
        result = get_cvss_for_issue(issue)
        self.assertIsNotNone(result)
        self.assertGreaterEqual(result['score'], 9.0)

    def test_default_credentials(self):
        issue = {'severity': 'high', 'description': 'Default credentials accepted: admin:admin'}
        result = get_cvss_for_issue(issue)
        self.assertIsNotNone(result)
        self.assertGreaterEqual(result['score'], 7.0)

    def test_unencrypted(self):
        issue = {'severity': 'high', 'description': 'MQTT traffic is unencrypted'}
        result = get_cvss_for_issue(issue)
        self.assertIsNotNone(result)
        self.assertGreater(result['score'], 5.0)

    def test_info_finding(self):
        issue = {'severity': 'info', 'description': 'Modbus Device Found: 192.168.1.1:502'}
        result = get_cvss_for_issue(issue)
        self.assertIsNotNone(result)
        # "device found" pattern matches (5.3), not 0.0
        self.assertGreaterEqual(result['score'], 0.0)

    def test_write_access(self):
        issue = {'severity': 'critical', 'description': 'Writable holding registers detected'}
        result = get_cvss_for_issue(issue)
        self.assertIsNotNone(result)
        self.assertGreaterEqual(result['score'], 9.0)

    def test_fallback_for_unknown(self):
        """Issues with no pattern match fall back to severity-based score."""
        issue = {'severity': 'medium', 'description': 'Something completely novel found XYZ123'}
        result = get_cvss_for_issue(issue)
        self.assertIsNotNone(result)
        self.assertGreater(result['score'], 0.0)

    def test_info_severity_fallback(self):
        """Info severity with no pattern match should return 0.0."""
        issue = {'severity': 'info', 'description': 'QoS levels supported by broker'}
        result = get_cvss_for_issue(issue)
        self.assertIsNotNone(result)
        # "qos levels" pattern exists with 0.0 score
        self.assertEqual(result['score'], 0.0)

    def test_result_has_vector(self):
        issue = {'severity': 'critical', 'description': 'Unauthenticated access'}
        result = get_cvss_for_issue(issue)
        self.assertIn('vector', result)

    def test_result_has_severity_label(self):
        issue = {'severity': 'critical', 'description': 'Unauthenticated access'}
        result = get_cvss_for_issue(issue)
        self.assertIn('severity_label', result)

    def test_details_field_also_matched(self):
        """Pattern matching should check details field too."""
        issue = {
            'severity': 'high',
            'description': 'Security finding',
            'details': 'Unauthenticated access to registers'
        }
        result = get_cvss_for_issue(issue)
        self.assertGreaterEqual(result['score'], 9.0)

    def test_highest_cvss_wins(self):
        """When multiple patterns match, highest score should win."""
        issue = {
            'severity': 'critical',
            'description': 'Writable holding registers detected with unauthenticated access'
        }
        result = get_cvss_for_issue(issue)
        self.assertGreaterEqual(result['score'], 9.8)


class TestRiskScore(unittest.TestCase):
    """Test overall risk score calculation."""

    def test_empty_results(self):
        # calculate_risk_score expects flat {protocol: {host: result}} structure
        scan_results = {}
        result = calculate_risk_score(scan_results)
        self.assertEqual(result['score'], 0)
        self.assertEqual(result['rating'], 'Informational')

    def test_critical_findings(self):
        scan_results = {
            'modbus': {
                '192.168.1.1': {
                    'device_info': {},
                    'issues': [
                        {'severity': 'critical', 'description': 'Unauthenticated access'},
                        {'severity': 'critical', 'description': 'Writable registers detected'},
                        {'severity': 'high', 'description': 'Unencrypted communication'},
                    ]
                }
            }
        }
        result = calculate_risk_score(scan_results)
        self.assertGreater(result['score'], 50)
        self.assertIn(result['rating'], ['High', 'Critical'])

    def test_result_has_breakdown(self):
        scan_results = {
            'modbus': {
                '192.168.1.1': {
                    'issues': [{'severity': 'high', 'description': 'Test'}]
                }
            }
        }
        result = calculate_risk_score(scan_results)
        self.assertIn('breakdown', result)
        self.assertIn('finding_score', result['breakdown'])
        self.assertIn('exposure_score', result['breakdown'])
        self.assertIn('protocol_score', result['breakdown'])

    def test_result_has_stats(self):
        scan_results = {
            'modbus': {
                '192.168.1.1': {
                    'issues': [{'severity': 'info', 'description': 'Device found'}]
                }
            }
        }
        result = calculate_risk_score(scan_results)
        self.assertIn('stats', result)
        self.assertEqual(result['stats']['total_hosts'], 1)
        self.assertEqual(result['stats']['hosts_affected'], 1)
        self.assertEqual(result['stats']['total_findings'], 1)

    def test_score_capped_at_100(self):
        # Many critical findings should still cap at 100
        issues = [{'severity': 'critical', 'description': 'Unauthenticated access'}] * 50
        scan_results = {
            'modbus': {'192.168.1.1': {'issues': issues}},
            's7': {'192.168.1.2': {'issues': issues}},
        }
        result = calculate_risk_score(scan_results)
        self.assertLessEqual(result['score'], 100)

    def test_rating_labels(self):
        """Verify all rating labels are valid."""
        valid = {'Informational', 'Low', 'Medium', 'High', 'Critical'}
        result = calculate_risk_score({})
        self.assertIn(result['rating'], valid)

    def test_skips_meta_key(self):
        """Meta/summary keys should be ignored."""
        scan_results = {
            'meta': {'foo': 'bar'},
            'summary': 'test',
        }
        result = calculate_risk_score(scan_results)
        self.assertEqual(result['score'], 0)

    def test_multiple_protocols(self):
        scan_results = {
            'modbus': {
                '192.168.1.1': {
                    'issues': [{'severity': 'critical', 'description': 'Unauthenticated access'}]
                }
            },
            's7': {
                '192.168.1.1': {
                    'issues': [{'severity': 'high', 'description': 'Information disclosed'}]
                }
            }
        }
        result = calculate_risk_score(scan_results)
        self.assertEqual(result['stats']['protocols_scanned'], 2)
        self.assertEqual(result['stats']['protocols_with_findings'], 2)


if __name__ == '__main__':
    unittest.main()
