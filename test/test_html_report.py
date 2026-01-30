#!/usr/bin/env python3
"""
Test suite for the HTML report generator.
Created by MottaSec Jedis for the MottaSec ICS Ninja Scanner.
"""

import unittest
import tempfile
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.html_report import generate_html_report


class TestHTMLReport(unittest.TestCase):
    """Test HTML report generation."""

    def _make_scan_results(self):
        return {
            'metadata': {
                'scan_time': '2026-01-29T15:00:00',
                'target': '192.168.1.0/24',
                'protocols': ['modbus', 's7'],
                'intensity': 'high',
                'version': '1.0.0',
                'codename': 'MottaSec-Fox',
                'scanner': 'MottaSec ICS Ninja Scanner'
            },
            'results': {
                '192.168.1.1': {
                    'modbus': {
                        'device_info': {'port': 502, 'connected': True},
                        'issues': [
                            {
                                'severity': 'critical',
                                'description': 'Unauthenticated Modbus access',
                                'details': 'No auth required',
                                'remediation': 'Enable authentication',
                                'cvss_score': 9.8,
                                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                            },
                            {
                                'severity': 'info',
                                'description': 'Modbus Device Found',
                                'details': 'Device on port 502'
                            }
                        ]
                    }
                }
            }
        }

    def test_generate_report_creates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, 'report.html')
            result = generate_html_report(self._make_scan_results(), output)
            self.assertTrue(os.path.exists(result))

    def test_report_returns_path_string(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, 'report.html')
            result = generate_html_report(self._make_scan_results(), output)
            self.assertIsInstance(result, str)

    def test_report_contains_html(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, 'report.html')
            generate_html_report(self._make_scan_results(), output)
            with open(output, 'r', encoding='utf-8') as f:
                content = f.read()
            self.assertIn('<!DOCTYPE html>', content)
            self.assertIn('ICS Security Assessment', content)

    def test_report_contains_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, 'report.html')
            generate_html_report(self._make_scan_results(), output)
            with open(output, 'r', encoding='utf-8') as f:
                content = f.read()
            self.assertIn('Unauthenticated Modbus access', content)
            self.assertIn('192.168.1.1', content)
            self.assertIn('critical', content.lower())

    def test_report_contains_remediation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, 'report.html')
            generate_html_report(self._make_scan_results(), output)
            with open(output, 'r', encoding='utf-8') as f:
                content = f.read()
            self.assertIn('Enable authentication', content)

    def test_report_with_branding(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, 'report.html')
            branding = {
                'company_name': 'TestCorp Security',
                'footer_text': 'Custom footer'
            }
            generate_html_report(self._make_scan_results(), output, branding=branding)
            with open(output, 'r', encoding='utf-8') as f:
                content = f.read()
            self.assertIn('TestCorp Security', content)

    def test_report_with_accent_color(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, 'report.html')
            branding = {'accent_color': '#ff5500'}
            generate_html_report(self._make_scan_results(), output, branding=branding)
            with open(output, 'r', encoding='utf-8') as f:
                content = f.read()
            self.assertIn('#ff5500', content)

    def test_report_empty_results(self):
        scan_results = {
            'metadata': {
                'scan_time': '2026-01-29T15:00:00',
                'target': '192.168.1.1',
                'protocols': ['modbus'],
                'intensity': 'low',
                'version': '1.0.0',
                'codename': 'Fox',
                'scanner': 'ICS Ninja'
            },
            'results': {}
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, 'report.html')
            result = generate_html_report(scan_results, output)
            self.assertTrue(os.path.exists(result))
            with open(output, 'r', encoding='utf-8') as f:
                content = f.read()
            self.assertIn('<!DOCTYPE html>', content)

    def test_report_with_cross_protocol(self):
        results = self._make_scan_results()
        results['results']['192.168.1.1']['_cross_protocol'] = {
            'issues': [
                {
                    'severity': 'high',
                    'description': 'Multi-protocol device detected',
                    'details': '2 protocols active',
                    'remediation': 'Review attack surface'
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, 'report.html')
            generate_html_report(results, output)
            with open(output, 'r', encoding='utf-8') as f:
                content = f.read()
            self.assertIn('Multi-protocol', content)

    def test_report_multiple_hosts(self):
        results = self._make_scan_results()
        results['results']['192.168.1.2'] = {
            'modbus': {
                'device_info': {'port': 502},
                'issues': [
                    {'severity': 'low', 'description': 'Minor issue found'}
                ]
            }
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, 'report.html')
            generate_html_report(results, output)
            with open(output, 'r', encoding='utf-8') as f:
                content = f.read()
            self.assertIn('192.168.1.1', content)
            self.assertIn('192.168.1.2', content)

    def test_report_creates_parent_dirs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, 'sub', 'dir', 'report.html')
            result = generate_html_report(self._make_scan_results(), output)
            self.assertTrue(os.path.exists(result))

    def test_report_no_branding_uses_default(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, 'report.html')
            generate_html_report(self._make_scan_results(), output)
            with open(output, 'r', encoding='utf-8') as f:
                content = f.read()
            self.assertIn('MottaSec ICS Ninja Scanner', content)


if __name__ == '__main__':
    unittest.main()
