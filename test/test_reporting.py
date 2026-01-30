#!/usr/bin/env python3
"""
Test suite for the reporting dispatcher module.
Created by MottaSec Jedis for the MottaSec ICS Ninja Scanner.
"""

import unittest
import tempfile
import os
import sys
import json
import csv
import shutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.reporting import generate_report, generate_txt_report, generate_json_report, generate_csv_report


class TestReportingBase(unittest.TestCase):
    """Base class with shared scan results fixture."""

    def setUp(self):
        self.scan_results = {
            'metadata': {
                'scan_time': '2026-01-29T15:00:00',
                'target': '192.168.1.0/24',
                'protocols': ['modbus', 's7'],
                'intensity': 'high',
                'version': '1.0.0',
                'codename': 'Fox',
                'scanner': 'ICS Ninja Scanner'
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
                                'remediation': 'Enable authentication'
                            },
                            {
                                'severity': 'info',
                                'description': 'Modbus Device Found',
                                'details': 'Device on port 502'
                            }
                        ]
                    }
                },
                '192.168.1.2': {
                    's7': {
                        'device_info': {'type': 'S7-300'},
                        'issues': [
                            {
                                'severity': 'high',
                                'description': 'S7 PLC identified without protection',
                                'details': 'No password set',
                                'remediation': 'Set PLC password'
                            }
                        ]
                    }
                }
            }
        }
        # Use a temp directory to avoid polluting workspace
        self._orig_cwd = os.getcwd()
        self._tmpdir = tempfile.mkdtemp()
        os.chdir(self._tmpdir)

    def tearDown(self):
        os.chdir(self._orig_cwd)
        shutil.rmtree(self._tmpdir, ignore_errors=True)


class TestTxtReport(TestReportingBase):
    """Test TXT report generation."""

    def test_generate_txt_report_creates_file(self):
        result = generate_report(self.scan_results, 'txt', 'test_report')
        self.assertTrue(os.path.exists(result))
        self.assertTrue(result.endswith('.txt'))

    def test_txt_report_content(self):
        result = generate_report(self.scan_results, 'txt', 'test_report')
        with open(result, 'r') as f:
            content = f.read()
        self.assertIn('ICS SECURITY SCAN REPORT', content)
        self.assertIn('192.168.1.1', content)
        self.assertIn('192.168.1.2', content)
        self.assertIn('Unauthenticated Modbus access', content)
        self.assertIn('CRITICAL', content)

    def test_txt_report_has_summary(self):
        result = generate_report(self.scan_results, 'txt', 'test_report')
        with open(result, 'r') as f:
            content = f.read()
        self.assertIn('SUMMARY', content)
        self.assertIn('Total issues found:', content)

    def test_txt_report_has_remediation(self):
        result = generate_report(self.scan_results, 'txt', 'test_report')
        with open(result, 'r') as f:
            content = f.read()
        self.assertIn('Enable authentication', content)


class TestJsonReport(TestReportingBase):
    """Test JSON report generation."""

    def test_generate_json_report_creates_file(self):
        result = generate_report(self.scan_results, 'json', 'test_report')
        self.assertTrue(os.path.exists(result))
        self.assertTrue(result.endswith('.json'))

    def test_json_report_is_valid_json(self):
        result = generate_report(self.scan_results, 'json', 'test_report')
        with open(result, 'r') as f:
            data = json.load(f)
        self.assertIn('metadata', data)
        self.assertIn('results', data)

    def test_json_report_preserves_data(self):
        result = generate_report(self.scan_results, 'json', 'test_report')
        with open(result, 'r') as f:
            data = json.load(f)
        self.assertEqual(data['metadata']['target'], '192.168.1.0/24')
        self.assertIn('192.168.1.1', data['results'])


class TestCsvReport(TestReportingBase):
    """Test CSV report generation."""

    def test_generate_csv_report_creates_file(self):
        result = generate_report(self.scan_results, 'csv', 'test_report')
        self.assertTrue(os.path.exists(result))
        self.assertTrue(result.endswith('.csv'))

    def test_csv_report_has_header(self):
        result = generate_report(self.scan_results, 'csv', 'test_report')
        with open(result, 'r', newline='') as f:
            reader = csv.reader(f)
            header = next(reader)
        self.assertIn('IP', header)
        self.assertIn('Protocol', header)
        self.assertIn('Severity', header)
        self.assertIn('Description', header)

    def test_csv_report_has_rows(self):
        result = generate_report(self.scan_results, 'csv', 'test_report')
        with open(result, 'r', newline='') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        # 2 issues for 192.168.1.1 + 1 for 192.168.1.2 = 3
        self.assertEqual(len(rows), 3)

    def test_csv_report_content(self):
        result = generate_report(self.scan_results, 'csv', 'test_report')
        with open(result, 'r', newline='') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        ips = [r['IP'] for r in rows]
        self.assertIn('192.168.1.1', ips)
        self.assertIn('192.168.1.2', ips)


class TestHtmlReport(TestReportingBase):
    """Test HTML report via the dispatcher."""

    def test_generate_html_report_creates_file(self):
        result = generate_report(self.scan_results, 'html', 'test_report')
        self.assertTrue(os.path.exists(result))
        self.assertTrue(result.endswith('.html'))

    def test_html_report_contains_html(self):
        result = generate_report(self.scan_results, 'html', 'test_report')
        with open(result, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertIn('<!DOCTYPE html>', content)


class TestReportDispatcher(TestReportingBase):
    """Test the generate_report dispatcher logic."""

    def test_unsupported_format_raises(self):
        with self.assertRaises(ValueError):
            generate_report(self.scan_results, 'xml', 'test_report')

    def test_auto_filename(self):
        """When output_file is None, should auto-generate a filename."""
        result = generate_report(self.scan_results, 'json')
        self.assertTrue(os.path.exists(result))
        self.assertIn('ics_scan_', result)

    def test_reports_dir_created(self):
        """Reports directory should be created automatically."""
        reports_dir = os.path.join(os.getcwd(), 'reports')
        if os.path.exists(reports_dir):
            shutil.rmtree(reports_dir)
        generate_report(self.scan_results, 'txt', 'test_report')
        self.assertTrue(os.path.isdir(reports_dir))


class TestEmptyResults(TestReportingBase):
    """Test reports with empty results."""

    def setUp(self):
        super().setUp()
        self.empty_results = {
            'metadata': {
                'scan_time': '2026-01-29T15:00:00',
                'target': '192.168.1.1',
                'protocols': ['modbus'],
                'intensity': 'low',
                'version': '1.0.0',
            },
            'results': {}
        }

    def test_txt_empty_results(self):
        result = generate_report(self.empty_results, 'txt', 'empty_test')
        self.assertTrue(os.path.exists(result))

    def test_json_empty_results(self):
        result = generate_report(self.empty_results, 'json', 'empty_test')
        with open(result, 'r') as f:
            data = json.load(f)
        self.assertEqual(data['results'], {})

    def test_csv_empty_results(self):
        result = generate_report(self.empty_results, 'csv', 'empty_test')
        with open(result, 'r', newline='') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        self.assertEqual(len(rows), 0)


if __name__ == '__main__':
    unittest.main()
