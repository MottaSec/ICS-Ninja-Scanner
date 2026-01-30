#!/usr/bin/env python3
"""Test suite for the Siemens S7 scanner."""

import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import socket

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from scanners.s7_scanner import S7Scanner, SIEMENS_VULNERABILITY_DB


class TestS7Scanner(unittest.TestCase):
    """Test cases for the S7Scanner class."""

    def test_initialization(self):
        """Test the initialization of the S7Scanner class."""
        scanner = S7Scanner(intensity='medium', timeout=10, verify=False)
        self.assertEqual(scanner.intensity, 'medium')
        self.assertEqual(scanner.timeout, 10)
        self.assertEqual(scanner.verify, False)
        self.assertEqual(scanner.standard_ports, [102])

    def test_initialization_defaults(self):
        """Test default initialization values."""
        scanner = S7Scanner()
        self.assertEqual(scanner.intensity, 'low')
        self.assertEqual(scanner.timeout, 5)

    @patch('scanners.s7_scanner.S7Scanner._check_s7_availability')
    def test_scan_not_available(self, mock_check):
        """Test scan returns None when S7 is not available."""
        mock_check.return_value = False
        scanner = S7Scanner()
        result = scanner.scan('192.168.1.1')
        self.assertIsNone(result)

    @patch('scanners.s7_scanner.S7Scanner._check_web_server')
    @patch('scanners.s7_scanner.snap7.client.Client')
    @patch('scanners.s7_scanner.S7Scanner._check_s7_availability')
    def test_scan_with_s7_device(self, mock_check, mock_client_class, mock_web):
        """Test scan with S7 device detected and connected."""
        mock_check.return_value = True

        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        mock_client.get_connected.return_value = True

        # Mock CPU info
        cpu_info = MagicMock()
        cpu_info.ModuleTypeName = b'CPU 1215C DC/DC/DC'
        cpu_info.SerialNumber = b'S V-12345678'
        cpu_info.ASName = b'S7-1200'
        cpu_info.ModuleName = b'PLC_1'
        mock_client.get_cpu_info.return_value = cpu_info

        # Mock CPU state
        mock_client.get_cpu_state.return_value = 'Run'

        # Mock PDU length
        mock_client.get_pdu_length.return_value = 480

        # Mock read_szl to raise (simplified)
        try:
            from snap7.exceptions import Snap7Exception
        except ImportError:
            Snap7Exception = Exception
        mock_client.read_szl.side_effect = Snap7Exception('Not available')

        # Mock PLC datetime
        from datetime import datetime
        mock_client.get_plc_datetime.return_value = datetime.now()

        # Mock order code
        order_code = MagicMock()
        order_code.Code = b'6ES7 215-1AG40-0XB0'
        order_code.V1 = 4
        order_code.V2 = 5
        order_code.V3 = 0
        mock_client.get_order_code.return_value = order_code

        scanner = S7Scanner(intensity='low')
        result = scanner.scan('192.168.1.1')

        self.assertIsNotNone(result)
        self.assertTrue(result['device_info']['connected'])
        self.assertEqual(result['device_info']['cpu_state'], 'Run')

        # Check that info issues are present
        severities = [i['severity'] for i in result['issues']]
        self.assertIn('info', severities)

    @patch('scanners.s7_scanner.socket.socket')
    def test_check_s7_availability_success(self, mock_socket_class):
        """Test S7 availability check with valid COTP response."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        # Valid COTP CC response: response[5] == 0xD0
        response = bytes([0x03, 0x00, 0x00, 0x08, 0x04, 0xD0, 0x00, 0x00])
        mock_sock.recv.return_value = response

        scanner = S7Scanner()
        result = scanner._check_s7_availability('192.168.1.1', 102)
        self.assertTrue(result)

    @patch('scanners.s7_scanner.socket.socket')
    def test_check_s7_availability_failure(self, mock_socket_class):
        """Test S7 availability check when connection fails."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.connect.side_effect = socket.timeout()

        scanner = S7Scanner()
        result = scanner._check_s7_availability('192.168.1.1', 102)
        self.assertFalse(result)

    def test_check_vulnerable_firmware_known_cve(self):
        """Test firmware vulnerability check with known vulnerable version."""
        scanner = S7Scanner()
        # S7-1200 firmware v4.3.0 should match CVE-2019-13945
        issues = scanner._check_vulnerable_firmware('6ES7 215-1AG40-0XB0', (4, 3, 0))
        self.assertTrue(len(issues) > 0)
        # Should have at least one high-severity issue with CVE reference
        descriptions = [i['description'] for i in issues]
        found_cve = any('CVE' in d for d in descriptions)
        self.assertTrue(found_cve)

    def test_check_vulnerable_firmware_safe_version(self):
        """Test firmware vulnerability check with safe version."""
        scanner = S7Scanner()
        # S7-1200 firmware v4.6.0 should be safe (above all thresholds)
        issues = scanner._check_vulnerable_firmware('6ES7 215-1AG40-0XB0', (4, 6, 0))
        self.assertEqual(len(issues), 0)

    def test_check_vulnerable_firmware_unknown_product(self):
        """Test firmware vulnerability check with unknown product code."""
        scanner = S7Scanner()
        issues = scanner._check_vulnerable_firmware('UNKNOWN-PRODUCT', (1, 0, 0))
        self.assertEqual(len(issues), 0)

    def test_check_vulnerable_firmware_old_s7_300(self):
        """Test firmware vulnerability for old S7-300."""
        scanner = S7Scanner()
        issues = scanner._check_vulnerable_firmware('6ES7 315-2AG10-0AB0', (3, 2, 0))
        self.assertTrue(len(issues) > 0)

    def test_cpu_state_check_stop(self):
        """Test CPU state check when PLC is in STOP state."""
        scanner = S7Scanner()
        mock_client = MagicMock()
        mock_client.get_cpu_state.return_value = 'Stop'

        results = {'device_info': {}, 'issues': []}
        scanner._check_cpu_state(mock_client, results)

        self.assertEqual(results['device_info']['cpu_state'], 'Stop')
        # Should flag medium issue for STOP state
        stop_issues = [i for i in results['issues'] if 'STOP' in i.get('description', '')]
        self.assertTrue(len(stop_issues) > 0)

    def test_cpu_state_check_run(self):
        """Test CPU state check when PLC is in RUN state."""
        scanner = S7Scanner()
        mock_client = MagicMock()
        mock_client.get_cpu_state.return_value = 'Run'

        results = {'device_info': {}, 'issues': []}
        scanner._check_cpu_state(mock_client, results)

        self.assertEqual(results['device_info']['cpu_state'], 'Run')
        # Should NOT have stop warning
        stop_issues = [i for i in results['issues'] if 'STOP' in i.get('description', '')]
        self.assertEqual(len(stop_issues), 0)

    def test_issue_format(self):
        """Test that issues have required fields."""
        scanner = S7Scanner()
        issue = scanner.create_issue(
            severity='critical',
            description='No password protection',
            details='PLC has no protection'
        )
        self.assertEqual(issue['severity'], 'critical')
        self.assertIn('description', issue)
        self.assertIn('timestamp', issue)


if __name__ == '__main__':
    unittest.main()
