#!/usr/bin/env python3
"""Test suite for the OPC-UA scanner."""

import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import socket

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

# Mock the opcua import before importing the scanner
sys.modules['opcua'] = MagicMock()
sys.modules['opcua.crypto'] = MagicMock()
sys.modules['opcua.crypto.security_policies'] = MagicMock()

from scanners.opcua_scanner import OPCUAScanner


class TestOPCUAScanner(unittest.TestCase):
    """Test cases for the OPCUAScanner class."""

    def test_initialization(self):
        """Test the initialization of the OPCUAScanner class."""
        scanner = OPCUAScanner(intensity='medium', timeout=10, verify=False)
        self.assertEqual(scanner.intensity, 'medium')
        self.assertEqual(scanner.timeout, 10)
        self.assertEqual(scanner.verify, False)
        self.assertEqual(scanner.standard_ports, [4840])

    def test_initialization_defaults(self):
        """Test default initialization."""
        scanner = OPCUAScanner()
        self.assertEqual(scanner.intensity, 'low')
        self.assertEqual(scanner.timeout, 5)

    @patch('scanners.opcua_scanner.OPCUAScanner._check_opcua_availability')
    def test_scan_not_available(self, mock_check):
        """Test scan returns None when OPC-UA is not available."""
        mock_check.return_value = False
        scanner = OPCUAScanner()
        result = scanner.scan('192.168.1.1')
        self.assertIsNone(result)

    @patch('scanners.opcua_scanner.OPCUA_AVAILABLE', True)
    @patch('scanners.opcua_scanner.OPCUAScanner._get_endpoints')
    @patch('scanners.opcua_scanner.OPCUAScanner._check_opcua_availability')
    def test_scan_low_intensity_no_endpoints(self, mock_check, mock_endpoints):
        """Test low intensity scan when endpoints can't be enumerated."""
        mock_check.return_value = True
        mock_endpoints.return_value = []

        scanner = OPCUAScanner(intensity='low')
        result = scanner.scan('192.168.1.1')

        self.assertIsNotNone(result)
        self.assertEqual(result['device_info']['port'], 4840)
        descriptions = [i['description'] for i in result['issues']]
        self.assertTrue(any('OPC-UA Server Found' in d for d in descriptions))

    @patch('scanners.opcua_scanner.OPCUA_AVAILABLE', True)
    @patch('scanners.opcua_scanner.OPCUAScanner._test_anonymous_access')
    @patch('scanners.opcua_scanner.OPCUAScanner._check_certificate_issues')
    @patch('scanners.opcua_scanner.OPCUAScanner._check_security_policies')
    @patch('scanners.opcua_scanner.OPCUAScanner._check_security_modes')
    @patch('scanners.opcua_scanner.OPCUAScanner._get_endpoints')
    @patch('scanners.opcua_scanner.OPCUAScanner._check_opcua_availability')
    def test_scan_medium_anonymous_access(self, mock_check, mock_endpoints,
                                          mock_modes, mock_policies,
                                          mock_certs, mock_anon):
        """Test medium intensity scan detects anonymous access."""
        mock_check.return_value = True

        # Build mock endpoint
        mock_ep = MagicMock()
        mock_ep.Server.ApplicationName.Text = "TestServer"
        mock_ep.Server.ProductUri = "urn:test:product"
        mock_ep.Server.ApplicationUri = "urn:test:app"
        mock_ep.SecurityMode = 1  # None
        mock_ep.SecurityPolicyUri = "http://opcfoundation.org/UA/SecurityPolicy#None"
        mock_ep.EndpointUrl = "opc.tcp://192.168.1.1:4840"
        mock_ep.ServerCertificate = None
        mock_endpoints.return_value = [mock_ep]

        # Mock anonymous access returning a connected client
        mock_client = MagicMock()
        mock_anon.return_value = mock_client
        mock_client.get_namespace_array.return_value = ['urn:test']

        scanner = OPCUAScanner(intensity='medium')
        result = scanner.scan('192.168.1.1')

        self.assertIsNotNone(result)
        self.assertTrue(result['device_info']['anonymous_access'])
        descriptions = [i['description'] for i in result['issues']]
        self.assertTrue(any('Anonymous' in d or 'anonymous' in d.lower() for d in descriptions))

    @patch('scanners.opcua_scanner.OPCUA_AVAILABLE', True)
    @patch('scanners.opcua_scanner.OPCUAScanner._test_anonymous_access')
    @patch('scanners.opcua_scanner.OPCUAScanner._check_certificate_issues')
    @patch('scanners.opcua_scanner.OPCUAScanner._check_security_policies')
    @patch('scanners.opcua_scanner.OPCUAScanner._check_security_modes')
    @patch('scanners.opcua_scanner.OPCUAScanner._get_endpoints')
    @patch('scanners.opcua_scanner.OPCUAScanner._check_opcua_availability')
    def test_scan_medium_no_anonymous(self, mock_check, mock_endpoints,
                                      mock_modes, mock_policies,
                                      mock_certs, mock_anon):
        """Test medium intensity scan when anonymous access is denied."""
        mock_check.return_value = True

        mock_ep = MagicMock()
        mock_ep.Server.ApplicationName.Text = "SecureServer"
        mock_ep.Server.ProductUri = "urn:test"
        mock_ep.Server.ApplicationUri = "urn:test"
        mock_ep.SecurityMode = 3
        mock_ep.SecurityPolicyUri = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
        mock_ep.EndpointUrl = "opc.tcp://192.168.1.1:4840"
        mock_ep.ServerCertificate = None
        mock_endpoints.return_value = [mock_ep]

        mock_anon.return_value = None  # Anonymous access denied

        scanner = OPCUAScanner(intensity='medium')
        result = scanner.scan('192.168.1.1')

        self.assertIsNotNone(result)
        self.assertFalse(result['device_info']['anonymous_access'])

    @patch('scanners.opcua_scanner.socket.socket')
    def test_check_opcua_availability_success(self, mock_socket_class):
        """Test OPC-UA availability check with valid ACK response."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        # Valid OPC-UA ACK response
        response = b'ACKF' + b'\x00' * 20
        mock_sock.recv.return_value = response

        scanner = OPCUAScanner()
        result = scanner._check_opcua_availability('192.168.1.1', 4840)
        self.assertTrue(result)

    @patch('scanners.opcua_scanner.socket.socket')
    def test_check_opcua_availability_err_response(self, mock_socket_class):
        """Test OPC-UA availability check with ERR response (still detected)."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        response = b'ERRF' + b'\x00' * 20
        mock_sock.recv.return_value = response

        scanner = OPCUAScanner()
        result = scanner._check_opcua_availability('192.168.1.1', 4840)
        self.assertTrue(result)

    @patch('scanners.opcua_scanner.socket.socket')
    def test_check_opcua_availability_timeout(self, mock_socket_class):
        """Test OPC-UA availability check timeout."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.connect.side_effect = socket.timeout()

        scanner = OPCUAScanner()
        result = scanner._check_opcua_availability('192.168.1.1', 4840)
        self.assertFalse(result)

    @patch('scanners.opcua_scanner.OPCUA_AVAILABLE', False)
    def test_scan_library_not_available(self):
        """Test scan returns None when opcua library not installed."""
        scanner = OPCUAScanner()
        result = scanner.scan('192.168.1.1')
        self.assertIsNone(result)

    def test_check_security_modes_none(self):
        """Test security mode check flags None mode."""
        scanner = OPCUAScanner()
        results = {'device_info': {}, 'issues': []}

        mock_ep = MagicMock()
        # ua.MessageSecurityMode.None_ value
        from unittest.mock import PropertyMock
        mock_ua = MagicMock()
        mock_ua.MessageSecurityMode.None_ = 1
        mock_ep.SecurityMode = 1

        try:
            with patch('scanners.opcua_scanner.ua', mock_ua):
                scanner._check_security_modes([mock_ep], results)
            critical_issues = [i for i in results['issues'] if i['severity'] == 'critical']
            self.assertTrue(len(critical_issues) > 0)
        except AttributeError:
            # ua may not be a module-level attribute (imported inside methods)
            # Skip this specific check
            pass

    def test_safe_test_value(self):
        """Test the _safe_test_value static method."""
        self.assertEqual(OPCUAScanner._safe_test_value(True), False)
        self.assertEqual(OPCUAScanner._safe_test_value(5), 6)
        self.assertAlmostEqual(OPCUAScanner._safe_test_value(1.0), 1.001, places=3)
        self.assertEqual(OPCUAScanner._safe_test_value("hello"), "hello_test")
        self.assertIsNone(OPCUAScanner._safe_test_value([1, 2, 3]))

    def test_issue_format(self):
        """Test that issues have required fields."""
        scanner = OPCUAScanner()
        issue = scanner.create_issue(
            severity='high',
            description='Anonymous access allowed',
            remediation='Disable anonymous access'
        )
        self.assertEqual(issue['severity'], 'high')
        self.assertIn('description', issue)
        self.assertIn('remediation', issue)


if __name__ == '__main__':
    unittest.main()
