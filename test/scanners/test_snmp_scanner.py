#!/usr/bin/env python3
"""
Test suite for the SNMP scanner.
Created by MottaSec Fox Team for the MottaSec ICS Ninja Scanner.
"""

import unittest
from unittest.mock import patch, MagicMock
from scanners.snmp_scanner import SNMPScanner
import socket

class TestSNMPScanner(unittest.TestCase):
    """Test cases for the SNMPScanner class."""
    
    def test_initialization(self):
        """Test the initialization of the SNMPScanner class."""
        scanner = SNMPScanner(intensity='medium', timeout=10, verify=False)
        self.assertEqual(scanner.intensity, 'medium')
        self.assertEqual(scanner.timeout, 10)
        self.assertEqual(scanner.verify, False)
        self.assertEqual(scanner.standard_ports, [161])
    
    @patch('scanners.snmp_scanner.SNMPScanner._check_snmp_availability')
    def test_scan_no_snmp_available(self, mock_check):
        """Test scan when SNMP is not available."""
        mock_check.return_value = False
        scanner = SNMPScanner()
        result = scanner.scan('192.168.1.1')
        self.assertIsNone(result)
        mock_check.assert_called_once_with('192.168.1.1', 161)
    
    @patch('scanners.snmp_scanner.SNMPScanner._check_snmp_availability')
    @patch('scanners.snmp_scanner.SNMPScanner._test_community_string')
    def test_scan_with_snmp_available(self, mock_test_community, mock_check):
        """Test scan when SNMP is available."""
        # Mock SNMP being available
        mock_check.return_value = True
        
        # Mock community string tests - public works, private doesn't
        # New API takes version kwarg
        def mock_community_side_effect(target, port, community, version=None):
            return community == 'public'
        
        mock_test_community.side_effect = mock_community_side_effect
        
        # Create scanner with low intensity (only tests a few community strings)
        scanner = SNMPScanner(intensity='low')
        result = scanner.scan('192.168.1.1')
        
        # Check that the result contains the expected data
        self.assertIsNotNone(result)
        self.assertEqual(result['device_info']['port'], 161)
        self.assertIn('public', result['device_info'].get('community_strings', result['device_info'].get('valid_communities', [])))
        
        # Check that we have issues
        self.assertGreaterEqual(len(result['issues']), 2)
        
        # Check issue severities
        severities = [issue['severity'] for issue in result['issues']]
        self.assertIn('info', severities)
        self.assertIn('high', severities)
    
    @patch('scanners.snmp_scanner.socket.socket')
    def test_test_community_string(self, mock_socket):
        """Test the _test_community_string method."""
        # Setup mock socket
        mock_socket_instance = MagicMock()
        mock_socket.return_value = mock_socket_instance
        
        # Mock a valid SNMP response (BER-encoded GetResponse)
        # Minimal valid: SEQUENCE { version INTEGER 0, community "public", GetResponse PDU }
        snmp_response = bytes([
            0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06]) + b'public' + bytes([
            0xa2, 0x19, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01,
            0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b,
            0x30, 0x09, 0x06, 0x03, 0x2b, 0x06, 0x01, 0x04,
            0x02, 0x54, 0x65])
        mock_socket_instance.recvfrom.return_value = (snmp_response, ('192.168.1.1', 161))
        
        scanner = SNMPScanner()
        result = scanner._test_community_string('192.168.1.1', 161, 'public')
        
        self.assertTrue(result)
        mock_socket_instance.sendto.assert_called_once()
    
    @patch('scanners.snmp_scanner.socket.socket')
    def test_test_community_string_timeout(self, mock_socket):
        """Test the _test_community_string method with timeout."""
        # Setup mock socket
        mock_socket_instance = MagicMock()
        mock_socket.return_value = mock_socket_instance
        
        # Mock timeout
        mock_socket_instance.recvfrom.side_effect = socket.timeout()
        
        scanner = SNMPScanner()
        result = scanner._test_community_string('192.168.1.1', 161, 'public')
        
        self.assertFalse(result)
        mock_socket_instance.sendto.assert_called_once()
        mock_socket_instance.close.assert_called_once()

if __name__ == '__main__':
    unittest.main() 