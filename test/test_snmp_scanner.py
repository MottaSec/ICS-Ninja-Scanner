#!/usr/bin/env python3
"""
Test suite for the SNMP scanner.
Created by MottaSec Fox Team for the MottaSec ICS Ninja Scanner.
"""

import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import socket

# Add the parent directory to the path so we can import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scanners.snmp_scanner import SNMPScanner

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
        
        # Mock community string tests - new API has version kwarg
        def mock_community_side_effect(target, port, community, version=None):
            return community == 'public'
        
        mock_test_community.side_effect = mock_community_side_effect
        
        scanner = SNMPScanner(intensity='low')
        result = scanner.scan('192.168.1.1')
        
        self.assertIsNotNone(result)
        self.assertEqual(result['device_info']['port'], 161)
        self.assertIn('public', result['device_info'].get('community_strings', []))
        
        severities = [issue['severity'] for issue in result['issues']]
        self.assertIn('info', severities)
        self.assertIn('high', severities)
    
    @patch('scanners.snmp_scanner.socket.socket')
    def test_test_community_string(self, mock_socket):
        """Test the _test_community_string method."""
        # Setup mock socket
        mock_socket_instance = MagicMock()
        mock_socket.return_value = mock_socket_instance
        
        # Valid BER-encoded SNMP response
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
        
    @patch('scanners.snmp_scanner.SNMPScanner._test_community_string')
    def test_get_system_info(self, mock_test_community):
        """Test the _get_system_info method."""
        # Only test in high intensity mode
        scanner = SNMPScanner(intensity='high')
        
        # Mock socket responses for different OIDs
        mock_test_community.return_value = True
        
        # Mock the socket to return system info
        with patch('scanners.snmp_scanner.socket.socket') as mock_socket:
            mock_socket_instance = MagicMock()
            mock_socket.return_value = mock_socket_instance
            
            # Mock successful response with system description
            mock_socket_instance.recvfrom.return_value = (
                b'\x30\x29\x02\x01\x00\x04\x06public\xa2\x1c\x02\x04\x00\x00\x00\x00'
                b'\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02'
                b'\x01\x01\x01\x00\x04\x04Test', 
                ('192.168.1.1', 161)
            )
            
            result = scanner._get_system_info('192.168.1.1', 161, 'public')
            
            # Check that we at least tried to get system info
            self.assertIsInstance(result, dict)

if __name__ == '__main__':
    unittest.main() 