#!/usr/bin/env python3
"""
Test suite for the network utilities.
Created by MottaSec Aces for the MottaSec ICS Ninja Scanner.
"""

import unittest
from unittest.mock import patch, MagicMock
import ipaddress
import socket
from utils.network import parse_target_input, check_port, port_scan, get_service_name

class TestNetworkUtils(unittest.TestCase):
    """Test cases for the network utilities."""
    
    def test_parse_target_input_single_ip(self):
        """Test parsing a single IP address."""
        result = parse_target_input('192.168.1.1')
        self.assertEqual(len(result), 1)
        self.assertEqual(str(result[0]), '192.168.1.1')
    
    def test_parse_target_input_cidr(self):
        """Test parsing a CIDR notation."""
        result = parse_target_input('192.168.1.0/30')
        self.assertEqual(len(result), 2)  # /30 gives 2 usable IPs
        self.assertEqual(str(result[0]), '192.168.1.1')
        self.assertEqual(str(result[1]), '192.168.1.2')
    
    def test_parse_target_input_range(self):
        """Test parsing an IP range."""
        result = parse_target_input('192.168.1.1-3')
        self.assertEqual(len(result), 3)
        self.assertEqual(str(result[0]), '192.168.1.1')
        self.assertEqual(str(result[1]), '192.168.1.2')
        self.assertEqual(str(result[2]), '192.168.1.3')
    
    def test_parse_target_input_comma_separated(self):
        """Test parsing comma-separated IPs."""
        result = parse_target_input('192.168.1.1,192.168.1.5')
        self.assertEqual(len(result), 2)
        self.assertEqual(str(result[0]), '192.168.1.1')
        self.assertEqual(str(result[1]), '192.168.1.5')
    
    @patch('socket.gethostbyname')
    def test_parse_target_input_hostname(self, mock_gethostbyname):
        """Test parsing a hostname."""
        mock_gethostbyname.return_value = '192.168.1.10'
        result = parse_target_input('example.com')
        self.assertEqual(len(result), 1)
        self.assertEqual(str(result[0]), '192.168.1.10')
        mock_gethostbyname.assert_called_once_with('example.com')
    
    def test_parse_target_input_invalid(self):
        """Test parsing an invalid input."""
        with self.assertRaises(ValueError):
            parse_target_input('invalid_input')
    
    @patch('socket.socket')
    def test_check_port_open(self, mock_socket):
        """Test checking if a port is open."""
        # Setup mock socket
        mock_socket_instance = MagicMock()
        mock_socket.return_value = mock_socket_instance
        
        # Mock successful connection
        mock_socket_instance.connect_ex.return_value = 0
        
        result = check_port('192.168.1.1', 80)
        self.assertEqual(result, (80, True))
        mock_socket_instance.connect_ex.assert_called_once_with(('192.168.1.1', 80))
        mock_socket_instance.close.assert_called_once()
    
    @patch('socket.socket')
    def test_check_port_closed(self, mock_socket):
        """Test checking if a port is closed."""
        # Setup mock socket
        mock_socket_instance = MagicMock()
        mock_socket.return_value = mock_socket_instance
        
        # Mock failed connection
        mock_socket_instance.connect_ex.return_value = 1
        
        result = check_port('192.168.1.1', 80)
        self.assertEqual(result, (80, False))
        mock_socket_instance.connect_ex.assert_called_once_with(('192.168.1.1', 80))
        mock_socket_instance.close.assert_called_once()
    
    @patch('utils.network.check_port')
    def test_port_scan(self, mock_check_port):
        """Test port scanning."""
        # Mock port check results
        def mock_check_port_side_effect(ip, port, timeout):
            return (port, port in [22, 80])
        
        mock_check_port.side_effect = mock_check_port_side_effect
        
        # Test scanning multiple ports
        result = port_scan('192.168.1.1', '22,80,443')
        self.assertEqual(result, [22, 80])
        self.assertEqual(mock_check_port.call_count, 3)
    
    @patch('socket.getservbyport')
    def test_get_service_name(self, mock_getservbyport):
        """Test getting service name for a port."""
        # Mock service name lookup
        mock_getservbyport.return_value = 'http'
        
        result = get_service_name(80)
        self.assertEqual(result, 'http')
        mock_getservbyport.assert_called_once_with(80)
    
    @patch('socket.getservbyport')
    def test_get_service_name_unknown(self, mock_getservbyport):
        """Test getting service name for an unknown port."""
        # Mock service name lookup failure
        mock_getservbyport.side_effect = socket.error()
        
        result = get_service_name(12345)
        self.assertEqual(result, 'unknown')
        mock_getservbyport.assert_called_once_with(12345)

if __name__ == '__main__':
    unittest.main() 