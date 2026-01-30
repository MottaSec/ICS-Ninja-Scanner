#!/usr/bin/env python3
"""Test suite for the Profinet scanner."""

import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import socket
import struct

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from scanners.profinet_scanner import (
    ProfinetScanner, PN_PORT_RT, PN_PORT_PNIO_CM, PN_PORT_ALARM,
    DCP_STYPE_RESPONSE, DCP_OPT_DEVICE, DCP_SUB_DEV_NAME,
    DCP_OPT_IP, DCP_SUB_IP_PARAM, DCP_OPT_ALL,
)


class TestProfinetScanner(unittest.TestCase):
    """Test cases for the ProfinetScanner class."""

    def test_initialization(self):
        """Test the initialization of the ProfinetScanner class."""
        scanner = ProfinetScanner(intensity='medium', timeout=10, verify=False)
        self.assertEqual(scanner.intensity, 'medium')
        self.assertEqual(scanner.timeout, 10)
        self.assertEqual(scanner.verify, False)
        self.assertEqual(scanner.standard_ports, [34962, 34963, 34964])

    def test_initialization_defaults(self):
        """Test default initialization."""
        scanner = ProfinetScanner()
        self.assertEqual(scanner.intensity, 'low')
        self.assertEqual(scanner.standard_ports, [PN_PORT_RT, PN_PORT_PNIO_CM, PN_PORT_ALARM])

    @patch('scanners.profinet_scanner.ProfinetScanner.check_port_open')
    @patch('scanners.profinet_scanner.ProfinetScanner._check_profinet_availability')
    def test_scan_not_available(self, mock_check, mock_port):
        """Test scan returns None when Profinet is not available."""
        mock_check.return_value = None
        mock_port.return_value = False
        scanner = ProfinetScanner()
        result = scanner.scan('192.168.1.1')
        self.assertIsNone(result)

    @patch('scanners.profinet_scanner.ProfinetScanner.check_port_open')
    @patch('scanners.profinet_scanner.ProfinetScanner._check_profinet_availability')
    def test_scan_device_found_via_dcp(self, mock_check, mock_port):
        """Test low-intensity scan with device found via DCP."""
        mock_check.return_value = {
            'name_of_station': 'plc-test-01',
            'vendor_id': '0x002A',
            'device_id': '0x0401',
        }
        mock_port.return_value = False  # No ports open for this test

        scanner = ProfinetScanner(intensity='low')
        result = scanner.scan('192.168.1.1')

        self.assertIsNotNone(result)
        self.assertEqual(result['device_info']['name_of_station'], 'plc-test-01')
        descriptions = [i['description'] for i in result['issues']]
        self.assertTrue(any('Profinet device detected' in d for d in descriptions))

    @patch('scanners.profinet_scanner.ProfinetScanner.check_port_open')
    @patch('scanners.profinet_scanner.ProfinetScanner._check_profinet_availability')
    def test_scan_device_found_via_port(self, mock_check, mock_port):
        """Test low-intensity scan with device found via open ports."""
        mock_check.return_value = None
        mock_port.side_effect = lambda t, p: p == 34962

        scanner = ProfinetScanner(intensity='low')
        result = scanner.scan('192.168.1.1')

        self.assertIsNotNone(result)
        self.assertIn(34962, result['device_info']['open_ports'])

    @patch('scanners.profinet_scanner.ProfinetScanner._check_security_class')
    @patch('scanners.profinet_scanner.ProfinetScanner._test_rpc_connection')
    @patch('scanners.profinet_scanner.ProfinetScanner._test_dcp_set')
    @patch('scanners.profinet_scanner.ProfinetScanner._send_dcp_get')
    @patch('scanners.profinet_scanner.ProfinetScanner.check_port_open')
    @patch('scanners.profinet_scanner.ProfinetScanner._check_profinet_availability')
    def test_scan_medium_intensity(self, mock_check, mock_port, mock_get,
                                    mock_set, mock_rpc, mock_sec_class):
        """Test medium intensity runs DCP Get, RPC connection test, and security class check."""
        mock_check.return_value = {'name_of_station': 'test-device'}
        mock_port.return_value = True
        mock_get.return_value = None
        mock_set.return_value = True  # DCP Set available
        mock_rpc.return_value = (True, 'RPC Bind-Ack received')
        mock_sec_class.return_value = 0

        scanner = ProfinetScanner(intensity='medium')
        result = scanner.scan('192.168.1.1')

        self.assertIsNotNone(result)
        # Should flag DCP Set availability and low security class
        high_issues = [i for i in result['issues'] if i['severity'] == 'high']
        self.assertTrue(len(high_issues) > 0)

    def test_parse_dcp_response_valid(self):
        """Test parsing a valid DCP Identify response."""
        scanner = ProfinetScanner()

        # Build a minimal DCP response
        # FrameID (2) + ServiceID (1) + ServiceType (1) + Xid (4) + Reserved (2) + DataLength (2)
        frame_id = struct.pack('!H', 0xFEFF)  # Identify Response
        service = struct.pack('!BB', 0x05, DCP_STYPE_RESPONSE)
        xid = b'\x00\x00\x00\x01'
        reserved = struct.pack('!H', 0)

        # Block: Device Name
        block_info = struct.pack('!H', 0)  # block qualifier
        name = b'test-station'
        block = struct.pack('!BBH', DCP_OPT_DEVICE, DCP_SUB_DEV_NAME, len(block_info) + len(name))
        block += block_info + name

        data_len = struct.pack('!H', len(block))
        raw = frame_id + service + xid + reserved + data_len + block

        result = scanner._parse_dcp_response(raw)
        self.assertIsNotNone(result)
        self.assertEqual(result['name_of_station'], 'test-station')

    def test_parse_dcp_response_ip_block(self):
        """Test parsing DCP response with IP parameter block."""
        scanner = ProfinetScanner()

        frame_id = struct.pack('!H', 0xFEFF)
        service = struct.pack('!BB', 0x05, DCP_STYPE_RESPONSE)
        xid = b'\x00\x00\x00\x02'
        reserved = struct.pack('!H', 0)

        # IP block: 2 bytes block info + 4 IP + 4 mask + 4 gateway = 14 bytes
        block_info = struct.pack('!H', 0)
        ip = socket.inet_aton('192.168.1.100')
        mask = socket.inet_aton('255.255.255.0')
        gw = socket.inet_aton('192.168.1.1')
        block_data = block_info + ip + mask + gw
        block = struct.pack('!BBH', DCP_OPT_IP, DCP_SUB_IP_PARAM, len(block_data))
        block += block_data

        data_len = struct.pack('!H', len(block))
        raw = frame_id + service + xid + reserved + data_len + block

        result = scanner._parse_dcp_response(raw)
        self.assertIsNotNone(result)
        self.assertEqual(result['ip_address'], '192.168.1.100')
        self.assertEqual(result['subnet_mask'], '255.255.255.0')
        self.assertEqual(result['gateway'], '192.168.1.1')

    def test_parse_dcp_response_invalid(self):
        """Test parsing invalid DCP response."""
        scanner = ProfinetScanner()
        result = scanner._parse_dcp_response(b'\x00\x01')
        self.assertIsNone(result)

    def test_parse_dcp_response_none(self):
        """Test parsing None returns None."""
        scanner = ProfinetScanner()
        result = scanner._parse_dcp_response(None)
        self.assertIsNone(result)

    def test_parse_dcp_response_wrong_service_type(self):
        """Test parsing DCP with request (not response) type."""
        scanner = ProfinetScanner()
        frame_id = struct.pack('!H', 0xFEFF)
        service = struct.pack('!BB', 0x05, 0x00)  # Request, not Response
        xid = b'\x00\x00\x00\x01'
        reserved = struct.pack('!H', 0)
        data_len = struct.pack('!H', 0)
        raw = frame_id + service + xid + reserved + data_len
        result = scanner._parse_dcp_response(raw)
        self.assertIsNone(result)

    @patch('scanners.profinet_scanner.socket.socket')
    def test_test_rpc_connection_bind_ack(self, mock_socket_class):
        """Test RPC connection test with Bind-Ack response."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        # Build minimal Bind-Ack response: byte[2] = 0x0C
        response = bytearray(8)
        response[2] = 0x0C  # Bind-Ack
        mock_sock.recv.return_value = bytes(response)

        scanner = ProfinetScanner()
        ok, detail = scanner._test_rpc_connection('192.168.1.1', 34963)
        self.assertTrue(ok)
        self.assertTrue('Bind' in detail and 'Ack' in detail)

    @patch('scanners.profinet_scanner.socket.socket')
    def test_test_rpc_connection_bind_nak(self, mock_socket_class):
        """Test RPC connection test with Bind-Nak response."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        response = bytearray(8)
        response[2] = 0x0D  # Bind-Nak
        mock_sock.recv.return_value = bytes(response)

        scanner = ProfinetScanner()
        ok, detail = scanner._test_rpc_connection('192.168.1.1', 34963)
        self.assertFalse(ok)

    @patch('scanners.profinet_scanner.socket.socket')
    def test_test_rpc_connection_timeout(self, mock_socket_class):
        """Test RPC connection test on timeout."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.connect.side_effect = socket.timeout()

        scanner = ProfinetScanner()
        ok, detail = scanner._test_rpc_connection('192.168.1.1', 34963)
        self.assertFalse(ok)

    def test_check_known_vulnerabilities_match(self):
        """Test known vulnerability check with matching firmware."""
        result = ProfinetScanner._check_known_vulnerabilities('siemens', 'S7-1200', 'v4.0')
        self.assertTrue(result)

    def test_check_known_vulnerabilities_no_match(self):
        """Test known vulnerability check with safe firmware."""
        result = ProfinetScanner._check_known_vulnerabilities('siemens', 'S7-1200', 'v5.0')
        self.assertFalse(result)

    def test_check_known_vulnerabilities_unknown_vendor(self):
        """Test known vulnerability check with unknown vendor."""
        result = ProfinetScanner._check_known_vulnerabilities('unknown', 'Device', 'v1.0')
        self.assertFalse(result)

    def test_issue_format(self):
        """Test that issues have required fields."""
        scanner = ProfinetScanner()
        issue = scanner.create_issue(
            severity='critical',
            description='DCP Set accepted name change',
            remediation='Enable Security Class >= 2'
        )
        self.assertEqual(issue['severity'], 'critical')
        self.assertIn('description', issue)


if __name__ == '__main__':
    unittest.main()
