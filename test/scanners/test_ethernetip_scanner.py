#!/usr/bin/env python3
"""Test suite for the EtherNet/IP scanner."""

import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import socket
import struct

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from scanners.ethernet_ip_scanner import (
    EtherNetIPScanner, ENIP_CMD_LIST_IDENTITY, ENIP_CMD_REGISTER_SESSION,
    VENDOR_IDS, DEVICE_TYPES,
)


class TestEtherNetIPScanner(unittest.TestCase):
    """Test cases for the EtherNetIPScanner class."""

    def test_initialization(self):
        """Test the initialization of the EtherNetIPScanner class."""
        scanner = EtherNetIPScanner(intensity='medium', timeout=10, verify=False)
        self.assertEqual(scanner.intensity, 'medium')
        self.assertEqual(scanner.timeout, 10)
        self.assertEqual(scanner.verify, False)
        self.assertEqual(scanner.standard_ports, [44818])

    def test_initialization_defaults(self):
        """Test default initialization."""
        scanner = EtherNetIPScanner()
        self.assertEqual(scanner.intensity, 'low')
        self.assertEqual(scanner.standard_ports, [44818])

    @patch('scanners.ethernet_ip_scanner.EtherNetIPScanner._check_enip_availability')
    def test_scan_not_available(self, mock_check):
        """Test scan returns None when EtherNet/IP is not available."""
        mock_check.return_value = None
        scanner = EtherNetIPScanner()
        result = scanner.scan('192.168.1.1')
        self.assertIsNone(result)

    @patch('scanners.ethernet_ip_scanner.EtherNetIPScanner._check_enip_availability')
    def test_scan_device_found_low_intensity(self, mock_check):
        """Test low-intensity scan with device found."""
        # Build a minimal ListIdentity response
        # Encap header (24 bytes) + item count (2) + item type (2) + item length (2) + identity data
        identity_data = self._build_identity_response()
        mock_check.return_value = identity_data

        scanner = EtherNetIPScanner(intensity='low')
        result = scanner.scan('192.168.1.1')

        self.assertIsNotNone(result)
        self.assertEqual(result['device_info']['port'], 44818)
        descriptions = [i['description'] for i in result['issues']]
        self.assertTrue(any('EtherNet/IP Device Found' in d for d in descriptions))

    @patch('scanners.ethernet_ip_scanner.EtherNetIPScanner._list_services')
    @patch('scanners.ethernet_ip_scanner.EtherNetIPScanner._check_cip_security')
    @patch('scanners.ethernet_ip_scanner.EtherNetIPScanner._enumerate_cip_objects')
    @patch('scanners.ethernet_ip_scanner.EtherNetIPScanner._unregister_session')
    @patch('scanners.ethernet_ip_scanner.EtherNetIPScanner._register_session')
    @patch('scanners.ethernet_ip_scanner.EtherNetIPScanner._check_enip_availability')
    def test_scan_medium_intensity(self, mock_check, mock_register, mock_unregister,
                                    mock_enum, mock_cip_sec, mock_services):
        """Test medium intensity scan runs session registration and CIP checks."""
        identity_data = self._build_identity_response()
        mock_check.return_value = identity_data
        mock_register.return_value = 0x12345678
        mock_enum.return_value = {'Identity (0x01)': 'some_data'}
        mock_cip_sec.return_value = False
        mock_services.return_value = [{'name': 'Communications', 'type': 1, 'version': 1, 'capability_flags': 0x20}]

        scanner = EtherNetIPScanner(intensity='medium')
        result = scanner.scan('192.168.1.1')

        self.assertIsNotNone(result)
        mock_register.assert_called_once()
        mock_unregister.assert_called_once()
        # Should flag unauthenticated session registration
        high_issues = [i for i in result['issues'] if i['severity'] == 'high']
        self.assertTrue(len(high_issues) > 0)

    def test_build_enip_header(self):
        """Test EtherNet/IP encapsulation header building."""
        scanner = EtherNetIPScanner()
        header = scanner._build_enip_header(ENIP_CMD_LIST_IDENTITY)
        self.assertEqual(len(header), 24)
        # Verify command field
        cmd = struct.unpack('<H', header[0:2])[0]
        self.assertEqual(cmd, ENIP_CMD_LIST_IDENTITY)

    def test_build_enip_header_with_session(self):
        """Test header building with session handle."""
        scanner = EtherNetIPScanner()
        header = scanner._build_enip_header(ENIP_CMD_REGISTER_SESSION, length=4, session_handle=0xABCD)
        cmd = struct.unpack('<H', header[0:2])[0]
        length = struct.unpack('<H', header[2:4])[0]
        session = struct.unpack('<I', header[4:8])[0]
        self.assertEqual(cmd, ENIP_CMD_REGISTER_SESSION)
        self.assertEqual(length, 4)
        self.assertEqual(session, 0xABCD)

    def test_parse_identity_response_valid(self):
        """Test parsing a valid ListIdentity response."""
        scanner = EtherNetIPScanner()
        data = self._build_identity_response()
        identity = scanner._parse_identity_response(data)

        self.assertIsNotNone(identity)
        self.assertEqual(identity['vendor_id'], 1)
        self.assertEqual(identity['device_type'], 14)
        self.assertEqual(identity['product_name'], 'TestPLC')
        self.assertIn('firmware_version', identity)

    def test_parse_identity_response_too_short(self):
        """Test parsing a too-short response."""
        scanner = EtherNetIPScanner()
        result = scanner._parse_identity_response(b'\x00' * 10)
        self.assertIsNone(result)

    def test_parse_identity_response_wrong_item_type(self):
        """Test parsing response with wrong item type."""
        scanner = EtherNetIPScanner()
        # Build response with wrong item type
        data = b'\x00' * 24  # header
        data += struct.pack('<H', 1)  # item count
        data += struct.pack('<H', 0x0001)  # wrong item type (not 0x000C)
        data += struct.pack('<H', 0)  # item length
        result = scanner._parse_identity_response(data)
        self.assertIsNone(result)

    @patch('scanners.ethernet_ip_scanner.socket.socket')
    def test_check_enip_availability_success(self, mock_socket_class):
        """Test EtherNet/IP availability check with valid response."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        # Build a valid ListIdentity response
        response = self._build_identity_response()
        mock_sock.recv.return_value = response

        scanner = EtherNetIPScanner()
        result = scanner._check_enip_availability('192.168.1.1', 44818)
        self.assertIsNotNone(result)

    @patch('scanners.ethernet_ip_scanner.socket.socket')
    def test_check_enip_availability_timeout(self, mock_socket_class):
        """Test availability check on timeout."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.connect.side_effect = socket.timeout()

        scanner = EtherNetIPScanner()
        result = scanner._check_enip_availability('192.168.1.1', 44818)
        self.assertIsNone(result)

    @patch('scanners.ethernet_ip_scanner.socket.socket')
    def test_register_session_success(self, mock_socket_class):
        """Test CIP session registration."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        # Build RegisterSession response: command=0x0065, session_handle=0x42
        response = bytearray(28)
        struct.pack_into('<H', response, 0, ENIP_CMD_REGISTER_SESSION)
        struct.pack_into('<I', response, 4, 0x42)  # session handle
        struct.pack_into('<I', response, 8, 0)  # status = success
        mock_sock.recv.return_value = bytes(response)

        scanner = EtherNetIPScanner()
        handle = scanner._register_session('192.168.1.1', 44818)
        self.assertEqual(handle, 0x42)

    def test_check_vulnerable_firmware_match(self):
        """Test firmware vulnerability check with known version."""
        scanner = EtherNetIPScanner()
        result = scanner._check_vulnerable_firmware('ControlLogix 5580', '20.011')
        self.assertIsNotNone(result)
        self.assertIn('ControlLogix', result)

    def test_check_vulnerable_firmware_safe(self):
        """Test firmware vulnerability check with safe version."""
        scanner = EtherNetIPScanner()
        result = scanner._check_vulnerable_firmware('ControlLogix 5580', '33.001')
        self.assertIsNone(result)

    def test_check_vulnerable_firmware_unknown(self):
        """Test firmware vulnerability check with unknown product."""
        scanner = EtherNetIPScanner()
        result = scanner._check_vulnerable_firmware('UnknownDevice', '1.0')
        self.assertIsNone(result)

    def test_issue_format(self):
        """Test that issues have required fields."""
        scanner = EtherNetIPScanner()
        issue = scanner.create_issue(
            severity='high',
            description='Unauthenticated CIP session',
            remediation='Implement CIP Security'
        )
        self.assertEqual(issue['severity'], 'high')
        self.assertIn('description', issue)

    # --- Helper to build a valid ListIdentity response ---

    @staticmethod
    def _build_identity_response():
        """Build a minimal valid ListIdentity response for testing."""
        # Encapsulation header (24 bytes)
        header = bytearray(24)
        struct.pack_into('<H', header, 0, ENIP_CMD_LIST_IDENTITY)  # Command

        # Item count
        items = struct.pack('<H', 1)

        # CIP Identity Item header
        item_type = struct.pack('<H', 0x000C)

        # Identity data
        identity = bytearray()
        identity += struct.pack('<H', 1)  # Protocol version
        identity += b'\x00' * 16  # Socket address (16 bytes)
        identity += struct.pack('<H', 1)  # Vendor ID (Rockwell)
        identity += struct.pack('<H', 14)  # Device Type (PLC)
        identity += struct.pack('<H', 55)  # Product Code
        identity += struct.pack('B', 20)  # Revision Major
        identity += struct.pack('B', 11)  # Revision Minor
        identity += struct.pack('<H', 0x0030)  # Status
        identity += struct.pack('<I', 0xDEADBEEF)  # Serial Number
        product_name = b'TestPLC'
        identity += struct.pack('B', len(product_name))
        identity += product_name
        identity += struct.pack('B', 3)  # State

        item_length = struct.pack('<H', len(identity))

        # Combine
        data = bytes(header) + items + item_type + item_length + bytes(identity)

        # Fix header length
        header_fixed = bytearray(data)
        struct.pack_into('<H', header_fixed, 2, len(data) - 24)  # Data length

        return bytes(header_fixed)


if __name__ == '__main__':
    unittest.main()
