#!/usr/bin/env python3
"""Test suite for the BACnet/IP scanner."""

import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import socket
import struct

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from scanners.bacnet_scanner import BACnetScanner, BVLL_TYPE, PDU_TYPE_UNCONFIRMED_REQUEST, UNCONFIRMED_I_AM


class TestBACnetScanner(unittest.TestCase):
    """Test cases for the BACnetScanner class."""

    def test_initialization(self):
        """Test the initialization of the BACnetScanner class."""
        scanner = BACnetScanner(intensity='medium', timeout=10, verify=False)
        self.assertEqual(scanner.intensity, 'medium')
        self.assertEqual(scanner.timeout, 10)
        self.assertEqual(scanner.verify, False)
        self.assertEqual(scanner.standard_ports, [47808])

    def test_initialization_defaults(self):
        """Test default initialization."""
        scanner = BACnetScanner()
        self.assertEqual(scanner.intensity, 'low')
        self.assertEqual(scanner.standard_ports, [47808])

    @patch('scanners.bacnet_scanner.BACnetScanner._check_bacnet_availability')
    def test_scan_not_available(self, mock_check):
        """Test scan returns None when BACnet is not available."""
        mock_check.return_value = None
        scanner = BACnetScanner()
        result = scanner.scan('192.168.1.1')
        self.assertIsNone(result)

    @patch('scanners.bacnet_scanner.BACnetScanner._check_bacnet_availability')
    def test_scan_device_found_low_intensity(self, mock_check):
        """Test scan with BACnet device found at low intensity."""
        mock_check.return_value = {
            'device_instance': 12345,
            'max_apdu': 1476,
            'vendor_id': 5,
            'segmentation': 'both'
        }

        scanner = BACnetScanner(intensity='low')
        result = scanner.scan('192.168.1.1')

        self.assertIsNotNone(result)
        self.assertEqual(result['device_info']['port'], 47808)
        self.assertEqual(result['device_info']['device_instance'], 12345)
        self.assertEqual(result['device_info']['vendor_id'], 5)
        # Should have detection issues
        descriptions = [i['description'] for i in result['issues']]
        self.assertTrue(any('BACnet device detected' in d for d in descriptions))
        self.assertTrue(any('WhoIs' in d for d in descriptions))

    @patch('scanners.bacnet_scanner.BACnetScanner._test_read_property_multiple')
    @patch('scanners.bacnet_scanner.BACnetScanner._enumerate_objects')
    @patch('scanners.bacnet_scanner.BACnetScanner._check_bacnet_sc_support')
    @patch('scanners.bacnet_scanner.BACnetScanner._read_device_properties')
    @patch('scanners.bacnet_scanner.BACnetScanner._check_bacnet_availability')
    def test_scan_medium_intensity(self, mock_check, mock_props, mock_sc, mock_enum, mock_rpm):
        """Test medium intensity scan runs property reads and object enumeration."""
        mock_check.return_value = {
            'device_instance': 100,
            'max_apdu': 1476,
            'vendor_id': 15,
            'segmentation': 'both'
        }
        mock_props.return_value = {
            'vendor_name': 'Honeywell',
            'model_name': 'TestModel',
            'firmware_revision': '1.0'
        }
        mock_sc.return_value = False
        mock_enum.return_value = [(8, 100), (0, 1), (0, 2)]
        mock_rpm.return_value = True

        scanner = BACnetScanner(intensity='medium')
        result = scanner.scan('192.168.1.1')

        self.assertIsNotNone(result)
        mock_props.assert_called_once()
        mock_enum.assert_called_once()
        # Should flag unauthenticated read access
        high_issues = [i for i in result['issues'] if i['severity'] == 'high']
        self.assertTrue(len(high_issues) > 0)

    def test_build_whois_packet(self):
        """Test WhoIs packet building."""
        scanner = BACnetScanner()
        packet = scanner._build_whois_packet()
        self.assertIsInstance(packet, bytes)
        # BVLL header: type 0x81
        self.assertEqual(packet[0], BVLL_TYPE)
        # BVLL function: 0x0B (original broadcast)
        self.assertEqual(packet[1], 0x0B)

    def test_build_read_property_packet(self):
        """Test ReadProperty packet building."""
        scanner = BACnetScanner()
        packet = scanner._build_read_property_packet(8, 100, 75)  # Device object, PROP_OBJECT_IDENTIFIER
        self.assertIsInstance(packet, bytes)
        self.assertEqual(packet[0], BVLL_TYPE)
        self.assertEqual(packet[1], 0x0A)  # Unicast

    def test_parse_iam_valid(self):
        """Test parsing a valid IAm response."""
        scanner = BACnetScanner()

        # Build a minimal IAm packet
        bvll = struct.pack('!BBH', BVLL_TYPE, 0x0A, 0)  # Will fix length later
        npdu = struct.pack('!BB', 0x01, 0x00)  # Version 1, no special flags
        apdu = bytes([PDU_TYPE_UNCONFIRMED_REQUEST, UNCONFIRMED_I_AM])

        # Object identifier: Device, instance 42 (0xC4 tag)
        obj_id = (8 << 22) | 42  # Device type = 8
        iam_data = struct.pack('!B', 0xC4) + struct.pack('!I', obj_id)
        # Max APDU: unsigned, tag 2, length 2
        iam_data += struct.pack('!B', 0x22) + struct.pack('!H', 1476)
        # Segmentation: enumerated, tag 9, length 1
        iam_data += struct.pack('!B', 0x91) + struct.pack('!B', 0)
        # Vendor ID: unsigned, tag 2, length 1
        iam_data += struct.pack('!B', 0x21) + struct.pack('!B', 5)

        payload = npdu + apdu + iam_data
        # Fix BVLL length
        bvll = struct.pack('!BBH', BVLL_TYPE, 0x0A, 4 + len(payload))
        packet = bvll + payload

        result = scanner._parse_iam(packet)
        self.assertIsNotNone(result)
        self.assertEqual(result['device_instance'], 42)
        self.assertEqual(result['max_apdu'], 1476)
        self.assertEqual(result['vendor_id'], 5)

    def test_parse_iam_invalid(self):
        """Test parsing an invalid IAm response."""
        scanner = BACnetScanner()
        result = scanner._parse_iam(b'\x00\x01\x02')
        self.assertIsNone(result)

    def test_parse_iam_none(self):
        """Test parsing None returns None."""
        scanner = BACnetScanner()
        result = scanner._parse_iam(None)
        self.assertIsNone(result)

    def test_is_simple_ack(self):
        """Test SimpleAck detection."""
        scanner = BACnetScanner()
        # Build a minimal packet with SimpleAck PDU type at APDU offset
        bvll = struct.pack('!BBH', BVLL_TYPE, 0x0A, 10)
        npdu = struct.pack('!BB', 0x01, 0x00)
        apdu = bytes([0x20, 0x01, 0x0F])  # SimpleAck PDU type
        data = bvll + npdu + apdu
        self.assertTrue(scanner._is_simple_ack(data))

    def test_is_complex_ack(self):
        """Test ComplexAck detection."""
        scanner = BACnetScanner()
        bvll = struct.pack('!BBH', BVLL_TYPE, 0x0A, 10)
        npdu = struct.pack('!BB', 0x01, 0x00)
        apdu = bytes([0x30, 0x01, 0x0C])  # ComplexAck PDU type
        data = bvll + npdu + apdu
        self.assertTrue(scanner._is_complex_ack(data))

    def test_encode_character_string(self):
        """Test BACnet character string encoding."""
        scanner = BACnetScanner()
        encoded = scanner._encode_character_string("Hello")
        self.assertIsInstance(encoded, bytes)
        # Should contain UTF-8 encoding byte (0x00) + "Hello"
        self.assertIn(b'Hello', encoded)

    def test_next_invoke_id_wraps(self):
        """Test invoke ID wraps at 255."""
        scanner = BACnetScanner()
        scanner._invoke_id = 254
        id1 = scanner._next_invoke_id()
        self.assertEqual(id1, 255)
        id2 = scanner._next_invoke_id()
        self.assertEqual(id2, 0)

    def test_issue_format(self):
        """Test that issues have required fields."""
        scanner = BACnetScanner()
        issue = scanner.create_issue(
            severity='medium',
            description='BACnet device responds to WhoIs',
            details='Any host can discover this device',
            remediation='Segment BACnet traffic'
        )
        self.assertEqual(issue['severity'], 'medium')
        self.assertIn('remediation', issue)


if __name__ == '__main__':
    unittest.main()
