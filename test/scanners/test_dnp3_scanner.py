#!/usr/bin/env python3
"""Test suite for the DNP3 scanner."""

import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import socket
import struct

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from scanners.dnp3_scanner import (
    DNP3Scanner, _calculate_crc, _init_crc_table,
    DNP3_START_BYTES, FC_READ, FC_RESPONSE, FC_WRITE,
    DL_DIR, DL_PRM, DL_UNCONFIRMED_USER_DATA,
    TL_FIR, TL_FIN, AC_FIR, AC_FIN,
    IIN2_NO_FUNC_CODE_SUPPORT, IIN2_OBJECT_UNKNOWN,
)


class TestDNP3Scanner(unittest.TestCase):
    """Test cases for the DNP3Scanner class."""

    def test_initialization(self):
        """Test the initialization of the DNP3Scanner class."""
        scanner = DNP3Scanner(intensity='medium', timeout=10, verify=False)
        self.assertEqual(scanner.intensity, 'medium')
        self.assertEqual(scanner.timeout, 10)
        self.assertEqual(scanner.verify, False)
        self.assertEqual(scanner.standard_ports, [20000])

    def test_initialization_defaults(self):
        """Test default initialization."""
        scanner = DNP3Scanner()
        self.assertEqual(scanner.intensity, 'low')
        self.assertEqual(scanner.standard_ports, [20000])

    @patch('scanners.dnp3_scanner.DNP3Scanner._check_dnp3_availability')
    def test_scan_not_available(self, mock_check):
        """Test scan returns None when DNP3 is not available."""
        mock_check.return_value = None
        scanner = DNP3Scanner()
        result = scanner.scan('192.168.1.1')
        self.assertIsNone(result)

    @patch('scanners.dnp3_scanner.DNP3Scanner._check_dnp3_availability')
    def test_scan_device_found_low_intensity(self, mock_check):
        """Test low-intensity scan with DNP3 device found."""
        mock_check.return_value = {'source': 10, 'destination': 1}

        scanner = DNP3Scanner(intensity='low')
        result = scanner.scan('192.168.1.1')

        self.assertIsNotNone(result)
        self.assertEqual(result['device_info']['port'], 20000)
        self.assertEqual(result['device_info']['protocol'], 'DNP3')
        self.assertEqual(result['device_info']['source_address'], 10)
        descriptions = [i['description'] for i in result['issues']]
        self.assertTrue(any('DNP3 Outstation Found' in d for d in descriptions))

    @patch('scanners.dnp3_scanner.DNP3Scanner._run_medium_checks')
    @patch('scanners.dnp3_scanner.DNP3Scanner._check_dnp3_availability')
    def test_scan_medium_intensity_runs_checks(self, mock_check, mock_medium):
        """Test that medium intensity runs medium checks."""
        mock_check.return_value = {'source': 10, 'destination': 1}

        scanner = DNP3Scanner(intensity='medium')
        result = scanner.scan('192.168.1.1')

        self.assertIsNotNone(result)
        mock_medium.assert_called_once()

    @patch('scanners.dnp3_scanner.DNP3Scanner._run_high_checks')
    @patch('scanners.dnp3_scanner.DNP3Scanner._run_medium_checks')
    @patch('scanners.dnp3_scanner.DNP3Scanner._check_dnp3_availability')
    def test_scan_high_intensity_runs_all_checks(self, mock_check, mock_medium, mock_high):
        """Test that high intensity runs both medium and high checks."""
        mock_check.return_value = {'source': 10, 'destination': 1}

        scanner = DNP3Scanner(intensity='high')
        result = scanner.scan('192.168.1.1')

        self.assertIsNotNone(result)
        mock_medium.assert_called_once()
        mock_high.assert_called_once()

    def test_crc_calculation(self):
        """Test DNP3 CRC-16 calculation."""
        _init_crc_table()
        # CRC should return a 16-bit value
        crc = _calculate_crc(b'\x05\x64\x05\xC0\x01\x00\x00\x00')
        self.assertIsInstance(crc, int)
        self.assertTrue(0 <= crc <= 0xFFFF)

    def test_crc_deterministic(self):
        """Test CRC calculation is deterministic."""
        data = b'Hello DNP3'
        crc1 = _calculate_crc(data)
        crc2 = _calculate_crc(data)
        self.assertEqual(crc1, crc2)

    def test_crc_different_data(self):
        """Test CRC produces different values for different data."""
        crc1 = _calculate_crc(b'\x00\x00')
        crc2 = _calculate_crc(b'\xFF\xFF')
        self.assertNotEqual(crc1, crc2)

    def test_build_dnp3_frame(self):
        """Test building a complete DNP3 frame."""
        scanner = DNP3Scanner()
        frame = scanner._build_dnp3_frame(
            control=DL_DIR | DL_PRM | DL_UNCONFIRMED_USER_DATA,
            destination=1,
            source=10,
            transport=TL_FIR | TL_FIN,
            app_control=AC_FIR | AC_FIN | 0,
            function_code=FC_READ,
            objects=b'\x3C\x01\x06'  # Class 0 all objects
        )
        self.assertIsInstance(frame, bytes)
        # Frame starts with DNP3 start bytes 0x05, 0x64
        self.assertEqual(frame[0], 0x05)
        self.assertEqual(frame[1], 0x64)

    def test_build_dnp3_frame_with_empty_objects(self):
        """Test frame building with no object data."""
        scanner = DNP3Scanner()
        frame = scanner._build_dnp3_frame(
            control=DL_DIR | DL_PRM | DL_UNCONFIRMED_USER_DATA,
            destination=1,
            source=10,
            transport=TL_FIR | TL_FIN,
            app_control=AC_FIR | AC_FIN,
            function_code=FC_READ,
            objects=b''
        )
        self.assertIsInstance(frame, bytes)
        self.assertEqual(frame[0], 0x05)

    def test_parse_dnp3_response_valid(self):
        """Test parsing a valid DNP3 response."""
        scanner = DNP3Scanner()

        # Build a minimal response manually
        # Header: 0x05, 0x64, length, control, dest_lo, dest_hi, src_lo, src_hi
        dl_header = bytes([0x05, 0x64, 10, 0x44, 0x01, 0x00, 0x0A, 0x00])
        header_crc = _calculate_crc(dl_header)
        header_with_crc = dl_header + struct.pack('<H', header_crc)

        # User data: transport + app_control + FC_RESPONSE + IIN1 + IIN2
        user_data = bytes([TL_FIR | TL_FIN, AC_FIR | AC_FIN, FC_RESPONSE, 0x00, 0x00])
        block_crc = _calculate_crc(user_data)
        data_block = user_data + struct.pack('<H', block_crc)

        raw = header_with_crc + data_block
        parsed = scanner._parse_dnp3_response(raw)

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed['source'], 10)
        self.assertEqual(parsed['destination'], 1)
        self.assertEqual(parsed['function_code'], FC_RESPONSE)

    def test_parse_dnp3_response_too_short(self):
        """Test parsing a too-short response."""
        scanner = DNP3Scanner()
        result = scanner._parse_dnp3_response(b'\x05\x64')
        self.assertIsNone(result)

    def test_parse_dnp3_response_wrong_start(self):
        """Test parsing response with wrong start bytes."""
        scanner = DNP3Scanner()
        result = scanner._parse_dnp3_response(b'\x00\x00' + b'\x00' * 20)
        self.assertIsNone(result)

    def test_parse_dnp3_response_none(self):
        """Test parsing None input."""
        scanner = DNP3Scanner()
        result = scanner._parse_dnp3_response(None)
        self.assertIsNone(result)

    def test_encode_object_header_all_objects(self):
        """Test encoding object header with qualifier 0x06 (all objects)."""
        header = DNP3Scanner._encode_object_header(60, 1, qualifier=0x06, count=0)
        self.assertEqual(header, bytes([60, 1, 0x06]))

    def test_encode_object_header_with_count(self):
        """Test encoding object header with 1-byte count qualifier."""
        header = DNP3Scanner._encode_object_header(1, 0, qualifier=0x17, count=5)
        self.assertEqual(header, bytes([1, 0, 0x17, 5]))

    def test_extract_printable(self):
        """Test printable string extraction from binary data."""
        data = b'\x00\x00Hello\x00World\x00\x00'
        result = DNP3Scanner._extract_printable(data)
        self.assertIn('Hello', result)
        self.assertIn('World', result)

    def test_extract_printable_empty(self):
        """Test printable extraction from empty data."""
        result = DNP3Scanner._extract_printable(b'')
        self.assertEqual(result, '')

    def test_extract_printable_none(self):
        """Test printable extraction from None."""
        result = DNP3Scanner._extract_printable(None)
        self.assertEqual(result, '')

    def test_next_seq_wraps(self):
        """Test application sequence number wraps at 15."""
        scanner = DNP3Scanner()
        scanner._seq = 14
        seq = scanner._next_seq()
        self.assertEqual(seq, 14)
        seq = scanner._next_seq()
        self.assertEqual(seq, 15)
        seq = scanner._next_seq()
        self.assertEqual(seq, 0)

    def test_issue_format(self):
        """Test that issues have required fields."""
        scanner = DNP3Scanner()
        issue = scanner.create_issue(
            severity='critical',
            description='No Secure Authentication',
            details='SA is not supported'
        )
        self.assertEqual(issue['severity'], 'critical')
        self.assertIn('description', issue)
        self.assertIn('timestamp', issue)


if __name__ == '__main__':
    unittest.main()
