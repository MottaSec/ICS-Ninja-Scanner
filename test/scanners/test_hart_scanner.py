#!/usr/bin/env python3
"""Test suite for the HART-IP scanner."""

import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import socket
import struct

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from scanners.hart_scanner import (
    HARTScanner, HART_IP_VERSION,
    MSG_TYPE_REQUEST, MSG_TYPE_RESPONSE, MSG_TYPE_NAK,
    MSG_ID_SESSION_INIT, MSG_ID_TOKEN_PASSING, MSG_ID_SESSION_CLOSE,
    DELIMITER_LONG_MASTER, DEFAULT_ADDRESS, MANUFACTURER_IDS,
)


class TestHARTScanner(unittest.TestCase):
    """Test cases for the HARTScanner class."""

    def test_initialization(self):
        """Test the initialization of the HARTScanner class."""
        scanner = HARTScanner(intensity='medium', timeout=10, verify=False)
        self.assertEqual(scanner.intensity, 'medium')
        self.assertEqual(scanner.timeout, 10)
        self.assertEqual(scanner.verify, False)
        self.assertEqual(scanner.standard_ports, [5094])

    def test_initialization_defaults(self):
        """Test default initialization."""
        scanner = HARTScanner()
        self.assertEqual(scanner.intensity, 'low')
        self.assertEqual(scanner.standard_ports, [5094])

    @patch('scanners.hart_scanner.HARTScanner._check_hart_availability')
    def test_scan_not_available(self, mock_check):
        """Test scan returns None when HART-IP is not available."""
        mock_check.return_value = (None, None)
        scanner = HARTScanner()
        result = scanner.scan('192.168.1.1')
        self.assertIsNone(result)

    @patch('scanners.hart_scanner.HARTScanner._close_session')
    @patch('scanners.hart_scanner.HARTScanner._check_hart_availability')
    def test_scan_device_found_low_intensity(self, mock_check, mock_close):
        """Test low-intensity scan with HART-IP device found."""
        mock_sock = MagicMock()
        # Command 0 response data: 13+ bytes
        cmd0_data = bytes([
            0xFE,  # 254 indicator
            0x02,  # manufacturer ID (Rosemount)
            0x10,  # device type
            0x05,  # preambles
            0x07,  # HART revision
            0x03,  # device revision
            0x02,  # software revision
            0x00, 0x00, 0x00,  # hardware rev / signaling / flags
            0xAB, 0xCD, 0xEF,  # device ID
        ])
        mock_check.return_value = (mock_sock, cmd0_data)

        scanner = HARTScanner(intensity='low')
        result = scanner.scan('192.168.1.1')

        self.assertIsNotNone(result)
        self.assertEqual(result['device_info']['port'], 5094)
        self.assertEqual(result['device_info']['protocol'], 'HART-IP')
        self.assertEqual(result['device_info']['manufacturer_id'], 0x02)
        descriptions = [i['description'] for i in result['issues']]
        self.assertTrue(any('HART-IP device' in d for d in descriptions))

    @patch('scanners.hart_scanner.HARTScanner._close_session')
    @patch('scanners.hart_scanner.HARTScanner._send_hart_command')
    @patch('scanners.hart_scanner.HARTScanner._check_hart_availability')
    def test_scan_medium_intensity(self, mock_check, mock_cmd, mock_close):
        """Test medium intensity runs enumeration and flags auth issues."""
        mock_sock = MagicMock()
        mock_check.return_value = (mock_sock, bytes(13))

        # Responses for commands: 13, 48, 3, and enumeration
        def cmd_side_effect(sock, cmd_num, **kwargs):
            if cmd_num == 13:
                return b'TAG   ' + b'DESCRIPTOR  ' + bytes([15, 6, 124])
            if cmd_num == 48:
                return b'\x00' * 10
            if cmd_num == 3:
                return b'\x00' * 8
            return None  # Not supported for enumeration

        mock_cmd.side_effect = cmd_side_effect

        scanner = HARTScanner(intensity='medium')
        result = scanner.scan('192.168.1.1')

        self.assertIsNotNone(result)
        # Should flag no authentication and plaintext
        high_issues = [i for i in result['issues'] if i['severity'] == 'high']
        self.assertTrue(len(high_issues) >= 2)

    def test_build_hart_ip_packet(self):
        """Test HART-IP packet building."""
        scanner = HARTScanner()
        packet = scanner._build_hart_ip_packet(
            msg_type=MSG_TYPE_REQUEST,
            msg_id=MSG_ID_SESSION_INIT,
            sequence=1,
            body=b''
        )
        self.assertEqual(len(packet), 8)  # Header only, no body
        self.assertEqual(packet[0], HART_IP_VERSION)
        self.assertEqual(packet[1], MSG_TYPE_REQUEST)
        self.assertEqual(packet[2], MSG_ID_SESSION_INIT)

    def test_build_hart_ip_packet_with_body(self):
        """Test HART-IP packet with body."""
        scanner = HARTScanner()
        body = b'\x01\x02\x03\x04'
        packet = scanner._build_hart_ip_packet(
            msg_type=MSG_TYPE_REQUEST,
            msg_id=MSG_ID_TOKEN_PASSING,
            sequence=5,
            body=body
        )
        self.assertEqual(len(packet), 8 + len(body))
        # Body length in header (bytes 6-7, big-endian)
        body_len = struct.unpack('>H', packet[6:8])[0]
        self.assertEqual(body_len, len(body))

    def test_build_hart_command(self):
        """Test HART command frame building."""
        scanner = HARTScanner()
        frame = scanner._build_hart_command(0)  # Command 0
        self.assertIsInstance(frame, bytes)
        # First byte is delimiter
        self.assertEqual(frame[0], DELIMITER_LONG_MASTER)
        # Next 5 bytes are address
        self.assertEqual(frame[1:6], DEFAULT_ADDRESS)
        # Command number
        self.assertEqual(frame[6], 0)
        # Byte count (no data)
        self.assertEqual(frame[7], 0)
        # Last byte is checksum (XOR of all preceding)
        chk = 0
        for b in frame[:-1]:
            chk ^= b
        self.assertEqual(frame[-1], chk)

    def test_build_hart_command_with_data(self):
        """Test HART command frame with data payload."""
        scanner = HARTScanner()
        data = b'\x01\x02\x03'
        frame = scanner._build_hart_command(6, data=data)
        self.assertEqual(frame[6], 6)  # Command 6
        self.assertEqual(frame[7], 3)  # Byte count
        self.assertEqual(frame[8:11], data)

    def test_build_hart_command_custom_address(self):
        """Test HART command with custom address."""
        scanner = HARTScanner()
        addr = b'\x01\x02\x03\x04\x05'
        frame = scanner._build_hart_command(0, address=addr)
        self.assertEqual(frame[1:6], addr)

    def test_parse_hart_ip_response_valid(self):
        """Test parsing a valid HART-IP response."""
        scanner = HARTScanner()
        # Build: version, msg_type=response, msg_id=session_init, status=0, seq=1, body_len=0
        data = struct.pack('>BBBBHH', HART_IP_VERSION, MSG_TYPE_RESPONSE,
                           MSG_ID_SESSION_INIT, 0, 1, 0)
        result = scanner._parse_hart_ip_response(data)
        self.assertIsNotNone(result)
        self.assertEqual(result['version'], HART_IP_VERSION)
        self.assertEqual(result['msg_type'], MSG_TYPE_RESPONSE)
        self.assertEqual(result['msg_id'], MSG_ID_SESSION_INIT)
        self.assertEqual(result['sequence'], 1)
        self.assertEqual(result['body_length'], 0)

    def test_parse_hart_ip_response_with_body(self):
        """Test parsing response with body."""
        scanner = HARTScanner()
        body = b'\xAA\xBB\xCC'
        data = struct.pack('>BBBBHH', HART_IP_VERSION, MSG_TYPE_RESPONSE,
                           MSG_ID_TOKEN_PASSING, 0, 2, len(body)) + body
        result = scanner._parse_hart_ip_response(data)
        self.assertIsNotNone(result)
        self.assertEqual(result['body'], body)

    def test_parse_hart_ip_response_too_short(self):
        """Test parsing too-short data returns None."""
        scanner = HARTScanner()
        result = scanner._parse_hart_ip_response(b'\x01\x02')
        self.assertIsNone(result)

    def test_parse_hart_ip_response_none(self):
        """Test parsing None returns None."""
        scanner = HARTScanner()
        result = scanner._parse_hart_ip_response(None)
        self.assertIsNone(result)

    def test_parse_command0_response_valid(self):
        """Test parsing Command 0 response data."""
        scanner = HARTScanner()
        cmd_data = bytes([
            0xFE,  # 254 indicator
            0x02,  # manufacturer ID (Rosemount)
            0x10,  # device type
            0x05,  # preambles
            0x07,  # HART revision
            0x03,  # device revision
            0x02,  # software revision
            0x00, 0x00, 0x00,  # hw rev / signal / flags
            0xAB, 0xCD, 0xEF,  # device ID
        ])
        result = scanner._parse_command0_response(cmd_data)
        self.assertIsNotNone(result)
        self.assertEqual(result['manufacturer_id'], 0x02)
        self.assertEqual(result['manufacturer'], 'Rosemount (Emerson)')
        self.assertEqual(result['device_type'], 0x10)
        self.assertEqual(result['hart_revision'], 7)
        self.assertEqual(result['device_revision'], 3)
        self.assertEqual(result['software_revision'], 2)
        self.assertEqual(result['device_id'], 'abcdef')

    def test_parse_command0_response_too_short(self):
        """Test parsing too-short Command 0 data."""
        scanner = HARTScanner()
        result = scanner._parse_command0_response(b'\x00\x01')
        self.assertIsNone(result)

    def test_parse_command0_response_none(self):
        """Test parsing None Command 0 data."""
        scanner = HARTScanner()
        result = scanner._parse_command0_response(None)
        self.assertIsNone(result)

    def test_parse_command13_response_valid(self):
        """Test parsing Command 13 response data."""
        scanner = HARTScanner()
        # 6 bytes tag + 12 bytes descriptor + 3 bytes date
        tag = b'TAG   '  # 6 bytes
        descriptor = b'DESCRIPTION ' # 12 bytes
        date = bytes([15, 6, 124])  # day=15, month=6, year=2024
        cmd_data = tag + descriptor + date

        result = scanner._parse_command13_response(cmd_data)
        self.assertIsNotNone(result)
        self.assertEqual(result['tag'], 'TAG')
        self.assertIn('DESCRIPTION', result['descriptor'])
        self.assertIn('15', result['date'])

    def test_parse_command13_response_too_short(self):
        """Test parsing too-short Command 13 data."""
        scanner = HARTScanner()
        result = scanner._parse_command13_response(b'\x00' * 10)
        self.assertEqual(result, {})

    def test_parse_command_response(self):
        """Test parsing HART command frame from Token-Passing PDU body."""
        scanner = HARTScanner()
        # Build minimal body: delimiter + 5-byte addr + cmd + byte_count + resp_code + data
        body = bytes([
            DELIMITER_LONG_MASTER,
            0x00, 0x00, 0x00, 0x00, 0x00,  # address
            0x00,  # command 0
            0x03,  # byte count
            0x00,  # response code (success)
            0xAA, 0xBB,  # 2 bytes data
        ])
        result = scanner._parse_command_response(body)
        self.assertIsNotNone(result)
        cmd, resp_code, data = result
        self.assertEqual(cmd, 0)
        self.assertEqual(resp_code, 0)
        self.assertEqual(data, bytes([0xAA, 0xBB]))

    def test_parse_command_response_too_short(self):
        """Test parsing too-short command response."""
        scanner = HARTScanner()
        result = scanner._parse_command_response(b'\x82\x00\x00')
        self.assertIsNone(result)

    def test_next_sequence_wraps(self):
        """Test sequence number wraps at 0xFFFF."""
        scanner = HARTScanner()
        scanner._sequence = 0xFFFE
        seq1 = scanner._next_sequence()
        self.assertEqual(seq1, 0xFFFF)
        seq2 = scanner._next_sequence()
        self.assertEqual(seq2, 0x0000)

    def test_manufacturer_ids_lookup(self):
        """Test manufacturer ID lookup table."""
        self.assertIn(0x02, MANUFACTURER_IDS)
        self.assertEqual(MANUFACTURER_IDS[0x02], 'Rosemount (Emerson)')
        self.assertIn(0x14, MANUFACTURER_IDS)
        self.assertEqual(MANUFACTURER_IDS[0x14], 'Endress+Hauser')

    def test_issue_format(self):
        """Test that issues have required fields."""
        scanner = HARTScanner()
        issue = scanner.create_issue(
            severity='critical',
            description='Write Polling Address accepted',
            details='Command 6 succeeded without auth',
            remediation='Enable write protection'
        )
        self.assertEqual(issue['severity'], 'critical')
        self.assertIn('description', issue)
        self.assertIn('remediation', issue)
        self.assertIn('timestamp', issue)


if __name__ == '__main__':
    unittest.main()
