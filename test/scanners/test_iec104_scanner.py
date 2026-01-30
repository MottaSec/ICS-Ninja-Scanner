#!/usr/bin/env python3
"""Test suite for the IEC 60870-5-104 scanner."""

import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import socket

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from scanners.iec104_scanner import (
    IEC104Scanner, _SeqTracker,
    IEC104_STARTDT_ACT, IEC104_TESTFR_ACT, IEC104_TESTFR_CON,
    CONTROL_COMMANDS,
)


class TestIEC104Scanner(unittest.TestCase):
    """Test cases for the IEC104Scanner class."""

    def test_initialization(self):
        """Test the initialization of the IEC104Scanner class."""
        scanner = IEC104Scanner(intensity='medium', timeout=10, verify=False)
        self.assertEqual(scanner.intensity, 'medium')
        self.assertEqual(scanner.timeout, 10)
        self.assertEqual(scanner.verify, False)
        self.assertEqual(scanner.standard_ports, [2404])

    def test_initialization_defaults(self):
        """Test default initialization."""
        scanner = IEC104Scanner()
        self.assertEqual(scanner.intensity, 'low')
        self.assertEqual(scanner.standard_ports, [2404])

    @patch('scanners.iec104_scanner.IEC104Scanner._check_iec104_availability')
    def test_scan_not_available(self, mock_check):
        """Test scan returns None when IEC-104 is not available."""
        mock_check.return_value = False
        scanner = IEC104Scanner()
        result = scanner.scan('192.168.1.1')
        self.assertIsNone(result)

    @patch('scanners.iec104_scanner.IEC104Scanner._detect_iec62351')
    @patch('scanners.iec104_scanner.IEC104Scanner._close')
    @patch('scanners.iec104_scanner.IEC104Scanner._connect')
    @patch('scanners.iec104_scanner.IEC104Scanner._check_iec104_availability')
    def test_scan_device_found_low_intensity(self, mock_check, mock_connect, mock_close, mock_tls):
        """Test scan with IEC-104 device found at low intensity."""
        mock_check.return_value = True
        mock_tls.return_value = False

        mock_sock = MagicMock()
        mock_connect.return_value = mock_sock

        # Return a valid STARTDT CON response
        startdt_con = bytes([0x68, 0x04, 0x0B, 0x00, 0x00, 0x00])
        mock_sock.recv.return_value = startdt_con

        scanner = IEC104Scanner(intensity='low')
        result = scanner.scan('192.168.1.1')

        self.assertIsNotNone(result)
        self.assertEqual(result['device_info']['port'], 2404)
        severities = [i['severity'] for i in result['issues']]
        self.assertIn('info', severities)
        self.assertIn('critical', severities)  # No auth issue
        self.assertIn('high', severities)  # Unencrypted

    def test_is_encrypted_iec104_bytes(self):
        """Test _is_encrypted returns False for IEC-104 framing."""
        # IEC-104 frame starts with 0x68
        data = bytes([0x68, 0x04, 0x0B, 0x00, 0x00, 0x00])
        result = IEC104Scanner._is_encrypted(data)
        self.assertFalse(result)

    def test_is_encrypted_tls_bytes(self):
        """Test _is_encrypted returns True for TLS record."""
        # TLS record starts with 0x16, 0x03
        data = bytes([0x16, 0x03, 0x01, 0x00, 0x05])
        result = IEC104Scanner._is_encrypted(data)
        self.assertTrue(result)

    def test_is_encrypted_empty_data(self):
        """Test _is_encrypted returns False for empty data."""
        result = IEC104Scanner._is_encrypted(b'')
        self.assertFalse(result)

    def test_is_encrypted_none(self):
        """Test _is_encrypted returns False for None."""
        result = IEC104Scanner._is_encrypted(None)
        self.assertFalse(result)

    def test_is_encrypted_unknown_bytes(self):
        """Test _is_encrypted returns True for unrecognized framing."""
        data = bytes([0xFF, 0xFF, 0xFF])
        result = IEC104Scanner._is_encrypted(data)
        self.assertTrue(result)

    @patch('scanners.iec104_scanner.socket.socket')
    def test_check_iec104_availability_valid(self, mock_socket_class):
        """Test availability check with valid TESTFR CON response."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        # STARTDT CON: control byte 0x0B
        response = bytes([0x68, 0x04, 0x0B, 0x00, 0x00, 0x00])
        mock_sock.recv.return_value = response

        scanner = IEC104Scanner()
        result = scanner._check_iec104_availability('192.168.1.1', 2404)
        self.assertTrue(result)

    @patch('scanners.iec104_scanner.socket.socket')
    def test_check_iec104_availability_timeout(self, mock_socket_class):
        """Test availability check when connection times out."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.connect.side_effect = socket.timeout()

        scanner = IEC104Scanner()
        result = scanner._check_iec104_availability('192.168.1.1', 2404)
        self.assertFalse(result)

    def test_seq_tracker(self):
        """Test the _SeqTracker helper class."""
        seq = _SeqTracker()
        self.assertEqual(seq.tx_seq, 0)
        self.assertEqual(seq.rx_seq, 0)

        # next_tx increments
        val = seq.next_tx()
        self.assertEqual(val, 0)
        self.assertEqual(seq.tx_seq, 1)

        # ack_rx increments rx
        seq.ack_rx(2)
        self.assertEqual(seq.rx_seq, 2)

        # encode_tx_rx returns 4 bytes
        encoded = seq.encode_tx_rx()
        self.assertEqual(len(encoded), 4)

        # s_frame returns 6 bytes
        s = seq.s_frame()
        self.assertEqual(len(s), 6)
        self.assertEqual(s[0], 0x68)

    def test_build_i_frame(self):
        """Test building an I-format APDU."""
        scanner = IEC104Scanner()
        seq = _SeqTracker()
        frame = scanner._build_i_frame(
            seq, type_id=100, cot=6, ca=1,
            ioa_payload=[0x00, 0x00, 0x00, 0x14]
        )
        self.assertIsInstance(frame, bytes)
        self.assertEqual(frame[0], 0x68)  # Start byte
        # After building, tx_seq should be 1
        self.assertEqual(seq.tx_seq, 1)

    def test_parse_device_info_startdt_con(self):
        """Test parsing device info from STARTDT CON response."""
        # STARTDT CON is a U-format (no device info to extract)
        response = bytes([0x68, 0x04, 0x0B, 0x00, 0x00, 0x00])
        result = IEC104Scanner._parse_device_info(response)
        self.assertIsInstance(result, dict)

    def test_extract_connection_params(self):
        """Test connection parameter extraction."""
        # Simple STARTDT CON frame
        response = bytes([0x68, 0x04, 0x0B, 0x00, 0x00, 0x00])
        params = IEC104Scanner._extract_connection_params(response)
        self.assertIsInstance(params, dict)
        self.assertIn('max_apdu_length_observed', params)
        self.assertEqual(params['max_apdu_length_observed'], 6)  # 4 + 2

    def test_extract_connection_params_empty(self):
        """Test connection parameter extraction with empty data."""
        params = IEC104Scanner._extract_connection_params(b'')
        self.assertEqual(params, {})

    @patch('scanners.iec104_scanner.IEC104Scanner._detect_iec62351')
    @patch('scanners.iec104_scanner.IEC104Scanner._detect_unsolicited_data')
    @patch('scanners.iec104_scanner.IEC104Scanner._test_control_commands')
    @patch('scanners.iec104_scanner.IEC104Scanner._close')
    @patch('scanners.iec104_scanner.IEC104Scanner._connect')
    @patch('scanners.iec104_scanner.IEC104Scanner._check_iec104_availability')
    def test_high_intensity_runs_control_commands(self, mock_check, mock_connect,
                                                   mock_close, mock_ctrl, mock_unsolicit, mock_tls):
        """Test that high intensity runs control command testing."""
        mock_check.return_value = True
        mock_tls.return_value = False
        mock_unsolicit.return_value = set()
        mock_ctrl.return_value = ['Single command (C_SC_NA_1)']

        mock_sock = MagicMock()
        mock_connect.return_value = mock_sock
        mock_sock.recv.return_value = bytes([0x68, 0x04, 0x0B, 0x00, 0x00, 0x00])

        scanner = IEC104Scanner(intensity='high')
        result = scanner.scan('192.168.1.1')

        self.assertIsNotNone(result)
        mock_ctrl.assert_called_once()

    def test_issue_format(self):
        """Test that issues have the required fields."""
        scanner = IEC104Scanner()
        issue = scanner.create_issue(
            severity='critical',
            description='No authentication',
            details='IEC-104 has no auth'
        )
        self.assertEqual(issue['severity'], 'critical')
        self.assertIn('description', issue)


if __name__ == '__main__':
    unittest.main()
