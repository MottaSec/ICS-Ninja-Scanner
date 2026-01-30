#!/usr/bin/env python3
"""Test suite for the Modbus scanner."""

import unittest
from unittest.mock import patch, MagicMock, PropertyMock
import sys
import os
import socket
import struct

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from scanners.modbus_scanner import ModbusScanner


class TestModbusScanner(unittest.TestCase):
    """Test cases for the ModbusScanner class."""

    def test_initialization(self):
        """Test the initialization of the ModbusScanner class."""
        scanner = ModbusScanner(intensity='medium', timeout=10, verify=False)
        self.assertEqual(scanner.intensity, 'medium')
        self.assertEqual(scanner.timeout, 10)
        self.assertEqual(scanner.verify, False)
        self.assertEqual(scanner.standard_ports, [502])

    def test_initialization_defaults(self):
        """Test default initialization values."""
        scanner = ModbusScanner()
        self.assertEqual(scanner.intensity, 'low')
        self.assertEqual(scanner.timeout, 5)
        self.assertEqual(scanner.verify, True)

    @patch('scanners.modbus_scanner.ModbusScanner._check_modbus_availability')
    def test_scan_not_available(self, mock_check):
        """Test scan returns None when Modbus is not available."""
        mock_check.return_value = False
        scanner = ModbusScanner()
        result = scanner.scan('192.168.1.1')
        self.assertIsNone(result)
        mock_check.assert_called_once_with('192.168.1.1', 502)

    @patch('scanners.modbus_scanner.ModbusTcpClient')
    @patch('scanners.modbus_scanner.ModbusScanner._check_modbus_tls')
    @patch('scanners.modbus_scanner.ModbusScanner._read_device_identification')
    @patch('scanners.modbus_scanner.ModbusScanner._check_modbus_availability')
    def test_scan_device_found_low_intensity(self, mock_check, mock_dev_id, mock_tls, mock_client_class):
        """Test scan with Modbus device found at low intensity."""
        mock_check.return_value = True
        mock_dev_id.return_value = {'vendor': 'TestVendor', 'product_code': 'TP100'}
        mock_tls.return_value = None  # side effect on results

        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        mock_client.is_socket_open.return_value = True

        scanner = ModbusScanner(intensity='low')
        result = scanner.scan('192.168.1.1')

        self.assertIsNotNone(result)
        self.assertEqual(result['device_info']['port'], 502)
        self.assertTrue(result['device_info']['connected'])
        # At low intensity, should have info + unauth issues, but NOT unit ID or function code scanning
        severities = [i['severity'] for i in result['issues']]
        self.assertIn('info', severities)
        self.assertIn('high', severities)

    @patch('scanners.modbus_scanner.ModbusTcpClient')
    @patch('scanners.modbus_scanner.ModbusScanner._check_modbus_tls')
    @patch('scanners.modbus_scanner.ModbusScanner._read_device_identification')
    @patch('scanners.modbus_scanner.ModbusScanner._check_modbus_availability')
    def test_scan_medium_intensity_runs_enumeration(self, mock_check, mock_dev_id, mock_tls, mock_client_class):
        """Test that medium intensity runs unit ID and function code enumeration."""
        mock_check.return_value = True
        mock_dev_id.return_value = None
        mock_tls.return_value = None

        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        mock_client.is_socket_open.return_value = True

        # Mock read_holding_registers to return non-error for unit ID scanning
        mock_resp = MagicMock()
        mock_resp.isError.return_value = False
        mock_client.read_holding_registers.return_value = mock_resp
        mock_client.read_coils.return_value = mock_resp
        mock_client.read_discrete_inputs.return_value = mock_resp
        mock_client.read_input_registers.return_value = mock_resp
        mock_client.socket = None  # prevent raw FC probes

        scanner = ModbusScanner(intensity='medium')
        result = scanner.scan('192.168.1.1')

        self.assertIsNotNone(result)
        # At medium, unit_ids should be populated (COMMON_UNIT_IDS = 1-10 + 247)
        self.assertIn('unit_ids', result['device_info'])

    @patch('scanners.modbus_scanner.ModbusTcpClient')
    @patch('scanners.modbus_scanner.ModbusScanner._check_modbus_tls')
    @patch('scanners.modbus_scanner.ModbusScanner._read_device_identification')
    @patch('scanners.modbus_scanner.ModbusScanner._check_modbus_availability')
    def test_scan_high_intensity_runs_write_tests(self, mock_check, mock_dev_id, mock_tls, mock_client_class):
        """Test that high intensity runs write access tests and broadcast."""
        mock_check.return_value = True
        mock_dev_id.return_value = None
        mock_tls.return_value = None

        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        mock_client.is_socket_open.return_value = True

        # Mock responses for coil reads/writes
        mock_read_resp = MagicMock()
        mock_read_resp.isError.return_value = False
        mock_read_resp.bits = [False]
        mock_read_resp.registers = [100]

        mock_write_resp = MagicMock()
        mock_write_resp.isError.return_value = False

        mock_client.read_holding_registers.return_value = mock_read_resp
        mock_client.read_coils.return_value = mock_read_resp
        mock_client.read_discrete_inputs.return_value = mock_read_resp
        mock_client.read_input_registers.return_value = mock_read_resp
        mock_client.write_coil.return_value = mock_write_resp
        mock_client.write_register.return_value = mock_write_resp
        mock_client.socket = None

        scanner = ModbusScanner(intensity='high')
        result = scanner.scan('192.168.1.1')

        self.assertIsNotNone(result)
        # high intensity should find writable coils and registers
        self.assertIn('writable_coils', result['device_info'])
        self.assertIn('writable_registers', result['device_info'])

    @patch('scanners.modbus_scanner.socket.socket')
    def test_check_modbus_availability_success(self, mock_socket_class):
        """Test availability check with valid Modbus response."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        # Build a fake Modbus response: MBAP header (7 bytes) + FC 3 response
        response = struct.pack('>HHHB', 1, 0, 4, 1) + bytes([3, 2, 0, 42])
        mock_sock.recv.return_value = response

        scanner = ModbusScanner()
        result = scanner._check_modbus_availability('192.168.1.1', 502)
        self.assertTrue(result)

    @patch('scanners.modbus_scanner.socket.socket')
    def test_check_modbus_availability_exception_response(self, mock_socket_class):
        """Test availability check with Modbus exception response (FC 0x83)."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        # Exception response: FC 0x83 (exception for FC 3)
        response = struct.pack('>HHHB', 1, 0, 3, 1) + bytes([0x83, 0x02])
        mock_sock.recv.return_value = response

        scanner = ModbusScanner()
        result = scanner._check_modbus_availability('192.168.1.1', 502)
        self.assertTrue(result)

    @patch('scanners.modbus_scanner.socket.socket')
    def test_check_modbus_availability_connection_fails(self, mock_socket_class):
        """Test availability check when connection fails."""
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        mock_sock.connect.side_effect = socket.timeout()

        scanner = ModbusScanner()
        result = scanner._check_modbus_availability('192.168.1.1', 502)
        self.assertFalse(result)

    def test_parse_device_id_response_valid(self):
        """Test parsing a valid device identification response."""
        # Build a minimal FC 43 response
        # MBAP header (7 bytes) + FC 0x2B + MEI type 0x0E + ...
        header = struct.pack('>HHHB', 1, 0, 20, 1)
        fc = bytes([0x2B, 0x0E, 0x01, 0x00, 0x00, 0x01])
        # num_objects=1, obj_id=0, obj_len=4, value="Test"
        objects = bytes([1, 0, 4]) + b'Test'
        data = header + fc + objects

        result = ModbusScanner._parse_device_id_response(data)
        self.assertIsNotNone(result)
        self.assertEqual(result.get('vendor'), 'Test')

    def test_parse_device_id_response_too_short(self):
        """Test parsing a too-short response returns None."""
        result = ModbusScanner._parse_device_id_response(b'\x00' * 5)
        self.assertIsNone(result)

    def test_summarise_list(self):
        """Test the list summarisation helper."""
        items = list(range(15))
        summary = ModbusScanner._summarise_list(items, limit=10)
        self.assertIn('and 5 more', summary)

    def test_summarise_list_short(self):
        """Test summarisation with short list."""
        items = [1, 2, 3]
        summary = ModbusScanner._summarise_list(items)
        self.assertEqual(summary, '1, 2, 3')

    def test_issue_format(self):
        """Test that created issues have required fields."""
        scanner = ModbusScanner()
        issue = scanner.create_issue(
            severity='high',
            description='Test issue',
            details='Some details'
        )
        self.assertEqual(issue['severity'], 'high')
        self.assertEqual(issue['description'], 'Test issue')
        self.assertIn('timestamp', issue)


if __name__ == '__main__':
    unittest.main()
