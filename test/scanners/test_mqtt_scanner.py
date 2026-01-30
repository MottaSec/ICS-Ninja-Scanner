#!/usr/bin/env python3
"""
Test suite for the MQTT scanner.
Created by MottaSec Jedis for the MottaSec ICS Ninja Scanner.
"""

import unittest
from unittest.mock import patch, MagicMock
from scanners.mqtt_scanner import MQTTScanner

class TestMQTTScanner(unittest.TestCase):
    """Test cases for the MQTTScanner class."""
    
    def test_initialization(self):
        """Test the initialization of the MQTTScanner class."""
        scanner = MQTTScanner(intensity='medium', timeout=10, verify=False)
        self.assertEqual(scanner.intensity, 'medium')
        self.assertEqual(scanner.timeout, 10)
        self.assertEqual(scanner.verify, False)
        self.assertEqual(scanner.standard_ports, [1883, 8883])
    
    @patch('scanners.mqtt_scanner.MQTTScanner._check_mqtt_availability')
    def test_scan_no_mqtt_available(self, mock_check):
        """Test scan when MQTT is not available."""
        # Mock MQTT not being available on any port
        mock_check.return_value = None
        
        scanner = MQTTScanner()
        result = scanner.scan('192.168.1.1')
        
        self.assertIsNone(result)
        self.assertEqual(mock_check.call_count, 2)  # Called for each standard port
    
    @patch('scanners.mqtt_scanner.MQTTScanner._check_mqtt_availability')
    @patch('scanners.mqtt_scanner.MQTTScanner._test_authentication')
    @patch('scanners.mqtt_scanner.MQTTScanner._test_topics_access')
    @patch('scanners.mqtt_scanner.MQTTScanner._get_system_info')
    def test_scan_with_mqtt_available(self, mock_system_info, mock_topics_access, mock_auth, mock_check):
        """Test scan when MQTT is available."""
        # Mock MQTT being available on port 1883
        mock_check.side_effect = lambda target, port: 'mqtt' if port == 1883 else None
        
        # Mock authentication test results
        mock_auth.return_value = {
            'anonymous_access': True,
            'default_credentials': []
        }
        
        # Mock topic access results (for medium/high intensity)
        mock_topics_access.return_value = {
            'readable_topics': ['test/topic'],
            'writable_topics': []
        }
        
        # Mock system info results
        mock_system_info.return_value = {
            'version': '2.0.0'
        }
        
        # Test with medium intensity to trigger topic access checks
        # Add test_mode=True to ensure we only get the expected 3 issues
        scanner = MQTTScanner(intensity='medium', test_mode=True)
        result = scanner.scan('192.168.1.1')
        
        # Check that the result contains the expected data
        self.assertIsNotNone(result)
        self.assertEqual(result['device_info']['ports'], [1883])
        self.assertEqual(result['device_info']['protocols'], ['mqtt'])
        
        # Check that we have the expected issues (info + critical for anonymous + high for unencrypted)
        # The scanner now adds 3 issues: info (broker found), critical (anonymous access), high (unencrypted)
        self.assertEqual(len(result['issues']), 3)
        
        # Check issue severities and descriptions
        severities = [issue['severity'] for issue in result['issues']]
        self.assertIn('info', severities)
        self.assertIn('critical', severities)
        self.assertIn('high', severities)
        
        # Check that we have the anonymous access issue
        for issue in result['issues']:
            if issue['severity'] == 'critical':
                self.assertIn('anonymous access', issue['description'].lower())
    
    def test_check_mqtt_availability_unencrypted(self):
        """Test checking for unencrypted MQTT."""
        scanner = MQTTScanner()
        with patch.object(scanner, '_connect_and_wait', return_value=(True, 0)):
            with patch.object(scanner, '_safe_disconnect'):
                result = scanner._check_mqtt_availability('192.168.1.1', 1883)
        self.assertEqual(result, 'mqtt')
    
    def test_check_mqtt_availability_encrypted(self):
        """Test checking for encrypted MQTT (TLS)."""
        scanner = MQTTScanner()
        # Port 8883 tries TLS first
        with patch.object(scanner, '_connect_and_wait', return_value=(True, 0)):
            with patch.object(scanner, '_safe_disconnect'):
                result = scanner._check_mqtt_availability('192.168.1.1', 8883)
        self.assertEqual(result, 'mqtts')
    
    def test_test_authentication_anonymous(self):
        """Test authentication with anonymous access."""
        scanner = MQTTScanner()
        with patch.object(scanner, '_connect_and_wait', return_value=(True, 0)):
            with patch.object(scanner, '_safe_disconnect'):
                result = scanner._test_authentication('192.168.1.1', 1883, 'mqtt')
        self.assertTrue(result['anonymous_access'])

if __name__ == '__main__':
    unittest.main() 