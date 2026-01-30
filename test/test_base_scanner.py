#!/usr/bin/env python3
"""
Test suite for the base scanner class.
Created by MottaSec Jedis for the MottaSec ICS Ninja Scanner.
"""

import unittest
from scanners.base_scanner import BaseScanner

class TestBaseScanner(unittest.TestCase):
    """Test cases for the BaseScanner class."""
    
    def test_initialization(self):
        """Test the initialization of the BaseScanner class."""
        scanner = BaseScanner(intensity='medium', timeout=10, verify=False)
        self.assertEqual(scanner.intensity, 'medium')
        self.assertEqual(scanner.timeout, 10)
        self.assertEqual(scanner.verify, False)
        self.assertEqual(scanner.name, 'BaseScanner')
        self.assertEqual(scanner.standard_ports, [])
    
    def test_create_issue(self):
        """Test the create_issue method."""
        scanner = BaseScanner()
        
        # Test with minimal parameters
        issue = scanner.create_issue('high', 'Test issue')
        self.assertEqual(issue['severity'], 'high')
        self.assertEqual(issue['description'], 'Test issue')
        self.assertNotIn('details', issue)
        self.assertNotIn('remediation', issue)
        
        # Test with all parameters
        issue = scanner.create_issue(
            'critical', 
            'Critical issue', 
            'This is a critical issue that needs attention',
            'Apply patch XYZ'
        )
        self.assertEqual(issue['severity'], 'critical')
        self.assertEqual(issue['description'], 'Critical issue')
        self.assertEqual(issue['details'], 'This is a critical issue that needs attention')
        self.assertEqual(issue['remediation'], 'Apply patch XYZ')
    
    def test_scan_not_implemented(self):
        """Test that the scan method raises NotImplementedError."""
        scanner = BaseScanner()
        with self.assertRaises(NotImplementedError):
            scanner.scan('192.168.1.1')

class TestSeverityConstants(unittest.TestCase):
    """Test severity level constants."""

    def test_severity_constants(self):
        self.assertEqual(BaseScanner.SEVERITY_CRITICAL, 'critical')
        self.assertEqual(BaseScanner.SEVERITY_HIGH, 'high')
        self.assertEqual(BaseScanner.SEVERITY_MEDIUM, 'medium')
        self.assertEqual(BaseScanner.SEVERITY_LOW, 'low')
        self.assertEqual(BaseScanner.SEVERITY_INFO, 'info')


class TestRateLimiting(unittest.TestCase):
    """Test rate limiting functionality."""

    def test_rate_limit_default(self):
        """Default request_delay=0 should not sleep."""
        scanner = BaseScanner()
        import time
        start = time.time()
        scanner.rate_limit()
        elapsed = time.time() - start
        self.assertLess(elapsed, 0.05)

    def test_rate_limit_with_delay(self):
        """Should sleep for at least request_delay seconds."""
        scanner = BaseScanner(request_delay=0.01)
        import time
        start = time.time()
        scanner.rate_limit()
        elapsed = time.time() - start
        self.assertGreaterEqual(elapsed, 0.01)

    def test_request_delay_stored(self):
        scanner = BaseScanner(request_delay=1.5)
        self.assertEqual(scanner.request_delay, 1.5)


class TestSafeWriteTest(unittest.TestCase):
    """Test the safe_write_test method."""

    def test_safe_write_test_success(self):
        scanner = BaseScanner()
        state = [42]
        def read_fn():
            return state[0]
        def write_fn(val):
            state[0] = val
        result = scanner.safe_write_test(read_fn, write_fn)
        self.assertTrue(result['writable'])
        self.assertTrue(result['restored'])
        self.assertEqual(result['original_value'], 42)

    def test_safe_write_test_read_failure(self):
        scanner = BaseScanner()
        def read_fn():
            raise Exception("read failed")
        def write_fn(val):
            pass
        result = scanner.safe_write_test(read_fn, write_fn)
        self.assertFalse(result['writable'])
        self.assertIsNone(result['original_value'])

    def test_safe_write_test_write_failure(self):
        scanner = BaseScanner()
        def read_fn():
            return 10
        def write_fn(val):
            raise Exception("write failed")
        result = scanner.safe_write_test(read_fn, write_fn)
        self.assertFalse(result['writable'])
        self.assertEqual(result['original_value'], 10)

    def test_safe_write_test_restore_warning(self):
        """Write succeeds but restore fails."""
        scanner = BaseScanner()
        call_count = [0]
        def read_fn():
            return 42
        def write_fn(val):
            call_count[0] += 1
            if call_count[0] == 2:  # restore write
                raise Exception("restore failed")
        result = scanner.safe_write_test(read_fn, write_fn)
        self.assertIsNotNone(result['restore_warning'])


class TestSafeTestValue(unittest.TestCase):
    """Test the _safe_test_value helper."""

    def test_safe_test_value_int(self):
        scanner = BaseScanner()
        self.assertEqual(scanner._safe_test_value(42), 43)
        self.assertEqual(scanner._safe_test_value(65535), 65534)
        self.assertEqual(scanner._safe_test_value(0), 1)

    def test_safe_test_value_bool(self):
        scanner = BaseScanner()
        self.assertEqual(scanner._safe_test_value(True), False)
        self.assertEqual(scanner._safe_test_value(False), True)

    def test_safe_test_value_bytes(self):
        scanner = BaseScanner()
        result = scanner._safe_test_value(b'\x00\x01')
        self.assertEqual(result[0], 1)  # First byte incremented

    def test_safe_test_value_float(self):
        scanner = BaseScanner()
        result = scanner._safe_test_value(3.14)
        self.assertAlmostEqual(result, 3.24, places=2)

    def test_safe_test_value_string(self):
        scanner = BaseScanner()
        self.assertEqual(scanner._safe_test_value("hello"), "hello")

    def test_safe_test_value_unknown(self):
        scanner = BaseScanner()
        obj = [1, 2, 3]
        self.assertEqual(scanner._safe_test_value(obj), obj)


class TestValidateResults(unittest.TestCase):
    """Test validate_results method."""

    def test_validate_results_none(self):
        scanner = BaseScanner()
        self.assertIsNone(scanner.validate_results(None))

    def test_validate_results_missing_keys(self):
        scanner = BaseScanner()
        result = scanner.validate_results({})
        self.assertIn('device_info', result)
        self.assertIn('issues', result)
        self.assertEqual(result['device_info'], {})
        self.assertEqual(result['issues'], [])

    def test_validate_results_patches_issues(self):
        scanner = BaseScanner()
        result = scanner.validate_results({
            'device_info': {'type': 'PLC'},
            'issues': [
                {},  # missing severity and description
                {'severity': 'high'},  # missing description
            ]
        })
        self.assertEqual(result['issues'][0]['severity'], 'info')
        self.assertEqual(result['issues'][0]['description'], 'Unknown issue')
        self.assertEqual(result['issues'][1]['description'], 'Unknown issue')

    def test_validate_results_preserves_existing(self):
        scanner = BaseScanner()
        result = scanner.validate_results({
            'device_info': {'type': 'PLC'},
            'issues': [{'severity': 'critical', 'description': 'Bad'}]
        })
        self.assertEqual(result['issues'][0]['severity'], 'critical')
        self.assertEqual(result['issues'][0]['description'], 'Bad')


class TestRetryOnFailure(unittest.TestCase):
    """Test retry_on_failure method."""

    def test_retry_success(self):
        scanner = BaseScanner()
        result = scanner.retry_on_failure(lambda: 42, retries=2)
        self.assertEqual(result, 42)

    def test_retry_failure_then_success(self):
        scanner = BaseScanner()
        call_count = [0]
        def flaky():
            call_count[0] += 1
            if call_count[0] < 3:
                raise Exception("fail")
            return "success"
        result = scanner.retry_on_failure(flaky, retries=3, delay=0.01)
        self.assertEqual(result, "success")
        self.assertEqual(call_count[0], 3)

    def test_retry_all_fail(self):
        scanner = BaseScanner()
        def always_fail():
            raise Exception("nope")
        result = scanner.retry_on_failure(always_fail, retries=2, delay=0.01)
        self.assertIsNone(result)

    def test_retry_zero_retries(self):
        scanner = BaseScanner()
        result = scanner.retry_on_failure(lambda: "ok", retries=0)
        self.assertEqual(result, "ok")


class TestCreateIssueWithCVSS(unittest.TestCase):
    """Test create_issue auto-CVSS attachment."""

    def test_create_issue_auto_cvss(self):
        scanner = BaseScanner()
        issue = scanner.create_issue('critical', 'Unauthenticated access detected')
        self.assertEqual(issue['severity'], 'critical')
        self.assertEqual(issue['description'], 'Unauthenticated access detected')
        # CVSS module should attach score
        if 'cvss_score' in issue:
            self.assertGreaterEqual(issue['cvss_score'], 9.0)
            self.assertIn('cvss_vector', issue)

    def test_create_issue_explicit_vector(self):
        scanner = BaseScanner()
        issue = scanner.create_issue(
            'high', 'Test finding',
            cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
        )
        if 'cvss_score' in issue:
            self.assertEqual(issue['cvss_score'], 7.5)

    def test_create_issue_has_timestamp(self):
        scanner = BaseScanner()
        issue = scanner.create_issue('info', 'Test')
        self.assertIn('timestamp', issue)


class TestScanTimer(unittest.TestCase):
    """Test scan timing helpers."""

    def test_scan_timer(self):
        import time
        scanner = BaseScanner()
        scanner.start_scan_timer()
        time.sleep(0.01)
        duration = scanner.stop_scan_timer()
        self.assertIsNotNone(duration)
        self.assertGreater(duration, 0)

    def test_get_scan_duration(self):
        scanner = BaseScanner()
        self.assertIsNone(scanner.get_scan_duration())
        scanner.start_scan_timer()
        scanner.stop_scan_timer()
        self.assertIsNotNone(scanner.get_scan_duration())


class TestBanner(unittest.TestCase):
    """Test banner generation."""

    def test_mottasec_banner(self):
        scanner = BaseScanner()
        banner = scanner.mottasec_banner()
        self.assertIn('MottaSec ICS Ninja Scanner', banner)
        self.assertIn('BaseScanner', banner)


if __name__ == '__main__':
    unittest.main() 