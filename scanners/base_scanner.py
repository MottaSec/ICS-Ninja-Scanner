#!/usr/bin/env python3
"""
Base scanner class for ICS protocol scanners.
All protocol-specific scanners should inherit from this class.

ICS Ninja Scanner - Open source industrial control system security scanner.
"""

import logging
import time
import socket
from datetime import datetime


class BaseScanner:
    """
    Base scanner class that provides common functionality for all protocol scanners.

    ICS Ninja Scanner - Core component for all protocol-specific scanners.
    """

    # Severity constants — use these instead of magic strings
    SEVERITY_CRITICAL = 'critical'
    SEVERITY_HIGH = 'high'
    SEVERITY_MEDIUM = 'medium'
    SEVERITY_LOW = 'low'
    SEVERITY_INFO = 'info'

    def __init__(self, intensity='low', timeout=5, verify=True, request_delay=0.0):
        """
        Initialize the scanner.

        Args:
            intensity (str): Scan intensity level ('low', 'medium', 'high')
            timeout (int): Connection timeout in seconds
            verify (bool): Whether to verify SSL/TLS certificates
            request_delay (float): Seconds to wait between operations (rate limiting).
                                   Default 0.0 for backward compatibility.
        """
        self.intensity = intensity
        self.timeout = timeout
        self.verify = verify
        self.request_delay = request_delay
        self.name = self.__class__.__name__
        self.standard_ports = []
        self.scan_start_time = None
        self.scan_end_time = None
        self._abort = False

        # Setup logging
        self.logger = logging.getLogger(f"ICSNinja.{self.name}")

    # ------------------------------------------------------------------
    # Core scan interface (must be overridden by subclasses)
    # ------------------------------------------------------------------

    def scan(self, target, open_ports=None):
        """
        Scan a target for the specific protocol.
        This method should be overridden by subclasses.

        Args:
            target (str): Target IP address
            open_ports (list): List of open ports (optional)

        Returns:
            dict: Scan results with the following format:
                {
                    'device_info': {
                        'type': 'Device type',
                        'version': 'Version info',
                        'other_key': 'other_value'
                    },
                    'issues': [
                        {
                            'severity': 'critical|high|medium|low|info',
                            'description': 'Issue description',
                            'details': 'Additional details',
                            'remediation': 'How to fix'
                        }
                    ]
                }
        """
        raise NotImplementedError("Subclasses must implement the scan method")

    # ------------------------------------------------------------------
    # Network helpers
    # ------------------------------------------------------------------

    def check_port_open(self, target, port):
        """
        Check if a specific port is open on the target.

        Args:
            target (str): Target IP address
            port (int): Port number to check

        Returns:
            bool: True if port is open, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except Exception as e:
            self.logger.debug(f"Port check error: {str(e)}")
            return False

    # ------------------------------------------------------------------
    # Issue / result helpers
    # ------------------------------------------------------------------

    def create_issue(self, severity, description, details=None, remediation=None, cvss_vector=None):
        """
        Create an issue entry in a standard format.

        Args:
            severity (str): Issue severity ('critical', 'high', 'medium', 'low', 'info')
            description (str): Brief description of the issue
            details (str, optional): Detailed information about the issue
            remediation (str, optional): Guidance for fixing the issue
            cvss_vector (str, optional): Explicit CVSS 3.1 vector string.
                If provided, the score is calculated from it. Otherwise the
                description is matched against known ICS finding patterns.

        Returns:
            dict: Issue entry in standard format
        """
        issue = {
            'severity': severity,
            'description': description,
            'timestamp': datetime.now().isoformat()
        }

        if details:
            issue['details'] = details

        if remediation:
            issue['remediation'] = remediation

        # Auto-attach CVSS score
        try:
            from utils.cvss import get_cvss_for_issue, calculate_cvss_base_score

            cvss = None
            if cvss_vector:
                cvss = calculate_cvss_base_score(cvss_vector)
            else:
                cvss = get_cvss_for_issue(issue)

            if cvss:
                issue['cvss_score'] = cvss.get('score', 0.0)
                issue['cvss_vector'] = cvss.get('vector', '')
                issue['cvss_severity'] = cvss.get('severity_label', cvss.get('severity', ''))
        except ImportError:
            pass  # CVSS module not available, skip

        return issue

    def validate_results(self, results):
        """
        Validate scan results structure before returning.

        Ensures the result dict always contains 'device_info' and 'issues',
        and that every issue has at least 'severity' and 'description'.

        Args:
            results (dict | None): Raw scan results.

        Returns:
            dict | None: The validated (and possibly patched) results.
        """
        if results is None:
            return None
        if 'device_info' not in results:
            results['device_info'] = {}
        if 'issues' not in results:
            results['issues'] = []
        for issue in results['issues']:
            if 'severity' not in issue:
                issue['severity'] = self.SEVERITY_INFO
            if 'description' not in issue:
                issue['description'] = 'Unknown issue'
        return results

    # ------------------------------------------------------------------
    # Timing helpers
    # ------------------------------------------------------------------

    def start_scan_timer(self):
        """Start the scan timer to measure scan duration."""
        self.scan_start_time = time.time()

    def stop_scan_timer(self):
        """Stop the scan timer and return the duration in seconds."""
        if self.scan_start_time:
            self.scan_end_time = time.time()
            return self.scan_end_time - self.scan_start_time
        return None

    def get_scan_duration(self):
        """Get the scan duration in seconds."""
        if self.scan_start_time and self.scan_end_time:
            return self.scan_end_time - self.scan_start_time
        return None

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    def rate_limit(self):
        """
        Sleep for ``self.request_delay`` seconds (if > 0).

        Call this between successive network operations to avoid
        overwhelming fragile ICS devices.
        """
        if self.request_delay > 0:
            self._safe_sleep(self.request_delay)

    def _safe_sleep(self, seconds):
        """
        Sleep for *seconds*, but return early if the scan is aborted.

        The sleep is broken into 0.1 s slices so that an abort request
        (``self._abort = True``) is honoured promptly.
        """
        remaining = seconds
        while remaining > 0 and not self._abort:
            chunk = min(remaining, 0.1)
            time.sleep(chunk)
            remaining -= chunk

    # ------------------------------------------------------------------
    # Retry logic
    # ------------------------------------------------------------------

    def retry_on_failure(self, fn, retries=2, delay=0.5, description="operation"):
        """
        Retry an operation with configurable attempts and delay.

        Args:
            fn (callable): The operation to attempt.
            retries (int): Number of *extra* attempts after the first failure.
            delay (float): Seconds to wait between attempts.
            description (str): Label used in log messages.

        Returns:
            The return value of *fn* on success, or ``None`` after all
            attempts are exhausted.
        """
        last_error = None
        for attempt in range(retries + 1):
            try:
                return fn()
            except Exception as e:
                last_error = e
                self.logger.debug(f"{description} attempt {attempt + 1} failed: {e}")
                if attempt < retries:
                    time.sleep(delay)
        self.logger.debug(f"{description} failed after {retries + 1} attempts: {last_error}")
        return None

    # ------------------------------------------------------------------
    # Safe write-test helpers
    # ------------------------------------------------------------------

    def safe_write_test(self, read_fn, write_fn, verify_fn=None, description="write test"):
        """
        Safely test write access with automatic restore and verification.

        The pattern is: read → write test value → (optional verify) →
        restore original → (optional verify restore).

        Args:
            read_fn: callable that returns the current value.
            write_fn: callable(value) that writes a value.
            verify_fn: optional callable that returns the current value for
                       verification (defaults to *read_fn*).
            description: human-readable label for log messages.

        Returns:
            dict with keys:
                writable (bool): whether the write appeared to succeed.
                restored (bool): whether the original value was restored.
                original_value: the value that was read before testing.
                restore_warning (str | None): warning if restore failed.
        """
        if verify_fn is None:
            verify_fn = read_fn

        result = {
            'writable': False,
            'restored': False,
            'original_value': None,
            'restore_warning': None,
        }

        # 1. Read original value
        try:
            original = read_fn()
            result['original_value'] = original
        except Exception as e:
            self.logger.debug(f"{description}: failed to read original value: {e}")
            return result

        # 2. Compute a safe test value
        test_value = self._safe_test_value(original)

        # 3. Write test value
        try:
            write_fn(test_value)
        except Exception as e:
            self.logger.debug(f"{description}: write failed: {e}")
            return result

        # 4. Verify write (optional — only meaningful when test_value != original)
        try:
            current = verify_fn()
            if current == test_value:
                result['writable'] = True
            elif test_value == original:
                # We wrote the same value back; can't truly tell, assume writable
                result['writable'] = True
            else:
                self.logger.debug(f"{description}: verify after write returned unexpected value")
                result['writable'] = False
        except Exception as e:
            self.logger.debug(f"{description}: verify after write failed: {e}")
            # Write didn't raise, optimistically mark writable
            result['writable'] = True

        # 5. Restore original value
        try:
            write_fn(original)
        except Exception as e:
            warning = f"RESTORE FAILED for {description}: could not write back original value ({e})"
            self.logger.warning(warning)
            result['restore_warning'] = warning
            return result

        # 6. Verify restore
        try:
            restored_value = verify_fn()
            if restored_value == original:
                result['restored'] = True
            else:
                warning = (
                    f"RESTORE VERIFY FAILED for {description}: "
                    f"expected {original!r}, got {restored_value!r}"
                )
                self.logger.warning(warning)
                result['restore_warning'] = warning
        except Exception as e:
            warning = f"RESTORE VERIFY READ FAILED for {description}: {e}"
            self.logger.warning(warning)
            result['restore_warning'] = warning

        return result

    def _safe_test_value(self, original_value):
        """
        Generate a safe test value close to the original to minimise impact.

        For unknown types the original value is returned (safest no-op write).
        """
        if isinstance(original_value, bool):
            return not original_value
        if isinstance(original_value, int):
            return original_value + 1 if original_value < 65535 else original_value - 1
        if isinstance(original_value, float):
            return original_value + 0.1
        if isinstance(original_value, str):
            return original_value  # Write same value back (safest)
        if isinstance(original_value, (bytes, bytearray)):
            modified = bytearray(original_value)
            if len(modified) > 0:
                modified[0] = (modified[0] + 1) % 256
            return bytes(modified)
        return original_value  # Unknown type, write same value

    # ------------------------------------------------------------------
    # Banner
    # ------------------------------------------------------------------

    def mottasec_banner(self):
        """Return a MottaSec banner for the scanner."""
        return f"""
        ╔═══════════════════════════════════════════════╗
        ║  MottaSec ICS Ninja Scanner - {self.name:<15} ║
        ║  Intensity: {self.intensity:<6}  Timeout: {self.timeout}s        ║
        ╚═══════════════════════════════════════════════╝
        """
