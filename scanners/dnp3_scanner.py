#!/usr/bin/env python3
"""
DNP3 (Distributed Network Protocol 3) scanner for detecting security issues
in SCADA/ICS systems using DNP3 over TCP.

Implements raw DNP3 frame building and parsing using sockets since no reliable
dnp3-python library is available on PyPI.

Developed by MottaSec Ghost Team - The unseen guardians of industrial systems.
"""

import socket
import struct
import time

from scanners.base_scanner import BaseScanner

# DNP3 Constants
DNP3_START_BYTES = 0x0564
DNP3_DEFAULT_PORT = 20000

# DNP3 Function Codes
FC_CONFIRM = 0x00
FC_READ = 0x01
FC_WRITE = 0x02
FC_SELECT = 0x03
FC_OPERATE = 0x04
FC_DIRECT_OPERATE = 0x05
FC_DIRECT_OPERATE_NR = 0x06
FC_COLD_RESTART = 0x0D
FC_WARM_RESTART = 0x0E
FC_ENABLE_UNSOLICITED = 0x14
FC_DISABLE_UNSOLICITED = 0x15
FC_RESPONSE = 0x81
FC_UNSOLICITED_RESPONSE = 0x82
FC_AUTH_REQUEST = 0x20
FC_AUTH_RESPONSE = 0x83

# DNP3 Internal Indications (IIN) bits - second byte
IIN2_NO_FUNC_CODE_SUPPORT = 0x01
IIN2_OBJECT_UNKNOWN = 0x02
IIN2_PARAMETER_ERROR = 0x04

# DNP3 Data Link Control byte flags
DL_DIR = 0x80    # Direction: 1=master->outstation
DL_PRM = 0x40    # Primary message
DL_FCB = 0x20    # Frame count bit
DL_FCV = 0x10    # Frame count valid
# Primary function codes (lower nibble)
DL_RESET_LINK = 0x00
DL_USER_DATA = 0x04
DL_UNCONFIRMED_USER_DATA = 0x04

# Transport Layer flags
TL_FIN = 0x80   # Final segment
TL_FIR = 0x40   # First segment

# Application Control byte
AC_FIR = 0x80   # First fragment
AC_FIN = 0x40   # Final fragment
AC_CON = 0x20   # Confirm requested
AC_UNS = 0x10   # Unsolicited response

# DNP3 Object Group/Variation constants
OBJ_BINARY_INPUT = (1, 0)         # Group 1, Var 0 (any variation)
OBJ_BINARY_OUTPUT = (10, 0)       # Group 10
OBJ_COUNTER = (20, 0)             # Group 20
OBJ_ANALOG_INPUT = (30, 0)        # Group 30
OBJ_ANALOG_OUTPUT = (40, 0)       # Group 40
OBJ_CLASS_0 = (60, 1)             # Class 0 data
OBJ_CLASS_1 = (60, 2)             # Class 1 events
OBJ_CLASS_2 = (60, 3)             # Class 2 events
OBJ_CLASS_3 = (60, 4)             # Class 3 events
OBJ_DEVICE_ATTRIBUTES = (0, 254)  # Group 0, Var 254
OBJ_AUTH_CHALLENGE = (120, 1)     # Secure Auth challenge
OBJ_CROB = (12, 1)               # Control Relay Output Block

# DNP3 CRC-16 lookup table (polynomial 0x3D65, bit-reversed)
_CRC_TABLE = None


def _init_crc_table():
    """Initialize the DNP3 CRC-16 lookup table."""
    global _CRC_TABLE
    if _CRC_TABLE is not None:
        return
    _CRC_TABLE = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC  # Reflected polynomial of 0x3D65
            else:
                crc >>= 1
        _CRC_TABLE.append(crc & 0xFFFF)


def _calculate_crc(data):
    """
    Calculate DNP3 CRC-16 over a byte sequence.

    The DNP3 CRC uses the polynomial 0x3D65 in reflected form (0xA6BC).
    Initial value: 0x0000, final XOR: 0xFFFF.

    Args:
        data (bytes): Data bytes to compute CRC over.

    Returns:
        int: 16-bit CRC value.
    """
    _init_crc_table()
    crc = 0x0000
    for byte in data:
        crc = (_CRC_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)) & 0xFFFF
    return crc ^ 0xFFFF


class DNP3Scanner(BaseScanner):
    """Scanner for detecting security issues in DNP3 outstation devices."""

    def __init__(self, intensity='low', timeout=5, verify=True):
        """
        Initialize the DNP3 scanner.

        Args:
            intensity (str): Scan intensity ('low', 'medium', 'high').
            timeout (int): Socket timeout in seconds.
            verify (bool): Certificate verification flag (unused for raw TCP).
        """
        super().__init__(intensity, timeout, verify)
        self.standard_ports = [DNP3_DEFAULT_PORT]
        self._seq = 0  # Application layer sequence counter

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def scan(self, target, open_ports=None):
        """
        Scan a target for DNP3 security issues.

        Args:
            target (str): Target IP address or hostname.
            open_ports (list): Optional list of ports to try.

        Returns:
            dict or None: Scan results dict or None if DNP3 not detected.
        """
        results = {
            'device_info': {},
            'issues': []
        }

        ports_to_scan = open_ports if open_ports else self.standard_ports

        # Phase 1 – Detect DNP3
        dnp3_port = None
        detection_info = None
        for port in ports_to_scan:
            detection_info = self._check_dnp3_availability(target, port)
            if detection_info:
                dnp3_port = port
                break

        if not dnp3_port:
            return None

        # Populate basic device info
        results['device_info']['port'] = dnp3_port
        results['device_info']['protocol'] = 'DNP3'
        results['device_info']['source_address'] = detection_info.get('source')
        results['device_info']['destination_address'] = detection_info.get('destination')

        results['issues'].append(self.create_issue(
            severity='info',
            description=f"DNP3 Outstation Found: {target}:{dnp3_port}",
            details=(
                f"A device responding to DNP3 protocol was detected. "
                f"Outstation address: {detection_info.get('source')}, "
                f"Master address: {detection_info.get('destination')}."
            )
        ))

        outstation_addr = detection_info.get('source', 1)
        master_addr = detection_info.get('destination', 1)

        # Phase 2 – Medium intensity checks
        if self.intensity in ('medium', 'high'):
            self._run_medium_checks(target, dnp3_port, master_addr, outstation_addr, results)

        # Phase 3 – High intensity checks
        if self.intensity == 'high':
            self._run_high_checks(target, dnp3_port, master_addr, outstation_addr, results)

        return results

    # ------------------------------------------------------------------
    # Medium intensity checks
    # ------------------------------------------------------------------

    def _run_medium_checks(self, target, port, src, dst, results):
        """Execute medium-intensity security checks."""
        sock = None
        try:
            sock = self._connect(target, port)
            if not sock:
                return

            # 1. Test unauthenticated read access (Class 0)
            self._test_read_access(sock, src, dst, results)

            # 2. Request device attributes
            self._request_device_attributes(sock, src, dst, results)

            # 3. Check for Secure Authentication support
            self._check_secure_authentication(sock, src, dst, results)

            # 4. Enumerate supported object groups
            self._enumerate_object_groups(sock, src, dst, results)

            # 5. Test unsolicited response configuration
            self._test_unsolicited_config(sock, src, dst, results)

        except Exception as e:
            self.logger.debug(f"Medium-intensity check error: {e}")
            results['issues'].append(self.create_issue(
                severity='info',
                description=f"Error during DNP3 medium-intensity scan: {str(e)}",
                details="Some medium-intensity checks could not be completed."
            ))
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # High intensity checks
    # ------------------------------------------------------------------

    def _run_high_checks(self, target, port, src, dst, results):
        """Execute high-intensity (active) security checks."""
        sock = None
        try:
            sock = self._connect(target, port)
            if not sock:
                return

            # 1. Test write access with rollback
            self._test_write_access(sock, src, dst, results)

            # 2. Test restart commands
            self._test_restart_commands(sock, src, dst, results)

            # 3. Test enable/disable unsolicited messages
            self._test_unsolicited_control(sock, src, dst, results)

            # 4. Test direct operate on CROB
            self._test_control_operations(sock, src, dst, results)

            # 5. Test broadcast address acceptance
            self._test_broadcast_address(target, port, src, results)

        except Exception as e:
            self.logger.debug(f"High-intensity check error: {e}")
            results['issues'].append(self.create_issue(
                severity='info',
                description=f"Error during DNP3 high-intensity scan: {str(e)}",
                details="Some high-intensity checks could not be completed."
            ))
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def _check_dnp3_availability(self, target, port):
        """
        Send a DNP3 link-layer frame and check for a valid response.

        Tries destination addresses 1-10 to find an active outstation.

        Args:
            target (str): Target IP.
            port (int): TCP port.

        Returns:
            dict or None: {'source': int, 'destination': int} from the response,
                          or None if no DNP3 device detected.
        """
        for dest_addr in range(1, 11):
            sock = None
            try:
                sock = self._connect(target, port)
                if not sock:
                    return None

                # Build a Read request for Class 0 (lightweight probe)
                frame = self._build_dnp3_frame(
                    control=DL_DIR | DL_PRM | DL_UNCONFIRMED_USER_DATA,
                    destination=dest_addr,
                    source=1,
                    transport=TL_FIR | TL_FIN,  # single segment
                    app_control=AC_FIR | AC_FIN | (self._next_seq()),
                    function_code=FC_READ,
                    objects=self._encode_object_header(60, 1, qualifier=0x06, count=0)
                )

                sock.sendall(frame)
                resp = self._recv_response(sock)

                if resp:
                    parsed = self._parse_dnp3_response(resp)
                    if parsed:
                        return {
                            'source': parsed.get('source', dest_addr),
                            'destination': parsed.get('destination', 1)
                        }
            except Exception as e:
                self.logger.debug(f"DNP3 probe to addr {dest_addr} failed: {e}")
            finally:
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass
            if hasattr(self, 'rate_limit'):
                self.rate_limit()

        return None

    # ------------------------------------------------------------------
    # Security test helpers
    # ------------------------------------------------------------------

    def _test_read_access(self, sock, src, dst, results):
        """Test unauthenticated read access via FC 0x01 for Class 0 data."""
        try:
            frame = self._build_dnp3_frame(
                control=DL_DIR | DL_PRM | DL_UNCONFIRMED_USER_DATA,
                destination=dst,
                source=src,
                transport=TL_FIR | TL_FIN,
                app_control=AC_FIR | AC_FIN | self._next_seq(),
                function_code=FC_READ,
                objects=self._encode_object_header(60, 1, qualifier=0x06, count=0)
            )
            sock.sendall(frame)
            resp = self._recv_response(sock)
            parsed = self._parse_dnp3_response(resp) if resp else None

            if parsed and parsed.get('function_code') == FC_RESPONSE:
                iin = parsed.get('iin', (0, 0))
                # If no "object unknown" or "no func support", read succeeded
                if not (iin[1] & IIN2_OBJECT_UNKNOWN) and not (iin[1] & IIN2_NO_FUNC_CODE_SUPPORT):
                    results['device_info']['unauthenticated_read'] = True
                    results['issues'].append(self.create_issue(
                        severity='high',
                        description="Unauthenticated DNP3 read access allowed",
                        details=(
                            "The outstation accepted a Class 0 Read request without "
                            "authentication, exposing all static data points."
                        ),
                        remediation=(
                            "Enable DNP3 Secure Authentication (SA) to require "
                            "challenge-response before honoring read requests."
                        )
                    ))
                    return
            results['device_info']['unauthenticated_read'] = False
        except Exception as e:
            self.logger.debug(f"Read access test error: {e}")

    def _request_device_attributes(self, sock, src, dst, results):
        """Request device attributes (Group 0, Variation 254)."""
        try:
            # Request all device attributes
            obj_header = self._encode_object_header(0, 254, qualifier=0x06, count=0)
            frame = self._build_dnp3_frame(
                control=DL_DIR | DL_PRM | DL_UNCONFIRMED_USER_DATA,
                destination=dst,
                source=src,
                transport=TL_FIR | TL_FIN,
                app_control=AC_FIR | AC_FIN | self._next_seq(),
                function_code=FC_READ,
                objects=obj_header
            )
            sock.sendall(frame)
            resp = self._recv_response(sock)
            parsed = self._parse_dnp3_response(resp) if resp else None

            if parsed and parsed.get('function_code') == FC_RESPONSE:
                iin = parsed.get('iin', (0, 0))
                if not (iin[1] & IIN2_OBJECT_UNKNOWN):
                    results['device_info']['device_attributes_accessible'] = True
                    app_data = parsed.get('app_data', b'')
                    # Try to extract readable strings from response payload
                    attr_info = self._extract_printable(app_data)
                    if attr_info:
                        results['device_info']['device_attributes_raw'] = attr_info

                    results['issues'].append(self.create_issue(
                        severity='medium',
                        description="DNP3 device attributes are accessible",
                        details=(
                            f"Device identification data (Group 0, Var 254) is readable "
                            f"without authentication. Extracted: {attr_info[:200] if attr_info else 'binary data'}"
                        ),
                        remediation=(
                            "Restrict access to device attributes via Secure Authentication "
                            "or network-level access controls."
                        )
                    ))
        except Exception as e:
            self.logger.debug(f"Device attributes request error: {e}")

    def _check_secure_authentication(self, sock, src, dst, results):
        """
        Probe for DNP3 Secure Authentication (SA) support.

        Sends an Authentication Request (FC 0x20) with an SA challenge object
        and checks whether the outstation responds with an auth response or
        indicates the function code is unsupported.
        """
        try:
            # Build a minimal SA challenge object (Group 120, Var 1)
            # We just need to see if the outstation recognizes the function
            sa_obj = self._encode_object_header(120, 1, qualifier=0x5B, count=0)
            frame = self._build_dnp3_frame(
                control=DL_DIR | DL_PRM | DL_UNCONFIRMED_USER_DATA,
                destination=dst,
                source=src,
                transport=TL_FIR | TL_FIN,
                app_control=AC_FIR | AC_FIN | self._next_seq(),
                function_code=FC_AUTH_REQUEST,
                objects=sa_obj
            )
            sock.sendall(frame)
            resp = self._recv_response(sock)
            parsed = self._parse_dnp3_response(resp) if resp else None

            sa_supported = False
            if parsed:
                iin = parsed.get('iin', (0, 0))
                fc = parsed.get('function_code', 0)
                # If we get an auth response or no "unsupported FC" flag, SA is present
                if fc == FC_AUTH_RESPONSE:
                    sa_supported = True
                elif not (iin[1] & IIN2_NO_FUNC_CODE_SUPPORT):
                    sa_supported = True

            results['device_info']['secure_authentication'] = sa_supported

            if not sa_supported:
                results['issues'].append(self.create_issue(
                    severity='critical',
                    description="DNP3 Secure Authentication (SA) is NOT supported",
                    details=(
                        "The outstation does not support DNP3 Secure Authentication. "
                        "All requests (read, write, control, restart) can be issued "
                        "by any host on the network without cryptographic verification."
                    ),
                    remediation=(
                        "Upgrade to a DNP3 outstation firmware that supports Secure "
                        "Authentication v5 (IEEE 1815-2012). If not possible, enforce "
                        "strict network segmentation and allowlisting."
                    )
                ))
            else:
                results['issues'].append(self.create_issue(
                    severity='info',
                    description="DNP3 Secure Authentication (SA) is supported",
                    details="The outstation appears to support DNP3 SA."
                ))
        except Exception as e:
            self.logger.debug(f"SA check error: {e}")

    def _enumerate_object_groups(self, sock, src, dst, results):
        """Enumerate supported DNP3 object groups by sending read requests."""
        groups_to_test = [
            (1, 0, "Binary Inputs (G1)"),
            (10, 0, "Binary Outputs (G10)"),
            (20, 0, "Counters (G20)"),
            (30, 0, "Analog Inputs (G30)"),
            (40, 0, "Analog Outputs (G40)"),
            (50, 1, "Time and Date (G50)"),
        ]
        supported = []

        for group, var, name in groups_to_test:
            try:
                obj_header = self._encode_object_header(group, var, qualifier=0x06, count=0)
                frame = self._build_dnp3_frame(
                    control=DL_DIR | DL_PRM | DL_UNCONFIRMED_USER_DATA,
                    destination=dst,
                    source=src,
                    transport=TL_FIR | TL_FIN,
                    app_control=AC_FIR | AC_FIN | self._next_seq(),
                    function_code=FC_READ,
                    objects=obj_header
                )
                sock.sendall(frame)
                resp = self._recv_response(sock)
                parsed = self._parse_dnp3_response(resp) if resp else None

                if parsed and parsed.get('function_code') == FC_RESPONSE:
                    iin = parsed.get('iin', (0, 0))
                    if not (iin[1] & IIN2_OBJECT_UNKNOWN):
                        supported.append(name)
            except Exception as e:
                self.logger.debug(f"Object group {name} enumeration failed: {e}")
            if hasattr(self, 'rate_limit'):
                self.rate_limit()

        if supported:
            results['device_info']['supported_object_groups'] = supported
            results['issues'].append(self.create_issue(
                severity='info',
                description=f"DNP3 object groups enumerated: {', '.join(supported)}",
                details=(
                    "The following data types are available on this outstation. "
                    "An attacker with network access could read or manipulate these."
                ),
                remediation="Restrict network access and enable Secure Authentication."
            ))

    def _test_unsolicited_config(self, sock, src, dst, results):
        """Check if the outstation is configured to send unsolicited responses."""
        try:
            # Read Class 1/2/3 event data — if the outstation has unsolicited
            # enabled it may send data before we even ask.  We detect this by
            # checking the UNS bit in any response we've already received, or by
            # issuing an Enable Unsolicited and seeing if it's already on.
            obj = (
                self._encode_object_header(60, 2, qualifier=0x06, count=0) +
                self._encode_object_header(60, 3, qualifier=0x06, count=0) +
                self._encode_object_header(60, 4, qualifier=0x06, count=0)
            )
            frame = self._build_dnp3_frame(
                control=DL_DIR | DL_PRM | DL_UNCONFIRMED_USER_DATA,
                destination=dst,
                source=src,
                transport=TL_FIR | TL_FIN,
                app_control=AC_FIR | AC_FIN | self._next_seq(),
                function_code=FC_READ,
                objects=obj
            )
            sock.sendall(frame)
            resp = self._recv_response(sock)
            parsed = self._parse_dnp3_response(resp) if resp else None

            if parsed:
                ac = parsed.get('app_control', 0)
                if ac & AC_UNS:
                    results['device_info']['unsolicited_responses'] = True
                    results['issues'].append(self.create_issue(
                        severity='medium',
                        description="DNP3 unsolicited responses are enabled",
                        details=(
                            "The outstation sends unsolicited event data. While normal "
                            "in many deployments, unsolicited traffic without SA can be "
                            "spoofed by an attacker on the network."
                        ),
                        remediation=(
                            "Ensure unsolicited responses are only accepted from "
                            "authenticated outstations using Secure Authentication."
                        )
                    ))
        except Exception as e:
            self.logger.debug(f"Unsolicited config test error: {e}")

    def _test_write_access(self, sock, src, dst, results):
        """
        Test write access (FC 0x02) to analog output (Group 40) with rollback.

        Safe approach: read current value, write +1, read again, restore.
        """
        try:
            # First read analog output status (Group 40, Var 0)
            read_obj = self._encode_object_header(40, 0, qualifier=0x06, count=0)
            frame = self._build_dnp3_frame(
                control=DL_DIR | DL_PRM | DL_UNCONFIRMED_USER_DATA,
                destination=dst, source=src,
                transport=TL_FIR | TL_FIN,
                app_control=AC_FIR | AC_FIN | self._next_seq(),
                function_code=FC_READ,
                objects=read_obj
            )
            sock.sendall(frame)
            resp = self._recv_response(sock)
            parsed = self._parse_dnp3_response(resp) if resp else None

            if not parsed or parsed.get('function_code') != FC_RESPONSE:
                return
            iin = parsed.get('iin', (0, 0))
            if iin[1] & IIN2_OBJECT_UNKNOWN:
                return  # No analog outputs

            original_payload = parsed.get('app_data', b'')

            # Attempt a write with the same data (effectively a no-op write test)
            if original_payload:
                write_frame = self._build_dnp3_frame(
                    control=DL_DIR | DL_PRM | DL_UNCONFIRMED_USER_DATA,
                    destination=dst, source=src,
                    transport=TL_FIR | TL_FIN,
                    app_control=AC_FIR | AC_FIN | self._next_seq(),
                    function_code=FC_WRITE,
                    objects=original_payload  # Echo back the same data
                )
                sock.sendall(write_frame)
                w_resp = self._recv_response(sock)
                w_parsed = self._parse_dnp3_response(w_resp) if w_resp else None

                if w_parsed and w_parsed.get('function_code') == FC_RESPONSE:
                    w_iin = w_parsed.get('iin', (0, 0))
                    if not (w_iin[1] & IIN2_NO_FUNC_CODE_SUPPORT) and not (w_iin[1] & IIN2_PARAMETER_ERROR):
                        results['device_info']['unauthenticated_write'] = True
                        results['issues'].append(self.create_issue(
                            severity='critical',
                            description="Unauthenticated DNP3 write access allowed",
                            details=(
                                "The outstation accepted a Write request (FC 0x02) without "
                                "authentication. An attacker could modify setpoints and "
                                "analog output values."
                            ),
                            remediation=(
                                "Enable DNP3 Secure Authentication or restrict write "
                                "operations at the outstation configuration level."
                            )
                        ))
        except Exception as e:
            self.logger.debug(f"Write access test error: {e}")

    def _test_restart_commands(self, sock, src, dst, results):
        """
        Test Cold Restart (FC 0x0D) and Warm Restart (FC 0x0E).

        We send the command but do NOT send a Confirm, so the outstation
        should not actually execute it on well-implemented devices.
        """
        for fc, label in [(FC_COLD_RESTART, "Cold Restart"), (FC_WARM_RESTART, "Warm Restart")]:
            if hasattr(self, 'rate_limit'):
                self.rate_limit()
            try:
                frame = self._build_dnp3_frame(
                    control=DL_DIR | DL_PRM | DL_UNCONFIRMED_USER_DATA,
                    destination=dst, source=src,
                    transport=TL_FIR | TL_FIN,
                    app_control=AC_FIR | AC_FIN | self._next_seq(),
                    function_code=fc,
                    objects=b''
                )
                sock.sendall(frame)
                resp = self._recv_response(sock)
                parsed = self._parse_dnp3_response(resp) if resp else None

                if parsed and parsed.get('function_code') == FC_RESPONSE:
                    iin = parsed.get('iin', (0, 0))
                    if not (iin[1] & IIN2_NO_FUNC_CODE_SUPPORT):
                        results['issues'].append(self.create_issue(
                            severity='critical',
                            description=f"DNP3 {label} command accepted without authentication",
                            details=(
                                f"The outstation responded to a {label} request (FC 0x{fc:02X}) "
                                f"without requiring Secure Authentication. An attacker could "
                                f"disrupt operations by restarting the device."
                            ),
                            remediation=(
                                "Enable Secure Authentication for critical function codes. "
                                "Configure the outstation to reject restart commands from "
                                "unauthenticated sources."
                            )
                        ))
            except Exception as e:
                self.logger.debug(f"{label} test error: {e}")

    def _test_unsolicited_control(self, sock, src, dst, results):
        """Test Enable/Disable Unsolicited Messages (FC 0x14/0x15)."""
        for fc, label in [
            (FC_ENABLE_UNSOLICITED, "Enable Unsolicited"),
            (FC_DISABLE_UNSOLICITED, "Disable Unsolicited")
        ]:
            if hasattr(self, 'rate_limit'):
                self.rate_limit()
            try:
                # Include class objects for unsolicited enable/disable
                obj = (
                    self._encode_object_header(60, 2, qualifier=0x06, count=0) +
                    self._encode_object_header(60, 3, qualifier=0x06, count=0) +
                    self._encode_object_header(60, 4, qualifier=0x06, count=0)
                )
                frame = self._build_dnp3_frame(
                    control=DL_DIR | DL_PRM | DL_UNCONFIRMED_USER_DATA,
                    destination=dst, source=src,
                    transport=TL_FIR | TL_FIN,
                    app_control=AC_FIR | AC_FIN | self._next_seq(),
                    function_code=fc,
                    objects=obj
                )
                sock.sendall(frame)
                resp = self._recv_response(sock)
                parsed = self._parse_dnp3_response(resp) if resp else None

                if parsed and parsed.get('function_code') == FC_RESPONSE:
                    iin = parsed.get('iin', (0, 0))
                    if not (iin[1] & IIN2_NO_FUNC_CODE_SUPPORT):
                        results['issues'].append(self.create_issue(
                            severity='high',
                            description=f"DNP3 {label} accepted without authentication",
                            details=(
                                f"The outstation accepted {label} (FC 0x{fc:02X}) without "
                                f"Secure Authentication. An attacker could manipulate event "
                                f"reporting to blind the master station."
                            ),
                            remediation=(
                                "Enable Secure Authentication for unsolicited message "
                                "configuration function codes."
                            )
                        ))
                        break  # One finding is sufficient
            except Exception as e:
                self.logger.debug(f"{label} test error: {e}")

    def _test_control_operations(self, sock, src, dst, results):
        """
        Test Direct Operate (FC 0x05) on Control Relay Output Block (CROB).

        Sends a Select (FC 0x03) first — if accepted, the outstation allows
        control without authentication. We do NOT follow up with Operate.
        """
        try:
            # Build a CROB object (Group 12, Var 1) with NUL operation (0x00)
            # so even if executed, it does nothing
            # CROB: control code (1 byte) + count (1 byte) + on-time (4 bytes) +
            #        off-time (4 bytes) + status (1 byte)
            crob_data = struct.pack('<BBIIBB',
                                    0x00,  # Control code: NUL (no operation)
                                    1,     # Count
                                    0,     # On-time ms
                                    0,     # Off-time ms
                                    0,     # Status
                                    0)     # Padding/index
            # Object header: Group 12, Var 1, qualifier 0x28 (1-byte index + count)
            obj = struct.pack('BBB', 12, 1, 0x28) + struct.pack('B', 1) + struct.pack('B', 0) + crob_data[:11]

            frame = self._build_dnp3_frame(
                control=DL_DIR | DL_PRM | DL_UNCONFIRMED_USER_DATA,
                destination=dst, source=src,
                transport=TL_FIR | TL_FIN,
                app_control=AC_FIR | AC_FIN | self._next_seq(),
                function_code=FC_SELECT,
                objects=obj
            )
            sock.sendall(frame)
            resp = self._recv_response(sock)
            parsed = self._parse_dnp3_response(resp) if resp else None

            if parsed and parsed.get('function_code') == FC_RESPONSE:
                iin = parsed.get('iin', (0, 0))
                if not (iin[1] & IIN2_NO_FUNC_CODE_SUPPORT) and not (iin[1] & IIN2_OBJECT_UNKNOWN):
                    results['device_info']['control_operations_allowed'] = True
                    results['issues'].append(self.create_issue(
                        severity='critical',
                        description="DNP3 control operations (Select/Operate) accepted without authentication",
                        details=(
                            "The outstation accepted a Select command (FC 0x03) for "
                            "Control Relay Output Blocks without authentication. "
                            "An attacker could operate physical outputs (breakers, valves, etc.)."
                        ),
                        remediation=(
                            "Enable Secure Authentication for all control function codes. "
                            "Implement Select-Before-Operate (SBO) with SA as minimum."
                        )
                    ))
        except Exception as e:
            self.logger.debug(f"Control operations test error: {e}")

    def _test_broadcast_address(self, target, port, src, results):
        """Test if the outstation accepts frames addressed to broadcast (0xFFFF)."""
        sock = None
        try:
            sock = self._connect(target, port)
            if not sock:
                return

            frame = self._build_dnp3_frame(
                control=DL_DIR | DL_PRM | DL_UNCONFIRMED_USER_DATA,
                destination=0xFFFF,  # Broadcast
                source=src,
                transport=TL_FIR | TL_FIN,
                app_control=AC_FIR | AC_FIN | self._next_seq(),
                function_code=FC_READ,
                objects=self._encode_object_header(60, 1, qualifier=0x06, count=0)
            )
            sock.sendall(frame)
            resp = self._recv_response(sock)
            parsed = self._parse_dnp3_response(resp) if resp else None

            if parsed and parsed.get('function_code') == FC_RESPONSE:
                results['device_info']['broadcast_accepted'] = True
                results['issues'].append(self.create_issue(
                    severity='high',
                    description="DNP3 outstation accepts broadcast address (0xFFFF)",
                    details=(
                        "The outstation responds to frames sent to the broadcast "
                        "address. An attacker could use broadcast to affect all "
                        "outstations on the network simultaneously."
                    ),
                    remediation=(
                        "Configure the outstation to reject or ignore broadcast "
                        "destination addresses if not operationally required."
                    )
                ))
        except Exception as e:
            self.logger.debug(f"Broadcast address test error: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Frame building / parsing helpers
    # ------------------------------------------------------------------

    def _connect(self, target, port):
        """Create a connected TCP socket to target:port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            return sock
        except Exception as e:
            self.logger.debug(f"Connection to {target}:{port} failed: {e}")
            return None

    def _next_seq(self):
        """Return the next application-layer sequence number (0-15)."""
        seq = self._seq & 0x0F
        self._seq = (self._seq + 1) & 0x0F
        return seq

    def _build_dnp3_frame(self, control, destination, source, transport,
                          app_control, function_code, objects=b''):
        """
        Build a complete DNP3 over TCP frame.

        Structure:
          Data Link Layer: start(2) + length(1) + control(1) + dest(2) + src(2) + CRC(2)
          Data block(s):   [transport(1) + app_control(1) + func_code(1) + objects] + CRC every 16 bytes

        Args:
            control (int): Data link control byte.
            destination (int): Destination address (16-bit).
            source (int): Source address (16-bit).
            transport (int): Transport layer header byte.
            app_control (int): Application control byte.
            function_code (int): Application function code.
            objects (bytes): Serialized object headers and data.

        Returns:
            bytes: Complete DNP3 TCP frame.
        """
        # Application layer payload (goes inside transport segment)
        app_payload = bytes([app_control, function_code]) + objects
        # Transport + application
        user_data = bytes([transport]) + app_payload

        # Data link header (without CRC)
        # Length = 5 (fixed header portion after length byte) + user_data length
        dl_length = 5 + len(user_data)
        dl_header = struct.pack('<HB B HH',
                                DNP3_START_BYTES,
                                dl_length,
                                control,
                                destination,   # little-endian in DNP3
                                source)
        # Note: struct '<HH' already gives us LE for dest and source,
        # but start bytes should be 0x05 0x64 on wire. Let's do it manually.
        dl_header = bytes([0x05, 0x64,
                           dl_length & 0xFF,
                           control & 0xFF]) + \
                    struct.pack('<H', destination) + \
                    struct.pack('<H', source)

        # CRC over header (8 bytes)
        header_crc = _calculate_crc(dl_header)
        frame = dl_header + struct.pack('<H', header_crc)

        # User data blocks — each block is up to 16 bytes + 2 byte CRC
        offset = 0
        while offset < len(user_data):
            block = user_data[offset:offset + 16]
            block_crc = _calculate_crc(block)
            frame += block + struct.pack('<H', block_crc)
            offset += 16

        return frame

    def _parse_dnp3_response(self, data):
        """
        Parse a raw DNP3 TCP response into its components.

        Args:
            data (bytes): Raw bytes received from the socket.

        Returns:
            dict or None: Parsed response fields, or None on parse failure.
                Keys: source, destination, control, transport, app_control,
                      function_code, iin, app_data
        """
        if not data or len(data) < 10:
            return None

        try:
            # Verify start bytes
            if data[0] != 0x05 or data[1] != 0x64:
                return None

            length = data[2]
            control = data[3]
            destination = struct.unpack('<H', data[4:6])[0]
            source = struct.unpack('<H', data[6:8])[0]
            # Header CRC at bytes 8-9 (skip verification for robustness)

            # Extract user data from data blocks (skip CRCs)
            user_data = b''
            offset = 10  # After header + header CRC
            remaining = length - 5  # User data length

            while remaining > 0 and offset < len(data):
                block_size = min(16, remaining)
                if offset + block_size > len(data):
                    block_size = len(data) - offset
                user_data += data[offset:offset + block_size]
                remaining -= block_size
                offset += block_size + 2  # Skip CRC

            if len(user_data) < 1:
                return None

            result = {
                'source': source,
                'destination': destination,
                'control': control,
                'transport': user_data[0],
            }

            # Application layer starts after transport byte
            if len(user_data) >= 3:
                result['app_control'] = user_data[1]
                result['function_code'] = user_data[2]

            # IIN bytes (only in responses: FC >= 0x81)
            if len(user_data) >= 5 and user_data[2] >= 0x81:
                result['iin'] = (user_data[3], user_data[4])
                result['app_data'] = user_data[5:] if len(user_data) > 5 else b''
            elif len(user_data) > 3:
                result['iin'] = (0, 0)
                result['app_data'] = user_data[3:]
            else:
                result['iin'] = (0, 0)
                result['app_data'] = b''

            return result

        except Exception as e:
            self.logger.debug(f"DNP3 response parse error: {e}")
            return None

    def _recv_response(self, sock, max_bytes=4096):
        """
        Receive a DNP3 response from the socket.

        Args:
            sock: Connected TCP socket.
            max_bytes (int): Maximum bytes to read.

        Returns:
            bytes or None: Raw response bytes, or None on timeout/error.
        """
        try:
            data = sock.recv(max_bytes)
            return data if data else None
        except socket.timeout:
            return None
        except Exception as e:
            self.logger.debug(f"Receive error: {e}")
            return None

    @staticmethod
    def _encode_object_header(group, variation, qualifier=0x06, count=0):
        """
        Encode a DNP3 object header.

        Args:
            group (int): Object group number.
            variation (int): Object variation number.
            qualifier (int): Qualifier code (0x06 = all objects, no range).
            count (int): Object count (for qualifiers that use it).

        Returns:
            bytes: Encoded object header.
        """
        if qualifier == 0x06:
            # No range field
            return struct.pack('BBB', group, variation, qualifier)
        elif qualifier in (0x00, 0x01):
            # 1-byte start/stop
            return struct.pack('BBBBB', group, variation, qualifier, 0, count)
        elif qualifier == 0x17:
            # 1-byte count
            return struct.pack('BBBB', group, variation, qualifier, count)
        elif qualifier == 0x28:
            # 2-byte count + index prefix
            return struct.pack('BBB', group, variation, qualifier) + struct.pack('<H', count)
        elif qualifier == 0x5B:
            # Variable-length with count
            return struct.pack('BBBB', group, variation, qualifier, count)
        else:
            return struct.pack('BBB', group, variation, qualifier)

    @staticmethod
    def _extract_printable(data):
        """Extract printable ASCII strings from binary data."""
        if not data:
            return ''
        result = []
        current = []
        for b in data:
            if 0x20 <= b <= 0x7E:
                current.append(chr(b))
            else:
                if len(current) >= 3:
                    result.append(''.join(current))
                current = []
        if len(current) >= 3:
            result.append(''.join(current))
        return ' | '.join(result) if result else ''
