#!/usr/bin/env python3
"""
HART-IP protocol scanner for detecting security issues in HART-enabled
process automation systems and HART-IP gateways.

Implements raw HART-IP protocol communication over TCP/UDP (port 5094)
using the IEC 62591 / HCF specification packet format.

Developed by MottaSec Ghost Team - The unseen guardians of industrial systems.
"""

import socket
import struct
import time
from scanners.base_scanner import BaseScanner

# ---------------------------------------------------------------------------
# HART-IP constants
# ---------------------------------------------------------------------------
HART_IP_VERSION = 0x01

# Message types
MSG_TYPE_REQUEST = 0x00
MSG_TYPE_RESPONSE = 0x01
MSG_TYPE_PUBLISH = 0x02
MSG_TYPE_NAK = 0x03

# Message IDs
MSG_ID_SESSION_INIT = 0x00
MSG_ID_SESSION_CLOSE = 0x01
MSG_ID_KEEP_ALIVE = 0x02
MSG_ID_TOKEN_PASSING = 0x03

# HART frame constants
DELIMITER_LONG_MASTER = 0x82  # Master-to-field, long frame
DEFAULT_ADDRESS = b'\x00\x00\x00\x00\x00'  # Broadcast / polling address 0

# Well-known HART manufacturer IDs (subset)
MANUFACTURER_IDS = {
    0x00: "Unknown",
    0x01: "Fisher-Rosemount (Emerson)",
    0x02: "Rosemount (Emerson)",
    0x06: "Honeywell",
    0x0A: "Yokogawa",
    0x0E: "ABB",
    0x11: "Siemens",
    0x14: "Endress+Hauser",
    0x1A: "Micro Motion (Emerson)",
    0x26: "KROHNE",
    0x2B: "VEGA",
    0x37: "Phoenix Contact",
    0x42: "Pepperl+Fuchs",
    0x44: "Turck",
}


class HARTScanner(BaseScanner):
    """Scanner for detecting security issues in HART-IP devices and gateways."""

    def __init__(self, intensity='low', timeout=5, verify=True):
        """
        Initialize the HART-IP scanner.

        Args:
            intensity (str): Scan intensity level ('low', 'medium', 'high')
            timeout (int): Connection timeout in seconds
            verify (bool): Whether to verify TLS certificates
        """
        super().__init__(intensity, timeout, verify)
        self.standard_ports = [5094]  # Standard HART-IP port
        self._sequence = 0

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def scan(self, target, open_ports=None):
        """
        Scan a target for HART-IP security issues.

        Args:
            target (str): Target IP address
            open_ports (list): List of open ports (optional)

        Returns:
            dict: Scan results with 'device_info' and 'issues', or None
        """
        results = {
            'device_info': {},
            'issues': []
        }

        ports_to_scan = open_ports if open_ports else self.standard_ports

        # --- Detect HART-IP service ---
        hart_port = None
        session_sock = None
        cmd0_data = None

        for port in ports_to_scan:
            sock, resp = self._check_hart_availability(target, port)
            if sock is not None:
                hart_port = port
                session_sock = sock
                cmd0_data = resp
                break

        if hart_port is None:
            return None

        results['device_info']['port'] = hart_port
        results['device_info']['protocol'] = 'HART-IP'

        try:
            # ---- LOW intensity: identify device ---
            self._low_intensity_checks(session_sock, cmd0_data, target, hart_port, results)

            # ---- MEDIUM intensity: enumerate ---
            if self.intensity in ('medium', 'high'):
                self._medium_intensity_checks(session_sock, target, hart_port, results)

            # ---- HIGH intensity: active write tests ---
            if self.intensity == 'high':
                self._high_intensity_checks(session_sock, target, hart_port, results)

        except Exception as exc:
            self.logger.debug(f"HART scan error: {exc}")
            results['issues'].append(self.create_issue(
                severity='info',
                description=f"Error during HART-IP scan: {str(exc)}",
                details="The scanner encountered an error during deeper inspection."
            ))
        finally:
            self._close_session(session_sock)

        return results

    # ------------------------------------------------------------------
    # Intensity-level check groupings
    # ------------------------------------------------------------------

    def _low_intensity_checks(self, sock, cmd0_data, target, port, results):
        """Run low-intensity detection and identification checks."""

        results['issues'].append(self.create_issue(
            severity='info',
            description=f"HART-IP device/gateway detected at {target}:{port}",
            details="A device responding to the HART-IP protocol was found."
        ))

        # Parse Command 0 response
        if cmd0_data is not None:
            dev_info = self._parse_command0_response(cmd0_data)
            if dev_info:
                results['device_info'].update(dev_info)
                details_lines = [f"  {k}: {v}" for k, v in dev_info.items()]
                results['issues'].append(self.create_issue(
                    severity='info',
                    description="HART device identification via Command 0",
                    details="Device identity:\n" + "\n".join(details_lines)
                ))

    def _medium_intensity_checks(self, sock, target, port, results):
        """Run medium-intensity enumeration checks."""

        # 1. No authentication on session
        results['issues'].append(self.create_issue(
            severity='high',
            description="HART-IP session established without authentication",
            details=(
                "The HART-IP gateway accepted a session and responded to "
                "commands without requiring any authentication credentials."
            ),
            remediation=(
                "Enable HART-IP session authentication if supported by the "
                "gateway firmware. Restrict network access to the HART-IP port "
                "via firewall rules and VLAN segmentation."
            )
        ))

        # 2. Plaintext communication (no TLS)
        results['issues'].append(self.create_issue(
            severity='high',
            description="HART-IP communication is unencrypted (plaintext)",
            details=(
                "The session was established over plain TCP without TLS. "
                "HART-IP supports TLS encryption but it is not in use."
            ),
            remediation=(
                "Configure the HART-IP gateway to require TLS-encrypted "
                "connections. Use certificates and mutual TLS where possible."
            )
        ))

        # 3. Command 13 — Read Tag, Descriptor, Date
        resp13 = self._send_hart_command(sock, 13)
        if resp13 is not None:
            parsed = self._parse_command13_response(resp13)
            if parsed:
                results['device_info'].update(parsed)
                results['issues'].append(self.create_issue(
                    severity='info',
                    description="Device tag/descriptor retrieved (Command 13)",
                    details=f"Tag: {parsed.get('tag', 'N/A')}, "
                            f"Descriptor: {parsed.get('descriptor', 'N/A')}, "
                            f"Date: {parsed.get('date', 'N/A')}"
                ))

        # 4. Command 48 — Additional Device Status
        resp48 = self._send_hart_command(sock, 48)
        if resp48 is not None:
            results['issues'].append(self.create_issue(
                severity='info',
                description="Additional device status accessible (Command 48)",
                details=f"Raw status data ({len(resp48)} bytes) retrieved without authentication."
            ))

        # 5. Command 3 — Read Dynamic Variables (process data)
        resp3 = self._send_hart_command(sock, 3)
        if resp3 is not None:
            results['issues'].append(self.create_issue(
                severity='medium',
                description="Process data readable without authentication (Command 3)",
                details=(
                    "Dynamic process variables (loop current, PV, SV, TV, QV) "
                    "can be read by any network client."
                ),
                remediation=(
                    "Restrict access to process data through network controls. "
                    "Sensitive process values should not be exposed to untrusted networks."
                )
            ))

        # 6. Enumerate supported commands
        supported = self._enumerate_commands(sock)
        if supported:
            results['device_info']['supported_commands'] = supported
            results['issues'].append(self.create_issue(
                severity='info',
                description=f"Enumerated {len(supported)} supported HART commands",
                details=f"Supported command numbers: {supported}"
            ))

    def _high_intensity_checks(self, sock, target, port, results):
        """Run high-intensity active/write security tests."""

        # 1. Test write commands (6, 17, 18) with rollback
        write_results = self._test_write_commands(sock)
        for wr in write_results:
            results['issues'].append(wr)

        # 2. Command 2 — Loop current range check
        resp2 = self._send_hart_command(sock, 2)
        if resp2 is not None and len(resp2) >= 8:
            try:
                loop_current = struct.unpack('>f', resp2[0:4])[0]
                pct_range = struct.unpack('>f', resp2[4:8])[0]
                results['device_info']['loop_current_mA'] = round(loop_current, 3)
                results['device_info']['percent_range'] = round(pct_range, 3)
                if loop_current < 3.5 or loop_current > 21.5:
                    results['issues'].append(self.create_issue(
                        severity='medium',
                        description=f"Loop current out of normal range: {loop_current:.2f} mA",
                        details=(
                            "Normal HART loop current is 4-20 mA. Values outside "
                            "this range may indicate misconfiguration or fault."
                        ),
                        remediation="Investigate the loop current reading and verify sensor wiring."
                    ))
            except Exception as e:
                self.logger.debug(f"Loop current parsing failed: {e}")

        # 3. Manufacturer-specific / undocumented commands (128-253)
        mfr_cmds = self._probe_manufacturer_commands(sock)
        if mfr_cmds:
            results['device_info']['manufacturer_commands'] = mfr_cmds
            results['issues'].append(self.create_issue(
                severity='medium',
                description=f"Manufacturer-specific commands accessible: {mfr_cmds}",
                details=(
                    "Commands in the 128-253 range are vendor-specific and may "
                    "expose undocumented functionality or configuration options."
                ),
                remediation=(
                    "Review vendor documentation for these commands and restrict "
                    "access. Disable unnecessary vendor commands if possible."
                )
            ))

        # 4. Sub-device enumeration (gateway with multiple field devices)
        sub_devices = self._enumerate_sub_devices(sock)
        if sub_devices and len(sub_devices) > 1:
            results['device_info']['sub_devices'] = sub_devices
            results['issues'].append(self.create_issue(
                severity='medium',
                description=f"HART-IP gateway exposes {len(sub_devices)} field devices",
                details=(
                    f"Sub-device addresses: {sub_devices}. A single gateway "
                    "provides unauthenticated access to multiple field instruments."
                ),
                remediation=(
                    "Segment HART-IP gateways from general-purpose networks. "
                    "Limit which sub-devices are accessible remotely."
                )
            ))

    # ------------------------------------------------------------------
    # Packet building helpers
    # ------------------------------------------------------------------

    def _next_sequence(self):
        """Return the next sequence number (wraps at 0xFFFF)."""
        self._sequence = (self._sequence + 1) & 0xFFFF
        return self._sequence

    def _build_hart_ip_packet(self, msg_type, msg_id, sequence, body=b''):
        """
        Build a HART-IP packet (8-byte header + body).

        Args:
            msg_type (int): Message type (0=Request, 1=Response, …)
            msg_id (int): Message ID (0=Session Init, 3=Token-Passing PDU, …)
            sequence (int): Sequence number
            body (bytes): Payload body

        Returns:
            bytes: Complete HART-IP packet
        """
        header = struct.pack('>BBBBHH',
                             HART_IP_VERSION,
                             msg_type,
                             msg_id,
                             0x00,        # status
                             sequence,
                             len(body))
        return header + body

    def _build_hart_command(self, command_number, data=b'', address=None):
        """
        Build a HART command frame (long-frame format) suitable for
        inclusion as the body of a Token-Passing PDU.

        Args:
            command_number (int): HART command number (0-255)
            data (bytes): Command data payload
            address (bytes): 5-byte device address (default: broadcast)

        Returns:
            bytes: HART command frame including checksum
        """
        if address is None:
            address = DEFAULT_ADDRESS

        frame = bytearray()
        frame.append(DELIMITER_LONG_MASTER)   # delimiter
        frame.extend(address)                  # 5-byte address
        frame.append(command_number & 0xFF)    # command
        frame.append(len(data) & 0xFF)         # byte count
        frame.extend(data)                     # data payload

        # Checksum: XOR of all preceding bytes
        chk = 0
        for b in frame:
            chk ^= b
        frame.append(chk)

        return bytes(frame)

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    def _parse_hart_ip_response(self, data):
        """
        Parse a HART-IP response header.

        Args:
            data (bytes): Raw received data (>= 8 bytes)

        Returns:
            dict or None: Parsed header fields and body, or None on error
        """
        if data is None or len(data) < 8:
            return None
        version, msg_type, msg_id, status, seq, body_len = struct.unpack('>BBBBHH', data[:8])
        body = data[8:8 + body_len] if len(data) >= 8 + body_len else data[8:]
        return {
            'version': version,
            'msg_type': msg_type,
            'msg_id': msg_id,
            'status': status,
            'sequence': seq,
            'body_length': body_len,
            'body': body,
        }

    def _parse_command_response(self, body):
        """
        Parse the HART command frame out of a Token-Passing PDU body.

        Returns:
            tuple: (command_number, response_code, data_bytes) or None
        """
        if body is None or len(body) < 9:
            # Minimum: delimiter(1) + addr(5) + cmd(1) + len(1) + chk(1)
            return None
        try:
            # delimiter at [0], address at [1:6], command at [6], byte_count at [7]
            cmd = body[6]
            byte_count = body[7]
            # Response code is first data byte (if present)
            if byte_count >= 1:
                resp_code = body[8]
                cmd_data = body[9:9 + byte_count - 1] if byte_count > 1 else b''
            else:
                resp_code = 0
                cmd_data = b''
            return (cmd, resp_code, cmd_data)
        except (IndexError, struct.error):
            return None

    def _parse_command0_response(self, cmd_data):
        """
        Parse Command 0 (Read Unique Identifier) response data.

        Expected data (after response code): >=12 bytes
          [0]    254 indicator
          [1]    manufacturer ID
          [2]    device type
          [3]    preambles
          [4]    HART revision
          [5]    device revision
          [6]    software revision
          [7-9]  hardware revision / physical signaling code / flags
          [10-12] device ID (3 bytes)

        Returns:
            dict or None
        """
        if cmd_data is None or len(cmd_data) < 12:
            return None
        try:
            mfr_id = cmd_data[1]
            dev_type = cmd_data[2]
            hart_rev = cmd_data[4]
            dev_rev = cmd_data[5]
            sw_rev = cmd_data[6]
            device_id = cmd_data[10:13].hex() if len(cmd_data) >= 13 else 'N/A'
            return {
                'manufacturer_id': mfr_id,
                'manufacturer': MANUFACTURER_IDS.get(mfr_id, f"ID 0x{mfr_id:02X}"),
                'device_type': dev_type,
                'hart_revision': hart_rev,
                'device_revision': dev_rev,
                'software_revision': sw_rev,
                'device_id': device_id,
            }
        except (IndexError, struct.error):
            return None

    def _parse_command13_response(self, cmd_data):
        """
        Parse Command 13 (Read Tag, Descriptor, Date) response data.

        Expected: 6 bytes tag + 12 bytes descriptor + 3 bytes date = 21 bytes.

        Returns:
            dict or None
        """
        if cmd_data is None or len(cmd_data) < 21:
            return {}
        try:
            tag = cmd_data[0:6].decode('ascii', errors='replace').strip('\x00').strip()
            descriptor = cmd_data[6:18].decode('ascii', errors='replace').strip('\x00').strip()
            day = cmd_data[18]
            month = cmd_data[19]
            year = cmd_data[20] + 1900 if cmd_data[20] < 100 else cmd_data[20]
            date_str = f"{day:02d}/{month:02d}/{year}"
            return {'tag': tag, 'descriptor': descriptor, 'date': date_str}
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # Communication helpers
    # ------------------------------------------------------------------

    def _initiate_session(self, target, port):
        """
        Open a TCP connection and initiate a HART-IP session.

        Args:
            target (str): Target IP address
            port (int): Target port

        Returns:
            tuple: (socket, parsed_response_dict) or (None, None)
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((target, port))

            # Session Initiation request (empty body)
            pkt = self._build_hart_ip_packet(
                MSG_TYPE_REQUEST, MSG_ID_SESSION_INIT, self._next_sequence()
            )
            sock.sendall(pkt)
            resp_raw = sock.recv(1024)
            parsed = self._parse_hart_ip_response(resp_raw)

            if parsed and parsed['msg_type'] == MSG_TYPE_RESPONSE and parsed['msg_id'] == MSG_ID_SESSION_INIT:
                return sock, parsed
            # Some gateways respond with NAK but still keep the socket open
            if parsed and parsed['msg_type'] == MSG_TYPE_NAK:
                return sock, parsed
            sock.close()
            return None, None
        except Exception as exc:
            self.logger.debug(f"HART session init failed: {exc}")
            try:
                sock.close()
            except Exception:
                pass
            return None, None

    def _send_hart_command(self, sock, command_number, data=b'', address=None):
        """
        Send a HART command inside a Token-Passing PDU and return the
        parsed command response data (bytes after response code).

        Args:
            sock (socket.socket): Connected TCP socket
            command_number (int): HART command number
            data (bytes): Optional command data
            address (bytes): Optional 5-byte address

        Returns:
            bytes or None: Command response data (excluding response code),
                           or None on failure / non-zero response code
        """
        if sock is None:
            return None
        try:
            cmd_frame = self._build_hart_command(command_number, data, address)
            pkt = self._build_hart_ip_packet(
                MSG_TYPE_REQUEST, MSG_ID_TOKEN_PASSING, self._next_sequence(), cmd_frame
            )
            sock.sendall(pkt)
            resp_raw = sock.recv(4096)
            parsed = self._parse_hart_ip_response(resp_raw)
            if parsed is None or parsed['msg_type'] not in (MSG_TYPE_RESPONSE,):
                return None
            cmd_resp = self._parse_command_response(parsed['body'])
            if cmd_resp is None:
                return None
            _cmd, resp_code, cmd_data = cmd_resp
            # Response code 0 = success; some codes (e.g. 6, 14) are warnings
            if resp_code > 15:
                return None  # command not implemented or error
            return cmd_data
        except Exception as exc:
            self.logger.debug(f"HART command {command_number} error: {exc}")
            return None

    def _check_hart_availability(self, target, port):
        """
        Check if a HART-IP device is reachable: initiate session + Command 0.

        Returns:
            tuple: (socket, cmd0_response_data) or (None, None)
        """
        sock, session_resp = self._initiate_session(target, port)
        if sock is None:
            return None, None
        # Send Command 0 to confirm HART
        cmd0_data = self._send_hart_command(sock, 0)
        if cmd0_data is not None:
            return sock, cmd0_data
        # Even without cmd0 data, session response alone is strong evidence
        if session_resp:
            return sock, None
        try:
            sock.close()
        except Exception:
            pass
        return None, None

    def _close_session(self, sock):
        """Send Session Close and close the socket gracefully."""
        if sock is None:
            return
        try:
            pkt = self._build_hart_ip_packet(
                MSG_TYPE_REQUEST, MSG_ID_SESSION_CLOSE, self._next_sequence()
            )
            sock.sendall(pkt)
            sock.recv(256)  # absorb response
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # High-intensity test helpers
    # ------------------------------------------------------------------

    def _test_write_commands(self, sock):
        """
        Test write-capable commands with safe read-first / rollback approach.

        Returns:
            list: Issue dicts for each finding
        """
        issues = []

        # --- Command 6: Write Polling Address ---
        # Read current address via Command 0, attempt write, restore
        original_cmd0 = self._send_hart_command(sock, 0)
        if original_cmd0 is not None and len(original_cmd0) >= 2:
            # Attempt to write polling address 0 (same as current broadcast)
            resp6 = self._send_hart_command(sock, 6, data=b'\x00')
            if resp6 is not None:
                issues.append(self.create_issue(
                    severity='critical',
                    description="HART device accepts Write Polling Address (Command 6)",
                    details=(
                        "Command 6 (Write Polling Address) succeeded without "
                        "authentication. An attacker could reassign the device "
                        "address, disrupting communication with the control system."
                    ),
                    remediation=(
                        "Enable write-protection on the field device. Implement "
                        "HART-IP gateway access controls and network segmentation."
                    )
                ))

        # --- Command 17: Write Message ---
        resp17 = self._send_hart_command(sock, 17, data=b'\x20' * 24)  # 24 spaces
        if resp17 is not None:
            issues.append(self.create_issue(
                severity='high',
                description="HART device accepts Write Message (Command 17)",
                details=(
                    "Command 17 (Write Message) succeeded. An attacker could "
                    "alter the message displayed on the device, potentially "
                    "misleading field operators."
                ),
                remediation=(
                    "Enable write-protection on field devices. Restrict "
                    "HART-IP network access to authorised management stations."
                )
            ))

        # --- Command 18: Write Tag, Descriptor, Date ---
        # Read first via Command 13
        original13 = self._send_hart_command(sock, 13)
        if original13 is not None and len(original13) >= 21:
            # Attempt write with original data (no change — safe)
            resp18 = self._send_hart_command(sock, 18, data=original13[:21])
            if resp18 is not None:
                issues.append(self.create_issue(
                    severity='critical',
                    description="HART device accepts Write Tag/Descriptor/Date (Command 18)",
                    details=(
                        "Command 18 succeeded. Device tag, descriptor and "
                        "commissioning date can be modified remotely without "
                        "authentication, enabling identity spoofing or confusion."
                    ),
                    remediation=(
                        "Enable hardware write-protection on field instruments. "
                        "Restrict write access at the HART-IP gateway level."
                    )
                ))

        return issues

    def _enumerate_commands(self, sock):
        """
        Discover which HART commands the device supports by testing
        a set of common universal and common-practice commands.

        Returns:
            list: Sorted list of supported command numbers
        """
        supported = []
        test_commands = [0, 1, 2, 3, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18,
                         19, 20, 21, 22, 38, 48, 49, 50, 51, 54, 59]
        for cmd_num in test_commands:
            resp = self._send_hart_command(sock, cmd_num)
            if resp is not None:
                supported.append(cmd_num)
            if hasattr(self, 'rate_limit'):
                self.rate_limit()
        return sorted(supported)

    def _probe_manufacturer_commands(self, sock):
        """
        Probe manufacturer-specific command range (128-253) for accessible commands.

        Returns:
            list: Command numbers that returned a valid response
        """
        accessible = []
        # Sample a spread of vendor-specific commands instead of all 126
        probe_set = list(range(128, 160)) + [176, 192, 200, 208, 224, 240, 253]
        for cmd_num in probe_set:
            resp = self._send_hart_command(sock, cmd_num)
            if resp is not None:
                accessible.append(cmd_num)
            if hasattr(self, 'rate_limit'):
                self.rate_limit()
        return accessible

    def _enumerate_sub_devices(self, sock):
        """
        Enumerate sub-devices behind a HART-IP gateway by sending Command 0
        to different polling addresses (long-frame address bytes).

        Returns:
            list: Polling addresses that responded
        """
        found = []
        for poll_addr in range(0, 16):
            address = bytes([0x00, 0x00, 0x00, 0x00, poll_addr & 0x3F])
            resp = self._send_hart_command(sock, 0, address=address)
            if resp is not None:
                found.append(poll_addr)
            if hasattr(self, 'rate_limit'):
                self.rate_limit()
        return found
