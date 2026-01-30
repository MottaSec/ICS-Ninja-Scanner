#!/usr/bin/env python3
"""
IEC 60870-5-104 protocol scanner for detecting security issues in power grid systems.

Supports detection of:
- Unauthenticated access and control command acceptance
- Unencrypted communications (lack of IEC 62351-3 / TLS)
- Spontaneous data leakage and multi-station exposure
- Counter interrogation and clock synchronization vulnerabilities
"""

import socket
import ssl
import struct
import time
from datetime import datetime

from scanners.base_scanner import BaseScanner

# ---------------------------------------------------------------------------
# IEC-104 U-format (unnumbered) control words
# ---------------------------------------------------------------------------
IEC104_STARTDT_ACT  = bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])
IEC104_STARTDT_CON  = bytes([0x68, 0x04, 0x0B, 0x00, 0x00, 0x00])
IEC104_TESTFR_ACT   = bytes([0x68, 0x04, 0x43, 0x00, 0x00, 0x00])
IEC104_TESTFR_CON   = bytes([0x68, 0x04, 0x83, 0x00, 0x00, 0x00])
IEC104_STOPDT_ACT   = bytes([0x68, 0x04, 0x13, 0x00, 0x00, 0x00])

# Legacy aliases used in some external references
IEC104_STARTDT = IEC104_STARTDT_ACT
IEC104_TESTFR  = IEC104_TESTFR_ACT
IEC104_STOPDT  = IEC104_STOPDT_ACT

# ---------------------------------------------------------------------------
# ASDU type-id catalogue
# ---------------------------------------------------------------------------
ASDU_TYPES = {
    1:   "M_SP_NA_1 (Single-point information)",
    3:   "M_DP_NA_1 (Double-point information)",
    5:   "M_ST_NA_1 (Step position information)",
    7:   "M_BO_NA_1 (Bitstring of 32 bit)",
    9:   "M_ME_NA_1 (Measured value, normalized value)",
    11:  "M_ME_NB_1 (Measured value, scaled value)",
    13:  "M_ME_NC_1 (Measured value, short floating point value)",
    30:  "M_SP_TB_1 (Single-point with time tag CP56Time2a)",
    31:  "M_DP_TB_1 (Double-point with time tag CP56Time2a)",
    45:  "C_SC_NA_1 (Single command)",
    46:  "C_DC_NA_1 (Double command)",
    47:  "C_RC_NA_1 (Regulating step command)",
    48:  "C_SE_NA_1 (Set-point command, normalized value)",
    49:  "C_SE_NB_1 (Set-point command, scaled value)",
    50:  "C_SE_NC_1 (Set-point command, short floating point value)",
    100: "C_IC_NA_1 (Interrogation command)",
    101: "C_CI_NA_1 (Counter interrogation command)",
    103: "C_CS_NA_1 (Clock synchronization command)",
    107: "C_TS_TA_1 (Test command with time tag CP56Time2a)",
}

CRITICAL_ASDU_TYPES = [45, 46, 47, 48, 49, 50, 103]

# Control command descriptors used in high-intensity testing
CONTROL_COMMANDS = {
    45: ("C_SC_NA_1", "Single command",                  0x0E, [0x01, 0x00, 0x00]),
    46: ("C_DC_NA_1", "Double command",                  0x0E, [0x01, 0x00, 0x00]),
    47: ("C_RC_NA_1", "Regulating step command",         0x0E, [0x01, 0x00, 0x00]),
    48: ("C_SE_NA_1", "Set-point command, normalized",   0x10, [0x01, 0x00, 0x00, 0x00, 0x00]),
    50: ("C_SE_NC_1", "Set-point command, float",        0x12, [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
}


class _SeqTracker:
    """Tracks IEC-104 send / receive sequence numbers."""

    def __init__(self):
        self.tx_seq = 0   # next send sequence number (I-format)
        self.rx_seq = 0   # next expected receive sequence number

    def next_tx(self):
        """Return current tx seq and increment."""
        val = self.tx_seq
        self.tx_seq = (self.tx_seq + 1) % 32768
        return val

    def ack_rx(self, count=1):
        """Advance rx seq after receiving I-format frames."""
        self.rx_seq = (self.rx_seq + count) % 32768

    def encode_tx_rx(self):
        """Encode tx/rx into the 4 APCI control octets for I-format."""
        tx = self.tx_seq << 1
        rx = self.rx_seq << 1
        return struct.pack('<HH', tx, rx)

    def s_frame(self):
        """Build an S-format acknowledgement frame."""
        rx = self.rx_seq << 1
        return bytes([0x68, 0x04, 0x01, 0x00]) + struct.pack('<H', rx)


class IEC104Scanner(BaseScanner):
    """Scanner for detecting security issues in IEC 60870-5-104 devices."""

    def __init__(self, intensity='low', timeout=5, verify=True):
        super().__init__(intensity, timeout, verify)
        self.standard_ports = [2404]

    # ------------------------------------------------------------------
    # Main scan entry-point
    # ------------------------------------------------------------------
    def scan(self, target, open_ports=None):
        """
        Scan a target for IEC-104 security issues.

        Args:
            target:     Target IP address.
            open_ports: Optional list of ports to probe.

        Returns:
            dict with 'device_info' and 'issues', or None.
        """
        self.start_scan_timer()

        results = {'device_info': {}, 'issues': []}
        ports_to_scan = open_ports if open_ports else self.standard_ports

        # --- Locate an IEC-104 service -----------------------------------
        iec104_port = None
        for port in ports_to_scan:
            if self._check_iec104_availability(target, port):
                iec104_port = port
                break

        if not iec104_port:
            self.stop_scan_timer()
            return None

        results['device_info']['port'] = iec104_port
        results['issues'].append(self.create_issue(
            severity='info',
            description=f"IEC 60870-5-104 Device Found: {target}:{iec104_port}",
            details="A device responding to IEC 60870-5-104 protocol was detected.",
        ))

        # --- IEC 62351-3 (TLS) detection ---------------------------------
        tls_secured = self._detect_iec62351(target, iec104_port)
        if tls_secured:
            results['device_info']['iec62351_tls'] = True
            results['issues'].append(self.create_issue(
                severity='info',
                description="IEC 62351-3 TLS detected on IEC-104 port",
                details="The device accepts a TLS handshake, indicating IEC 62351 transport security is enabled.",
            ))

        # --- Main inspection session -------------------------------------
        seq = _SeqTracker()
        sock = None
        try:
            sock = self._connect(target, iec104_port)
            sock.send(IEC104_STARTDT_ACT)
            response = sock.recv(1024)

            device_info = self._parse_device_info(response)
            if device_info:
                results['device_info'].update(device_info)

            # Encryption check on the raw response bytes
            if not tls_secured and not self._is_encrypted(response):
                results['issues'].append(self.create_issue(
                    severity='high',
                    description="IEC-104 communication is unencrypted",
                    details="The protocol transmits control data in plaintext, making it vulnerable to eavesdropping and tampering.",
                    remediation="Implement IEC 62351-3 TLS tunneling or VPN for IEC-104 communications.",
                ))

            # No native authentication
            results['issues'].append(self.create_issue(
                severity='critical',
                description="No authentication mechanism detected in IEC-104",
                details="The IEC-104 protocol doesn't implement authentication, allowing unauthorized access to power grid controls.",
                remediation="Implement access control at the network level, use secure gateways, or upgrade to IEC 62351 with authentication.",
            ))

            # --- Unsolicited data detection (all intensities) ------------
            spontaneous = self._detect_unsolicited_data(sock, seq, listen_seconds=3)
            if spontaneous:
                type_names = [ASDU_TYPES.get(t, f"Unknown({t})") for t in sorted(spontaneous)]
                results['device_info']['spontaneous_asdu_types'] = sorted(spontaneous)
                results['issues'].append(self.create_issue(
                    severity='medium',
                    description="Spontaneous data detected from IEC-104 station",
                    details=f"The device sent unsolicited I-format data with ASDU types: {'; '.join(type_names)}. "
                            "This reveals monitored data points to any connected client.",
                    remediation="Restrict network access so only authorised clients can establish IEC-104 sessions.",
                ))

            # --- Connection parameter extraction -------------------------
            conn_params = self._extract_connection_params(response)
            if conn_params:
                results['device_info'].update(conn_params)

            # --- Medium+ intensity tests ---------------------------------
            if self.intensity in ('medium', 'high'):
                # Interrogation command
                if self._test_interrogation_command(sock, seq):
                    results['device_info']['supports_interrogation'] = True
                    results['issues'].append(self.create_issue(
                        severity='medium',
                        description="IEC-104 interrogation command accepted",
                        details="Unauthenticated users can request full state information from the device.",
                        remediation="Restrict access to authorised hosts only.",
                    ))

                # Counter interrogation
                if self._test_counter_interrogation(sock, seq):
                    results['device_info']['supports_counter_interrogation'] = True
                    results['issues'].append(self.create_issue(
                        severity='medium',
                        description="IEC-104 counter interrogation command accepted",
                        details="Unauthenticated users can read counter/energy values from the device.",
                        remediation="Restrict access to authorised hosts only.",
                    ))

                # Clock synchronisation
                if self._test_clock_sync_vulnerability(sock, seq):
                    results['device_info']['vulnerable_clock_sync'] = True
                    results['issues'].append(self.create_issue(
                        severity='high',
                        description="IEC-104 clock synchronization vulnerability",
                        details="Unauthenticated users can change the device's clock, potentially affecting operations and logging.",
                        remediation="Implement network-level controls to restrict who can send clock sync commands.",
                    ))

                # Multiple station addresses
                extra_stations = self._test_multiple_stations(target, iec104_port)
                if extra_stations:
                    results['device_info']['accessible_stations'] = extra_stations
                    results['issues'].append(self.create_issue(
                        severity='medium',
                        description="Multiple IEC-104 station addresses accessible",
                        details=f"The device responded to Common Addresses: {extra_stations}. "
                                "Multiple logical stations are reachable on the same TCP connection.",
                        remediation="Restrict access per station address at the network/firewall level.",
                    ))

            # --- High intensity: control commands ------------------------
            if self.intensity == 'high':
                vulnerable_commands = self._test_control_commands(sock, seq)
                if vulnerable_commands:
                    results['device_info']['vulnerable_commands'] = vulnerable_commands
                    results['issues'].append(self.create_issue(
                        severity='critical',
                        description="IEC-104 control commands accepted without authentication",
                        details=f"The device accepts unauthenticated control commands: {', '.join(vulnerable_commands)}",
                        remediation="Implement access control at network level and restrict command authorization.",
                    ))

        except Exception as e:
            results['issues'].append(self.create_issue(
                severity='info',
                description=f"Error during IEC-104 inspection: {str(e)}",
                details="A device was detected but the scanner encountered an error during deeper inspection.",
            ))
        finally:
            self._close(sock)

        self.stop_scan_timer()
        return results

    # ------------------------------------------------------------------
    # Helpers – connection management
    # ------------------------------------------------------------------
    def _connect(self, target, port, timeout=None):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout or self.timeout)
        sock.connect((target, port))
        return sock

    @staticmethod
    def _close(sock):
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Protocol availability check
    # ------------------------------------------------------------------
    def _check_iec104_availability(self, target, port):
        """Send TESTFR and check for a valid IEC-104 response."""
        sock = None
        try:
            sock = self._connect(target, port, self.timeout)
            sock.send(IEC104_TESTFR_ACT)
            response = sock.recv(1024)

            if len(response) >= 6 and response[0] == 0x68 and response[1] == 0x04:
                valid_ctrl = {0x0B, 0x07, 0x13, 0x43, 0x23, 0x83}
                return response[2] in valid_ctrl
            return False
        except Exception:
            return False
        finally:
            self._close(sock)

    # ------------------------------------------------------------------
    # Device info parsing
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_device_info(response):
        """Extract basic device info from the initial IEC-104 response."""
        info = {}
        if len(response) > 6 and (response[2] & 0x01) == 0:
            if len(response) >= 10:
                asdu_type = response[6]
                info['asdu_type'] = ASDU_TYPES.get(asdu_type, f"Unknown type ({asdu_type})")
        return info

    # ------------------------------------------------------------------
    # Encryption / TLS detection
    # ------------------------------------------------------------------
    @staticmethod
    def _is_encrypted(response):
        """
        Heuristic check on raw bytes: if the first bytes look like a
        TLS record (0x16 0x03 …) instead of IEC-104 framing (0x68 …),
        the link is likely secured with IEC 62351-3.
        """
        if not response:
            return False
        # TLS record header: ContentType=0x16, Version=0x03 0x0X
        if len(response) >= 3 and response[0] == 0x16 and response[1] == 0x03:
            return True
        # Valid IEC-104 framing → not encrypted at application layer
        if response[0] == 0x68:
            return False
        # Unrecognisable framing – conservatively treat as possibly encrypted
        return True

    def _detect_iec62351(self, target, port):
        """
        Attempt a TLS handshake on the IEC-104 port.
        Returns True if the server responds with a valid TLS ServerHello.
        """
        sock = None
        try:
            sock = self._connect(target, port, self.timeout)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            wrapped = ctx.wrap_socket(sock, server_hostname=target)
            wrapped.do_handshake()
            wrapped.close()
            return True
        except (ssl.SSLError, ConnectionResetError, OSError):
            return False
        finally:
            self._close(sock)

    # ------------------------------------------------------------------
    # Connection parameter extraction
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_connection_params(response):
        """
        Parse S-format frames and initial data for connection parameters.
        Reports observed max APDU length from the first APCI length field.
        """
        params = {}
        if not response or len(response) < 6:
            return params

        # Walk through possibly concatenated APDUs
        offset = 0
        while offset < len(response) - 1:
            if response[offset] != 0x68:
                break
            apdu_len = response[offset + 1]
            params['max_apdu_length_observed'] = max(params.get('max_apdu_length_observed', 0), apdu_len + 2)

            if offset + 2 + apdu_len > len(response):
                break

            ctrl = response[offset + 2]
            # S-format: bit0=1, bit1=0
            if (ctrl & 0x03) == 0x01 and apdu_len == 4:
                recv_seq = struct.unpack_from('<H', response, offset + 4)[0] >> 1
                params.setdefault('s_format_recv_seqs', []).append(recv_seq)

            offset += 2 + apdu_len

        return params

    # ------------------------------------------------------------------
    # Unsolicited (spontaneous) data detection
    # ------------------------------------------------------------------
    def _detect_unsolicited_data(self, sock, seq, listen_seconds=3):
        """
        Listen for spontaneous I-format messages after STARTDT.
        Returns a set of ASDU type-ids observed.
        """
        detected_types = set()
        deadline = time.time() + listen_seconds
        sock.setblocking(False)

        try:
            while time.time() < deadline:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                sock.settimeout(max(remaining, 0.1))
                try:
                    data = sock.recv(2048)
                except (socket.timeout, BlockingIOError, OSError):
                    break
                if not data:
                    break
                self._parse_i_frames(data, detected_types, seq)
        except Exception:
            pass
        finally:
            sock.setblocking(True)
            sock.settimeout(self.timeout)
            # Acknowledge received I-frames
            if seq.rx_seq > 0:
                try:
                    sock.send(seq.s_frame())
                except Exception:
                    pass

        return detected_types

    @staticmethod
    def _parse_i_frames(data, type_set, seq):
        """Walk concatenated APDUs and collect ASDU type-ids from I-frames."""
        offset = 0
        while offset < len(data) - 5:
            if data[offset] != 0x68:
                offset += 1
                continue
            apdu_len = data[offset + 1]
            end = offset + 2 + apdu_len
            if end > len(data):
                break
            ctrl = data[offset + 2]
            # I-format: bit0 of first control octet == 0
            if (ctrl & 0x01) == 0 and apdu_len > 4:
                seq.ack_rx()
                if offset + 6 < end:
                    type_set.add(data[offset + 6])
            offset = end

    # ------------------------------------------------------------------
    # I-format packet builder
    # ------------------------------------------------------------------
    def _build_i_frame(self, seq, type_id, cot, ca, ioa_payload):
        """
        Build a complete I-format APDU.

        Args:
            seq:          _SeqTracker instance.
            type_id:      ASDU type identifier.
            cot:          Cause of transmission.
            ca:           Common address of ASDU (2 bytes LE).
            ioa_payload:  IOA address + value bytes.
        """
        asdu = bytearray([
            type_id,
            0x01,                    # SQ=0, number=1
            cot,
            0x00,                    # originator address
            ca & 0xFF, (ca >> 8) & 0xFF,
        ])
        asdu.extend(ioa_payload)

        apdu_len = 4 + len(asdu)
        tx = seq.next_tx() << 1
        rx = seq.rx_seq << 1

        frame = bytearray([0x68, apdu_len & 0xFF])
        frame.extend(struct.pack('<HH', tx, rx))
        frame.extend(asdu)
        return bytes(frame)

    # ------------------------------------------------------------------
    # Interrogation command (C_IC_NA_1 = 100)
    # ------------------------------------------------------------------
    def _test_interrogation_command(self, sock, seq):
        try:
            packet = self._build_i_frame(
                seq, type_id=100, cot=6, ca=1,
                ioa_payload=[0x00, 0x00, 0x00, 0x14],  # IOA=0, QOI=20 (station)
            )
            sock.send(packet)
            response = sock.recv(1024)
            return len(response) > 6 and response[0] == 0x68
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Counter interrogation (C_CI_NA_1 = 101)
    # ------------------------------------------------------------------
    def _test_counter_interrogation(self, sock, seq):
        """Test acceptance of counter interrogation at medium+ intensity."""
        try:
            packet = self._build_i_frame(
                seq, type_id=101, cot=6, ca=1,
                ioa_payload=[0x00, 0x00, 0x00, 0x05],  # IOA=0, QCC=5 (general)
            )
            sock.send(packet)
            response = sock.recv(1024)
            return len(response) > 6 and response[0] == 0x68
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Clock synchronisation vulnerability (C_CS_NA_1 = 103)
    # ------------------------------------------------------------------
    def _test_clock_sync_vulnerability(self, sock, seq):
        try:
            now = datetime.now()
            ms = now.second * 1000 + now.microsecond // 1000
            cp56 = bytearray([
                ms & 0xFF, (ms >> 8) & 0xFF,
                now.minute & 0x3F,
                now.hour & 0x1F,
                now.day & 0x1F,
                now.month & 0x0F,
                now.year % 100,
            ])
            ioa_payload = bytearray([0x00, 0x00, 0x00])
            ioa_payload.extend(cp56)

            packet = self._build_i_frame(seq, type_id=103, cot=6, ca=1, ioa_payload=ioa_payload)
            sock.send(packet)
            response = sock.recv(1024)
            return len(response) > 6 and response[0] == 0x68
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Control command testing (high intensity)
    # ------------------------------------------------------------------
    def _test_control_commands(self, sock, seq):
        """
        Test acceptance of multiple control command ASDU types.
        Each command is sent with COT=5 (request/deactivation) and a
        benign value to minimise impact.
        """
        vulnerable = []

        for type_id, (name, desc, _apdu_len, ioa_bytes) in CONTROL_COMMANDS.items():
            try:
                packet = self._build_i_frame(
                    seq, type_id=type_id, cot=5, ca=1,
                    ioa_payload=ioa_bytes,
                )
                sock.send(packet)
                response = sock.recv(1024)

                if len(response) > 6 and response[0] == 0x68:
                    # Check for negative confirmation (COT=44-47 → unknown type / bad addr)
                    rejected = False
                    if len(response) >= 9:
                        resp_cot = response[8] & 0x3F
                        if resp_cot in (44, 45, 46, 47):
                            rejected = True
                    if not rejected:
                        vulnerable.append(f"{desc} ({name})")
            except Exception as e:
                self.logger.debug(f"Control command {name} test failed: {e}")
            if hasattr(self, 'rate_limit'):
                self.rate_limit()

        return vulnerable

    # ------------------------------------------------------------------
    # Multiple station address testing (medium+ intensity)
    # ------------------------------------------------------------------
    def _test_multiple_stations(self, target, port):
        """
        Try Common Addresses 1-5 on separate connections to see which
        stations respond to interrogation.
        """
        accessible = []
        for ca in range(1, 6):
            sock = None
            try:
                sock = self._connect(target, port, self.timeout)
                sock.send(IEC104_STARTDT_ACT)
                sock.recv(1024)  # consume STARTDT con

                seq = _SeqTracker()
                packet = self._build_i_frame(
                    seq, type_id=100, cot=6, ca=ca,
                    ioa_payload=[0x00, 0x00, 0x00, 0x14],
                )
                sock.send(packet)
                resp = sock.recv(1024)

                if len(resp) > 8 and resp[0] == 0x68:
                    resp_cot = resp[8] & 0x3F if len(resp) >= 9 else 0
                    if resp_cot not in (44, 45, 46, 47):
                        accessible.append(ca)
            except Exception as e:
                self.logger.debug(f"Station CA={ca} test failed: {e}")
            finally:
                self._close(sock)
            if hasattr(self, 'rate_limit'):
                self.rate_limit()

        return accessible if len(accessible) > 1 else []
