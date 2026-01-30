#!/usr/bin/env python3
"""
Modbus protocol scanner for detecting security issues in Modbus devices.

Supports Modbus TCP (port 502) and checks for Modbus/TLS (port 802).
Performs device identification (FC 43/14), unit ID enumeration, function
code scanning, register/coil read-write testing, and broadcast ID checks.

Developed by MottaSec Ghost Team - The unseen guardians of industrial systems.
"""

import socket
import struct
import time
from pymodbus.client import ModbusTcpClient
from pymodbus.pdu import ExceptionResponse

from scanners.base_scanner import BaseScanner


class ModbusScanner(BaseScanner):
    """Scanner for detecting security issues in Modbus TCP devices."""

    # Common Modbus unit IDs found in the wild (gateways, PLCs, RTUs)
    COMMON_UNIT_IDS = list(range(1, 11)) + [247]

    # Register ranges to probe
    REGISTER_RANGES = [
        (0, 10),        # Configuration / status
        (1000, 1010),   # Process variables
        (4000, 4010),   # 4xxxx registers
        (40000, 40010), # Alternate 4xxxx notation
    ]

    COIL_RANGES = [(0, 10), (100, 110)]

    def __init__(self, intensity='low', timeout=5, verify=True):
        """Initialize the Modbus scanner."""
        super().__init__(intensity, timeout, verify)
        self.standard_ports = [502]

    # ------------------------------------------------------------------
    # Main scan entry point
    # ------------------------------------------------------------------
    def scan(self, target, open_ports=None):
        """
        Scan a target for Modbus security issues.

        Args:
            target: Target IP address.
            open_ports: List of open ports (optional).

        Returns:
            dict with 'device_info' and 'issues', or None if no Modbus found.
        """
        self.start_scan_timer()

        results = {'device_info': {}, 'issues': []}
        ports_to_scan = open_ports if open_ports else self.standard_ports

        # --- Modbus availability (with retry) ---
        modbus_port = None
        for port in ports_to_scan:
            if self._check_modbus_availability(target, port):
                modbus_port = port
                break

        if not modbus_port:
            self.stop_scan_timer()
            return None

        results['device_info']['port'] = modbus_port
        results['issues'].append(self.create_issue(
            severity='info',
            description=f"Modbus Device Found: {target}:{modbus_port}",
            details="A device responding to Modbus TCP protocol was detected."
        ))

        # --- Modbus/TLS check (port 802) ---
        self._check_modbus_tls(target, results)

        # --- Device identification via FC 43/14 ---
        dev_id = self._read_device_identification(target, modbus_port)
        if dev_id:
            results['device_info']['identification'] = dev_id
            id_str = ', '.join(f"{k}: {v}" for k, v in dev_id.items())
            results['issues'].append(self.create_issue(
                severity='info',
                description=f"Modbus Device Identification: {id_str}",
                details="Device responded to Read Device Identification (FC 43 / MEI 14)."
            ))

        # --- Deep inspection via pymodbus client ---
        client = ModbusTcpClient(target, port=modbus_port, timeout=self.timeout)
        try:
            client.connect()
            if not client.is_socket_open():
                self.stop_scan_timer()
                return results

            results['device_info']['connected'] = True

            # Unauthenticated access (always flagged)
            results['issues'].append(self.create_issue(
                severity='high',
                description="Unauthenticated Modbus access detected",
                details="Modbus protocol does not implement authentication, allowing unauthorized access.",
                remediation="Implement network segmentation, ACLs, or a secure gateway."
            ))

            # Unit ID scanning (medium+)
            if self.intensity in ('medium', 'high'):
                self._enumerate_unit_ids(client, results)

            # Function code scanning (medium+)
            if self.intensity in ('medium', 'high'):
                self._enumerate_function_codes(client, results)

            # Read access — holding registers (medium+)
            if self.intensity in ('medium', 'high'):
                self._test_holding_register_reads(client, results)

            # Read access — input registers & discrete inputs (medium+)
            if self.intensity in ('medium', 'high'):
                self._test_input_registers(client, results)
                self._test_discrete_inputs(client, results)

            # Write access — coils & registers (high only)
            if self.intensity == 'high':
                self._test_coil_writes(client, results)
                self._test_register_writes(client, results)

            # Broadcast unit ID test (high only)
            if self.intensity == 'high':
                self._test_broadcast_unit_id(client, results)

        except Exception as e:
            results['issues'].append(self.create_issue(
                severity='info',
                description=f"Error during Modbus inspection: {str(e)}",
                details="The device was detected but an error occurred during deeper analysis."
            ))
        finally:
            if client and client.is_socket_open():
                client.close()

        self.stop_scan_timer()
        return results

    # ------------------------------------------------------------------
    # Availability & connectivity helpers
    # ------------------------------------------------------------------
    def _check_modbus_availability(self, target, port, retries=2):
        """Check if a Modbus device is available (with retry logic)."""
        for attempt in range(retries):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                sock.connect((target, port))
                # Read Holding Registers request: unit 1, addr 0, count 1
                packet = struct.pack('>HHHBBHH', 1, 0, 6, 1, 3, 0, 1)
                sock.send(packet)
                response = sock.recv(1024)
                if len(response) >= 9:
                    fc = response[7]
                    if fc in (3, 0x83):  # Normal or exception response
                        return True
            except Exception as e:
                self.logger.debug(f"Modbus availability check attempt {attempt + 1} failed: {e}")
                if attempt < retries - 1:
                    time.sleep(min(0.5, self.timeout / 4))
            finally:
                sock.close()
        return False

    def _check_modbus_tls(self, target, results):
        """Check whether Modbus/TLS (port 802) is available."""
        tls_available = self.check_port_open(target, 802)
        if tls_available:
            results['device_info']['modbus_tls'] = True
            results['issues'].append(self.create_issue(
                severity='info',
                description="Modbus/TLS port (802) is open",
                details="The device appears to support Modbus/TLS for encrypted communication."
            ))
        else:
            results['device_info']['modbus_tls'] = False
            results['issues'].append(self.create_issue(
                severity='medium',
                description="Modbus/TLS (port 802) not available",
                details="No Modbus/TLS endpoint detected. All Modbus traffic is unencrypted.",
                remediation="Enable Modbus/TLS on port 802 or tunnel traffic through a VPN/TLS wrapper."
            ))

    # ------------------------------------------------------------------
    # Device identification (FC 43 / MEI type 14) via raw socket
    # ------------------------------------------------------------------
    def _read_device_identification(self, target, port):
        """
        Send Read Device Identification (FC 43, MEI type 14) and parse
        vendor name, product code, and firmware revision.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((target, port))
            # FC=43(0x2B), MEI=14(0x0E), ReadDevId=1 (basic), ObjId=0
            pdu = struct.pack('BBBB', 0x2B, 0x0E, 0x01, 0x00)
            mbap = struct.pack('>HHH B', 0x0001, 0x0000, len(pdu) + 1, 1)
            sock.send(mbap + pdu)
            resp = sock.recv(1024)
            return self._parse_device_id_response(resp)
        except Exception as e:
            self.logger.debug(f"Device identification read failed: {e}")
            return None
        finally:
            sock.close()

    @staticmethod
    def _parse_device_id_response(data):
        """Parse a Read Device Identification response into a dict."""
        if not data or len(data) < 15:
            return None
        fc = data[7]
        if fc != 0x2B:
            return None

        obj_names = {0: 'vendor', 1: 'product_code', 2: 'firmware_version'}
        result = {}
        try:
            num_objects = data[13]
            offset = 14
            for _ in range(num_objects):
                if offset + 2 > len(data):
                    break
                obj_id = data[offset]
                obj_len = data[offset + 1]
                offset += 2
                if offset + obj_len > len(data):
                    break
                value = data[offset:offset + obj_len].decode('ascii', errors='replace')
                key = obj_names.get(obj_id, f'object_{obj_id}')
                result[key] = value
                offset += obj_len
        except Exception:
            pass
        return result if result else None

    # ------------------------------------------------------------------
    # Unit ID enumeration
    # ------------------------------------------------------------------
    def _enumerate_unit_ids(self, client, results):
        """Scan for valid Modbus unit IDs (scope depends on intensity)."""
        if self.intensity == 'high':
            ids_to_scan = range(1, 248)
        else:
            ids_to_scan = self.COMMON_UNIT_IDS

        valid_ids = []
        for uid in ids_to_scan:
            try:
                resp = client.read_holding_registers(0, 1, slave=uid)
                if not resp.isError():
                    valid_ids.append(uid)
            except Exception as e:
                self.logger.debug(f"Unit ID {uid} probe failed: {e}")
            if hasattr(self, 'rate_limit'):
                self.rate_limit()

        if valid_ids:
            results['device_info']['unit_ids'] = valid_ids
            if len(valid_ids) > 1:
                results['issues'].append(self.create_issue(
                    severity='medium',
                    description=f"Multiple Modbus Unit IDs detected: {valid_ids}",
                    details="Multiple Unit IDs may indicate multiple devices or a Modbus gateway.",
                    remediation="Verify all Unit IDs are authorized and restrict access if needed."
                ))

    # ------------------------------------------------------------------
    # Function code scanning
    # ------------------------------------------------------------------
    def _enumerate_function_codes(self, client, results, unit_id=1):
        """Scan for supported Modbus function codes with safe probes."""
        supported = []

        # Safe tests using public pymodbus API
        safe_tests = {
            1: lambda: client.read_coils(0, 1, slave=unit_id),
            2: lambda: client.read_discrete_inputs(0, 1, slave=unit_id),
            3: lambda: client.read_holding_registers(0, 1, slave=unit_id),
            4: lambda: client.read_input_registers(0, 1, slave=unit_id),
        }

        for fc, test_fn in safe_tests.items():
            try:
                resp = test_fn()
                if not isinstance(resp, ExceptionResponse) or resp.exception_code != 1:
                    supported.append(fc)
            except Exception as e:
                self.logger.debug(f"Function code {fc} test failed: {e}")
            if hasattr(self, 'rate_limit'):
                self.rate_limit()

        # Raw-socket probes for write / diagnostic FCs (read-only probes)
        raw_probes = self._build_raw_fc_probes(unit_id)
        for fc, pdu in raw_probes:
            if self._probe_function_code(client, pdu):
                supported.append(fc)
            if hasattr(self, 'rate_limit'):
                self.rate_limit()

        if not supported:
            return

        results['device_info']['supported_functions'] = sorted(supported)

        diag_fcs = [8, 43, 125, 126, 127]
        found_diag = [f for f in supported if f in diag_fcs]
        if found_diag:
            results['issues'].append(self.create_issue(
                severity='medium',
                description=f"Diagnostic function codes supported: {found_diag}",
                details="Diagnostic functions may allow information gathering or DoS.",
                remediation="Disable unused diagnostic functions if possible."
            ))

        prog_fcs = [90, 91, 125, 126]
        found_prog = [f for f in supported if f in prog_fcs]
        if found_prog:
            results['issues'].append(self.create_issue(
                severity='critical',
                description=f"Programming function codes supported: {found_prog}",
                details="Programming functions may allow firmware or logic modification.",
                remediation="Disable programming functions in production or add strong access controls."
            ))

    @staticmethod
    def _build_raw_fc_probes(unit_id):
        """Build raw PDU probes for function codes that need careful handling."""
        probes = []
        # FC 5  — Write Single Coil (addr 0, value 0x0000 = OFF — safe no-op)
        probes.append((5, struct.pack('B', 5) + struct.pack('>HH', 0, 0x0000)))
        # FC 6  — Write Single Register (addr 0, value 0 — effectively no-op read-back)
        probes.append((6, struct.pack('B', 6) + struct.pack('>HH', 0, 0)))
        # FC 8  — Diagnostics sub 0x0000 (Return Query Data, echo test — harmless)
        probes.append((8, struct.pack('B', 8) + struct.pack('>HH', 0, 0)))
        # FC 15 — Write Multiple Coils (addr 0, qty 1, 1 byte, value 0)
        probes.append((15, struct.pack('B', 15) + struct.pack('>HHB', 0, 1, 1) + b'\x00'))
        # FC 16 — Write Multiple Registers (addr 0, qty 1, 2 bytes, value 0)
        probes.append((16, struct.pack('B', 16) + struct.pack('>HHB', 0, 1, 2) + b'\x00\x00'))
        # FC 22 — Mask Write Register (addr 0, AND=0xFFFF, OR=0x0000 — no change)
        probes.append((22, struct.pack('B', 22) + struct.pack('>HHH', 0, 0xFFFF, 0x0000)))
        # FC 23 — Read/Write Multiple Registers (read addr 0 qty 1, write addr 0 qty 0)
        probes.append((23, struct.pack('B', 23) + struct.pack('>HHHHB', 0, 1, 0, 0, 0)))
        # FC 43 — MEI (Read Device Identification)
        probes.append((43, struct.pack('BBBB', 0x2B, 0x0E, 0x01, 0x00)))
        return probes

    def _probe_function_code(self, client, pdu):
        """Send a raw Modbus PDU via the client's socket and check for support."""
        try:
            sock = client.socket
            if not sock:
                return False
            tid = int(time.time() * 1000) & 0xFFFF
            mbap = struct.pack('>HHH', tid, 0, len(pdu) + 1) + pdu[0:1]  # unit in pdu
            # Rebuild: MBAP header + full PDU (unit ID already in first byte? No.)
            # Actually we need unit_id separately. Use unit=1.
            unit_id = 1
            frame = struct.pack('>HHHB', tid, 0, len(pdu) + 1, unit_id) + pdu
            sock.settimeout(self.timeout)
            sock.send(frame)
            resp = sock.recv(1024)
            if len(resp) >= 9:
                resp_fc = resp[7]
                # If response FC matches (no error) or exception code != 1 (illegal function)
                if resp_fc == pdu[0]:
                    return True
                if resp_fc == (pdu[0] | 0x80) and len(resp) >= 9:
                    exc_code = resp[8]
                    return exc_code != 1  # 1 = illegal function → not supported
            return False
        except Exception as e:
            self.logger.debug(f"Function code probe failed: {e}")
            return False

    # ------------------------------------------------------------------
    # Register & coil read tests
    # ------------------------------------------------------------------
    def _test_holding_register_reads(self, client, results, unit_id=1):
        """Test read access to holding registers (FC 3)."""
        readable = []
        for start, end in self.REGISTER_RANGES:
            for addr in range(start, end):
                try:
                    resp = client.read_holding_registers(addr, 1, slave=unit_id)
                    if not resp.isError():
                        readable.append(addr)
                except Exception as e:
                    self.logger.debug(f"Holding register {addr} read failed: {e}")
                if hasattr(self, 'rate_limit'):
                    self.rate_limit()

        if readable:
            text = self._summarise_list(readable)
            results['device_info']['readable_registers'] = readable
            results['issues'].append(self.create_issue(
                severity='medium',
                description=f"Readable holding registers: {text}",
                details="Unauthenticated read access could expose sensitive process data.",
                remediation="Restrict access through firewall rules or ACLs."
            ))

    def _test_input_registers(self, client, results, unit_id=1):
        """Test read access to input registers (FC 4)."""
        readable = []
        for start, end in self.REGISTER_RANGES:
            for addr in range(start, end):
                try:
                    resp = client.read_input_registers(addr, 1, slave=unit_id)
                    if not resp.isError():
                        readable.append(addr)
                except Exception as e:
                    self.logger.debug(f"Input register {addr} read failed: {e}")
                if hasattr(self, 'rate_limit'):
                    self.rate_limit()

        if readable:
            text = self._summarise_list(readable)
            results['device_info']['readable_input_registers'] = readable
            results['issues'].append(self.create_issue(
                severity='medium',
                description=f"Readable input registers (FC 4): {text}",
                details="Input registers expose real-time process measurements.",
                remediation="Restrict Modbus read access via network controls."
            ))

    def _test_discrete_inputs(self, client, results, unit_id=1):
        """Test read access to discrete inputs (FC 2)."""
        readable = []
        for start, end in self.COIL_RANGES:
            for addr in range(start, end):
                try:
                    resp = client.read_discrete_inputs(addr, 1, slave=unit_id)
                    if not resp.isError():
                        readable.append(addr)
                except Exception as e:
                    self.logger.debug(f"Discrete input {addr} read failed: {e}")
                if hasattr(self, 'rate_limit'):
                    self.rate_limit()

        if readable:
            text = self._summarise_list(readable)
            results['device_info']['readable_discrete_inputs'] = readable
            results['issues'].append(self.create_issue(
                severity='low',
                description=f"Readable discrete inputs (FC 2): {text}",
                details="Discrete inputs expose binary sensor states.",
                remediation="Restrict Modbus access via network segmentation."
            ))

    # ------------------------------------------------------------------
    # Write-access tests (high intensity only)
    # ------------------------------------------------------------------
    def _test_coil_writes(self, client, results, unit_id=1):
        """Test write access to coils (FC 5)."""
        writable = []
        for start, end in self.COIL_RANGES:
            for addr in range(start, end):
                try:
                    read_resp = client.read_coils(addr, 1, slave=unit_id)
                    if read_resp.isError():
                        continue
                    original = read_resp.bits[0]
                    write_resp = client.write_coil(addr, not original, slave=unit_id)
                    if not write_resp.isError():
                        client.write_coil(addr, original, slave=unit_id)
                        writable.append(addr)
                except Exception as e:
                    self.logger.debug(f"Coil {addr} write test failed: {e}")
                if hasattr(self, 'rate_limit'):
                    self.rate_limit()

        if writable:
            text = self._summarise_list(writable)
            results['device_info']['writable_coils'] = writable
            results['issues'].append(self.create_issue(
                severity='high',
                description=f"Writable coils: {text}",
                details="Unauthenticated write access to coils allows control of device operations.",
                remediation="Implement write protection or access control for coils."
            ))

    def _test_register_writes(self, client, results, unit_id=1):
        """Test write access to holding registers (FC 6)."""
        writable = []
        for start, end in self.REGISTER_RANGES:
            for addr in range(start, end):
                try:
                    read_resp = client.read_holding_registers(addr, 1, slave=unit_id)
                    if read_resp.isError():
                        continue
                    original = read_resp.registers[0]
                    test_val = original + 1 if original < 65535 else original - 1
                    write_resp = client.write_register(addr, test_val, slave=unit_id)
                    if not write_resp.isError():
                        client.write_register(addr, original, slave=unit_id)
                        writable.append(addr)
                except Exception as e:
                    self.logger.debug(f"Register {addr} write test failed: {e}")
                if hasattr(self, 'rate_limit'):
                    self.rate_limit()

        if writable:
            text = self._summarise_list(writable)
            results['device_info']['writable_registers'] = writable
            results['issues'].append(self.create_issue(
                severity='critical',
                description=f"Writable holding registers: {text}",
                details="Unauthenticated write access allows modification of device settings.",
                remediation="Implement write protection or access control for holding registers."
            ))

    # ------------------------------------------------------------------
    # Broadcast unit ID test (high intensity)
    # ------------------------------------------------------------------
    def _test_broadcast_unit_id(self, client, results):
        """Test if device responds to broadcast unit ID 0."""
        try:
            resp = client.read_holding_registers(0, 1, slave=0)
            if not resp.isError():
                results['device_info']['broadcast_responsive'] = True
                results['issues'].append(self.create_issue(
                    severity='medium',
                    description="Device responds to broadcast unit ID (0)",
                    details="The device processes broadcast Modbus commands, which could be abused "
                            "to send commands to all devices on a shared bus simultaneously.",
                    remediation="Configure the device to ignore broadcast unit ID if not required."
                ))
        except Exception as e:
            self.logger.debug(f"Broadcast unit ID test failed: {e}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _summarise_list(items, limit=10):
        """Format a list of ints into a short summary string."""
        text = ', '.join(str(i) for i in items[:limit])
        if len(items) > limit:
            text += f" and {len(items) - limit} more"
        return text
