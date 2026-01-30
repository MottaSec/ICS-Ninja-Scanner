#!/usr/bin/env python3
"""
Siemens S7 protocol scanner for detecting security issues in S7 PLCs.
Developed by MottaSec Ghost Team - The unseen guardians of industrial systems.
"""

import socket
import snap7
try:
    from snap7.exceptions import Snap7Exception
except ImportError:
    # snap7 >= 2.0 removed exceptions module
    Snap7Exception = Exception
from datetime import datetime

from scanners.base_scanner import BaseScanner

S7_PROTECTION_LEVELS = {
    0: "No protection",
    1: "Password protected",
    2: "Reserved",
    3: "Full protection (no read/write allowed)"
}

# Known vulnerable firmware — real Siemens advisories with CVE references
SIEMENS_VULNERABILITY_DB = [
    {"pattern": "6ES7 21", "series": "S7-1200", "max_vuln_version": (4, 3, 99),
     "cves": ["CVE-2019-13945"], "advisory": "SSA-232418",
     "description": "S7-1200 firmware < V4.4 vulnerable to access protection bypass"},
    {"pattern": "6ES7 51", "series": "S7-1500", "max_vuln_version": (2, 8, 0),
     "cves": ["CVE-2019-10929", "CVE-2019-10943"], "advisory": "SSA-232418",
     "description": "S7-1500 firmware < V2.8.1 vulnerable to cryptographic attacks (session hijack)"},
    {"pattern": "6ES7 51", "series": "S7-1500", "max_vuln_version": (2, 8, 0),
     "cves": ["CVE-2019-13945"], "advisory": "SSA-480230",
     "description": "S7-1500 firmware < V2.8.1 vulnerable to hardware-based access protection bypass"},
    {"pattern": "6ES7 31", "series": "S7-300", "max_vuln_version": (3, 99, 99),
     "cves": ["CVE-2016-9159"], "advisory": "SSA-731239",
     "description": "S7-300 firmware vulnerable to credential disclosure over S7 communication"},
    {"pattern": "6ES7 41", "series": "S7-400", "max_vuln_version": (6, 99, 99),
     "cves": ["CVE-2016-9159"], "advisory": "SSA-731239",
     "description": "S7-400 firmware vulnerable to credential disclosure over S7 communication"},
    {"pattern": "6ES7 31", "series": "S7-300", "max_vuln_version": (3, 3, 99),
     "cves": ["CVE-2011-4879", "CVE-2011-4878"], "advisory": "ICSA-11-223-01",
     "description": "S7-300 firmware < V3.4 vulnerable to replay attacks and remote CPU stop"},
    {"pattern": "6ES7 41", "series": "S7-400", "max_vuln_version": (1, 99, 99),
     "cves": ["CVE-2011-4879"], "advisory": "ICSA-11-223-01",
     "description": "S7-400 legacy firmware vulnerable to remote CPU stop"},
    {"pattern": "6ES7 21", "series": "S7-1200", "max_vuln_version": (4, 4, 99),
     "cves": ["CVE-2020-15782"], "advisory": "SSA-434534",
     "description": "S7-1200 firmware <= V4.4 vulnerable to memory protection bypass (code execution)"},
    {"pattern": "6ES7 51", "series": "S7-1500", "max_vuln_version": (2, 8, 3),
     "cves": ["CVE-2020-15782"], "advisory": "SSA-434534",
     "description": "S7-1500 firmware < V2.9 vulnerable to memory protection bypass (code execution)"},
]

# General firmware age thresholds — flag old firmware even without exact CVE match
FIRMWARE_AGE_THRESHOLDS = {
    "6ES7 31": {"series": "S7-300", "min_safe": (4, 0, 0)},
    "6ES7 41": {"series": "S7-400", "min_safe": (2, 0, 0)},
    "6ES7 21": {"series": "S7-1200", "min_safe": (4, 4, 0)},
    "6ES7 51": {"series": "S7-1500", "min_safe": (2, 9, 0)},
}


class S7Scanner(BaseScanner):
    """Scanner for detecting security issues in Siemens S7 PLCs."""

    def __init__(self, intensity='low', timeout=5, verify=True):
        super().__init__(intensity, timeout, verify)
        self.standard_ports = [102]

    def scan(self, target, open_ports=None):
        """Scan a target for S7 security issues."""
        self.start_scan_timer()
        results = {'device_info': {}, 'issues': []}
        ports_to_scan = open_ports if open_ports else self.standard_ports

        # Check if S7 is available on any port
        s7_port = None
        for port in ports_to_scan:
            if self._check_s7_availability(target, port):
                s7_port = port
                break
        if not s7_port:
            self.stop_scan_timer()
            return None

        results['device_info']['port'] = s7_port
        results['issues'].append(self.create_issue(
            severity='info',
            description=f"Siemens S7 PLC Found: {target}:{s7_port}",
            details="A device responding to Siemens S7 protocol was detected."))

        # Try to connect with different rack/slot combinations
        rack_slot_combinations = [(0, 1), (0, 2), (0, 0), (1, 0), (1, 1)]
        client = None
        rack, slot = 0, 1

        for test_rack, test_slot in rack_slot_combinations:
            try:
                client = snap7.client.Client()
                client.set_connection_type(1)
                client.connect(target, test_rack, test_slot, tcp_port=s7_port)
                if client.get_connected():
                    rack, slot = test_rack, test_slot
                    break
            except Snap7Exception:
                if client:
                    client.disconnect()
                    client.destroy()
                    client = None

        if not client and self._check_s7_availability(target, s7_port):
            results['device_info'].update({'detected': True, 'rack': 'unknown', 'slot': 'unknown'})
            results['issues'].append(self.create_issue(
                severity='info',
                description="S7 device detected but couldn't establish full connection",
                details="The device appears to be an S7 PLC but the correct rack/slot couldn't be determined."))
            if self.intensity in ['medium', 'high']:
                self._check_web_server(target, results)
            self.stop_scan_timer()
            return results

        if not client:
            self.stop_scan_timer()
            return None

        try:
            results['device_info'].update({'connected': True, 'rack': rack, 'slot': slot})

            # Get CPU info
            try:
                cpu_info = client.get_cpu_info()
                if cpu_info:
                    mod_type = cpu_info.ModuleTypeName.decode('utf-8').strip()
                    serial = cpu_info.SerialNumber.decode('utf-8').strip()
                    results['device_info']['module_type'] = mod_type
                    results['device_info']['serial_number'] = serial
                    results['device_info']['as_name'] = cpu_info.ASName.decode('utf-8').strip()
                    results['device_info']['module_name'] = cpu_info.ModuleName.decode('utf-8').strip()
                    details = f"Module: {mod_type}"
                    if serial:
                        details += f", Serial: {serial}"
                    results['issues'].append(self.create_issue(
                        severity='info', description=f"S7 PLC Identified: {mod_type}", details=details))
            except Snap7Exception as e:
                results['issues'].append(self.create_issue(
                    severity='info', description="Couldn't retrieve CPU info", details=f"Error: {str(e)}"))

            # CPU State Check
            self._check_cpu_state(client, results)
            # S7 Communication Parameters
            self._check_comm_params(client, results)
            # PLC Date/Time Check
            self._check_plc_datetime(client, results)

            # Protection level (medium+ intensity)
            if self.intensity in ['medium', 'high']:
                try:
                    protection = client.get_protection()
                    plevel = protection.sch_schal
                    results['device_info']['protection_level'] = plevel
                    results['device_info']['protection_description'] = S7_PROTECTION_LEVELS.get(plevel, "Unknown")
                    if plevel == 0:
                        results['issues'].append(self.create_issue(
                            severity='critical',
                            description="S7 PLC has no password protection",
                            details="No protection mechanism enabled, allowing unauthorized program changes.",
                            remediation="Enable password protection in the hardware configuration."))
                    elif plevel == 1:
                        results['issues'].append(self.create_issue(
                            severity='medium',
                            description="S7 PLC has only password protection",
                            details="Password-only protection can be brute-forced or sniffed.",
                            remediation="Use the highest protection level available for your PLC model."))
                except Snap7Exception as e:
                    self.logger.debug(f"Protection level check failed: {e}")

            # Firmware version and vulnerability check
            try:
                order_code = client.get_order_code()
                if order_code:
                    ver = f"v{order_code.V1}.{order_code.V2}.{order_code.V3}"
                    code_str = order_code.Code.decode('utf-8').strip()
                    results['device_info']['order_code'] = code_str
                    results['device_info']['firmware_version'] = ver
                    results['issues'].append(self.create_issue(
                        severity='info', description=f"S7 PLC Order Code: {code_str}",
                        details=f"Firmware version: {ver}"))
                    for vuln in self._check_vulnerable_firmware(
                            code_str, (order_code.V1, order_code.V2, order_code.V3)):
                        results['issues'].append(vuln)
            except Snap7Exception as e:
                self.logger.debug(f"Order code/firmware check failed: {e}")

            # Module Inventory (medium+ intensity)
            if self.intensity in ['medium', 'high']:
                self._enumerate_modules(client, results)

            # Web Server Detection (medium+ intensity)
            if self.intensity in ['medium', 'high']:
                self._check_web_server(target, results)

            # Block information (medium+ intensity)
            if self.intensity in ['medium', 'high']:
                try:
                    blocks = client.list_blocks()
                    if blocks:
                        bc = {}
                        if blocks.OBCount: bc['OB'] = blocks.OBCount
                        if blocks.FBCount: bc['FB'] = blocks.FBCount
                        if blocks.FCCount: bc['FC'] = blocks.FCCount
                        if blocks.DBCount: bc['DB'] = blocks.DBCount
                        if blocks.SFBCount: bc['SFB'] = blocks.SFBCount
                        if blocks.SFCCount: bc['SFC'] = blocks.SFCCount
                        results['device_info']['program_blocks'] = bc
                        blocks_str = ", ".join(f"{v} {k}" for k, v in bc.items())
                        results['issues'].append(self.create_issue(
                            severity='medium',
                            description="PLC program information accessible",
                            details=f"Block information can be read: {blocks_str}",
                            remediation="Enable access protection in the PLC configuration."))
                except Snap7Exception as e:
                    self.logger.debug(f"Block listing failed: {e}")

            # High-intensity checks
            if self.intensity == 'high':
                # Diagnostic buffer
                try:
                    diag_buffer = client.read_szl(0x0132, 0x0004)
                    if diag_buffer:
                        results['issues'].append(self.create_issue(
                            severity='medium',
                            description="PLC diagnostic buffer is readable",
                            details="Unauthorized access to diagnostic information is possible.",
                            remediation="Restrict access to diagnostic functions."))
                except Snap7Exception as e:
                    self.logger.debug(f"Diagnostic buffer read failed: {e}")

                # DB read access
                readable_dbs = self._test_db_read_access(client)
                if readable_dbs:
                    results['device_info']['readable_dbs'] = readable_dbs
                    results['issues'].append(self.create_issue(
                        severity='high',
                        description=f"Unauthorized access to Data Blocks: {', '.join(map(str, readable_dbs[:5]))}",
                        details="Data blocks can be read without authentication, potentially exposing sensitive data.",
                        remediation="Enable block protection and access control."))

                # DB write access
                writable_dbs = self._test_db_write_access(client, readable_dbs)
                if writable_dbs:
                    results['device_info']['writable_dbs'] = writable_dbs
                    results['issues'].append(self.create_issue(
                        severity='critical',
                        description=f"Unauthorized write access to Data Blocks: {', '.join(map(str, writable_dbs[:5]))}",
                        details="Data blocks can be modified without authentication, allowing control of PLC operations.",
                        remediation="Enable block protection and access control. Use know-how protection for critical blocks."))

                # CPU state change test
                self._test_cpu_state_change(client, results)

        except Exception as e:
            results['issues'].append(self.create_issue(
                severity='info',
                description=f"Error during S7 PLC inspection: {str(e)}",
                details="A device was detected but the scanner encountered an error during deeper inspection."))
        finally:
            if client:
                try:
                    client.disconnect()
                    client.destroy()
                except Exception:
                    pass

        self.stop_scan_timer()
        return results

    # ── Private helpers ──────────────────────────────────────────────────

    def _check_s7_availability(self, target, port):
        """Check if an S7 device is available via COTP connection request."""
        cotp_cr = bytes([
            0x03, 0x00, 0x00, 0x16,
            0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
            0xC1, 0x02, 0x10, 0x00, 0xC2, 0x02, 0x03, 0x00,
            0xC0, 0x01, 0x0A
        ])
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((target, port))
            sock.send(cotp_cr)
            response = sock.recv(1024)
            return len(response) > 7 and response[5] == 0xD0
        except Exception:
            return False
        finally:
            sock.close()

    def _check_cpu_state(self, client, results):
        """Read and report the current CPU state (RUN/STOP/unknown)."""
        try:
            state = client.get_cpu_state()
            state_str = state if isinstance(state, str) else str(state)
            results['device_info']['cpu_state'] = state_str
            results['issues'].append(self.create_issue(
                severity='info', description=f"PLC CPU State: {state_str}",
                details=f"The PLC CPU is currently in {state_str} state."))
            if 'stop' in state_str.lower():
                results['issues'].append(self.create_issue(
                    severity='medium',
                    description="PLC CPU is in STOP state",
                    details="The PLC CPU is not running. This could indicate maintenance, "
                            "misconfiguration, or a denial-of-service condition.",
                    remediation="Verify that the CPU STOP state is intentional."))
        except (Snap7Exception, Exception):
            results['device_info']['cpu_state'] = 'unknown'

    def _test_cpu_state_change(self, client, results):
        """At high intensity, test if CPU state can be changed remotely.
        If stop succeeds, immediately restart the PLC."""
        stop_works = False
        try:
            client.plc_stop()
            stop_works = True
            # Immediately restart
            try:
                client.plc_cold_start()
            except Snap7Exception:
                try:
                    client.plc_hot_start()
                except Snap7Exception:
                    results['issues'].append(self.create_issue(
                        severity='critical',
                        description="PLC was stopped during test but could not be restarted automatically",
                        details="The scanner stopped the PLC CPU to test access control but failed to restart it. "
                                "Manual intervention may be required.",
                        remediation="Restart the PLC manually and enable CPU access protection immediately."))
        except (Snap7Exception, Exception):
            stop_works = False

        if stop_works:
            results['issues'].append(self.create_issue(
                severity='critical',
                description="PLC CPU state can be changed remotely without authentication",
                details="The scanner issued a PLC STOP command without credentials. An attacker could halt "
                        "the PLC, causing denial of service. The PLC was immediately restarted after the test.",
                remediation="Enable CPU access protection with a strong password. "
                            "Implement network segmentation to restrict access to port 102."))
        else:
            results['issues'].append(self.create_issue(
                severity='info',
                description="PLC CPU state change is protected",
                details="Attempt to change CPU state was rejected — access protection is in place."))

    def _check_comm_params(self, client, results):
        """Extract S7 communication parameters (PDU size, connection info)."""
        try:
            pdu_size = client.get_pdu_length()
            results['device_info']['pdu_size'] = pdu_size
            details = f"Negotiated PDU size: {pdu_size} bytes."
            if pdu_size > 480:
                details += " Large PDU indicates S7-1200/1500 series."
            results['issues'].append(self.create_issue(
                severity='info', description=f"S7 Communication — PDU size: {pdu_size}", details=details))
        except (Snap7Exception, AttributeError) as e:
            self.logger.debug(f"PDU size check failed: {e}")
        # SZL 0x0131 — communication parameters
        try:
            szl_data = client.read_szl(0x0131, 0x0001)
            if szl_data:
                results['issues'].append(self.create_issue(
                    severity='info',
                    description="S7 communication setup information accessible",
                    details="Communication parameters (SZL 0x0131) readable — reveals PLC capacity and connection limits."))
        except Snap7Exception as e:
            self.logger.debug(f"SZL 0x0131 read failed: {e}")

    def _check_plc_datetime(self, client, results):
        """Read PLC clock and flag significant drift (>1 hour) from system time."""
        try:
            plc_time = client.get_plc_datetime()
            if not plc_time:
                return
            results['device_info']['plc_datetime'] = plc_time.isoformat()
            now = datetime.now()
            drift_hours = abs((now - plc_time).total_seconds()) / 3600.0
            results['issues'].append(self.create_issue(
                severity='info',
                description=f"PLC Clock: {plc_time.strftime('%Y-%m-%d %H:%M:%S')}",
                details=f"Time drift from scanner: {drift_hours:.1f} hours."))
            if drift_hours > 1.0:
                results['issues'].append(self.create_issue(
                    severity='medium',
                    description=f"PLC clock drift detected: {drift_hours:.1f} hours from system time",
                    details=f"PLC: {plc_time.strftime('%Y-%m-%d %H:%M:%S')}, "
                            f"Scanner: {now.strftime('%Y-%m-%d %H:%M:%S')}. "
                            "Significant drift impacts logging, event correlation, and certificate auth.",
                    remediation="Synchronize the PLC clock using NTP or TIA Portal time sync."))
        except (Snap7Exception, Exception):
            pass

    def _enumerate_modules(self, client, results):
        """Enumerate installed modules via SZL 0x0011 and 0x001C (medium+ intensity)."""
        modules_found = []
        for szl_id, label in [(0x0011, "Module identification"), (0x001C, "Component identification")]:
            try:
                szl_data = client.read_szl(szl_id, 0x0000)
                if szl_data:
                    modules_found.append(f"{label} (SZL 0x{szl_id:04X}) readable")
                    results['device_info'][f'szl_0x{szl_id:04X}'] = True
            except Snap7Exception as e:
                self.logger.debug(f"SZL 0x{szl_id:04X} read failed: {e}")
        if modules_found:
            results['issues'].append(self.create_issue(
                severity='medium',
                description="PLC module/component inventory is accessible",
                details=f"Readable SZL lists: {'; '.join(modules_found)}. "
                        "Reveals installed hardware modules, firmware components, and rack/slot config.",
                remediation="Restrict SZL read access via CPU protection settings."))

    def _check_web_server(self, target, results):
        """Check if the PLC exposes a web interface on ports 80/443."""
        web_ports = [p for p in [80, 443] if self.check_port_open(target, p)]
        if web_ports:
            ports_str = ", ".join(str(p) for p in web_ports)
            results['device_info']['web_ports'] = web_ports
            results['issues'].append(self.create_issue(
                severity='medium',
                description=f"PLC web interface detected on port(s): {ports_str}",
                details=f"Web server on port(s) {ports_str}. Siemens PLC web servers may expose "
                        "diagnostic pages, config interfaces, or known web-based vulnerabilities.",
                remediation="Disable the web server if not required. Restrict access via firewall "
                            "and enable HTTPS-only with strong authentication."))

    def _test_db_read_access(self, client, max_db=100):
        """Test read access to data blocks 1..max_db."""
        readable = []
        for db_num in range(1, max_db + 1):
            try:
                data = client.db_read(db_num, 0, 4)
                if data and len(data) == 4:
                    readable.append(db_num)
            except Snap7Exception:
                pass  # Expected for non-existent DBs
            if hasattr(self, 'rate_limit'):
                self.rate_limit()
        return readable

    def _test_db_write_access(self, client, readable_dbs=None):
        """Test write access by modifying and restoring data blocks."""
        writable = []
        for db_num in (readable_dbs or []):
            try:
                original = client.db_read(db_num, 0, 4)
                if not original or len(original) != 4:
                    continue
                modified = bytearray(original)
                modified[0] = (modified[0] + 1) % 256
                client.db_write(db_num, 0, modified)
                verify = client.db_read(db_num, 0, 4)
                if verify and verify[0] == modified[0]:
                    client.db_write(db_num, 0, original)  # restore
                    writable.append(db_num)
            except Snap7Exception as e:
                self.logger.debug(f"DB {db_num} write test failed: {e}")
            if hasattr(self, 'rate_limit'):
                self.rate_limit()
        return writable

    def _check_vulnerable_firmware(self, order_code, version_tuple):
        """Check firmware against known Siemens vulnerability advisories.
        Returns a list of issue dicts for matched vulnerabilities."""
        issues = []
        matched_cves = set()

        for entry in SIEMENS_VULNERABILITY_DB:
            if entry["pattern"] not in order_code:
                continue
            if version_tuple <= entry["max_vuln_version"]:
                cve_key = tuple(entry["cves"])
                if cve_key in matched_cves:
                    continue
                matched_cves.add(cve_key)
                cve_str = ", ".join(entry["cves"])
                ver_str = f"v{version_tuple[0]}.{version_tuple[1]}.{version_tuple[2]}"
                issues.append(self.create_issue(
                    severity='high',
                    description=f"Known vulnerability: {cve_str} ({entry['series']})",
                    details=f"{entry['description']}. Firmware: {ver_str}, Order: {order_code}. "
                            f"Advisory: {entry['advisory']}.",
                    remediation=f"Update firmware. Refer to Siemens advisory {entry['advisory']}."))

        # Fallback: flag old firmware even without specific CVE match
        if not issues:
            for pattern, info in FIRMWARE_AGE_THRESHOLDS.items():
                if pattern in order_code and version_tuple < info["min_safe"]:
                    min_v = f"v{info['min_safe'][0]}.{info['min_safe'][1]}.{info['min_safe'][2]}"
                    cur_v = f"v{version_tuple[0]}.{version_tuple[1]}.{version_tuple[2]}"
                    issues.append(self.create_issue(
                        severity='high',
                        description=f"Outdated {info['series']} firmware detected",
                        details=f"Firmware {cur_v} is below recommended minimum ({min_v}) for {info['series']}. "
                                "Older versions are likely affected by multiple known vulnerabilities.",
                        remediation="Update to latest firmware. Check Siemens ProductCERT advisories."))
                    break
        return issues
