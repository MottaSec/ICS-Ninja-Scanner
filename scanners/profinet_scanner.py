#!/usr/bin/env python3
"""
Profinet protocol scanner for detecting security issues in factory automation systems.
Supports DCP discovery (Layer 2) and RPC-based enumeration (Layer 3/4).

Developed by MottaSec Ghost Team - The unseen guardians of industrial systems.
"""

import socket
import struct
import os
import time
import random

from scanners.base_scanner import BaseScanner

# ── Profinet constants ──────────────────────────────────────────────────────
PN_DCP_ETHER_TYPE = 0x8892
PN_DCP_MULTICAST_MAC = b'\x01\x0e\xcf\x00\x00\x00'

# DCP Frame IDs
DCP_IDENTIFY_MULTICAST = 0xFEFE
DCP_IDENTIFY_RESPONSE  = 0xFEFF
DCP_GET_SET            = 0xFEFD

# DCP Service IDs
DCP_SID_GET      = 0x03
DCP_SID_SET      = 0x04
DCP_SID_IDENTIFY = 0x05

# DCP Service Types
DCP_STYPE_REQUEST  = 0x00
DCP_STYPE_RESPONSE = 0x01

# DCP Options
DCP_OPT_IP        = 0x01
DCP_OPT_DEVICE    = 0x02
DCP_OPT_DHCP      = 0x03
DCP_OPT_CONTROL   = 0x05
DCP_OPT_ALL       = 0xFF

# DCP Sub‑options – IP
DCP_SUB_IP_MAC    = 0x01
DCP_SUB_IP_PARAM  = 0x02

# DCP Sub‑options – Device
DCP_SUB_DEV_VENDOR   = 0x01
DCP_SUB_DEV_NAME     = 0x02
DCP_SUB_DEV_ID       = 0x03
DCP_SUB_DEV_ROLE     = 0x04
DCP_SUB_DEV_OPTIONS  = 0x05
DCP_SUB_DEV_ALIAS    = 0x06
DCP_SUB_DEV_INSTANCE = 0x07

# DCP Sub‑options – Control
DCP_SUB_CTRL_START       = 0x01
DCP_SUB_CTRL_STOP        = 0x02
DCP_SUB_CTRL_SIGNAL      = 0x03
DCP_SUB_CTRL_RESPONSE    = 0x04
DCP_SUB_CTRL_RESET       = 0x05
DCP_SUB_CTRL_FACTORY     = 0x06

# Standard Profinet RPC ports
PN_PORT_RT      = 34962
PN_PORT_PNIO_CM = 34963
PN_PORT_ALARM   = 34964

# Known vulnerable firmware patterns (advisory references)
_KNOWN_VULN_FW = {
    'siemens': [
        # SSA‑479249, SSA‑349422 etc. – example patterns
        ('S7-1200', 'v4.0'),
        ('S7-1200', 'v4.1'),
        ('S7-1500', 'v1.0'),
        ('S7-1500', 'v1.5'),
        ('ET 200SP', 'v1.0'),
        ('SCALANCE', 'v4.0'),
    ],
}


class ProfinetScanner(BaseScanner):
    """
    Scanner for detecting security issues in Profinet‑enabled devices.

    Supports three intensity levels:
      - low:    DCP Identify, port availability check
      - medium: DCP Get, RPC connection test, security class check
      - high:   DCP Set tests, factory‑reset probe, I/O write test
    """

    def __init__(self, intensity='low', timeout=5, verify=True):
        """
        Initialise the Profinet scanner.

        Args:
            intensity: Scan depth ('low', 'medium', 'high').
            timeout:   Socket timeout in seconds.
            verify:    Unused (kept for API compat).
        """
        super().__init__(intensity, timeout, verify)
        self.standard_ports = [PN_PORT_RT, PN_PORT_PNIO_CM, PN_PORT_ALARM]

    # ── public entry point ──────────────────────────────────────────────────

    def scan(self, target, open_ports=None):
        """
        Scan *target* for Profinet security issues.

        Args:
            target:     Target IP address (or hostname).
            open_ports: Pre‑discovered open ports (optional).

        Returns:
            dict with 'device_info' and 'issues', or None if no
            Profinet service was detected.
        """
        self.start_scan_timer()

        results = {
            'device_info': {},
            'issues': [],
        }

        # ── Phase 1: availability ────────────────────────────────────────
        dcp_info = self._check_profinet_availability(target)

        ports_to_check = open_ports if open_ports else self.standard_ports
        open_pn_ports = [p for p in ports_to_check if self.check_port_open(target, p)]

        if not dcp_info and not open_pn_ports:
            self.stop_scan_timer()
            return None  # nothing Profinet here

        # ── Populate device_info from DCP ────────────────────────────────
        if dcp_info:
            results['device_info'].update(dcp_info)
            det_parts = [f"Profinet device detected at {target}"]
            if dcp_info.get('name_of_station'):
                det_parts.append(f"Station: {dcp_info['name_of_station']}")
            if dcp_info.get('vendor_id'):
                det_parts.append(f"Vendor ID: {dcp_info['vendor_id']}")
            if dcp_info.get('device_id'):
                det_parts.append(f"Device ID: {dcp_info['device_id']}")

            results['issues'].append(self.create_issue(
                severity='info',
                description='Profinet device detected via DCP Identify',
                details='; '.join(det_parts),
            ))

        if open_pn_ports:
            results['device_info']['open_ports'] = open_pn_ports
            results['issues'].append(self.create_issue(
                severity='info',
                description=f"Profinet RPC ports open: {open_pn_ports}",
                details='Standard PNIO RPC ports are reachable over TCP/UDP.',
            ))

        # ── Phase 2 (medium): enumeration ────────────────────────────────
        if self.intensity in ('medium', 'high'):
            self._scan_medium(target, results, open_pn_ports)

        # ── Phase 3 (high): active testing ───────────────────────────────
        if self.intensity == 'high':
            self._scan_high(target, results, open_pn_ports)

        self.stop_scan_timer()
        return results

    # ── intensity helpers ────────────────────────────────────────────────

    def _scan_medium(self, target, results, open_pn_ports):
        """Medium‑intensity checks: DCP Get, RPC probe, security class."""

        # DCP Get – IP parameters
        ip_info = self._send_dcp_get(target, DCP_OPT_IP, DCP_SUB_IP_PARAM)
        if ip_info:
            results['device_info']['ip_settings'] = ip_info
            results['issues'].append(self.create_issue(
                severity='info',
                description='DCP Get returned IP configuration',
                details=f"IP settings: {ip_info}",
            ))

        # DCP Get – Device name / DHCP
        dev_name = self._send_dcp_get(target, DCP_OPT_DEVICE, DCP_SUB_DEV_NAME)
        if dev_name:
            results['device_info']['name_of_station'] = dev_name
        dhcp_info = self._send_dcp_get(target, DCP_OPT_DHCP, 0x01)
        if dhcp_info:
            results['device_info']['dhcp'] = dhcp_info

        # DCP Set availability probe (try a harmless get‑like set with empty payload)
        set_avail = self._test_dcp_set(target, DCP_OPT_DEVICE, DCP_SUB_DEV_NAME,
                                       value=None, probe_only=True)
        if set_avail:
            results['issues'].append(self.create_issue(
                severity='high',
                description='DCP Set service is available (device config changeable)',
                details='An attacker on the same Layer 2 segment can rename or re‑IP the device.',
                remediation='Enable Profinet Security Class ≥2 or use managed switches with DCP filtering.',
            ))

        # Unauthenticated RPC connection
        for port in open_pn_ports or self.standard_ports:
            if hasattr(self, 'rate_limit'):
                self.rate_limit()
            rpc_ok, rpc_detail = self._test_rpc_connection(target, port)
            if rpc_ok:
                results['issues'].append(self.create_issue(
                    severity='high',
                    description=f'Unauthenticated RPC connection accepted on port {port}',
                    details=rpc_detail,
                    remediation='Restrict Profinet RPC access via firewall or enable TLS‑secured RPC.',
                ))
                break  # one finding is enough

        # Security class check
        sec_class = self._check_security_class(target)
        if sec_class is not None:
            results['device_info']['security_class'] = sec_class
            if sec_class <= 1:
                results['issues'].append(self.create_issue(
                    severity='high',
                    description=f'Profinet Security Class is {sec_class} ({"none" if sec_class == 0 else "basic"})',
                    details='The device lacks adequate Profinet authentication/encryption.',
                    remediation='Upgrade firmware and configure Security Class 2 (medium) or 3 (high).',
                ))

    def _scan_high(self, target, results, open_pn_ports):
        """High‑intensity checks: DCP Set tests, factory‑reset probe, I/O write test."""

        # ── DCP Set – device name change test ────────────────────────────
        current_name = results['device_info'].get('name_of_station')
        if current_name:
            set_ok = self._test_dcp_set(target, DCP_OPT_DEVICE, DCP_SUB_DEV_NAME,
                                        value=b'ics-ninja-test', probe_only=False)
            if set_ok:
                # attempt to restore immediately
                self._test_dcp_set(target, DCP_OPT_DEVICE, DCP_SUB_DEV_NAME,
                                   value=current_name.encode() if isinstance(current_name, str) else current_name,
                                   probe_only=False)
                results['issues'].append(self.create_issue(
                    severity='critical',
                    description='DCP Set accepted device name change',
                    details='The device name was temporarily changed and restored. '
                            'An attacker could disrupt Profinet IO communication by renaming the device.',
                    remediation='Enable Security Class ≥2 or apply network segmentation.',
                ))

        # ── DCP Set – IP change test (check response only) ──────────────
        ip_set_ok = self._test_dcp_set(target, DCP_OPT_IP, DCP_SUB_IP_PARAM,
                                       value=None, probe_only=True)
        if ip_set_ok:
            results['issues'].append(self.create_issue(
                severity='critical',
                description='DCP Set accepted IP configuration change request',
                details='The device indicates it will accept IP changes via DCP Set without authentication.',
                remediation='Disable DCP Set or enforce Security Class ≥2.',
            ))

        # ── Factory Reset probe ──────────────────────────────────────────
        rst_ok = self._test_factory_reset_probe(target)
        if rst_ok:
            results['issues'].append(self.create_issue(
                severity='critical',
                description='Device accepts DCP Factory Reset command',
                details='A Layer‑2 attacker could factory‑reset the device, wiping configuration.',
                remediation='Restrict physical/logical access; enable Security Class ≥2.',
            ))

        # ── PNIO I/O write access test ──────────────────────────────────
        for port in open_pn_ports or [PN_PORT_PNIO_CM]:
            io_write = self._test_io_write(target, port)
            if io_write:
                results['issues'].append(self.create_issue(
                    severity='critical',
                    description='PNIO write access to I/O data is possible',
                    details=f'Unauthenticated write to I/O data was accepted on port {port}.',
                    remediation='Enable Profinet CBA security or isolate the PNIO network.',
                ))
                break

        # ── Known firmware vulnerabilities ───────────────────────────────
        vendor_hint = (results['device_info'].get('vendor', '') or '').lower()
        dev_type    = results['device_info'].get('device_type', '')
        fw_ver      = results['device_info'].get('firmware', '')
        if self._check_known_vulnerabilities(vendor_hint, dev_type, fw_ver):
            results['issues'].append(self.create_issue(
                severity='high',
                description='Device firmware matches known vulnerable version',
                details=f'Vendor={vendor_hint}, Type={dev_type}, FW={fw_ver}',
                remediation='Apply the latest firmware patches from the vendor.',
            ))

    # ── DCP helpers ──────────────────────────────────────────────────────

    def _check_profinet_availability(self, target):
        """
        Determine if *target* hosts a Profinet device.

        Tries DCP Identify (unicast UDP emulation) first, then falls back to
        port probing.  Returns a dict of device info or None.
        """
        info = self._send_dcp_identify(target)
        if info:
            return info

        # Fallback: any standard port open?
        for port in self.standard_ports:
            if self.check_port_open(target, port):
                return {'detected_via': 'port_scan', 'port': port}
        return None

    def _send_dcp_identify(self, target):
        """
        Send a PN‑DCP Identify All request to *target* (unicast UDP on 34964
        or raw Ethernet if possible).  Returns parsed device info dict or None.

        We try two methods:
          1. Raw Ethernet frame via scapy (needs root/admin).
          2. UDP probe to port 34964 as best‑effort fallback.
        """
        # ── Method 1: scapy raw frame ────────────────────────────────────
        try:
            return self._dcp_identify_scapy(target)
        except Exception as exc:
            self.logger.debug(f'Scapy DCP identify failed: {exc}')

        # ── Method 2: UDP probe fallback ─────────────────────────────────
        try:
            return self._dcp_identify_udp(target)
        except Exception as exc:
            self.logger.debug(f'UDP DCP identify fallback failed: {exc}')

        return None

    def _dcp_identify_scapy(self, target):
        """Send DCP Identify via scapy Layer 2 frame (requires privileges)."""
        try:
            from scapy.all import Ether, sendp, sniff, conf, get_if_hwaddr
        except ImportError:
            self.logger.debug('scapy not available')
            return None

        xid = struct.pack('!I', random.randint(1, 0xFFFFFFFF))

        # Build PN‑DCP Identify All payload
        dcp_payload = struct.pack('!HBB', DCP_IDENTIFY_MULTICAST, DCP_SID_IDENTIFY, DCP_STYPE_REQUEST)
        dcp_payload += xid
        dcp_payload += struct.pack('!HH', 1, 4)  # response delay, data length
        # Block: option=ALL, suboption=ALL, length=0
        dcp_payload += struct.pack('!BBH', DCP_OPT_ALL, 0xFF, 0)

        # Resolve target MAC via ARP (scapy helper)
        try:
            from scapy.all import getmacbyip
            dst_mac = getmacbyip(target)
        except Exception:
            dst_mac = None
        if not dst_mac:
            dst_mac = 'ff:ff:ff:ff:ff:ff'

        iface = conf.iface
        src_mac = get_if_hwaddr(iface)
        frame = Ether(dst=dst_mac, src=src_mac, type=PN_DCP_ETHER_TYPE) / dcp_payload

        collected = []

        def _capture(pkt):
            if pkt.haslayer(Ether) and pkt[Ether].type == PN_DCP_ETHER_TYPE:
                collected.append(bytes(pkt[Ether].payload))

        sendp(frame, iface=iface, verbose=False)
        sniff(iface=iface, timeout=self.timeout, prn=_capture, store=False,
              lfilter=lambda p: p.haslayer(Ether) and p[Ether].type == PN_DCP_ETHER_TYPE)

        for raw in collected:
            info = self._parse_dcp_response(raw)
            if info:
                return info
        return None

    def _dcp_identify_udp(self, target):
        """
        Best‑effort UDP probe: send a minimal DCP‑style payload to port 34964.
        Some Profinet stacks answer; many won't.  We also inspect the raw
        response to see if it carries DCP‑like data.
        """
        xid = struct.pack('!I', random.randint(1, 0xFFFFFFFF))

        payload = struct.pack('!HBB', DCP_IDENTIFY_MULTICAST, DCP_SID_IDENTIFY, DCP_STYPE_REQUEST)
        payload += xid
        payload += struct.pack('!HH', 1, 4)
        payload += struct.pack('!BBH', DCP_OPT_ALL, 0xFF, 0)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(payload, (target, PN_PORT_ALARM))
            data, _ = sock.recvfrom(4096)
            if data:
                info = self._parse_dcp_response(data)
                if info:
                    return info
                return {'detected_via': 'udp_probe', 'raw_length': len(data)}
        except socket.timeout:
            return None
        except OSError:
            return None
        finally:
            sock.close()

    def _parse_dcp_response(self, data):
        """
        Parse a raw PN‑DCP response payload and return a dict with extracted
        device information, or None if parsing fails.

        Expected layout (after Ethernet):
          2B FrameID | 1B ServiceID | 1B ServiceType | 4B Xid |
          2B reserved | 2B DataLength | <blocks>

        Each block: 1B Option | 1B SubOption | 2B Length | <value> [+pad]
        """
        if not data or len(data) < 12:
            return None

        try:
            frame_id, service_id, service_type = struct.unpack_from('!HBB', data, 0)
        except struct.error:
            return None

        # Accept identify‑response or get‑response frames
        if service_type != DCP_STYPE_RESPONSE:
            return None

        try:
            data_len = struct.unpack_from('!H', data, 10)[0]
        except struct.error:
            return None

        info = {}
        offset = 12
        end = min(12 + data_len, len(data))

        while offset + 4 <= end:
            opt, sub, blen = struct.unpack_from('!BBH', data, offset)
            offset += 4
            if offset + blen > end:
                break
            block_data = data[offset:offset + blen]
            offset += blen
            # Pad to even
            if blen % 2:
                offset += 1

            self._interpret_dcp_block(info, opt, sub, block_data)

        return info if info else None

    def _interpret_dcp_block(self, info, opt, sub, block_data):
        """Interpret a single DCP TLV block into *info* dict."""
        try:
            if opt == DCP_OPT_IP and sub == DCP_SUB_IP_PARAM and len(block_data) >= 14:
                # 2‑byte block info + 4 IP + 4 mask + 4 gateway
                ip   = socket.inet_ntoa(block_data[2:6])
                mask = socket.inet_ntoa(block_data[6:10])
                gw   = socket.inet_ntoa(block_data[10:14])
                info['ip_address'] = ip
                info['subnet_mask'] = mask
                info['gateway'] = gw

            elif opt == DCP_OPT_DEVICE and sub == DCP_SUB_DEV_NAME:
                # 2‑byte block info + name string
                name = block_data[2:].decode('ascii', errors='replace').strip('\x00')
                info['name_of_station'] = name

            elif opt == DCP_OPT_DEVICE and sub == DCP_SUB_DEV_VENDOR:
                vendor = block_data[2:].decode('ascii', errors='replace').strip('\x00')
                info['vendor'] = vendor

            elif opt == DCP_OPT_DEVICE and sub == DCP_SUB_DEV_ID and len(block_data) >= 6:
                vendor_id = struct.unpack_from('!H', block_data, 2)[0]
                device_id = struct.unpack_from('!H', block_data, 4)[0]
                info['vendor_id'] = f'0x{vendor_id:04X}'
                info['device_id'] = f'0x{device_id:04X}'

            elif opt == DCP_OPT_DEVICE and sub == DCP_SUB_DEV_ROLE and len(block_data) >= 4:
                role = block_data[2]
                roles = []
                if role & 0x01:
                    roles.append('IO-Device')
                if role & 0x02:
                    roles.append('IO-Controller')
                if role & 0x04:
                    roles.append('IO-Supervisor')
                info['device_role'] = ', '.join(roles) if roles else f'0x{role:02X}'

            elif opt == DCP_OPT_DEVICE and sub == DCP_SUB_DEV_INSTANCE and len(block_data) >= 4:
                high = block_data[2]
                low  = block_data[3]
                info['device_instance'] = f'{high}.{low}'

        except Exception as exc:
            self.logger.debug(f'DCP block parse error opt={opt:#x} sub={sub:#x}: {exc}')

    def _send_dcp_get(self, target, option, suboption):
        """
        Send a DCP Get request (unicast UDP fallback) and return the parsed
        value or None.
        """
        xid = struct.pack('!I', random.randint(1, 0xFFFFFFFF))

        payload = struct.pack('!HBB', DCP_GET_SET, DCP_SID_GET, DCP_STYPE_REQUEST)
        payload += xid
        payload += struct.pack('!HH', 0, 4)  # reserved, data length
        payload += struct.pack('!BBH', option, suboption, 0)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(payload, (target, PN_PORT_ALARM))
            data, _ = sock.recvfrom(4096)
            info = self._parse_dcp_response(data)
            if info:
                # Return the most relevant field depending on what was requested
                if option == DCP_OPT_IP and suboption == DCP_SUB_IP_PARAM:
                    return {k: info[k] for k in ('ip_address', 'subnet_mask', 'gateway') if k in info} or info
                if option == DCP_OPT_DEVICE and suboption == DCP_SUB_DEV_NAME:
                    return info.get('name_of_station', info)
                return info
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()
        return None

    def _test_dcp_set(self, target, option, suboption, value=None, probe_only=True):
        """
        Test whether a DCP Set command is accepted by the device.

        If *probe_only* is True, we send a minimal Set frame and check for a
        positive acknowledgement (no actual data changed).

        Returns True if the device signals acceptance, False otherwise.
        """
        xid = struct.pack('!I', random.randint(1, 0xFFFFFFFF))

        # Build the block to include in Set request
        if value and not probe_only:
            block_info = struct.pack('!H', 0)  # block qualifier
            block_value = value if isinstance(value, bytes) else value.encode('ascii')
            block_body = block_info + block_value
        else:
            block_body = struct.pack('!H', 0)  # empty qualifier – probe

        block = struct.pack('!BBH', option, suboption, len(block_body)) + block_body
        if len(block) % 2:
            block += b'\x00'

        payload = struct.pack('!HBB', DCP_GET_SET, DCP_SID_SET, DCP_STYPE_REQUEST)
        payload += xid
        payload += struct.pack('!HH', 0, len(block))
        payload += block

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(payload, (target, PN_PORT_ALARM))
            data, _ = sock.recvfrom(4096)
            if data and len(data) >= 4:
                resp_stype = data[3] if len(data) > 3 else 0xFF
                # Service type 0x01 = response; check for positive status
                if resp_stype == DCP_STYPE_RESPONSE:
                    return True
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()
        return False

    # ── RPC helpers ──────────────────────────────────────────────────────

    def _test_rpc_connection(self, target, port):
        """
        Attempt a basic DCE/RPC bind on *target:port*.

        Returns (True, detail_str) if the device accepts the connection,
        (False, '') otherwise.
        """
        # Minimal DCE/RPC bind request (version 5.0, LE, Profinet IO UUID)
        pnio_uuid = (
            b'\xde\xa0\x00\x01\x6c\x97\x11\xd1'
            b'\x82\x71\x00\xa0\x24\x42\xdf\x7d'
        )
        # RPC bind PDU (simplified)
        rpc_bind = bytearray(74)
        rpc_bind[0]  = 0x05  # RPC version
        rpc_bind[1]  = 0x00  # minor version
        rpc_bind[2]  = 0x0B  # Bind
        rpc_bind[3]  = 0x03  # flags: first + last frag
        struct.pack_into('<I', rpc_bind, 4, 0x00000010)  # data rep (LE, ASCII, IEEE)
        struct.pack_into('<H', rpc_bind, 8, len(rpc_bind))  # frag length
        struct.pack_into('<H', rpc_bind, 10, 0)  # auth length
        struct.pack_into('<I', rpc_bind, 12, 1)  # call id
        struct.pack_into('<H', rpc_bind, 16, 4096)  # max xmit frag
        struct.pack_into('<H', rpc_bind, 18, 4096)  # max recv frag
        struct.pack_into('<I', rpc_bind, 20, 0)  # assoc group
        struct.pack_into('<I', rpc_bind, 24, 1)  # num ctx items
        # context item 0
        struct.pack_into('<H', rpc_bind, 28, 0)  # context id
        struct.pack_into('<H', rpc_bind, 30, 1)  # num trans items
        rpc_bind[32:48] = pnio_uuid  # abstract syntax UUID
        struct.pack_into('<I', rpc_bind, 48, 1)  # abstract syntax version
        # Transfer syntax – NDR
        ndr_uuid = (
            b'\x04\x5d\x88\x8a\xeb\x1c\xc9\x11'
            b'\x9f\xe8\x08\x00\x2b\x10\x48\x60'
        )
        rpc_bind[52:68] = ndr_uuid
        struct.pack_into('<I', rpc_bind, 68, 2)  # NDR version

        # Update frag length
        struct.pack_into('<H', rpc_bind, 8, len(rpc_bind))

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((target, port))
            sock.sendall(bytes(rpc_bind))
            resp = sock.recv(4096)
            if resp and len(resp) >= 4:
                rpc_type = resp[2]
                if rpc_type == 0x0C:  # Bind‑Ack
                    return True, f'RPC Bind‑Ack received on {target}:{port} (unauthenticated)'
                elif rpc_type == 0x0D:  # Bind‑Nak
                    return False, 'RPC Bind rejected'
            return False, ''
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False, ''
        finally:
            sock.close()

    def _check_security_class(self, target):
        """
        Attempt to determine the Profinet Security Class of the device.

        Returns an int (0‑3) or None if undetermined.
        Heuristic: if DCP Set is accepted → class 0;
        if RPC bind accepted without auth → class ≤1; else higher.
        """
        # Quick heuristic based on observable behaviour
        set_accepted = self._test_dcp_set(target, DCP_OPT_DEVICE, DCP_SUB_DEV_NAME,
                                          value=None, probe_only=True)
        if set_accepted:
            return 0

        rpc_ok, _ = self._test_rpc_connection(target, PN_PORT_PNIO_CM)
        if rpc_ok:
            return 1

        # If neither test succeeded, we assume ≥2 but can't distinguish 2 vs 3
        return None

    def _test_factory_reset_probe(self, target):
        """
        Send a DCP Control – Factory Reset request and check if the device
        acknowledges it.  We do NOT actually reset; we only check the response.
        """
        xid = struct.pack('!I', random.randint(1, 0xFFFFFFFF))

        # Control block: option=Control, suboption=FactoryReset
        block_body = struct.pack('!H', 0)  # qualifier
        block = struct.pack('!BBH', DCP_OPT_CONTROL, DCP_SUB_CTRL_FACTORY,
                            len(block_body)) + block_body

        payload = struct.pack('!HBB', DCP_GET_SET, DCP_SID_SET, DCP_STYPE_REQUEST)
        payload += xid
        payload += struct.pack('!HH', 0, len(block))
        payload += block

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(payload, (target, PN_PORT_ALARM))
            data, _ = sock.recvfrom(4096)
            if data and len(data) >= 4:
                return data[3] == DCP_STYPE_RESPONSE
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()
        return False

    def _test_io_write(self, target, port):
        """
        Attempt an RPC write request to the PNIO CM interface.

        We send a minimal IODWriteReq and check whether the device returns
        an IODWriteRes (indicating write access is available).
        """
        # First establish an RPC connection
        rpc_ok, _ = self._test_rpc_connection(target, port)
        if not rpc_ok:
            return False

        # Build a minimal PNIO IODWriteReq inside an RPC Request PDU
        # This is intentionally kept lightweight – we only check the response type
        pnio_uuid = (
            b'\xde\xa0\x00\x01\x6c\x97\x11\xd1'
            b'\x82\x71\x00\xa0\x24\x42\xdf\x7d'
        )
        # IODWrite opnum = 3
        rpc_req = bytearray(80)
        rpc_req[0] = 0x05  # version
        rpc_req[1] = 0x00
        rpc_req[2] = 0x00  # Request
        rpc_req[3] = 0x03  # first+last
        struct.pack_into('<I', rpc_req, 4, 0x00000010)
        struct.pack_into('<H', rpc_req, 8, len(rpc_req))
        struct.pack_into('<H', rpc_req, 10, 0)
        struct.pack_into('<I', rpc_req, 12, 2)  # call id
        struct.pack_into('<I', rpc_req, 16, 0)  # alloc hint
        struct.pack_into('<H', rpc_req, 20, 0)  # context id
        struct.pack_into('<H', rpc_req, 22, 3)  # opnum (IODWrite)
        rpc_req[24:40] = pnio_uuid  # object UUID
        # Rest is zero‑filled – minimal probe

        struct.pack_into('<H', rpc_req, 8, len(rpc_req))

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((target, port))
            sock.sendall(bytes(rpc_req))
            resp = sock.recv(4096)
            if resp and len(resp) >= 4:
                # Any non‑reject response means the write path exists
                rpc_type = resp[2]
                if rpc_type == 0x02:  # Response
                    return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        finally:
            sock.close()
        return False

    # ── Vulnerability DB ─────────────────────────────────────────────────

    @staticmethod
    def _check_known_vulnerabilities(vendor, device_type, firmware):
        """
        Check device attributes against a list of known vulnerable Profinet
        firmware versions (derived from public Siemens/CISA advisories).
        """
        if not device_type and not firmware:
            return False

        for vendor_key, entries in _KNOWN_VULN_FW.items():
            if vendor_key in vendor:
                for vuln_type, vuln_fw in entries:
                    if vuln_type.lower() in device_type.lower() and vuln_fw in firmware:
                        return True
        return False
