#!/usr/bin/env python3
"""
EtherNet/IP protocol scanner for detecting security issues in CIP-based industrial devices.

Targets Rockwell Automation / Allen-Bradley PLCs and other EtherNet/IP devices.
Uses raw sockets for protocol-level detection and pylogix for Rockwell-specific operations.

Developed by MottaSec Ghost Team - The unseen guardians of industrial systems.
"""

import socket
import struct
import time

from scanners.base_scanner import BaseScanner

# EtherNet/IP Encapsulation Commands
ENIP_CMD_LIST_IDENTITY = 0x0063
ENIP_CMD_LIST_SERVICES = 0x0004
ENIP_CMD_REGISTER_SESSION = 0x0065
ENIP_CMD_UNREGISTER_SESSION = 0x0066
ENIP_CMD_SEND_RR_DATA = 0x006F

# CIP Object Class IDs
CIP_OBJ_IDENTITY = 0x01
CIP_OBJ_MESSAGE_ROUTER = 0x02
CIP_OBJ_CONNECTION_MANAGER = 0x06
CIP_OBJ_ASSEMBLY = 0x04
CIP_OBJ_CIP_SECURITY = 0x5D

# CIP Service Codes
CIP_SERVICE_GET_ATTR_ALL = 0x01
CIP_SERVICE_GET_ATTR_SINGLE = 0x0E
CIP_SERVICE_FORWARD_OPEN = 0x54

# EtherNet/IP Vendor IDs (common)
VENDOR_IDS = {
    1: "Rockwell Automation/Allen-Bradley",
    2: "Namco Controls Corp.",
    5: "Rockwell Automation/Allen-Bradley",
    9: "Schneider Electric",
    26: "ABB",
    43: "GE Automation",
    44: "Omron",
    50: "Molex",
    58: "Phoenix Contact",
    67: "Eaton",
    283: "Turck",
    674: "WAGO",
    780: "Pilz",
    802: "Prosoft Technology",
}

# EtherNet/IP Device Types
DEVICE_TYPES = {
    0: "Generic Device",
    2: "AC Drive",
    3: "Motor Overload",
    4: "Limit Switch",
    5: "Inductive Proximity Switch",
    6: "Photoelectric Sensor",
    7: "General Purpose Discrete I/O",
    12: "Communications Adapter",
    14: "Programmable Logic Controller",
    18: "Position Controller",
    21: "Managed Ethernet Switch",
    22: "Unmanaged Ethernet Switch",
    27: "AC/DC Drive",
    33: "Generic Device (keyable)",
    38: "Safety Discrete I/O Device",
    39: "Safety Controller",
    43: "Managed Safety Ethernet Switch",
}

# Known vulnerable Rockwell firmware versions (based on public advisories)
VULNERABLE_FIRMWARE = {
    "1756-EN2T": ["20.054", "21.001", "10.012", "11.002"],
    "1756-L6": ["16.056", "17.003", "18.011", "19.015", "20.011"],
    "1756-L7": ["20.011", "20.013", "20.014", "24.011", "24.013"],
    "1769-L3": ["20.011", "21.003", "24.011"],
    "CompactLogix": ["20.011", "20.013", "21.001", "24.011"],
    "ControlLogix": ["20.011", "20.013", "20.054", "21.001", "24.011"],
    "MicroLogix 1400": ["21.003", "21.006"],
    "MicroLogix 1100": ["10.000", "12.000"],
}


class EtherNetIPScanner(BaseScanner):
    """Scanner for detecting security issues in EtherNet/IP and CIP devices."""

    def __init__(self, intensity='low', timeout=5, verify=True):
        """
        Initialize the EtherNet/IP scanner.

        Args:
            intensity (str): Scan intensity level ('low', 'medium', 'high')
            timeout (int): Connection timeout in seconds
            verify (bool): Whether to verify SSL/TLS certificates
        """
        super().__init__(intensity, timeout, verify)
        self.standard_ports = [44818]  # Standard EtherNet/IP TCP port

    def scan(self, target, open_ports=None):
        """
        Scan a target for EtherNet/IP security issues.

        Args:
            target (str): Target IP address
            open_ports (list): List of open ports (optional)

        Returns:
            dict: Scan results or None if no EtherNet/IP device found
        """
        results = {
            'device_info': {},
            'issues': []
        }

        # Determine which ports to scan
        ports_to_scan = open_ports if open_ports else self.standard_ports

        # Check if EtherNet/IP is available on any port
        enip_port = None
        identity_data = None
        for port in ports_to_scan:
            identity_data = self._check_enip_availability(target, port)
            if identity_data is not None:
                enip_port = port
                break

        if not enip_port:
            return None

        # Parse identity response
        results['device_info']['port'] = enip_port
        device_identity = self._parse_identity_response(identity_data)

        if device_identity:
            results['device_info'].update(device_identity)
            vendor_name = VENDOR_IDS.get(
                device_identity.get('vendor_id', 0),
                f"Unknown (ID: {device_identity.get('vendor_id', 'N/A')})"
            )
            device_type_name = DEVICE_TYPES.get(
                device_identity.get('device_type', 0),
                f"Unknown (Type: {device_identity.get('device_type', 'N/A')})"
            )
            results['device_info']['vendor_name'] = vendor_name
            results['device_info']['device_type_name'] = device_type_name

            details = (
                f"Vendor: {vendor_name}, "
                f"Device Type: {device_type_name}, "
                f"Product: {device_identity.get('product_name', 'N/A')}, "
                f"Serial: 0x{device_identity.get('serial_number', 0):08X}, "
                f"Firmware: {device_identity.get('firmware_version', 'N/A')}"
            )
            results['issues'].append(self.create_issue(
                severity='info',
                description=f"EtherNet/IP Device Found: {target}:{enip_port}",
                details=details
            ))

            # Report device state
            status = device_identity.get('status', 0)
            state = device_identity.get('state', 0)
            results['issues'].append(self.create_issue(
                severity='info',
                description=f"Device status: 0x{status:04X}, state: {state}",
                details=f"Status word indicates device operational state and fault conditions."
            ))
        else:
            results['issues'].append(self.create_issue(
                severity='info',
                description=f"EtherNet/IP Device Found: {target}:{enip_port}",
                details="Device responded to ListIdentity but response could not be fully parsed."
            ))

        # === Medium intensity checks ===
        if self.intensity in ['medium', 'high']:
            # Test unauthenticated CIP session registration
            session_handle = self._register_session(target, enip_port)
            if session_handle:
                results['device_info']['session_registration'] = True
                results['issues'].append(self.create_issue(
                    severity='high',
                    description="Unauthenticated CIP session registration allowed",
                    details=f"Successfully registered a CIP session (handle: 0x{session_handle:08X}) without any authentication.",
                    remediation="Implement CIP Security (TLS/DTLS) to require authentication for session registration. "
                                "Use network segmentation and firewall rules to restrict access to port 44818."
                ))

                # Enumerate CIP objects using the session
                cip_objects = self._enumerate_cip_objects(target, enip_port, session_handle)
                if cip_objects:
                    results['device_info']['cip_objects'] = cip_objects
                    obj_names = ', '.join(cip_objects.keys())
                    results['issues'].append(self.create_issue(
                        severity='medium',
                        description=f"CIP objects enumerated without authentication: {obj_names}",
                        details="Device attributes and configuration are accessible without credentials.",
                        remediation="Enable CIP Security and restrict access to CIP services."
                    ))

                # Unregister the session (cleanup)
                self._unregister_session(target, enip_port, session_handle)

            # Check for CIP Security support
            cip_security_supported = self._check_cip_security(target, enip_port)
            if cip_security_supported is False:
                results['device_info']['cip_security'] = False
                results['issues'].append(self.create_issue(
                    severity='medium',
                    description="CIP Security (Object 0x5D) not supported",
                    details="The device does not support CIP Security, meaning all communications are unencrypted "
                            "and unauthenticated at the protocol level.",
                    remediation="Upgrade firmware to a version supporting CIP Security, or use VPN/encrypted tunnels "
                                "for EtherNet/IP traffic. Implement strict network segmentation."
                ))
            elif cip_security_supported is True:
                results['device_info']['cip_security'] = True
                results['issues'].append(self.create_issue(
                    severity='info',
                    description="CIP Security (Object 0x5D) is supported",
                    details="The device supports CIP Security. Verify it is properly configured and enforced."
                ))

            # Test ListServices command
            services = self._list_services(target, enip_port)
            if services:
                results['device_info']['services'] = services
                svc_desc = ', '.join([s.get('name', 'Unknown') for s in services])
                results['issues'].append(self.create_issue(
                    severity='info',
                    description=f"EtherNet/IP services enumerated: {svc_desc}",
                    details=f"Found {len(services)} service(s) available on the device."
                ))

        # === High intensity checks ===
        if self.intensity == 'high':
            # Test tag read/write access via pylogix
            tag_results = self._test_tag_access(target)
            if tag_results:
                if tag_results.get('readable_tags'):
                    tag_list = ', '.join(tag_results['readable_tags'][:5])
                    extra = f" and {len(tag_results['readable_tags']) - 5} more" \
                        if len(tag_results['readable_tags']) > 5 else ""
                    results['device_info']['readable_tags'] = tag_results['readable_tags']
                    results['issues'].append(self.create_issue(
                        severity='high',
                        description=f"Unauthenticated tag read access: {tag_list}{extra}",
                        details="PLC tags can be read without authentication, exposing process data and configuration.",
                        remediation="Enable CIP Security or use Rockwell's Controller Access Control feature. "
                                    "Restrict network access to authorized engineering workstations only."
                    ))

                if tag_results.get('writable_tags'):
                    tag_list = ', '.join(tag_results['writable_tags'][:5])
                    results['device_info']['writable_tags'] = tag_results['writable_tags']
                    results['issues'].append(self.create_issue(
                        severity='critical',
                        description=f"Unauthenticated tag WRITE access: {tag_list}",
                        details="PLC tags can be written without authentication. An attacker could manipulate "
                                "process values, setpoints, or control logic outputs.",
                        remediation="IMMEDIATELY enable write protection. Use Rockwell's Controller Access Control "
                                    "or key switch to restrict write access. Implement CIP Security."
                    ))

                if tag_results.get('program_names'):
                    results['device_info']['programs'] = tag_results['program_names']
                    results['issues'].append(self.create_issue(
                        severity='high',
                        description=f"PLC program names accessible: {', '.join(tag_results['program_names'])}",
                        details="Program structure is visible to unauthenticated users, aiding reconnaissance.",
                        remediation="Restrict access using CIP Security and network segmentation."
                    ))

            # Test ForwardOpen for unauthorized I/O connections
            forward_open_result = self._test_forward_open(target, enip_port)
            if forward_open_result:
                results['device_info']['forward_open_allowed'] = True
                results['issues'].append(self.create_issue(
                    severity='critical',
                    description="Unauthenticated ForwardOpen (I/O connection) accepted",
                    details="The device accepted a CIP ForwardOpen request without authentication, allowing "
                            "establishment of implicit (I/O) messaging connections that could be used to "
                            "send real-time control commands.",
                    remediation="Enable CIP Security with DTLS for implicit messaging. Configure connection "
                                "restrictions and use network segmentation to block unauthorized I/O connections."
                ))

            # Check for known vulnerable firmware
            product_name = results['device_info'].get('product_name', '')
            fw_version = results['device_info'].get('firmware_version', '')
            if product_name and fw_version:
                vuln_match = self._check_vulnerable_firmware(product_name, fw_version)
                if vuln_match:
                    results['issues'].append(self.create_issue(
                        severity='high',
                        description=f"Known vulnerable firmware detected: {product_name} v{fw_version}",
                        details=f"The firmware version matches known Rockwell Automation security advisories. "
                                f"Matched pattern: {vuln_match}",
                        remediation="Update firmware to the latest version. Check Rockwell Automation security "
                                    "advisories at https://www.rockwellautomation.com/en-us/trust-center/security-advisories.html"
                    ))

            # Test GetAttributeAll on sensitive objects
            sensitive_results = self._test_sensitive_objects(target, enip_port)
            if sensitive_results:
                for obj_name, obj_data in sensitive_results.items():
                    results['issues'].append(self.create_issue(
                        severity='medium',
                        description=f"Sensitive CIP object readable: {obj_name}",
                        details=f"GetAttributeAll on {obj_name} returned {len(obj_data)} bytes of data.",
                        remediation="Restrict access to sensitive CIP objects using CIP Security."
                    ))

        return results

    # =========================================================================
    # Private Helper Methods
    # =========================================================================

    def _build_enip_header(self, command, length=0, session_handle=0, sender_context=b'\x00' * 8):
        """
        Build an EtherNet/IP encapsulation header.

        Args:
            command (int): EtherNet/IP command code
            length (int): Length of command-specific data
            session_handle (int): Session handle (0 for no session)
            sender_context (bytes): 8-byte sender context

        Returns:
            bytes: 24-byte EtherNet/IP header
        """
        return struct.pack('<HHI I 8s I',
                           command,          # Command (2)
                           length,           # Length (2)
                           session_handle,   # Session Handle (4)
                           0,                # Status (4)
                           sender_context,   # Sender Context (8)
                           0)                # Options (4)

    def _check_enip_availability(self, target, port):
        """
        Send a ListIdentity command to detect an EtherNet/IP device.

        Args:
            target (str): Target IP address
            port (int): Port number

        Returns:
            bytes: Raw response data, or None if not detected
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect((target, port))

            # Build ListIdentity packet
            packet = self._build_enip_header(ENIP_CMD_LIST_IDENTITY)
            sock.send(packet)

            response = sock.recv(4096)
            if len(response) >= 24:
                resp_cmd = struct.unpack('<H', response[0:2])[0]
                if resp_cmd == ENIP_CMD_LIST_IDENTITY:
                    return response
            return None

        except Exception as e:
            self.logger.debug(f"EtherNet/IP availability check failed for {target}:{port}: {e}")
            return None

        finally:
            sock.close()

    def _parse_identity_response(self, data):
        """
        Parse a ListIdentity response to extract device information.

        Args:
            data (bytes): Raw ListIdentity response

        Returns:
            dict: Parsed device identity, or None if parsing fails
        """
        try:
            if len(data) < 26:
                return None

            # Skip the 24-byte encapsulation header
            # Then parse Item Count (2 bytes)
            offset = 24
            item_count = struct.unpack('<H', data[offset:offset + 2])[0]
            offset += 2

            if item_count < 1:
                return None

            # Parse first item: Type ID (2) + Length (2)
            item_type = struct.unpack('<H', data[offset:offset + 2])[0]
            offset += 2
            item_length = struct.unpack('<H', data[offset:offset + 2])[0]
            offset += 2

            if item_type != 0x000C:  # CIP Identity Item
                return None

            # Parse identity fields
            # Protocol Version (2), Socket Address (16), Vendor ID (2), Device Type (2),
            # Product Code (2), Revision Major (1), Revision Minor (1), Status (2),
            # Serial Number (4), Product Name Length (1), Product Name (variable), State (1)
            if len(data) < offset + 33:
                return None

            identity = {}
            identity['protocol_version'] = struct.unpack('<H', data[offset:offset + 2])[0]
            offset += 2

            # Socket address structure (sin_family, sin_port, sin_addr, sin_zero) = 16 bytes
            # We skip it but could extract the IP/port
            offset += 16

            identity['vendor_id'] = struct.unpack('<H', data[offset:offset + 2])[0]
            offset += 2
            identity['device_type'] = struct.unpack('<H', data[offset:offset + 2])[0]
            offset += 2
            identity['product_code'] = struct.unpack('<H', data[offset:offset + 2])[0]
            offset += 2
            identity['revision_major'] = struct.unpack('B', data[offset:offset + 1])[0]
            offset += 1
            identity['revision_minor'] = struct.unpack('B', data[offset:offset + 1])[0]
            offset += 1
            identity['firmware_version'] = f"{identity['revision_major']}.{identity['revision_minor']:03d}"
            identity['status'] = struct.unpack('<H', data[offset:offset + 2])[0]
            offset += 2
            identity['serial_number'] = struct.unpack('<I', data[offset:offset + 4])[0]
            offset += 4

            # Product name (length-prefixed string)
            name_length = struct.unpack('B', data[offset:offset + 1])[0]
            offset += 1
            if len(data) >= offset + name_length:
                identity['product_name'] = data[offset:offset + name_length].decode('utf-8', errors='replace')
                offset += name_length

            # State (1 byte)
            if len(data) >= offset + 1:
                identity['state'] = struct.unpack('B', data[offset:offset + 1])[0]

            return identity

        except Exception as e:
            self.logger.debug(f"Failed to parse identity response: {e}")
            return None

    def _register_session(self, target, port):
        """
        Attempt to register a CIP session without authentication.

        Args:
            target (str): Target IP address
            port (int): Port number

        Returns:
            int: Session handle if successful, None otherwise
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect((target, port))

            # RegisterSession command-specific data:
            # Protocol Version (2 bytes) + Options Flags (2 bytes)
            cmd_data = struct.pack('<HH', 1, 0)  # Version 1, no options
            header = self._build_enip_header(ENIP_CMD_REGISTER_SESSION, len(cmd_data))
            sock.send(header + cmd_data)

            response = sock.recv(4096)
            if len(response) >= 24:
                resp_cmd = struct.unpack('<H', response[0:2])[0]
                resp_status = struct.unpack('<I', response[8:12])[0]
                session_handle = struct.unpack('<I', response[4:8])[0]

                if resp_cmd == ENIP_CMD_REGISTER_SESSION and resp_status == 0 and session_handle != 0:
                    return session_handle

            return None

        except Exception as e:
            self.logger.debug(f"Session registration failed for {target}:{port}: {e}")
            return None

        finally:
            sock.close()

    def _unregister_session(self, target, port, session_handle):
        """
        Unregister a CIP session (cleanup).

        Args:
            target (str): Target IP address
            port (int): Port number
            session_handle (int): Session handle to unregister
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect((target, port))
            header = self._build_enip_header(ENIP_CMD_UNREGISTER_SESSION, 0, session_handle)
            sock.send(header)
        except Exception:
            pass
        finally:
            sock.close()

    def _send_cip_request(self, target, port, session_handle, cip_service, class_id,
                          instance_id=1, attribute_id=None):
        """
        Send a CIP explicit message via SendRRData.

        Args:
            target (str): Target IP address
            port (int): Port number
            session_handle (int): Active session handle
            cip_service (int): CIP service code
            class_id (int): CIP class ID
            instance_id (int): CIP instance ID
            attribute_id (int): CIP attribute ID (optional)

        Returns:
            bytes: CIP response data, or None on failure
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect((target, port))

            # Build CIP path
            if attribute_id is not None:
                # 3-segment path: class/instance/attribute
                cip_path = struct.pack('BBBBBB',
                                       0x20, class_id,      # 8-bit class segment
                                       0x24, instance_id,   # 8-bit instance segment
                                       0x30, attribute_id)  # 8-bit attribute segment
                path_size = 3  # in words
            else:
                # 2-segment path: class/instance
                cip_path = struct.pack('BBBB',
                                       0x20, class_id,      # 8-bit class segment
                                       0x24, instance_id)   # 8-bit instance segment
                path_size = 2  # in words

            # CIP message: Service (1) + Path Size (1) + Path (variable)
            cip_message = struct.pack('BB', cip_service, path_size) + cip_path

            # SendRRData command-specific data:
            # Interface Handle (4) + Timeout (2) + Item Count (2) +
            # Null Address Item (Type 0x0000, Length 0x0000) +
            # Unconnected Data Item (Type 0x00B2, Length, Data)
            item_data = struct.pack('<IH H HH HH',
                                    0,                              # Interface Handle
                                    10,                             # Timeout
                                    2,                              # Item Count
                                    0x0000, 0x0000,                 # Null Address Item
                                    0x00B2, len(cip_message))       # Unconnected Data Item
            item_data += cip_message

            header = self._build_enip_header(ENIP_CMD_SEND_RR_DATA, len(item_data), session_handle)
            sock.send(header + item_data)

            response = sock.recv(4096)
            if len(response) >= 24:
                resp_status = struct.unpack('<I', response[8:12])[0]
                if resp_status == 0:
                    # Extract CIP response from the encapsulated reply
                    # Skip encap header (24) + interface handle (4) + timeout (2) + item count (2)
                    # + null addr item (4) + unconnected data item header (4)
                    cip_offset = 24 + 4 + 2 + 2 + 4 + 4
                    if len(response) > cip_offset:
                        return response[cip_offset:]
            return None

        except Exception as e:
            self.logger.debug(f"CIP request failed: {e}")
            return None

        finally:
            sock.close()

    def _enumerate_cip_objects(self, target, port, session_handle=None):
        """
        Enumerate CIP objects by reading their attributes.

        Args:
            target (str): Target IP address
            port (int): Port number
            session_handle (int): Active session handle (optional, will register if None)

        Returns:
            dict: Dictionary of discovered objects and their data
        """
        own_session = False
        if session_handle is None:
            session_handle = self._register_session(target, port)
            if not session_handle:
                return None
            own_session = True

        objects = {}
        object_map = {
            'Identity (0x01)': CIP_OBJ_IDENTITY,
            'Message Router (0x02)': CIP_OBJ_MESSAGE_ROUTER,
            'Connection Manager (0x06)': CIP_OBJ_CONNECTION_MANAGER,
        }

        try:
            for obj_name, class_id in object_map.items():
                resp = self._send_cip_request(
                    target, port, session_handle,
                    CIP_SERVICE_GET_ATTR_ALL, class_id, instance_id=1
                )
                if resp and len(resp) > 2:
                    # Check CIP response status (first byte is service reply, second is reserved,
                    # third is general status)
                    if len(resp) >= 4:
                        general_status = resp[2]
                        if general_status == 0:  # Success
                            objects[obj_name] = resp[4:].hex() if len(resp) > 4 else "empty"
                        elif general_status == 0x08:  # Service not supported — object exists
                            objects[obj_name] = "exists (service not supported)"
                if hasattr(self, 'rate_limit'):
                    self.rate_limit()
        except Exception as e:
            self.logger.debug(f"CIP object enumeration error: {e}")
        finally:
            if own_session:
                self._unregister_session(target, port, session_handle)

        return objects if objects else None

    def _check_cip_security(self, target, port):
        """
        Check if the device supports CIP Security (Object 0x5D).

        Args:
            target (str): Target IP address
            port (int): Port number

        Returns:
            bool: True if supported, False if not, None if check failed
        """
        session_handle = self._register_session(target, port)
        if not session_handle:
            return None

        try:
            resp = self._send_cip_request(
                target, port, session_handle,
                CIP_SERVICE_GET_ATTR_ALL, CIP_OBJ_CIP_SECURITY, instance_id=1
            )
            if resp and len(resp) >= 3:
                general_status = resp[2]
                # Status 0 = success (object exists and is accessible)
                # Status 0x08 = service not supported (object exists)
                # Status 0x05 = path segment error (object doesn't exist)
                # Status 0x14 = object does not exist
                if general_status in (0, 0x08):
                    return True
                elif general_status in (0x05, 0x14):
                    return False
            return False  # No valid response — assume not supported

        except Exception as e:
            self.logger.debug(f"CIP Security check failed: {e}")
            return None

        finally:
            self._unregister_session(target, port, session_handle)

    def _list_services(self, target, port):
        """
        Send a ListServices command to enumerate available services.

        Args:
            target (str): Target IP address
            port (int): Port number

        Returns:
            list: List of service dicts, or None
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect((target, port))
            packet = self._build_enip_header(ENIP_CMD_LIST_SERVICES)
            sock.send(packet)

            response = sock.recv(4096)
            if len(response) < 26:
                return None

            resp_cmd = struct.unpack('<H', response[0:2])[0]
            if resp_cmd != ENIP_CMD_LIST_SERVICES:
                return None

            offset = 24
            item_count = struct.unpack('<H', response[offset:offset + 2])[0]
            offset += 2

            services = []
            for _ in range(item_count):
                if len(response) < offset + 4:
                    break
                svc_type = struct.unpack('<H', response[offset:offset + 2])[0]
                offset += 2
                svc_length = struct.unpack('<H', response[offset:offset + 2])[0]
                offset += 2

                svc_data = response[offset:offset + svc_length]
                offset += svc_length

                svc = {'type': svc_type}
                if len(svc_data) >= 4:
                    svc['version'] = struct.unpack('<H', svc_data[0:2])[0]
                    svc['capability_flags'] = struct.unpack('<H', svc_data[2:4])[0]
                if len(svc_data) >= 20:
                    svc['name'] = svc_data[4:20].decode('utf-8', errors='replace').rstrip('\x00')
                else:
                    svc['name'] = 'Unknown'

                services.append(svc)

            return services if services else None

        except Exception as e:
            self.logger.debug(f"ListServices failed for {target}:{port}: {e}")
            return None

        finally:
            sock.close()

    def _test_tag_access(self, target):
        """
        Use pylogix to test tag read/write access on Rockwell/Allen-Bradley PLCs.

        Args:
            target (str): Target IP address

        Returns:
            dict: Results with 'readable_tags', 'writable_tags', 'program_names', or None
        """
        try:
            from pylogix import PLC
        except ImportError:
            self.logger.debug("pylogix not available, skipping tag access tests")
            return None

        results = {}
        comm = PLC()
        comm.IPAddress = target
        comm.Timeout = self.timeout

        try:
            # Try to get tag list
            tag_response = comm.GetTagList()
            if tag_response and tag_response.Value:
                tags = tag_response.Value
                results['readable_tags'] = []
                results['program_names'] = []

                # Collect program names
                for tag in tags:
                    if hasattr(tag, 'TagName'):
                        tag_name = tag.TagName
                        if tag_name.startswith('Program:'):
                            prog_name = tag_name.split(':')[1] if ':' in tag_name else tag_name
                            if prog_name not in results['program_names']:
                                results['program_names'].append(prog_name)

                # Try reading a few tags (limit to first 10 non-program tags)
                test_tags = [t for t in tags if hasattr(t, 'TagName')
                             and not t.TagName.startswith('Program:')][:10]

                for tag in test_tags:
                    try:
                        read_result = comm.Read(tag.TagName)
                        if read_result and read_result.Status == 'Success':
                            results['readable_tags'].append(tag.TagName)
                    except Exception as e:
                        self.logger.debug(f"Tag read {tag.TagName} failed: {e}")
                    if hasattr(self, 'rate_limit'):
                        self.rate_limit()

                # Test write access (only on high intensity, safe approach)
                if self.intensity == 'high' and results.get('readable_tags'):
                    results['writable_tags'] = []
                    # Only test first tag to minimize risk
                    test_tag = results['readable_tags'][0]
                    try:
                        # Read current value
                        original = comm.Read(test_tag)
                        if original and original.Status == 'Success' and original.Value is not None:
                            original_val = original.Value
                            # Write the same value back (safest possible write test)
                            write_result = comm.Write(test_tag, original_val)
                            if write_result and write_result.Status == 'Success':
                                results['writable_tags'].append(test_tag)
                    except Exception as e:
                        self.logger.debug(f"Tag write test failed for {test_tag}: {e}")

                if not results['readable_tags']:
                    del results['readable_tags']
                if not results.get('program_names'):
                    del results['program_names']
                if not results.get('writable_tags'):
                    results.pop('writable_tags', None)

        except Exception as e:
            self.logger.debug(f"pylogix tag access test failed: {e}")

        finally:
            try:
                comm.Close()
            except Exception:
                pass

        return results if results else None

    def _test_forward_open(self, target, port):
        """
        Test if the device accepts an unauthenticated CIP ForwardOpen request.

        Args:
            target (str): Target IP address
            port (int): Port number

        Returns:
            bool: True if ForwardOpen accepted, False otherwise
        """
        session_handle = self._register_session(target, port)
        if not session_handle:
            return False

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect((target, port))

            # Build a minimal ForwardOpen CIP request via Connection Manager (0x06)
            # This is a benign probe — small timeout, no actual data exchange
            connection_params = struct.pack('<B',  0)  # Priority/Tick time
            connection_params += struct.pack('<B', 6)  # Timeout ticks
            connection_params += struct.pack('<I', 0x12345678)  # O->T Connection ID
            connection_params += struct.pack('<I', 0x87654321)  # T->O Connection ID
            connection_params += struct.pack('<H', 0x0001)      # Connection Serial Number
            connection_params += struct.pack('<H', 0x0001)      # Originator Vendor ID
            connection_params += struct.pack('<I', 0x00000001)  # Originator Serial Number
            connection_params += struct.pack('<B', 1)           # Connection Timeout Multiplier
            connection_params += b'\x00' * 3                    # Reserved
            connection_params += struct.pack('<I', 0x000007D0)  # O->T RPI (2000ms)
            connection_params += struct.pack('<H', 0x43F4)      # O->T Network Params (point-to-point, 500 bytes)
            connection_params += struct.pack('<I', 0x000007D0)  # T->O RPI
            connection_params += struct.pack('<H', 0x43F4)      # T->O Network Params
            connection_params += struct.pack('<B', 0x01)        # Transport Type/Trigger

            # Connection path: to backplane, slot 0
            conn_path = struct.pack('BBBB', 0x01, 0x00, 0x20, 0x02)  # port 1, link 0, class 0x02
            connection_params += struct.pack('B', len(conn_path) // 2)  # Path size in words
            connection_params += conn_path

            # CIP service header
            path_to_conn_mgr = struct.pack('BBBB',
                                           0x20, CIP_OBJ_CONNECTION_MANAGER,
                                           0x24, 0x01)
            cip_message = struct.pack('BB', CIP_SERVICE_FORWARD_OPEN, len(path_to_conn_mgr) // 2)
            cip_message += path_to_conn_mgr
            cip_message += connection_params

            # Wrap in SendRRData
            item_data = struct.pack('<IH H HH HH',
                                    0, 10, 2,
                                    0x0000, 0x0000,
                                    0x00B2, len(cip_message))
            item_data += cip_message

            header = self._build_enip_header(ENIP_CMD_SEND_RR_DATA, len(item_data), session_handle)
            sock.send(header + item_data)

            response = sock.recv(4096)
            if len(response) >= 44:
                # Check encapsulation status
                encap_status = struct.unpack('<I', response[8:12])[0]
                if encap_status == 0:
                    # Look for CIP response — ForwardOpen reply service code is 0xD4
                    cip_offset = 24 + 4 + 2 + 2 + 4 + 4
                    if len(response) > cip_offset + 2:
                        cip_service_reply = response[cip_offset]
                        cip_status = response[cip_offset + 2]
                        if cip_service_reply == (CIP_SERVICE_FORWARD_OPEN | 0x80) and cip_status == 0:
                            return True

            return False

        except Exception as e:
            self.logger.debug(f"ForwardOpen test failed: {e}")
            return False

        finally:
            sock.close()
            self._unregister_session(target, port, session_handle)

    def _check_vulnerable_firmware(self, product_name, firmware_version):
        """
        Check if the firmware version matches known vulnerable versions.

        Args:
            product_name (str): Product name from identity response
            firmware_version (str): Firmware version string

        Returns:
            str: Matched vulnerability pattern, or None
        """
        for pattern, versions in VULNERABLE_FIRMWARE.items():
            if pattern.lower() in product_name.lower():
                if firmware_version in versions:
                    return f"{pattern} firmware {firmware_version}"
        return None

    def _test_sensitive_objects(self, target, port):
        """
        Test GetAttributeAll on sensitive CIP objects (Identity, Assembly).

        Args:
            target (str): Target IP address
            port (int): Port number

        Returns:
            dict: Object names to raw data bytes, or None
        """
        session_handle = self._register_session(target, port)
        if not session_handle:
            return None

        results = {}
        sensitive_objects = {
            'Identity Object (0x01)': CIP_OBJ_IDENTITY,
            'Assembly Object (0x04)': CIP_OBJ_ASSEMBLY,
        }

        try:
            for obj_name, class_id in sensitive_objects.items():
                resp = self._send_cip_request(
                    target, port, session_handle,
                    CIP_SERVICE_GET_ATTR_ALL, class_id, instance_id=1
                )
                if resp and len(resp) >= 4:
                    general_status = resp[2]
                    if general_status == 0 and len(resp) > 4:
                        results[obj_name] = resp[4:]
                if hasattr(self, 'rate_limit'):
                    self.rate_limit()
        except Exception as e:
            self.logger.debug(f"Sensitive object test error: {e}")
        finally:
            self._unregister_session(target, port, session_handle)

        return results if results else None
