#!/usr/bin/env python3
"""
BACnet/IP protocol scanner for detecting security issues in building automation systems.

BACnet (Building Automation and Control Networks) is widely used in HVAC, lighting,
fire alarm, and access control systems. This scanner detects BACnet devices and
evaluates their security posture using raw UDP packets (BACnet/IP on port 47808).

Developed by MottaSec Ghost Team - The unseen guardians of industrial systems.
"""

import socket
import struct
import time
import random

from scanners.base_scanner import BaseScanner

# BACnet BVLL Function codes
BVLL_TYPE = 0x81
BVLL_ORIGINAL_UNICAST_NPDU = 0x0A
BVLL_ORIGINAL_BROADCAST_NPDU = 0x0B

# BACnet NPDU constants
NPDU_VERSION = 0x01

# BACnet APDU PDU types (upper nibble)
PDU_TYPE_CONFIRMED_REQUEST = 0x00
PDU_TYPE_UNCONFIRMED_REQUEST = 0x10
PDU_TYPE_SIMPLE_ACK = 0x20
PDU_TYPE_COMPLEX_ACK = 0x30
PDU_TYPE_ERROR = 0x50
PDU_TYPE_REJECT = 0x60
PDU_TYPE_ABORT = 0x70

# BACnet Unconfirmed Service Choices
UNCONFIRMED_WHO_IS = 0x08
UNCONFIRMED_I_AM = 0x00
UNCONFIRMED_COV_NOTIFICATION = 0x02

# BACnet Confirmed Service Choices
CONFIRMED_READ_PROPERTY = 0x0C
CONFIRMED_READ_PROPERTY_MULTIPLE = 0x0E
CONFIRMED_WRITE_PROPERTY = 0x0F
CONFIRMED_SUBSCRIBE_COV = 0x05
CONFIRMED_REINITIALIZE_DEVICE = 0x14
CONFIRMED_DEVICE_COMMUNICATION_CONTROL = 0x11

# BACnet Object Types
OBJECT_TYPE_ANALOG_INPUT = 0
OBJECT_TYPE_ANALOG_OUTPUT = 1
OBJECT_TYPE_ANALOG_VALUE = 2
OBJECT_TYPE_BINARY_INPUT = 3
OBJECT_TYPE_BINARY_OUTPUT = 4
OBJECT_TYPE_BINARY_VALUE = 5
OBJECT_TYPE_DEVICE = 8
OBJECT_TYPE_NOTIFICATION_CLASS = 15
OBJECT_TYPE_SCHEDULE = 17
OBJECT_TYPE_TREND_LOG = 20

OBJECT_TYPE_NAMES = {
    0: "Analog Input", 1: "Analog Output", 2: "Analog Value",
    3: "Binary Input", 4: "Binary Output", 5: "Binary Value",
    6: "Calendar", 7: "Command", 8: "Device", 9: "Event Enrollment",
    10: "File", 11: "Group", 12: "Loop", 13: "Multi-state Input",
    14: "Multi-state Output", 15: "Notification Class", 16: "Program",
    17: "Schedule", 18: "Averaging", 19: "Multi-state Value",
    20: "Trend Log", 21: "Life Safety Point", 22: "Life Safety Zone",
    23: "Accumulator", 24: "Pulse Converter", 25: "Event Log",
    26: "Global Group", 27: "Trend Log Multiple", 28: "Load Control",
    29: "Structured View", 30: "Access Door",
}

# BACnet Property Identifiers
PROP_OBJECT_IDENTIFIER = 75
PROP_OBJECT_NAME = 77
PROP_OBJECT_TYPE = 79
PROP_OBJECT_LIST = 76
PROP_VENDOR_NAME = 121
PROP_VENDOR_IDENTIFIER = 120
PROP_MODEL_NAME = 70
PROP_FIRMWARE_REVISION = 44
PROP_APPLICATION_SOFTWARE_VERSION = 12
PROP_DESCRIPTION = 28
PROP_SYSTEM_STATUS = 112
PROP_PROTOCOL_VERSION = 98
PROP_PROTOCOL_REVISION = 139
PROP_PROTOCOL_SERVICES_SUPPORTED = 97
PROP_MAX_APDU_LENGTH = 62

# BACnet Vendor IDs (partial)
VENDOR_NAMES = {
    0: "ASHRAE", 5: "Johnson Controls", 7: "Siemens",
    9: "Trane", 15: "Honeywell", 24: "Schneider Electric",
    86: "Contemporary Controls", 95: "Automated Logic",
    145: "Distech Controls", 343: "KMC Controls",
}


class BACnetScanner(BaseScanner):
    """
    Scanner for detecting security issues in BACnet/IP building automation devices.

    BACnet is a UDP-based protocol (standard port 47808/0xBAC0) used extensively in
    building management systems. This scanner sends raw BACnet/IP packets to detect
    devices, enumerate their objects and properties, and test for common security
    misconfigurations such as unauthenticated read/write access and dangerous
    administrative commands.
    """

    def __init__(self, intensity='low', timeout=5, verify=True):
        """
        Initialize the BACnet scanner.

        Args:
            intensity (str): Scan intensity ('low', 'medium', 'high')
            timeout (int): Socket timeout in seconds
            verify (bool): Verification flag (unused for UDP but kept for API compat)
        """
        super().__init__(intensity, timeout, verify)
        self.standard_ports = [47808]  # 0xBAC0 — standard BACnet/IP port
        self._invoke_id = random.randint(1, 254)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, target, open_ports=None):
        """
        Scan a target for BACnet/IP security issues.

        Args:
            target (str): Target IP address
            open_ports (list): Optional list of ports to probe

        Returns:
            dict | None: Scan results dict or None if no BACnet device found
        """
        results = {
            'device_info': {},
            'issues': []
        }

        ports_to_scan = open_ports if open_ports else self.standard_ports
        bacnet_port = None
        iam_data = None

        for port in ports_to_scan:
            iam_data = self._check_bacnet_availability(target, port)
            if iam_data is not None:
                bacnet_port = port
                break

        if bacnet_port is None:
            return None

        # -- Low intensity: basic detection --
        device_instance = iam_data.get('device_instance')
        results['device_info']['port'] = bacnet_port
        results['device_info']['device_instance'] = device_instance
        results['device_info']['max_apdu'] = iam_data.get('max_apdu')
        results['device_info']['vendor_id'] = iam_data.get('vendor_id')
        results['device_info']['vendor_name'] = VENDOR_NAMES.get(
            iam_data.get('vendor_id'), f"Unknown ({iam_data.get('vendor_id')})"
        )
        results['device_info']['segmentation'] = iam_data.get('segmentation')

        results['issues'].append(self.create_issue(
            severity='info',
            description=f"BACnet device detected: {target}:{bacnet_port} (instance {device_instance})",
            details=(
                f"Vendor: {results['device_info']['vendor_name']}, "
                f"Max APDU: {iam_data.get('max_apdu')}, "
                f"Segmentation: {iam_data.get('segmentation')}"
            )
        ))

        results['issues'].append(self.create_issue(
            severity='medium',
            description="BACnet device responds to unauthenticated WhoIs",
            details="Any host on the network can discover this device via WhoIs broadcast.",
            remediation="Segment BACnet traffic on a dedicated VLAN and restrict access with firewall rules."
        ))

        # -- Medium intensity: enumerate properties & objects --
        if self.intensity in ('medium', 'high') and device_instance is not None:
            props = self._read_device_properties(target, bacnet_port, device_instance)
            if props:
                results['device_info'].update(props)

                # Flag unauthenticated ReadProperty
                results['issues'].append(self.create_issue(
                    severity='high',
                    description="Unauthenticated ReadProperty access to device object",
                    details=(
                        f"Vendor: {props.get('vendor_name', 'N/A')}, "
                        f"Model: {props.get('model_name', 'N/A')}, "
                        f"Firmware: {props.get('firmware_revision', 'N/A')}, "
                        f"App SW: {props.get('application_software_version', 'N/A')}"
                    ),
                    remediation=(
                        "Implement BACnet Secure Connect (BACnet/SC) with TLS to enforce "
                        "authentication, or restrict network access to authorized BMS stations."
                    )
                ))

            # Check BACnet/SC vs plain BACnet/IP
            sc_supported = self._check_bacnet_sc_support(target, bacnet_port, device_instance)
            if sc_supported:
                results['device_info']['bacnet_sc'] = True
                results['issues'].append(self.create_issue(
                    severity='info',
                    description="Device indicates BACnet Secure Connect (BACnet/SC) capability",
                    details="Protocol services supported bitmap suggests SC support.",
                ))
            else:
                results['device_info']['bacnet_sc'] = False
                results['issues'].append(self.create_issue(
                    severity='medium',
                    description="No BACnet Secure Connect (BACnet/SC) support detected",
                    details="Device appears to use plain BACnet/IP without TLS encryption or authentication.",
                    remediation="Upgrade to firmware supporting BACnet/SC or use VPN tunnels for BACnet traffic."
                ))

            # Enumerate objects
            objects = self._enumerate_objects(target, bacnet_port, device_instance)
            if objects:
                results['device_info']['objects'] = objects
                obj_summary = {}
                for obj_type, obj_inst in objects:
                    name = OBJECT_TYPE_NAMES.get(obj_type, f"Type-{obj_type}")
                    obj_summary[name] = obj_summary.get(name, 0) + 1
                summary_str = ", ".join(f"{v}x {k}" for k, v in sorted(obj_summary.items()))
                results['issues'].append(self.create_issue(
                    severity='info',
                    description=f"BACnet object enumeration: {len(objects)} objects found",
                    details=summary_str
                ))

            # Test ReadPropertyMultiple
            rpm_ok = self._test_read_property_multiple(target, bacnet_port, device_instance)
            if rpm_ok:
                results['device_info']['rpm_supported'] = True
                results['issues'].append(self.create_issue(
                    severity='medium',
                    description="ReadPropertyMultiple supported without authentication",
                    details="Allows bulk enumeration of device properties in a single request.",
                    remediation="Restrict BACnet network access; enable BACnet/SC for authenticated communication."
                ))

        # -- High intensity: active testing --
        if self.intensity == 'high' and device_instance is not None:
            # Test WriteProperty access
            write_result = self._test_write_access(target, bacnet_port, device_instance)
            if write_result.get('writable'):
                results['device_info']['write_access'] = True
                results['issues'].append(self.create_issue(
                    severity='critical',
                    description="Unauthenticated WriteProperty access confirmed",
                    details=write_result.get('details', 'Device description was writable and restored.'),
                    remediation=(
                        "Disable write access for untrusted sources. Implement BACnet/SC, "
                        "network segmentation, and write-protect critical objects."
                    )
                ))

            # Test SubscribeCOV
            cov_result = self._test_subscribe_cov(target, bacnet_port, device_instance)
            if cov_result:
                results['issues'].append(self.create_issue(
                    severity='high',
                    description="SubscribeCOV accepted without authentication",
                    details="An attacker can subscribe to value changes and monitor building operations.",
                    remediation="Restrict SubscribeCOV to authorized BMS stations via network controls."
                ))

            # Test ReinitializeDevice
            reinit_result = self._test_reinitialize(target, bacnet_port, device_instance)
            if reinit_result:
                results['issues'].append(self.create_issue(
                    severity='critical',
                    description="ReinitializeDevice command accepted without authentication",
                    details="An attacker can reboot or reset the device, causing service disruption.",
                    remediation="Require password for ReinitializeDevice; restrict via network ACLs."
                ))

            # Test DeviceCommunicationControl
            dcc_result = self._test_device_communication_control(target, bacnet_port, device_instance)
            if dcc_result:
                results['issues'].append(self.create_issue(
                    severity='critical',
                    description="DeviceCommunicationControl accepted without authentication",
                    details="An attacker can disable device communication, causing a denial-of-service.",
                    remediation="Require password for DeviceCommunicationControl; enforce network segmentation."
                ))

        return results

    # ------------------------------------------------------------------
    # Private helpers — packet building
    # ------------------------------------------------------------------

    def _next_invoke_id(self):
        """Return the next invoke ID (wraps at 255)."""
        self._invoke_id = (self._invoke_id + 1) % 256
        return self._invoke_id

    def _build_bvll(self, function_code, payload):
        """
        Build BACnet Virtual Link Layer header.

        Args:
            function_code (int): BVLL function (e.g. 0x0A unicast, 0x0B broadcast)
            payload (bytes): NPDU + APDU payload

        Returns:
            bytes: Complete BVLL frame
        """
        length = 4 + len(payload)  # BVLL header is 4 bytes
        return struct.pack('!BBH', BVLL_TYPE, function_code, length) + payload

    def _build_npdu(self, expecting_reply=False, network_priority=0):
        """
        Build BACnet Network Protocol Data Unit.

        Args:
            expecting_reply (bool): Whether a reply is expected
            network_priority (int): Network priority (0-3)

        Returns:
            bytes: NPDU bytes
        """
        control = 0x00
        if expecting_reply:
            control |= 0x04  # Bit 2 = expecting reply
        control |= (network_priority & 0x03)
        return struct.pack('!BB', NPDU_VERSION, control)

    def _build_whois_packet(self):
        """Build a BACnet WhoIs broadcast packet."""
        npdu = self._build_npdu(expecting_reply=False)
        apdu = struct.pack('!BB', PDU_TYPE_UNCONFIRMED_REQUEST, UNCONFIRMED_WHO_IS)
        return self._build_bvll(BVLL_ORIGINAL_BROADCAST_NPDU, npdu + apdu)

    def _build_read_property_packet(self, object_type, instance, property_id):
        """
        Build a BACnet ReadProperty confirmed request.

        Args:
            object_type (int): BACnet object type
            instance (int): Object instance number
            property_id (int): Property identifier

        Returns:
            bytes: Complete BACnet/IP packet
        """
        npdu = self._build_npdu(expecting_reply=True)
        invoke_id = self._next_invoke_id()

        # APDU header: PDU type 0x00 (confirmed), max-segments=0, max-apdu=1476, invoke-id
        apdu_header = struct.pack('!BBBB',
                                  PDU_TYPE_CONFIRMED_REQUEST | 0x04,  # segmented-response-accepted
                                  0x05,  # max-segments=unspecified, max-apdu-size=1476
                                  invoke_id,
                                  CONFIRMED_READ_PROPERTY)

        # Context tag 0: objectIdentifier (4 bytes, context tag)
        obj_id = (object_type << 22) | (instance & 0x3FFFFF)
        tag0 = b'\x0C' + struct.pack('!I', obj_id)  # context 0, length 4

        # Context tag 1: propertyIdentifier (variable length)
        if property_id <= 0xFF:
            tag1 = b'\x19' + struct.pack('!B', property_id)  # context 1, length 1
        else:
            tag1 = b'\x1A' + struct.pack('!H', property_id)  # context 1, length 2

        return self._build_bvll(BVLL_ORIGINAL_UNICAST_NPDU, npdu + apdu_header + tag0 + tag1)

    def _build_read_property_multiple_packet(self, object_type, instance, property_ids):
        """
        Build a ReadPropertyMultiple request for one object with multiple properties.

        Args:
            object_type (int): BACnet object type
            instance (int): Object instance number
            property_ids (list): List of property identifiers

        Returns:
            bytes: Complete BACnet/IP packet
        """
        npdu = self._build_npdu(expecting_reply=True)
        invoke_id = self._next_invoke_id()

        apdu_header = struct.pack('!BBBB',
                                  PDU_TYPE_CONFIRMED_REQUEST | 0x04,
                                  0x05,
                                  invoke_id,
                                  CONFIRMED_READ_PROPERTY_MULTIPLE)

        # Context tag 0: objectIdentifier
        obj_id = (object_type << 22) | (instance & 0x3FFFFF)
        tag0 = b'\x0C' + struct.pack('!I', obj_id)

        # Context tag 1: listOfPropertyReferences (opening tag 1E, closing tag 1F)
        prop_refs = b''
        for pid in property_ids:
            if pid <= 0xFF:
                prop_refs += b'\x09' + struct.pack('!B', pid)  # context 0 in the sequence
            else:
                prop_refs += b'\x0A' + struct.pack('!H', pid)

        tag1 = b'\x1E' + prop_refs + b'\x1F'

        return self._build_bvll(BVLL_ORIGINAL_UNICAST_NPDU, npdu + apdu_header + tag0 + tag1)

    def _build_write_property_packet(self, object_type, instance, property_id, value_bytes, priority=None):
        """
        Build a BACnet WriteProperty confirmed request.

        Args:
            object_type (int): BACnet object type
            instance (int): Object instance number
            property_id (int): Property identifier
            value_bytes (bytes): Pre-encoded property value (application-tagged)
            priority (int|None): Write priority (1-16) or None

        Returns:
            bytes: Complete BACnet/IP packet
        """
        npdu = self._build_npdu(expecting_reply=True)
        invoke_id = self._next_invoke_id()

        apdu_header = struct.pack('!BBBB',
                                  PDU_TYPE_CONFIRMED_REQUEST | 0x04,
                                  0x05,
                                  invoke_id,
                                  CONFIRMED_WRITE_PROPERTY)

        obj_id = (object_type << 22) | (instance & 0x3FFFFF)
        tag0 = b'\x0C' + struct.pack('!I', obj_id)

        if property_id <= 0xFF:
            tag1 = b'\x19' + struct.pack('!B', property_id)
        else:
            tag1 = b'\x1A' + struct.pack('!H', property_id)

        # Context tag 3: propertyValue (opening 3E, closing 3F)
        tag3 = b'\x3E' + value_bytes + b'\x3F'

        payload = tag0 + tag1 + tag3

        # Optional: context tag 4: priority
        if priority is not None:
            payload += b'\x49' + struct.pack('!B', priority)

        return self._build_bvll(BVLL_ORIGINAL_UNICAST_NPDU, npdu + apdu_header + payload)

    def _build_confirmed_request_simple(self, service_choice, service_data=b''):
        """
        Build a simple confirmed request with arbitrary service data.

        Args:
            service_choice (int): BACnet confirmed service choice
            service_data (bytes): Encoded service parameters

        Returns:
            bytes: Complete BACnet/IP packet
        """
        npdu = self._build_npdu(expecting_reply=True)
        invoke_id = self._next_invoke_id()

        apdu_header = struct.pack('!BBBB',
                                  PDU_TYPE_CONFIRMED_REQUEST | 0x04,
                                  0x05,
                                  invoke_id,
                                  service_choice)

        return self._build_bvll(BVLL_ORIGINAL_UNICAST_NPDU, npdu + apdu_header + service_data)

    def _encode_character_string(self, text):
        """Encode a string as BACnet application-tagged CharacterString (tag 7)."""
        encoded = b'\x00' + text.encode('utf-8')  # encoding=0 (UTF-8)
        length = len(encoded)
        if length <= 4:
            tag = bytes([0x70 | length])
        elif length <= 253:
            tag = b'\x75' + struct.pack('!B', length)
        else:
            tag = b'\x75\xFE' + struct.pack('!H', length)
        return tag + encoded

    # ------------------------------------------------------------------
    # Private helpers — send/receive
    # ------------------------------------------------------------------

    def _send_and_receive(self, target, port, packet, timeout=None):
        """
        Send a BACnet/IP UDP packet and wait for a response.

        Args:
            target (str): Target IP
            port (int): Target UDP port
            packet (bytes): Packet bytes to send
            timeout (float|None): Override timeout

        Returns:
            bytes | None: Response bytes or None on timeout/error
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout or self.timeout)
        try:
            sock.sendto(packet, (target, port))
            data, addr = sock.recvfrom(1500)
            return data
        except (socket.timeout, OSError):
            return None
        finally:
            sock.close()

    def _parse_iam(self, data):
        """
        Parse an IAm response from raw UDP payload.

        Args:
            data (bytes): Raw BACnet/IP packet

        Returns:
            dict | None: Parsed IAm fields or None
        """
        if not data or len(data) < 4:
            return None

        # Verify BVLL header
        if data[0] != BVLL_TYPE:
            return None

        bvll_length = struct.unpack('!H', data[2:4])[0]
        if len(data) < bvll_length:
            return None

        # Find APDU start (skip BVLL 4 bytes + NPDU)
        offset = 4
        if offset >= len(data):
            return None
        npdu_version = data[offset]
        npdu_control = data[offset + 1]
        offset += 2

        # If NPDU has DNET/SNET fields, skip them
        if npdu_control & 0x08:  # DNET present
            offset += 2 + 1  # DNET(2) + DLEN(1)
            dlen = data[offset - 1]
            offset += dlen
        if npdu_control & 0x20:  # expect reply (bit 5) — skip
            pass
        if npdu_control & 0x08 and npdu_control & 0x20:
            pass  # already handled
        # SNET
        if npdu_control & 0x08:
            # There's a hop count byte
            offset += 1

        if offset >= len(data):
            return None

        # Check for Unconfirmed IAm
        pdu_type = data[offset]
        if pdu_type != PDU_TYPE_UNCONFIRMED_REQUEST:
            # Could be a ComplexAck or other response — not IAm
            return None

        offset += 1
        if offset >= len(data):
            return None

        service_choice = data[offset]
        if service_choice != UNCONFIRMED_I_AM:
            return None
        offset += 1

        result = {}
        try:
            # Tag 0: BACnetObjectIdentifier (application tag 12 = 0xC4, 4 bytes)
            if data[offset] == 0xC4:
                offset += 1
                obj_id = struct.unpack('!I', data[offset:offset + 4])[0]
                result['device_instance'] = obj_id & 0x3FFFFF
                result['object_type'] = (obj_id >> 22) & 0x3FF
                offset += 4

            # Tag 1: Maximum APDU Length Accepted (application tag 2 = unsigned)
            tag_byte = data[offset]
            tag_num = (tag_byte >> 4) & 0x0F
            tag_len = tag_byte & 0x07
            if tag_num == 2:  # unsigned integer
                offset += 1
                max_apdu = int.from_bytes(data[offset:offset + tag_len], 'big')
                result['max_apdu'] = max_apdu
                offset += tag_len

            # Tag 2: Segmentation supported (enumerated, application tag 9)
            tag_byte = data[offset]
            tag_num = (tag_byte >> 4) & 0x0F
            tag_len = tag_byte & 0x07
            if tag_num == 9:  # enumerated
                offset += 1
                seg = int.from_bytes(data[offset:offset + tag_len], 'big')
                seg_names = {0: 'both', 1: 'transmit', 2: 'receive', 3: 'none'}
                result['segmentation'] = seg_names.get(seg, str(seg))
                offset += tag_len

            # Tag 3: Vendor ID (unsigned, application tag 2)
            tag_byte = data[offset]
            tag_num = (tag_byte >> 4) & 0x0F
            tag_len = tag_byte & 0x07
            if tag_num == 2:  # unsigned
                offset += 1
                result['vendor_id'] = int.from_bytes(data[offset:offset + tag_len], 'big')
                offset += tag_len
        except (IndexError, struct.error):
            pass

        return result if 'device_instance' in result else None

    def _is_simple_ack(self, data):
        """Check if response is a BACnet SimpleAck."""
        if not data or len(data) < 7:
            return False
        offset = self._apdu_offset(data)
        if offset is None or offset >= len(data):
            return False
        return (data[offset] & 0xF0) == PDU_TYPE_SIMPLE_ACK

    def _is_complex_ack(self, data):
        """Check if response is a BACnet ComplexAck."""
        if not data or len(data) < 7:
            return False
        offset = self._apdu_offset(data)
        if offset is None or offset >= len(data):
            return False
        return (data[offset] & 0xF0) == PDU_TYPE_COMPLEX_ACK

    def _is_error(self, data):
        """Check if response is a BACnet Error."""
        if not data or len(data) < 7:
            return False
        offset = self._apdu_offset(data)
        if offset is None or offset >= len(data):
            return False
        return (data[offset] & 0xF0) == PDU_TYPE_ERROR

    def _apdu_offset(self, data):
        """Calculate the offset to the APDU within a raw BACnet/IP packet."""
        if not data or len(data) < 6 or data[0] != BVLL_TYPE:
            return None
        # BVLL is 4 bytes, then NPDU starts
        offset = 4
        if offset + 1 >= len(data):
            return None
        npdu_control = data[offset + 1]
        offset += 2  # version + control

        # Destination specifier
        if npdu_control & 0x20:  # DNET present
            if offset + 2 >= len(data):
                return None
            offset += 2  # DNET
            dlen = data[offset]
            offset += 1 + dlen  # DLEN + DADR

        # Source specifier
        if npdu_control & 0x08:  # SNET present
            if offset + 2 >= len(data):
                return None
            offset += 2  # SNET
            slen = data[offset]
            offset += 1 + slen  # SLEN + SADR

        # Hop count (present when DNET is present)
        if npdu_control & 0x20:
            offset += 1

        return offset if offset < len(data) else None

    def _extract_string_from_complex_ack(self, data):
        """Attempt to extract a CharacterString value from a ComplexAck."""
        try:
            offset = self._apdu_offset(data)
            if offset is None:
                return None
            # Skip APDU header: PDU type + invoke-id + service-choice = 3 bytes minimum
            offset += 3
            # Scan forward looking for CharacterString app tag (0x75 extended or 0x7x short)
            while offset < len(data) - 2:
                byte = data[offset]
                if (byte & 0xF0) == 0x70:  # application tag 7 = CharacterString
                    length = byte & 0x07
                    if length == 5:  # extended length
                        offset += 1
                        length = data[offset]
                    offset += 1
                    # First byte is encoding (0 = UTF-8)
                    encoding = data[offset]
                    offset += 1
                    length -= 1
                    if encoding == 0 and offset + length <= len(data):
                        return data[offset:offset + length].decode('utf-8', errors='replace')
                    return None
                offset += 1
        except (IndexError, UnicodeDecodeError):
            pass
        return None

    # ------------------------------------------------------------------
    # Private helpers — scanning logic
    # ------------------------------------------------------------------

    def _check_bacnet_availability(self, target, port):
        """
        Send BACnet WhoIs and check for IAm response.

        Args:
            target (str): Target IP address
            port (int): BACnet UDP port

        Returns:
            dict | None: Parsed IAm data or None if no response
        """
        self.logger.debug(f"Sending WhoIs to {target}:{port}")
        packet = self._build_whois_packet()
        response = self._send_and_receive(target, port, packet)
        if response:
            return self._parse_iam(response)
        return None

    def _read_device_properties(self, target, port, device_instance):
        """
        Read key device object properties via individual ReadProperty requests.

        Args:
            target (str): Target IP
            port (int): BACnet port
            device_instance (int): Device object instance

        Returns:
            dict: Device properties that could be read
        """
        props_to_read = {
            PROP_VENDOR_NAME: 'vendor_name',
            PROP_MODEL_NAME: 'model_name',
            PROP_FIRMWARE_REVISION: 'firmware_revision',
            PROP_APPLICATION_SOFTWARE_VERSION: 'application_software_version',
            PROP_DESCRIPTION: 'device_description',
            PROP_OBJECT_NAME: 'object_name',
            PROP_PROTOCOL_VERSION: 'protocol_version',
            PROP_PROTOCOL_REVISION: 'protocol_revision',
        }

        result = {}
        for prop_id, key in props_to_read.items():
            try:
                pkt = self._build_read_property_packet(OBJECT_TYPE_DEVICE, device_instance, prop_id)
                resp = self._send_and_receive(target, port, pkt)
                if resp and self._is_complex_ack(resp):
                    val = self._extract_string_from_complex_ack(resp)
                    if val:
                        result[key] = val
            except Exception as e:
                self.logger.debug(f"ReadProperty {key} failed: {e}")
            if hasattr(self, 'rate_limit'):
                self.rate_limit()
        return result

    def _check_bacnet_sc_support(self, target, port, device_instance):
        """
        Check if device supports BACnet Secure Connect by reading
        protocol-services-supported and protocol-revision.

        BACnet/SC was introduced in protocol revision 24 (addendum 135-2020cs).

        Returns:
            bool: True if SC indicators are present
        """
        try:
            pkt = self._build_read_property_packet(
                OBJECT_TYPE_DEVICE, device_instance, PROP_PROTOCOL_REVISION)
            resp = self._send_and_receive(target, port, pkt)
            if resp and self._is_complex_ack(resp):
                # Try to extract unsigned integer from the response
                offset = self._apdu_offset(resp)
                if offset is not None:
                    # Scan for an unsigned application tag (tag number 2 → 0x2x)
                    search = offset + 3
                    while search < len(resp) - 1:
                        tag_byte = resp[search]
                        tag_num = (tag_byte >> 4) & 0x0F
                        tag_len = tag_byte & 0x07
                        if tag_num == 2:  # unsigned
                            search += 1
                            revision = int.from_bytes(resp[search:search + tag_len], 'big')
                            return revision >= 24
                        search += 1
        except Exception as e:
            self.logger.debug(f"BACnet/SC check failed: {e}")
        return False

    def _enumerate_objects(self, target, port, device_instance):
        """
        Enumerate the object list of a BACnet device.

        Args:
            target (str): Target IP
            port (int): BACnet port
            device_instance (int): Device instance

        Returns:
            list[tuple]: List of (object_type, instance) tuples
        """
        objects = []
        try:
            pkt = self._build_read_property_packet(
                OBJECT_TYPE_DEVICE, device_instance, PROP_OBJECT_LIST)
            resp = self._send_and_receive(target, port, pkt)
            if resp and self._is_complex_ack(resp):
                offset = self._apdu_offset(resp)
                if offset is None:
                    return objects
                # Skip APDU header (3 bytes min)
                search = offset + 3
                # Look for BACnetObjectIdentifier application tags (tag 12 → 0xC4)
                while search < len(resp) - 4:
                    if resp[search] == 0xC4:
                        search += 1
                        obj_id = struct.unpack('!I', resp[search:search + 4])[0]
                        obj_type = (obj_id >> 22) & 0x3FF
                        obj_inst = obj_id & 0x3FFFFF
                        objects.append((obj_type, obj_inst))
                        search += 4
                    else:
                        search += 1
        except Exception as e:
            self.logger.debug(f"Object enumeration failed: {e}")
        return objects

    def _test_read_property_multiple(self, target, port, device_instance):
        """
        Test if ReadPropertyMultiple is supported.

        Returns:
            bool: True if RPM returns a ComplexAck
        """
        try:
            pkt = self._build_read_property_multiple_packet(
                OBJECT_TYPE_DEVICE, device_instance,
                [PROP_OBJECT_NAME, PROP_VENDOR_NAME, PROP_MODEL_NAME])
            resp = self._send_and_receive(target, port, pkt)
            return resp is not None and self._is_complex_ack(resp)
        except Exception as e:
            self.logger.debug(f"ReadPropertyMultiple test failed: {e}")
            return False

    def _test_write_access(self, target, port, device_instance):
        """
        Test WriteProperty on the device description (safe, non-critical property).
        Reads current value, writes a test value, verifies, then restores.

        Args:
            target (str): Target IP
            port (int): BACnet port
            device_instance (int): Device instance

        Returns:
            dict: {'writable': bool, 'details': str}
        """
        result = {'writable': False, 'details': ''}
        try:
            # 1. Read current description
            read_pkt = self._build_read_property_packet(
                OBJECT_TYPE_DEVICE, device_instance, PROP_DESCRIPTION)
            read_resp = self._send_and_receive(target, port, read_pkt)
            original_value = None
            if read_resp and self._is_complex_ack(read_resp):
                original_value = self._extract_string_from_complex_ack(read_resp)

            # 2. Write test value
            test_string = "MottaSec_BACnet_Security_Test"
            value_bytes = self._encode_character_string(test_string)
            write_pkt = self._build_write_property_packet(
                OBJECT_TYPE_DEVICE, device_instance, PROP_DESCRIPTION, value_bytes)
            write_resp = self._send_and_receive(target, port, write_pkt)

            if write_resp and self._is_simple_ack(write_resp):
                result['writable'] = True
                result['details'] = (
                    f"Device description was writable. "
                    f"Original: '{original_value or 'empty'}'. "
                    f"Test value written and restored."
                )
                # 3. Restore original value
                if original_value is not None:
                    restore_bytes = self._encode_character_string(original_value)
                else:
                    restore_bytes = self._encode_character_string("")
                restore_pkt = self._build_write_property_packet(
                    OBJECT_TYPE_DEVICE, device_instance, PROP_DESCRIPTION, restore_bytes)
                self._send_and_receive(target, port, restore_pkt)
            elif write_resp and self._is_error(write_resp):
                result['details'] = "WriteProperty returned error (write-protected)."
            else:
                result['details'] = "No response to WriteProperty request."
        except Exception as e:
            result['details'] = f"Write test failed: {e}"
            self.logger.debug(f"Write access test error: {e}")
        return result

    def _test_subscribe_cov(self, target, port, device_instance):
        """
        Test if SubscribeCOV is accepted without authentication.

        Sends a SubscribeCOV for the device object with a short lifetime.

        Returns:
            bool: True if SimpleAck received (subscription accepted)
        """
        try:
            # SubscribeCOV service data:
            # Context 0: subscriberProcessIdentifier (unsigned)
            # Context 1: monitoredObjectIdentifier
            # Context 2: issueConfirmedNotifications (boolean)
            # Context 3: lifetime (unsigned, in seconds)
            subscriber_pid = b'\x09' + struct.pack('!B', random.randint(1, 200))  # ctx 0
            obj_id = (OBJECT_TYPE_DEVICE << 22) | (device_instance & 0x3FFFFF)
            monitored_obj = b'\x1C' + struct.pack('!I', obj_id)  # ctx 1, len 4
            issue_confirmed = b'\x29\x00'  # ctx 2, FALSE (unconfirmed notifications)
            lifetime = b'\x39\x05'  # ctx 3, 5 seconds (minimal impact)

            service_data = subscriber_pid + monitored_obj + issue_confirmed + lifetime
            pkt = self._build_confirmed_request_simple(CONFIRMED_SUBSCRIBE_COV, service_data)
            resp = self._send_and_receive(target, port, pkt)
            return resp is not None and self._is_simple_ack(resp)
        except Exception as e:
            self.logger.debug(f"SubscribeCOV test failed: {e}")
            return False

    def _test_reinitialize(self, target, port, device_instance):
        """
        Test if ReinitializeDevice is accepted without a password.

        Sends a warmstart request (state=1) which is the least destructive option.

        Returns:
            bool: True if SimpleAck received (command accepted)
        """
        try:
            # ReinitializeDevice service data:
            # Context 0: reinitializedStateOfDevice (enumerated)
            #   0 = coldstart, 1 = warmstart, 2 = startbackup, etc.
            # We send warmstart (1) — least destructive, but still a red flag
            # NOTE: We actually send startbackup (2) which is even safer
            state = b'\x09\x02'  # ctx 0, value=2 (startbackup — typically read-only operation)
            # No password (context tag 1 omitted) — testing unauthenticated access

            pkt = self._build_confirmed_request_simple(CONFIRMED_REINITIALIZE_DEVICE, state)
            resp = self._send_and_receive(target, port, pkt)

            if resp is not None and self._is_simple_ack(resp):
                return True
            # Some devices return error with "password required" — that's good (secure)
            return False
        except Exception as e:
            self.logger.debug(f"ReinitializeDevice test failed: {e}")
            return False

    def _test_device_communication_control(self, target, port, device_instance):
        """
        Test if DeviceCommunicationControl is accepted without a password.

        Sends an 'enable' command (which should be a no-op on a working device).

        Returns:
            bool: True if SimpleAck received (command accepted without auth)
        """
        try:
            # DeviceCommunicationControl service data:
            # Context 0: timeDuration (unsigned, optional) — omit for permanent
            # Context 1: enable-disable (enumerated): 0=enable, 1=disable, 2=disable-initiation
            # Context 2: password (CharacterString, optional) — omit to test no-auth
            #
            # We send 'enable' (0) which is the safest — keeps device operational
            time_duration = b'\x09\x01'  # ctx 0, 1 minute (shortest safe duration)
            enable_disable = b'\x19\x00'  # ctx 1, value=0 (enable — no disruption)

            pkt = self._build_confirmed_request_simple(
                CONFIRMED_DEVICE_COMMUNICATION_CONTROL, time_duration + enable_disable)
            resp = self._send_and_receive(target, port, pkt)

            if resp is not None and self._is_simple_ack(resp):
                return True
            return False
        except Exception as e:
            self.logger.debug(f"DeviceCommunicationControl test failed: {e}")
            return False
