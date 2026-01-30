#!/usr/bin/env python3
"""
SNMP protocol scanner for detecting security issues in SNMP-enabled ICS devices.
Supports SNMPv1, SNMPv2c, and SNMPv3 detection with proper BER/ASN.1 encoding.

Part of the ICS Ninja Scanner project.
"""

import socket
import struct
import time
import random
from scanners.base_scanner import BaseScanner

# SNMP version constants
SNMP_VERSION_1 = 0
SNMP_VERSION_2C = 1
SNMP_VERSION_3 = 3

# ASN.1/BER tag constants
TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30
TAG_GET_REQUEST = 0xA0
TAG_GET_NEXT_REQUEST = 0xA1
TAG_GET_RESPONSE = 0xA2
TAG_SET_REQUEST = 0xA3
TAG_GET_BULK_REQUEST = 0xA5
TAG_COUNTER32 = 0x41
TAG_GAUGE32 = 0x42
TAG_TIMETICKS = 0x43
TAG_COUNTER64 = 0x46
TAG_NO_SUCH_OBJECT = 0x80
TAG_NO_SUCH_INSTANCE = 0x81
TAG_END_OF_MIB = 0x82

# Well-known OIDs as tuples
OID_SYS_DESCR = (1, 3, 6, 1, 2, 1, 1, 1, 0)
OID_SYS_OBJECT_ID = (1, 3, 6, 1, 2, 1, 1, 2, 0)
OID_SYS_UPTIME = (1, 3, 6, 1, 2, 1, 1, 3, 0)
OID_SYS_CONTACT = (1, 3, 6, 1, 2, 1, 1, 4, 0)
OID_SYS_NAME = (1, 3, 6, 1, 2, 1, 1, 5, 0)
OID_SYS_LOCATION = (1, 3, 6, 1, 2, 1, 1, 6, 0)
OID_MIB2_BASE = (1, 3, 6, 1, 2, 1)
OID_TRAP_ENABLED = (1, 3, 6, 1, 6, 3, 1, 1, 6, 1, 0)
OID_TRAP_DEST_BASE = (1, 3, 6, 1, 6, 3, 12, 1, 3)

# Common SNMP community strings to check
DEFAULT_COMMUNITY_STRINGS = [
    # Standard defaults
    'public', 'private', 'manager', 'admin', 'cisco', 'secret',
    'supervisor', 'guest', 'system', 'device', 'scada', 'plc',
    'router', 'switch', 'control', 'automation', 'remote', 'write',
    # ICS vendor specific
    'siemens', 'rockwell', 'schneider', 'honeywell', 'emerson', 'abb',
    'yokogawa', 'ge', 'omron', 'mitsubishi', 'allen-bradley',
]


# ---------------------------------------------------------------------------
# BER Encoder helpers
# ---------------------------------------------------------------------------

def _ber_encode_length(length):
    """Encode a length value in BER format."""
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    else:
        return bytes([0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])


def _ber_encode_tlv(tag, value):
    """Encode a TLV (tag-length-value) triplet."""
    value = bytes(value) if not isinstance(value, bytes) else value
    return bytes([tag]) + _ber_encode_length(len(value)) + value


def _ber_encode_integer(value):
    """Encode an integer in BER format."""
    if value == 0:
        return _ber_encode_tlv(TAG_INTEGER, b'\x00')
    result = []
    if value > 0:
        while value > 0:
            result.insert(0, value & 0xFF)
            value >>= 8
        if result[0] & 0x80:
            result.insert(0, 0)
    else:
        # Negative integers (two's complement)
        value = abs(value) - 1
        while value > 0:
            result.insert(0, (~value) & 0xFF)
            value >>= 8
        if not result:
            result = [0xFF]
        elif not (result[0] & 0x80):
            result.insert(0, 0xFF)
    return _ber_encode_tlv(TAG_INTEGER, bytes(result))


def _ber_encode_octet_string(value):
    """Encode a string (or bytes) as an OCTET STRING."""
    if isinstance(value, str):
        value = value.encode('ascii')
    return _ber_encode_tlv(TAG_OCTET_STRING, value)


def _ber_encode_null():
    """Encode a NULL value."""
    return bytes([TAG_NULL, 0x00])


def _ber_encode_oid(oid_tuple):
    """Encode an OID tuple in BER format."""
    if len(oid_tuple) < 2:
        raise ValueError("OID must have at least 2 components")
    # First two components are encoded as 40 * first + second
    encoded = [40 * oid_tuple[0] + oid_tuple[1]]
    for component in oid_tuple[2:]:
        if component < 0x80:
            encoded.append(component)
        else:
            # Multi-byte encoding for values >= 128
            sub = []
            val = component
            sub.append(val & 0x7F)
            val >>= 7
            while val > 0:
                sub.append((val & 0x7F) | 0x80)
                val >>= 7
            sub.reverse()
            encoded.extend(sub)
    return _ber_encode_tlv(TAG_OID, bytes(encoded))


def _ber_encode_sequence(contents):
    """Wrap contents in a SEQUENCE."""
    if isinstance(contents, (list, tuple)):
        contents = b''.join(contents)
    return _ber_encode_tlv(TAG_SEQUENCE, contents)


# ---------------------------------------------------------------------------
# BER Decoder helpers
# ---------------------------------------------------------------------------

def _ber_decode_length(data, offset):
    """Decode a BER length field. Returns (length, new_offset)."""
    if offset >= len(data):
        raise ValueError("Truncated BER data at length")
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    num_bytes = first & 0x7F
    if num_bytes == 0 or offset + 1 + num_bytes > len(data):
        raise ValueError("Invalid BER length encoding")
    length = 0
    for i in range(num_bytes):
        length = (length << 8) | data[offset + 1 + i]
    return length, offset + 1 + num_bytes


def _ber_decode_tlv(data, offset):
    """Decode one TLV element. Returns (tag, value_bytes, new_offset)."""
    if offset >= len(data):
        raise ValueError("Truncated BER data at tag")
    tag = data[offset]
    length, val_offset = _ber_decode_length(data, offset + 1)
    if val_offset + length > len(data):
        raise ValueError(f"BER value overflows buffer: need {val_offset + length}, have {len(data)}")
    value = data[val_offset:val_offset + length]
    return tag, value, val_offset + length


def _ber_decode_integer(value_bytes):
    """Decode a BER-encoded integer value (raw bytes, no tag/length)."""
    if len(value_bytes) == 0:
        return 0
    result = 0
    negative = value_bytes[0] & 0x80
    for b in value_bytes:
        result = (result << 8) | b
    if negative:
        result -= (1 << (8 * len(value_bytes)))
    return result


def _ber_decode_oid(value_bytes):
    """Decode a BER-encoded OID value (raw bytes). Returns tuple."""
    if len(value_bytes) == 0:
        return ()
    first = value_bytes[0]
    components = [first // 40, first % 40]
    i = 1
    while i < len(value_bytes):
        component = 0
        while i < len(value_bytes):
            byte = value_bytes[i]
            component = (component << 7) | (byte & 0x7F)
            i += 1
            if not (byte & 0x80):
                break
        components.append(component)
    return tuple(components)


def _ber_decode_value(tag, value_bytes):
    """Decode a BER value based on its tag. Returns a Python object."""
    if tag == TAG_INTEGER:
        return _ber_decode_integer(value_bytes)
    elif tag == TAG_OCTET_STRING:
        try:
            return value_bytes.decode('utf-8', errors='replace')
        except Exception:
            return value_bytes.hex()
    elif tag == TAG_OID:
        return _ber_decode_oid(value_bytes)
    elif tag == TAG_NULL:
        return None
    elif tag in (TAG_COUNTER32, TAG_GAUGE32, TAG_TIMETICKS):
        return _ber_decode_integer(value_bytes)
    elif tag == TAG_COUNTER64:
        return _ber_decode_integer(value_bytes)
    elif tag in (TAG_NO_SUCH_OBJECT, TAG_NO_SUCH_INSTANCE, TAG_END_OF_MIB):
        return None
    else:
        # Unknown tag — return raw bytes as hex
        return value_bytes.hex()


def _ber_decode_sequence_items(data):
    """Decode all TLV items inside a SEQUENCE's value bytes. Returns list of (tag, value_bytes)."""
    items = []
    offset = 0
    while offset < len(data):
        tag, value, offset = _ber_decode_tlv(data, offset)
        items.append((tag, value))
    return items


def _ber_decode_response(data):
    """
    Parse a full SNMP response packet.
    Returns dict with: version, community, pdu_type, request_id,
    error_status, error_index, varbinds [(oid_tuple, value), ...].
    Returns None on parse failure.
    """
    try:
        # Outer SEQUENCE
        tag, seq_data, _ = _ber_decode_tlv(data, 0)
        if tag != TAG_SEQUENCE:
            return None

        offset = 0

        # Version (INTEGER)
        tag, val, offset = _ber_decode_tlv(seq_data, offset)
        version = _ber_decode_integer(val)

        # Community (OCTET STRING)
        tag, val, offset = _ber_decode_tlv(seq_data, offset)
        community = val.decode('utf-8', errors='replace')

        # PDU (context-specific tag: 0xA0-0xA5)
        pdu_tag, pdu_data, offset = _ber_decode_tlv(seq_data, offset)

        pdu_offset = 0
        # Request ID
        tag, val, pdu_offset = _ber_decode_tlv(pdu_data, pdu_offset)
        request_id = _ber_decode_integer(val)

        # Error status
        tag, val, pdu_offset = _ber_decode_tlv(pdu_data, pdu_offset)
        error_status = _ber_decode_integer(val)

        # Error index
        tag, val, pdu_offset = _ber_decode_tlv(pdu_data, pdu_offset)
        error_index = _ber_decode_integer(val)

        # Varbind list (SEQUENCE of SEQUENCE)
        tag, varbind_list_data, pdu_offset = _ber_decode_tlv(pdu_data, pdu_offset)

        varbinds = []
        vb_offset = 0
        while vb_offset < len(varbind_list_data):
            # Each varbind is a SEQUENCE of (OID, value)
            vb_tag, vb_data, vb_offset = _ber_decode_tlv(varbind_list_data, vb_offset)
            inner_offset = 0
            oid_tag, oid_val, inner_offset = _ber_decode_tlv(vb_data, inner_offset)
            oid_tuple = _ber_decode_oid(oid_val)
            val_tag, val_bytes, inner_offset = _ber_decode_tlv(vb_data, inner_offset)
            value = _ber_decode_value(val_tag, val_bytes)
            varbinds.append((oid_tuple, value, val_tag))

        return {
            'version': version,
            'community': community,
            'pdu_type': pdu_tag,
            'request_id': request_id,
            'error_status': error_status,
            'error_index': error_index,
            'varbinds': varbinds,
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------

def _build_snmp_get(community, oid_tuple, version=SNMP_VERSION_1, request_id=None):
    """Build an SNMP GET request packet with proper BER encoding."""
    if request_id is None:
        request_id = random.randint(1, 0x7FFFFFFF)
    varbind = _ber_encode_sequence([_ber_encode_oid(oid_tuple), _ber_encode_null()])
    varbind_list = _ber_encode_sequence([varbind])
    pdu_contents = (
        _ber_encode_integer(request_id) +
        _ber_encode_integer(0) +  # error-status
        _ber_encode_integer(0) +  # error-index
        varbind_list
    )
    pdu = _ber_encode_tlv(TAG_GET_REQUEST, pdu_contents)
    message = _ber_encode_sequence([
        _ber_encode_integer(version),
        _ber_encode_octet_string(community),
        pdu,
    ])
    return message, request_id


def _build_snmp_getnext(community, oid_tuple, version=SNMP_VERSION_1, request_id=None):
    """Build an SNMP GetNext request packet."""
    if request_id is None:
        request_id = random.randint(1, 0x7FFFFFFF)
    varbind = _ber_encode_sequence([_ber_encode_oid(oid_tuple), _ber_encode_null()])
    varbind_list = _ber_encode_sequence([varbind])
    pdu_contents = (
        _ber_encode_integer(request_id) +
        _ber_encode_integer(0) +
        _ber_encode_integer(0) +
        varbind_list
    )
    pdu = _ber_encode_tlv(TAG_GET_NEXT_REQUEST, pdu_contents)
    message = _ber_encode_sequence([
        _ber_encode_integer(version),
        _ber_encode_octet_string(community),
        pdu,
    ])
    return message, request_id


def _build_snmp_set(community, oid_tuple, value_tag, value_bytes, version=SNMP_VERSION_1, request_id=None):
    """Build an SNMP SET request packet."""
    if request_id is None:
        request_id = random.randint(1, 0x7FFFFFFF)
    value_tlv = _ber_encode_tlv(value_tag, value_bytes)
    varbind = _ber_encode_sequence([_ber_encode_oid(oid_tuple), value_tlv])
    varbind_list = _ber_encode_sequence([varbind])
    pdu_contents = (
        _ber_encode_integer(request_id) +
        _ber_encode_integer(0) +
        _ber_encode_integer(0) +
        varbind_list
    )
    pdu = _ber_encode_tlv(TAG_SET_REQUEST, pdu_contents)
    message = _ber_encode_sequence([
        _ber_encode_integer(version),
        _ber_encode_octet_string(community),
        pdu,
    ])
    return message, request_id


def _build_snmpv3_discovery():
    """
    Build an SNMPv3 discovery request with empty security parameters.
    This is a minimal USM discovery message (msgFlags = reportable + noAuthNoPriv).
    """
    # msgVersion = 3
    msg_version = _ber_encode_integer(SNMP_VERSION_3)
    # msgGlobalData: SEQUENCE { msgID, msgMaxSize, msgFlags, msgSecurityModel }
    msg_id = _ber_encode_integer(random.randint(1, 0x7FFFFFFF))
    msg_max_size = _ber_encode_integer(65507)
    # msgFlags: reportable (0x04), noAuthNoPriv
    msg_flags = _ber_encode_octet_string(b'\x04')
    msg_security_model = _ber_encode_integer(3)  # USM
    msg_global_data = _ber_encode_sequence([msg_id, msg_max_size, msg_flags, msg_security_model])
    # msgSecurityParameters: empty OCTET STRING wrapping an empty USM SEQUENCE
    usm_params = _ber_encode_sequence([
        _ber_encode_octet_string(b''),       # msgAuthoritativeEngineID
        _ber_encode_integer(0),               # msgAuthoritativeEngineBoots
        _ber_encode_integer(0),               # msgAuthoritativeEngineTime
        _ber_encode_octet_string(b''),       # msgUserName
        _ber_encode_octet_string(b''),       # msgAuthenticationParameters
        _ber_encode_octet_string(b''),       # msgPrivacyParameters
    ])
    msg_security_params = _ber_encode_octet_string(usm_params)
    # ScopedPDU: SEQUENCE { contextEngineID, contextName, PDU }
    # PDU is a GET with empty varbind list
    pdu_contents = (
        _ber_encode_integer(0) +  # request-id
        _ber_encode_integer(0) +  # error-status
        _ber_encode_integer(0) +  # error-index
        _ber_encode_sequence([])  # empty varbind list
    )
    pdu = _ber_encode_tlv(TAG_GET_REQUEST, pdu_contents)
    scoped_pdu = _ber_encode_sequence([
        _ber_encode_octet_string(b''),  # contextEngineID
        _ber_encode_octet_string(b''),  # contextName
        pdu,
    ])
    message = _ber_encode_sequence([msg_version, msg_global_data, msg_security_params, scoped_pdu])
    return message


# ---------------------------------------------------------------------------
# Scanner class
# ---------------------------------------------------------------------------

class SNMPScanner(BaseScanner):
    """Scanner for detecting security issues in SNMP-enabled ICS devices."""

    def __init__(self, intensity='low', timeout=5, verify=True):
        """Initialize the SNMP scanner."""
        super().__init__(intensity, timeout, verify)
        self.standard_ports = [161]

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def scan(self, target, open_ports=None):
        """
        Scan a target for SNMP security issues.

        Args:
            target (str): Target IP address
            open_ports (list): List of open ports (optional)

        Returns:
            dict: Scan results or None if no SNMP detected
        """
        self.logger.debug(f"Starting SNMP scan on {target}")
        results = {
            'device_info': {},
            'issues': [],
        }

        ports_to_scan = open_ports if open_ports else self.standard_ports

        # Detect SNMP on any port
        snmp_port = None
        for port in ports_to_scan:
            if self._check_snmp_availability(target, port):
                snmp_port = port
                break

        if not snmp_port:
            self.logger.debug(f"No SNMP service detected on {target}")
            return None

        results['device_info']['port'] = snmp_port
        results['issues'].append(self.create_issue(
            severity='info',
            description=f"SNMP Service Found: {target}:{snmp_port}",
            details="A device responding to SNMP requests was detected.",
        ))

        # Select community strings based on intensity
        if self.intensity == 'low':
            community_strings = ['public', 'private', 'manager', 'admin']
        elif self.intensity == 'medium':
            community_strings = DEFAULT_COMMUNITY_STRINGS[:15]
        else:
            community_strings = DEFAULT_COMMUNITY_STRINGS

        # Test community strings across v2c then v1
        valid_communities = []  # list of (community, version)

        for community in community_strings:
            try:
                # Try v2c first (more common on modern devices), then v1
                for ver in (SNMP_VERSION_2C, SNMP_VERSION_1):
                    if self._test_community_string(target, snmp_port, community, version=ver):
                        valid_communities.append((community, ver))
                        ver_label = 'v2c' if ver == SNMP_VERSION_2C else 'v1'
                        results['issues'].append(self.create_issue(
                            severity='high',
                            description=f"SNMP access with community string: '{community}' ({ver_label})",
                            details=f"The device allows SNMP {ver_label} access using the community string '{community}'.",
                            remediation="Change default community strings to strong, unique values. Consider using SNMPv3 with authentication and encryption.",
                        ))
                        break  # Don't test v1 if v2c already worked
            except Exception as e:
                self.logger.debug(f"Error testing community string {community}: {e}")
            if hasattr(self, 'rate_limit'):
                self.rate_limit()

        if valid_communities:
            results['device_info']['community_strings'] = [c for c, _ in valid_communities]
            versions_found = set(v for _, v in valid_communities)
            ver_names = []
            if SNMP_VERSION_1 in versions_found:
                ver_names.append('v1')
            if SNMP_VERSION_2C in versions_found:
                ver_names.append('v2c')

            results['issues'].append(self.create_issue(
                severity='high',
                description=f"SNMP {'/'.join(ver_names)} in use (unencrypted)",
                details="SNMPv1/v2c uses unencrypted communications and has weak authentication.",
                remediation="Upgrade to SNMPv3 with authentication and encryption.",
            ))

            # System info retrieval — available at medium+ intensity
            if self.intensity in ('medium', 'high') and valid_communities:
                first_community, first_ver = valid_communities[0]
                try:
                    system_info = self._get_system_info(target, snmp_port, first_community, first_ver)
                    if system_info:
                        results['device_info'].update(system_info)
                        results['issues'].append(self.create_issue(
                            severity='medium',
                            description="SNMP system information disclosure",
                            details=f"System information was disclosed via SNMP: {', '.join(system_info.keys())}",
                            remediation="Restrict access to system OIDs or use SNMPv3 with authentication and encryption.",
                        ))
                except Exception as e:
                    self.logger.debug(f"Error getting system info: {e}")

            # SNMP Walk — available at medium+ intensity
            if self.intensity in ('medium', 'high') and valid_communities:
                first_community, first_ver = valid_communities[0]
                try:
                    walk_count = self._snmp_walk_count(target, snmp_port, first_community, first_ver, max_requests=50)
                    if walk_count > 0:
                        results['device_info']['walkable_oids'] = walk_count
                        severity = 'medium' if walk_count > 20 else 'low'
                        results['issues'].append(self.create_issue(
                            severity=severity,
                            description=f"SNMP walk exposes {walk_count} OIDs from MIB-2 tree",
                            details=f"An SNMP walk from the MIB-2 base returned {walk_count} OIDs (capped at 50). "
                                    "This indicates significant data exposure via SNMP.",
                            remediation="Restrict SNMP views to limit accessible OIDs. Use SNMPv3 with access control.",
                        ))
                except Exception as e:
                    self.logger.debug(f"Error during SNMP walk: {e}")

            # High intensity: write access testing and trap config
            if self.intensity == 'high':
                # Write access testing
                for community, ver in valid_communities:
                    try:
                        if self._test_write_access(target, snmp_port, community, ver):
                            results['device_info'].setdefault('write_communities', []).append(community)
                            results['issues'].append(self.create_issue(
                                severity='critical',
                                description=f"SNMP write access with community string: '{community}'",
                                details=f"The community string '{community}' has write (SET) access. "
                                        "An attacker could modify device configuration.",
                                remediation="Remove write access from default community strings. Use SNMPv3 with authentication.",
                            ))
                    except Exception as e:
                        self.logger.debug(f"Error testing write access for '{community}': {e}")
                    if hasattr(self, 'rate_limit'):
                        self.rate_limit()

                # Trap configuration check
                first_community, first_ver = valid_communities[0]
                try:
                    trap_issues = self._check_trap_config(target, snmp_port, first_community, first_ver)
                    results['issues'].extend(trap_issues)
                except Exception as e:
                    self.logger.debug(f"Error checking trap config: {e}")

        # SNMPv3 detection — all intensity levels
        try:
            if self._detect_snmpv3(target, snmp_port):
                results['device_info']['snmpv3_supported'] = True
                results['issues'].append(self.create_issue(
                    severity='info',
                    description="SNMPv3 supported",
                    details="The device responded to an SNMPv3 discovery request, indicating support for secure SNMP.",
                ))
            else:
                results['device_info']['snmpv3_supported'] = False
        except Exception as e:
            self.logger.debug(f"Error detecting SNMPv3: {e}")

        self.logger.debug(f"Completed SNMP scan on {target}")
        return results

    # ------------------------------------------------------------------
    # Core helpers
    # ------------------------------------------------------------------

    def _send_recv(self, target, port, packet, timeout=None):
        """Send a UDP packet and return the response bytes, or None on timeout/error."""
        if timeout is None:
            timeout = self.timeout
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(packet, (target, port))
            response, _ = sock.recvfrom(4096)
            return response
        except socket.timeout:
            return None
        except Exception as e:
            self.logger.debug(f"Send/recv error: {e}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def _check_snmp_availability(self, target, port):
        """Check if SNMP is available on target:port by sending a GET for sysDescr."""
        # Try v2c first, then v1
        for ver in (SNMP_VERSION_2C, SNMP_VERSION_1):
            packet, _ = _build_snmp_get('public', OID_SYS_DESCR, version=ver)
            response = self._send_recv(target, port, packet)
            if response and len(response) > 0:
                return True
        return False

    def _test_community_string(self, target, port, community, version=SNMP_VERSION_2C):
        """Test if a community string is valid for the given SNMP version."""
        packet, req_id = _build_snmp_get(community, OID_SYS_DESCR, version=version)
        response = self._send_recv(target, port, packet)
        if not response:
            return False
        parsed = _ber_decode_response(response)
        if parsed is None:
            return False
        # Valid if no error and we got a response PDU
        return parsed['error_status'] == 0 and parsed['pdu_type'] == TAG_GET_RESPONSE

    def _snmp_get(self, target, port, community, oid_tuple, version=SNMP_VERSION_1):
        """Perform an SNMP GET and return the parsed response dict, or None."""
        packet, req_id = _build_snmp_get(community, oid_tuple, version=version)
        response = self._send_recv(target, port, packet)
        if not response:
            return None
        return _ber_decode_response(response)

    def _snmp_getnext(self, target, port, community, oid_tuple, version=SNMP_VERSION_1):
        """Perform an SNMP GetNext and return the parsed response dict, or None."""
        packet, req_id = _build_snmp_getnext(community, oid_tuple, version=version)
        response = self._send_recv(target, port, packet)
        if not response:
            return None
        return _ber_decode_response(response)

    # ------------------------------------------------------------------
    # Feature implementations
    # ------------------------------------------------------------------

    def _get_system_info(self, target, port, community, version=SNMP_VERSION_1):
        """Get system information via SNMP GET requests."""
        system_info = {}
        oid_map = {
            OID_SYS_DESCR: 'sysDescr',
            OID_SYS_NAME: 'sysName',
            OID_SYS_LOCATION: 'sysLocation',
            OID_SYS_CONTACT: 'sysContact',
            OID_SYS_OBJECT_ID: 'sysObjectID',
            OID_SYS_UPTIME: 'sysUpTime',
        }
        for oid, name in oid_map.items():
            try:
                parsed = self._snmp_get(target, port, community, oid, version=version)
                if parsed and parsed['error_status'] == 0 and parsed['varbinds']:
                    _, value, val_tag = parsed['varbinds'][0]
                    if value is not None and val_tag not in (TAG_NO_SUCH_OBJECT, TAG_NO_SUCH_INSTANCE, TAG_END_OF_MIB):
                        if isinstance(value, tuple):
                            # OID value — format as dotted string
                            system_info[name] = '.'.join(str(c) for c in value)
                        else:
                            system_info[name] = str(value)
            except Exception as e:
                self.logger.debug(f"SNMP GET {name} failed: {e}")
            if hasattr(self, 'rate_limit'):
                self.rate_limit()
        return system_info

    def _snmp_walk_count(self, target, port, community, version=SNMP_VERSION_1, max_requests=50):
        """
        Walk the MIB-2 tree using GetNext requests and count the number of OIDs returned.
        Returns the count of walkable OIDs (up to max_requests).
        """
        current_oid = OID_MIB2_BASE
        count = 0
        for _ in range(max_requests):
            parsed = self._snmp_getnext(target, port, community, current_oid, version=version)
            if not parsed or parsed['error_status'] != 0 or not parsed['varbinds']:
                break
            next_oid, value, val_tag = parsed['varbinds'][0]
            # Stop if we've left the MIB-2 subtree or hit end-of-mib
            if val_tag in (TAG_END_OF_MIB, TAG_NO_SUCH_OBJECT, TAG_NO_SUCH_INSTANCE):
                break
            if not isinstance(next_oid, tuple) or len(next_oid) < len(OID_MIB2_BASE):
                break
            if next_oid[:len(OID_MIB2_BASE)] != OID_MIB2_BASE:
                break
            # Ensure forward progress
            if next_oid <= current_oid:
                break
            current_oid = next_oid
            count += 1
            if hasattr(self, 'rate_limit'):
                self.rate_limit()
        return count

    def _test_write_access(self, target, port, community, version=SNMP_VERSION_1):
        """
        Test write access by reading sysContact, then writing the same value back.
        Returns True if write succeeded.
        """
        # Read current value
        parsed = self._snmp_get(target, port, community, OID_SYS_CONTACT, version=version)
        if not parsed or parsed['error_status'] != 0 or not parsed['varbinds']:
            return False
        _, current_value, val_tag = parsed['varbinds'][0]
        if val_tag in (TAG_NO_SUCH_OBJECT, TAG_NO_SUCH_INSTANCE, TAG_END_OF_MIB):
            return False

        # Write the same value back (safe — no change to device)
        if isinstance(current_value, str):
            write_bytes = current_value.encode('utf-8', errors='replace')
        elif isinstance(current_value, bytes):
            write_bytes = current_value
        else:
            write_bytes = str(current_value).encode('ascii')

        req_id = random.randint(1, 0x7FFFFFFF)
        packet, _ = _build_snmp_set(community, OID_SYS_CONTACT, TAG_OCTET_STRING, write_bytes, version=version, request_id=req_id)
        response = self._send_recv(target, port, packet)
        if not response:
            return False
        resp_parsed = _ber_decode_response(response)
        if not resp_parsed:
            return False
        return resp_parsed['error_status'] == 0

    def _check_trap_config(self, target, port, community, version=SNMP_VERSION_1):
        """
        Check trap configuration OIDs. Returns a list of issues found.
        """
        issues = []

        # Check snmpTrapEnabled
        parsed = self._snmp_get(target, port, community, OID_TRAP_ENABLED, version=version)
        if parsed and parsed['error_status'] == 0 and parsed['varbinds']:
            _, value, val_tag = parsed['varbinds'][0]
            if val_tag not in (TAG_NO_SUCH_OBJECT, TAG_NO_SUCH_INSTANCE, TAG_END_OF_MIB):
                if value == 2:  # disabled
                    issues.append(self.create_issue(
                        severity='medium',
                        description="SNMP traps are disabled",
                        details="snmpTrapEnabled is set to disabled (2). Traps are important for monitoring device events.",
                        remediation="Enable SNMP traps and configure a trap receiver for security monitoring.",
                    ))

        # Check trap destination — walk the trap target table
        parsed = self._snmp_getnext(target, port, community, OID_TRAP_DEST_BASE, version=version)
        if parsed and parsed['error_status'] == 0 and parsed['varbinds']:
            next_oid, value, val_tag = parsed['varbinds'][0]
            if isinstance(next_oid, tuple) and next_oid[:len(OID_TRAP_DEST_BASE)] == OID_TRAP_DEST_BASE:
                if val_tag not in (TAG_NO_SUCH_OBJECT, TAG_NO_SUCH_INSTANCE, TAG_END_OF_MIB):
                    issues.append(self.create_issue(
                        severity='info',
                        description="SNMP trap destination configured",
                        details=f"A trap target entry was found in the snmpTargetAddrTable.",
                    ))
            else:
                issues.append(self.create_issue(
                    severity='medium',
                    description="No SNMP trap destination configured",
                    details="No entries found in snmpTargetAddrTable. Traps may not be delivered to any receiver.",
                    remediation="Configure an SNMP trap destination to receive alerts from this device.",
                ))
        else:
            # Could not read trap destination table at all
            if parsed and parsed['error_status'] != 0:
                pass  # Access denied — not necessarily misconfigured

        return issues

    def _detect_snmpv3(self, target, port):
        """
        Send an SNMPv3 discovery request. Returns True if the device responds.
        """
        packet = _build_snmpv3_discovery()
        response = self._send_recv(target, port, packet, timeout=min(self.timeout, 3))
        if not response or len(response) < 10:
            return False
        # Verify it's an SNMP response by checking outer SEQUENCE tag
        try:
            tag, seq_data, _ = _ber_decode_tlv(response, 0)
            if tag != TAG_SEQUENCE:
                return False
            # Check version field is 3
            vtag, vval, _ = _ber_decode_tlv(seq_data, 0)
            if vtag == TAG_INTEGER and _ber_decode_integer(vval) == SNMP_VERSION_3:
                return True
        except Exception:
            pass
        return False
