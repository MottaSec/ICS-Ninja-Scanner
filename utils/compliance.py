#!/usr/bin/env python3
"""
Compliance Mapping Module for MottaSec ICS Ninja Scanner.

Maps scanner findings to ICS security standards and frameworks:
  - IEC 62443 (Industrial Automation and Control Systems Security)
  - NIST SP 800-82 (Guide to ICS Security)
  - NERC CIP (Critical Infrastructure Protection)

Each mapping includes the framework, requirement ID, title, description,
and a violation explanation tied to the specific finding.
"""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Compliance violation data class (plain dict)
# ---------------------------------------------------------------------------

def _violation(
    framework: str,
    requirement_id: str,
    requirement_title: str,
    description: str,
    violation_explanation: str,
) -> Dict[str, str]:
    """Create a single compliance violation record."""
    return {
        "framework": framework,
        "requirement_id": requirement_id,
        "requirement_title": requirement_title,
        "description": description,
        "violation_explanation": violation_explanation,
    }


# ---------------------------------------------------------------------------
# Mapping pattern definitions
# ---------------------------------------------------------------------------
# Each pattern has:
#   keywords   – list of regex patterns matched against finding description
#   severities – optional set of severities that must match (None = any)
#   violations – list of violation dicts to emit when matched

_MAPPING_PATTERNS: List[Dict[str, Any]] = [
    # 1 — No Authentication / Default Credentials
    {
        "id": "AUTH_NONE",
        "keywords": [
            r"no\s+auth",
            r"default\s+(credential|password)",
            r"anonymous\s+access",
            r"unauthenticated",
            r"authentication\s+(not|disabled|missing|absent)",
        ],
        "severities": None,
        "violations": [
            _violation(
                "IEC 62443",
                "IEC 62443-3-3 SR 1.1",
                "Human User Identification and Authentication",
                "All human users shall be identified and authenticated before "
                "accessing the IACS.",
                "Finding indicates missing or default authentication, allowing "
                "unauthorized access to industrial control components.",
            ),
            _violation(
                "IEC 62443",
                "IEC 62443-4-2 CR 1.1",
                "Component Human User Identification and Authentication",
                "Components shall identify and authenticate all human users.",
                "The component does not enforce user authentication, violating "
                "component-level access control requirements.",
            ),
            _violation(
                "NIST SP 800-82",
                "NIST SP 800-82 §6.2.1",
                "Identification and Authentication",
                "ICS should authenticate all users before granting access to "
                "system resources.",
                "The scanned device allows unauthenticated access, violating "
                "NIST ICS authentication guidance.",
            ),
            _violation(
                "NERC CIP",
                "CIP-007-6 R5",
                "System Access Controls",
                "Responsible entities shall enforce authentication of "
                "interactive user access.",
                "Missing or default credentials violate NERC CIP requirements "
                "for proper system access controls.",
            ),
        ],
    },
    # 2 — Unencrypted Communications / Cleartext Protocols
    {
        "id": "CLEARTEXT",
        "keywords": [
            r"unencrypted",
            r"clear\s*text",
            r"no\s+(ssl|tls|encryption)",
            r"plain\s*text\s+(protocol|communication|traffic)",
            r"encryption\s+(not|disabled|missing|absent)",
        ],
        "severities": None,
        "violations": [
            _violation(
                "IEC 62443",
                "IEC 62443-3-3 SR 4.1",
                "Communication Integrity",
                "The control system shall protect the integrity of transmitted "
                "information.",
                "Unencrypted communications allow interception and "
                "manipulation of ICS traffic.",
            ),
            _violation(
                "IEC 62443",
                "IEC 62443-3-3 SR 4.3",
                "Cryptographic Integrity Protection",
                "Cryptographic mechanisms shall protect communication integrity "
                "at SL2 and above.",
                "Cleartext protocols fail to provide cryptographic protection "
                "required at Security Level 2+.",
            ),
            _violation(
                "NIST SP 800-82",
                "NIST SP 800-82 §6.2.6",
                "Encryption of ICS Communications",
                "ICS communications should be encrypted where feasible.",
                "Finding reveals unencrypted ICS traffic, violating NIST "
                "guidance on protecting data in transit.",
            ),
            _violation(
                "NERC CIP",
                "CIP-012-1 R1",
                "Real-time Assessment and Monitoring Data Protection",
                "Protect real-time assessment and monitoring data during "
                "transmission.",
                "Unencrypted communications expose control data, violating "
                "NERC CIP data protection requirements.",
            ),
        ],
    },
    # 3 — Open / Exposed ICS Ports
    {
        "id": "OPEN_PORTS",
        "keywords": [
            r"open\s+port",
            r"exposed\s+(service|port|interface)",
            r"port\s+\d+\s+open",
            r"listening\s+on",
            r"accessible\s+(from|on)\s+network",
        ],
        "severities": None,
        "violations": [
            _violation(
                "IEC 62443",
                "IEC 62443-3-3 SR 5.1",
                "Network Segmentation",
                "The control system network shall be segmented into zones and "
                "conduits.",
                "Exposed ICS ports indicate inadequate network segmentation, "
                "violating zone/conduit architecture requirements.",
            ),
            _violation(
                "NIST SP 800-82",
                "NIST SP 800-82 §5.1",
                "Network Architecture",
                "ICS networks should implement defense-in-depth through proper "
                "segmentation.",
                "Open ICS service ports suggest flat network architecture "
                "without adequate separation.",
            ),
            _violation(
                "NERC CIP",
                "CIP-005-7 R1",
                "Electronic Security Perimeter",
                "Identify and protect Electronic Security Perimeter boundaries.",
                "Exposed ports indicate the Electronic Security Perimeter is "
                "not correctly configured.",
            ),
        ],
    },
    # 4 — Writable Registers / Coils (Modbus-style)
    {
        "id": "WRITABLE_REG",
        "keywords": [
            r"writ(e|able)\s+(register|coil|access)",
            r"register\s+writ",
            r"write\s+test\s+(succeed|success|pass)",
            r"coil\s+writ",
        ],
        "severities": None,
        "violations": [
            _violation(
                "IEC 62443",
                "IEC 62443-3-3 SR 1.3",
                "Account Management",
                "Control system accounts shall enforce least privilege.",
                "Writable registers without authorization violate the "
                "principle of least privilege for control operations.",
            ),
            _violation(
                "IEC 62443",
                "IEC 62443-4-2 CR 3.4",
                "Software and Information Integrity",
                "Components shall protect the integrity of software and "
                "information.",
                "Unprotected writable registers allow unauthorized "
                "modification of process variables.",
            ),
            _violation(
                "NIST SP 800-82",
                "NIST SP 800-82 §6.2.2",
                "Authorization and Access Control",
                "ICS should enforce access restrictions on control commands.",
                "Unrestricted write access to registers/coils violates ICS "
                "authorization guidance.",
            ),
            _violation(
                "NERC CIP",
                "CIP-007-6 R1",
                "Ports and Services",
                "Enable only needed logical ports and services.",
                "Writable access to control registers may be an unnecessary "
                "service violating least-functionality requirements.",
            ),
        ],
    },
    # 5 — Firmware / Software Version Disclosure
    {
        "id": "VERSION_DISCLOSURE",
        "keywords": [
            r"firmware\s+version",
            r"software\s+version",
            r"version\s+disclos",
            r"banner\s+(grab|disclos|expos)",
            r"device\s+info\s+(expos|leak|disclos)",
        ],
        "severities": None,
        "violations": [
            _violation(
                "IEC 62443",
                "IEC 62443-4-2 CR 7.7",
                "Least Functionality",
                "Components shall restrict information disclosure.",
                "Version disclosure enables targeted attacks against known "
                "vulnerabilities in specific firmware/software revisions.",
            ),
            _violation(
                "NIST SP 800-82",
                "NIST SP 800-82 §6.2.14",
                "Information Disclosure Protection",
                "ICS should minimize information available to potential "
                "attackers.",
                "Exposed version information aids attacker reconnaissance "
                "against ICS devices.",
            ),
            _violation(
                "NERC CIP",
                "CIP-007-6 R2",
                "Security Patch Management",
                "Evaluate and apply applicable security patches.",
                "Version disclosure combined with unpatched firmware may "
                "indicate non-compliance with patch management requirements.",
            ),
        ],
    },
    # 6 — Outdated / Vulnerable Firmware
    {
        "id": "OUTDATED_FW",
        "keywords": [
            r"outdated\s+(firmware|software|version)",
            r"vulnerab(le|ility)\s+(firmware|version|software)",
            r"known\s+vulnerabilit",
            r"(cve|CVE)-\d{4}",
            r"end.of.life",
            r"unsupported\s+(firmware|version|device)",
        ],
        "severities": {"critical", "high"},
        "violations": [
            _violation(
                "IEC 62443",
                "IEC 62443-2-3",
                "Patch Management in the IACS Environment",
                "Establish and maintain a patch management programme for IACS.",
                "Outdated firmware with known vulnerabilities indicates a lack "
                "of ICS patch management.",
            ),
            _violation(
                "NIST SP 800-82",
                "NIST SP 800-82 §6.2.11",
                "Patch and Vulnerability Management",
                "Implement a vulnerability/patch management process for ICS.",
                "Running vulnerable firmware violates NIST ICS patch "
                "management guidance.",
            ),
            _violation(
                "NERC CIP",
                "CIP-007-6 R2",
                "Security Patch Management",
                "Evaluate and apply applicable security patches within "
                "required timeframes.",
                "Unpatched known vulnerabilities directly violate CIP patch "
                "management requirements.",
            ),
        ],
    },
    # 7 — SNMP Default/Weak Community Strings
    {
        "id": "SNMP_COMMUNITY",
        "keywords": [
            r"(snmp|community)\s+(string|default|public|private|weak)",
            r"snmp\s*v[12]\b",
            r"community\s+string\s+(public|private|default)",
        ],
        "severities": None,
        "violations": [
            _violation(
                "IEC 62443",
                "IEC 62443-3-3 SR 1.5",
                "Authenticator Management",
                "Manage authenticator quality and lifecycle.",
                "Default/weak SNMP community strings are trivially guessable "
                "authenticators violating password management requirements.",
            ),
            _violation(
                "NIST SP 800-82",
                "NIST SP 800-82 §6.2.1",
                "Identification and Authentication",
                "Use SNMPv3 or stronger authentication for ICS management.",
                "SNMP v1/v2c with default community strings provides no real "
                "authentication.",
            ),
            _violation(
                "NERC CIP",
                "CIP-007-6 R5",
                "System Access Controls",
                "Change default passwords and manage shared accounts.",
                "Default SNMP community strings violate requirements to change "
                "default credentials.",
            ),
        ],
    },
    # 8 — Insecure Protocol (Modbus, DNP3 without SA, etc.)
    {
        "id": "INSECURE_PROTO",
        "keywords": [
            r"insecure\s+protocol",
            r"(modbus|dnp3|bacnet|s7|profinet)\s+(insecure|no\s+security)",
            r"protocol\s+lacks?\s+(security|auth|encryption)",
            r"no\s+secure\s+authentication",
            r"dnp3.*without\s+sa\b",
        ],
        "severities": None,
        "violations": [
            _violation(
                "IEC 62443",
                "IEC 62443-3-3 SR 3.1",
                "Communication Integrity",
                "Use authenticated and integrity-checked communications.",
                "Insecure legacy protocols lack authentication and integrity "
                "checks required by the standard.",
            ),
            _violation(
                "NIST SP 800-82",
                "NIST SP 800-82 §5.4",
                "Securing ICS Communications",
                "Replace or wrap insecure protocols with authenticated "
                "alternatives.",
                "Using inherently insecure ICS protocols without compensating "
                "controls violates NIST ICS guidance.",
            ),
            _violation(
                "NERC CIP",
                "CIP-005-7 R2",
                "Electronic Access Controls",
                "Implement controls for inbound and outbound access.",
                "Insecure protocols require compensating access controls per "
                "NERC CIP electronic access requirements.",
            ),
        ],
    },
    # 9 — PLC/Controller in Run Mode Accessible
    {
        "id": "PLC_RUN_MODE",
        "keywords": [
            r"run\s+mode",
            r"plc\s+(in\s+)?run",
            r"controller\s+state.*run",
            r"operating\s+mode.*run",
            r"cpu\s+(state|mode).*run",
        ],
        "severities": None,
        "violations": [
            _violation(
                "IEC 62443",
                "IEC 62443-4-2 CR 2.1",
                "Authorization Enforcement",
                "Components shall enforce authorization for all identified "
                "actions.",
                "Remotely accessible PLC run state without authorization "
                "allows potential process disruption.",
            ),
            _violation(
                "NIST SP 800-82",
                "NIST SP 800-82 §6.2.2",
                "Authorization and Access Control",
                "Restrict access to controller operating modes.",
                "Unrestricted access to PLC run mode violates ICS access "
                "control guidance.",
            ),
            _violation(
                "NERC CIP",
                "CIP-004-7 R4",
                "Access Management",
                "Authorize physical and electronic access to BES cyber "
                "systems.",
                "Unauthorized visibility into controller state may violate "
                "access management requirements.",
            ),
        ],
    },
    # 10 — Device Stop/Start Capability
    {
        "id": "STOP_START",
        "keywords": [
            r"stop\s+(command|capability|access)",
            r"(start|restart|reboot)\s+(command|capability|access)",
            r"remote\s+(stop|shutdown|restart)",
            r"cpu\s+stop",
        ],
        "severities": {"critical", "high"},
        "violations": [
            _violation(
                "IEC 62443",
                "IEC 62443-3-3 SR 2.1",
                "Authorization Enforcement",
                "Enforce authorization on all control commands.",
                "Ability to remotely stop/start controllers without "
                "authorization poses severe safety risks.",
            ),
            _violation(
                "NIST SP 800-82",
                "NIST SP 800-82 §6.3",
                "Safety System Integration",
                "Protect safety-critical ICS functions from unauthorized "
                "modification.",
                "Unauthorized stop/start access to controllers threatens "
                "process safety.",
            ),
            _violation(
                "NERC CIP",
                "CIP-003-8 R1",
                "Cyber Security Plans",
                "Implement cyber security plans for BES cyber systems.",
                "Unprotected remote control capability indicates inadequate "
                "cyber security planning.",
            ),
        ],
    },
    # 11 — MQTT Without TLS / No Access Control
    {
        "id": "MQTT_INSECURE",
        "keywords": [
            r"mqtt.*(no\s+tls|without\s+tls|unencrypted|insecure|no\s+auth)",
            r"mqtt.*anonymous",
            r"broker.*no\s+(auth|password|tls)",
        ],
        "severities": None,
        "violations": [
            _violation(
                "IEC 62443",
                "IEC 62443-3-3 SR 1.1",
                "Human User Identification and Authentication",
                "Authenticate all users accessing the IACS.",
                "Anonymous MQTT access bypasses identification and "
                "authentication requirements.",
            ),
            _violation(
                "NIST SP 800-82",
                "NIST SP 800-82 §6.2.6",
                "Encryption of ICS Communications",
                "Encrypt ICS message bus communications.",
                "MQTT without TLS exposes ICS telemetry and commands to "
                "interception.",
            ),
            _violation(
                "NERC CIP",
                "CIP-011-3 R1",
                "Information Protection",
                "Implement methods to protect BES Cyber System information.",
                "Unprotected MQTT topics may leak or allow manipulation of "
                "BES cyber system data.",
            ),
        ],
    },
    # 12 — OPC UA Security Mode None
    {
        "id": "OPCUA_NOSEC",
        "keywords": [
            r"opc\s*ua.*security\s*mode.*none",
            r"opc\s*ua.*no\s+security",
            r"security\s+policy.*none.*opc",
        ],
        "severities": None,
        "violations": [
            _violation(
                "IEC 62443",
                "IEC 62443-3-3 SR 4.1",
                "Communication Integrity",
                "Protect the integrity of transmitted information.",
                "OPC UA with SecurityMode=None provides zero message "
                "protection.",
            ),
            _violation(
                "NIST SP 800-82",
                "NIST SP 800-82 §6.2.6",
                "Encryption of ICS Communications",
                "Use OPC UA security policies to encrypt ICS traffic.",
                "SecurityMode None disables all OPC UA built-in protections.",
            ),
        ],
    },
    # 13 — Web Interface / HMI Exposed
    {
        "id": "WEB_HMI",
        "keywords": [
            r"(web|http|hmi)\s+(interface|server|panel)\s+(expos|detect|found|accessible)",
            r"(http|https)\s+service\s+detected",
            r"hmi\s+accessible",
        ],
        "severities": None,
        "violations": [
            _violation(
                "IEC 62443",
                "IEC 62443-3-3 SR 7.1",
                "Denial of Service Protection",
                "Protect against denial-of-service attacks on control "
                "interfaces.",
                "Exposed web/HMI interfaces increase the attack surface for "
                "denial-of-service and exploitation.",
            ),
            _violation(
                "NIST SP 800-82",
                "NIST SP 800-82 §5.3",
                "Boundary Protection",
                "Restrict ICS management interfaces to authorized networks.",
                "Web-accessible HMI/management interfaces should be restricted "
                "to operations networks only.",
            ),
            _violation(
                "NERC CIP",
                "CIP-005-7 R1",
                "Electronic Security Perimeter",
                "Define and protect network boundaries.",
                "Externally accessible HMI indicates gaps in the Electronic "
                "Security Perimeter.",
            ),
        ],
    },
    # 14 — Information Leakage / Device Enumeration
    {
        "id": "INFO_LEAK",
        "keywords": [
            r"(device|system|hardware)\s+(info|information|detail)\s+(expos|leak|disclos|enumerat)",
            r"enumerat(e|ion)",
            r"(serial\s+number|mac\s+address|model)\s+(expos|disclos|leak)",
            r"device\s+identification",
        ],
        "severities": None,
        "violations": [
            _violation(
                "IEC 62443",
                "IEC 62443-4-2 CR 7.7",
                "Least Functionality",
                "Restrict unnecessary information disclosure by components.",
                "Device enumeration reveals information useful for targeted "
                "attacks against specific hardware.",
            ),
            _violation(
                "NIST SP 800-82",
                "NIST SP 800-82 §6.2.14",
                "Information Disclosure Protection",
                "Minimize information available to potential attackers.",
                "Excessive device information leakage aids reconnaissance.",
            ),
        ],
    },
    # 15 — No Network Segmentation / Flat Network
    {
        "id": "FLAT_NETWORK",
        "keywords": [
            r"(flat|unsegmented)\s+network",
            r"no\s+(segmentation|separation|dmz|firewall)",
            r"network\s+segmentation\s+(missing|absent|not)",
            r"direct\s+access.*corporate",
        ],
        "severities": None,
        "violations": [
            _violation(
                "IEC 62443",
                "IEC 62443-3-3 SR 5.1",
                "Network Segmentation",
                "Segment the IACS network into zones connected by conduits.",
                "Lack of segmentation violates the fundamental IEC 62443 "
                "zones-and-conduits model.",
            ),
            _violation(
                "IEC 62443",
                "IEC 62443-3-2 ZCR 3.1",
                "Zone and Conduit Requirements",
                "Define security zones and conduits based on risk assessment.",
                "Flat network architecture shows no zone/conduit risk analysis "
                "was performed.",
            ),
            _violation(
                "NIST SP 800-82",
                "NIST SP 800-82 §5.1",
                "Network Architecture",
                "Implement defense-in-depth with segmented network layers.",
                "Flat ICS network without segmentation lacks defense-in-depth.",
            ),
            _violation(
                "NERC CIP",
                "CIP-005-7 R1",
                "Electronic Security Perimeter",
                "Identify and protect all ESP boundaries.",
                "No segmentation means no defined Electronic Security "
                "Perimeter.",
            ),
        ],
    },
    # 16 — Denial of Service / Resource Exhaustion
    {
        "id": "DOS",
        "keywords": [
            r"denial.of.service",
            r"resource\s+exhaust",
            r"(dos|DoS)\s+(vulnerab|attack|risk)",
            r"crash\s+(detect|risk|vulnerab)",
        ],
        "severities": {"critical", "high", "medium"},
        "violations": [
            _violation(
                "IEC 62443",
                "IEC 62443-3-3 SR 7.1",
                "Denial of Service Protection",
                "Protect against DoS attacks that could impact safety.",
                "Finding indicates susceptibility to denial-of-service "
                "impacting ICS availability.",
            ),
            _violation(
                "NIST SP 800-82",
                "NIST SP 800-82 §6.2.8",
                "System Availability",
                "Ensure ICS availability and resilience against disruption.",
                "DoS vulnerability threatens ICS operational continuity.",
            ),
            _violation(
                "NERC CIP",
                "CIP-008-6 R1",
                "Cyber Security Incident Response Plan",
                "Develop and maintain incident response plans.",
                "DoS vulnerabilities require documented response procedures "
                "per CIP incident response requirements.",
            ),
        ],
    },
    # 17 — Logging / Audit Trail Missing
    {
        "id": "NO_LOGGING",
        "keywords": [
            r"(no|missing|disabled|absent)\s+(logging|audit|log)",
            r"audit\s+(trail|log)\s+(missing|not|disabled)",
        ],
        "severities": None,
        "violations": [
            _violation(
                "IEC 62443",
                "IEC 62443-3-3 SR 6.1",
                "Audit Log Accessibility",
                "Provide audit logging for security-relevant events.",
                "Missing logging prevents forensic analysis of security "
                "incidents in the IACS.",
            ),
            _violation(
                "NIST SP 800-82",
                "NIST SP 800-82 §6.2.5",
                "Audit and Accountability",
                "Maintain audit logs of ICS security events.",
                "No audit trail violates NIST ICS accountability guidance.",
            ),
            _violation(
                "NERC CIP",
                "CIP-007-6 R4",
                "Security Event Monitoring",
                "Log and monitor security events on BES cyber systems.",
                "Missing logging directly violates CIP security event "
                "monitoring requirements.",
            ),
        ],
    },
    # 18 — Physical Access / Console Exposure
    {
        "id": "PHYSICAL_ACCESS",
        "keywords": [
            r"physical\s+access",
            r"(serial|console)\s+(port|interface)\s+(expos|open|accessible)",
            r"usb\s+(port|interface)\s+(expos|open|enabled)",
        ],
        "severities": None,
        "violations": [
            _violation(
                "IEC 62443",
                "IEC 62443-4-2 CR 2.4",
                "Mobile Code",
                "Restrict unauthorized physical and mobile code access.",
                "Exposed physical interfaces allow unauthorized local access "
                "to control components.",
            ),
            _violation(
                "NERC CIP",
                "CIP-006-6 R1",
                "Physical Security Plan",
                "Implement physical security controls for BES cyber systems.",
                "Exposed physical ports indicate inadequate physical security "
                "controls.",
            ),
        ],
    },
    # 19 — Weak or Missing Password Policy
    {
        "id": "WEAK_PASSWORD",
        "keywords": [
            r"weak\s+password",
            r"password\s+(policy|complexity)\s+(weak|missing|insufficient|none)",
            r"brute.?force\s+(possible|vulnerable|susceptib)",
            r"no\s+lockout",
            r"no\s+account\s+lockout",
        ],
        "severities": None,
        "violations": [
            _violation(
                "IEC 62443",
                "IEC 62443-3-3 SR 1.7",
                "Strength of Password-based Authentication",
                "Enforce minimum password strength for human users.",
                "Weak password policies allow trivial credential compromise "
                "on ICS components.",
            ),
            _violation(
                "NIST SP 800-82",
                "NIST SP 800-82 §6.2.1",
                "Identification and Authentication",
                "ICS should enforce strong password policies.",
                "Weak or absent password policies violate NIST ICS "
                "authentication guidance.",
            ),
            _violation(
                "NERC CIP",
                "CIP-007-6 R5",
                "System Access Controls",
                "Enforce password complexity and change requirements.",
                "Missing password policies violate CIP system access control "
                "requirements.",
            ),
        ],
    },
    # 20 — Unnecessary Services / Functions Enabled
    {
        "id": "UNNECESSARY_SERVICES",
        "keywords": [
            r"unnecessary\s+(service|function|port|feature)",
            r"(service|port|feature)\s+not\s+needed",
            r"(telnet|ftp|http)\s+(service\s+)?(enabled|running|detected)",
            r"unused\s+(service|port)",
        ],
        "severities": None,
        "violations": [
            _violation(
                "IEC 62443",
                "IEC 62443-4-2 CR 7.7",
                "Least Functionality",
                "Disable unnecessary functions, ports, protocols, and "
                "services.",
                "Unnecessary services expand the attack surface beyond what "
                "the control function requires.",
            ),
            _violation(
                "NIST SP 800-82",
                "NIST SP 800-82 §6.2.10",
                "Least Functionality",
                "Configure ICS to provide only essential capabilities.",
                "Running unnecessary services violates the principle of least "
                "functionality.",
            ),
            _violation(
                "NERC CIP",
                "CIP-007-6 R1",
                "Ports and Services",
                "Enable only logical network accessible ports needed.",
                "Unnecessary services must be disabled per CIP ports and "
                "services requirements.",
            ),
        ],
    },
    # 21 — Remote Access Without Controls
    {
        "id": "REMOTE_ACCESS",
        "keywords": [
            r"remote\s+access.*(uncontrol|unprotect|insecure|no\s+vpn)",
            r"(vpn|tunnel)\s+(missing|absent|not)",
            r"remote\s+desktop.*exposed",
            r"rdp\s+(expos|open|accessible)",
        ],
        "severities": None,
        "violations": [
            _violation(
                "IEC 62443",
                "IEC 62443-3-3 SR 1.13",
                "Remote Access",
                "Monitor and control all remote access to the IACS.",
                "Uncontrolled remote access bypasses zone/conduit security "
                "architecture.",
            ),
            _violation(
                "NIST SP 800-82",
                "NIST SP 800-82 §5.2",
                "Remote Access to ICS",
                "Implement multi-factor authentication and VPN for remote "
                "ICS access.",
                "Remote access without VPN/MFA violates NIST ICS remote "
                "access guidance.",
            ),
            _violation(
                "NERC CIP",
                "CIP-005-7 R2",
                "Electronic Access Controls",
                "Protect Interactive Remote Access with encryption and MFA.",
                "Uncontrolled remote access violates CIP electronic access "
                "control requirements.",
            ),
        ],
    },
    # 22 — Change Management / Configuration Not Controlled
    {
        "id": "NO_CHANGE_MGMT",
        "keywords": [
            r"(no|missing)\s+(change|configuration)\s+(management|control|baseline)",
            r"configuration\s+(drift|change)\s+detect",
            r"unauthorized\s+configuration",
        ],
        "severities": None,
        "violations": [
            _violation(
                "IEC 62443",
                "IEC 62443-2-4 SP.03.02",
                "Configuration Management",
                "Maintain configuration baselines for IACS components.",
                "Lack of configuration management undermines IACS integrity "
                "assurance.",
            ),
            _violation(
                "NERC CIP",
                "CIP-010-4 R1",
                "Configuration Change Management and Vulnerability "
                "Assessments",
                "Develop a baseline configuration and authorize changes.",
                "Missing change management violates CIP configuration "
                "baseline requirements.",
            ),
        ],
    },
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _match_pattern(finding: Dict[str, Any], pattern: Dict[str, Any]) -> bool:
    """Return True if a finding matches the given mapping pattern."""
    desc = (finding.get("description") or "").lower()
    details = (finding.get("details") or "").lower()
    combined = f"{desc} {details}"

    severity = (finding.get("severity") or "").lower()

    # Check severity filter
    if pattern["severities"] is not None:
        if severity not in pattern["severities"]:
            return False

    # Check keyword match
    for kw in pattern["keywords"]:
        if re.search(kw, combined, re.IGNORECASE):
            return True

    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def map_finding_to_compliance(finding_dict: Dict[str, Any]) -> List[Dict[str, str]]:
    """Map a single scanner finding to applicable compliance violations.

    Parameters
    ----------
    finding_dict:
        A finding/issue dict as produced by ``BaseScanner.create_issue``.
        Expected keys: ``severity``, ``description``, optionally ``details``.

    Returns
    -------
    list[dict]
        List of compliance violation dicts, each with keys:
        ``framework``, ``requirement_id``, ``requirement_title``,
        ``description``, ``violation_explanation``.
    """
    violations: List[Dict[str, str]] = []
    seen: set = set()  # deduplicate by requirement_id

    for pattern in _MAPPING_PATTERNS:
        if _match_pattern(finding_dict, pattern):
            for v in pattern["violations"]:
                key = (v["framework"], v["requirement_id"])
                if key not in seen:
                    seen.add(key)
                    violations.append(dict(v))  # copy

    return violations


def generate_compliance_report(
    scan_results: Dict[str, Any],
) -> Dict[str, Any]:
    """Generate a structured compliance report grouped by framework.

    Parameters
    ----------
    scan_results:
        Full scan results dict as produced by ``ics_scanner.py``.
        Expected structure::

            {
                "metadata": { ... },
                "results": {
                    "<ip>": {
                        "<protocol>": {
                            "issues": [ { severity, description, ... }, ... ]
                        }
                    }
                }
            }

    Returns
    -------
    dict
        A report dict with structure::

            {
                "generated_at": "<ISO timestamp>",
                "frameworks": {
                    "<framework_name>": {
                        "violations": [
                            {
                                "host": "<ip>",
                                "protocol": "<protocol>",
                                "finding_severity": "...",
                                "finding_description": "...",
                                "requirement_id": "...",
                                "requirement_title": "...",
                                "description": "...",
                                "violation_explanation": "..."
                            },
                            ...
                        ],
                        "total_violations": <int>
                    }
                },
                "total_violations": <int>,
                "total_findings_assessed": <int>
            }
    """
    frameworks: Dict[str, List[Dict[str, Any]]] = {}
    total_violations = 0
    total_findings = 0

    results = scan_results.get("results", {})

    for ip, protocols in results.items():
        for protocol, findings in protocols.items():
            issues = findings.get("issues", [])
            for issue in issues:
                total_findings += 1
                violations = map_finding_to_compliance(issue)
                for v in violations:
                    total_violations += 1
                    fw = v["framework"]
                    if fw not in frameworks:
                        frameworks[fw] = []
                    frameworks[fw].append({
                        "host": ip,
                        "protocol": protocol,
                        "finding_severity": issue.get("severity", "unknown"),
                        "finding_description": issue.get("description", ""),
                        "requirement_id": v["requirement_id"],
                        "requirement_title": v["requirement_title"],
                        "description": v["description"],
                        "violation_explanation": v["violation_explanation"],
                    })

    report: Dict[str, Any] = {
        "generated_at": datetime.now().isoformat(),
        "frameworks": {},
        "total_violations": total_violations,
        "total_findings_assessed": total_findings,
    }

    for fw_name in sorted(frameworks.keys()):
        report["frameworks"][fw_name] = {
            "violations": frameworks[fw_name],
            "total_violations": len(frameworks[fw_name]),
        }

    return report


def get_compliance_summary(
    scan_results: Dict[str, Any],
) -> Dict[str, Any]:
    """Return violation counts grouped by framework.

    Parameters
    ----------
    scan_results:
        Full scan results dict (same format as ``generate_compliance_report``).

    Returns
    -------
    dict
        Summary dict::

            {
                "generated_at": "<ISO timestamp>",
                "by_framework": {
                    "IEC 62443": <int>,
                    "NIST SP 800-82": <int>,
                    "NERC CIP": <int>
                },
                "total_violations": <int>,
                "total_findings_assessed": <int>,
                "findings_with_violations": <int>
            }
    """
    counts: Dict[str, int] = {}
    total_violations = 0
    total_findings = 0
    findings_with_violations = 0

    results = scan_results.get("results", {})

    for ip, protocols in results.items():
        for protocol, findings in protocols.items():
            issues = findings.get("issues", [])
            for issue in issues:
                total_findings += 1
                violations = map_finding_to_compliance(issue)
                if violations:
                    findings_with_violations += 1
                for v in violations:
                    fw = v["framework"]
                    counts[fw] = counts.get(fw, 0) + 1
                    total_violations += 1

    return {
        "generated_at": datetime.now().isoformat(),
        "by_framework": dict(sorted(counts.items())),
        "total_violations": total_violations,
        "total_findings_assessed": total_findings,
        "findings_with_violations": findings_with_violations,
    }
