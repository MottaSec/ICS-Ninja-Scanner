#!/usr/bin/env python3
"""
CVSS 3.1 Base Score Calculator and ICS-specific severity mapping.

Provides:
    - CVSS 3.1 base score calculation from vector strings
    - Pre-calculated CVSS mappings for common ICS security findings
    - Auto-CVSS assignment for scanner issues based on description matching
    - Overall risk score calculation for scan results

ICS Ninja Scanner - MottaSec
"""

import math
import re

# ---------------------------------------------------------------------------
# CVSS 3.1 Metric Values
# ---------------------------------------------------------------------------

# Attack Vector (AV)
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}

# Attack Complexity (AC)
_AC = {"L": 0.77, "H": 0.44}

# Privileges Required (PR) — values depend on Scope
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED   = {"N": 0.85, "L": 0.68, "H": 0.50}

# User Interaction (UI)
_UI = {"N": 0.85, "R": 0.62}

# Impact metrics — Confidentiality, Integrity, Availability
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value):
    """CVSS 3.1 'roundup' — round up to nearest 0.1."""
    return math.ceil(value * 10) / 10.0


def calculate_cvss_base_score(vector_string):
    """
    Calculate the CVSS 3.1 base score from a vector string.

    Args:
        vector_string (str): CVSS 3.1 vector, e.g.
            ``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``

    Returns:
        dict: ``{'score': float, 'severity': str, 'vector': str}``
              or ``None`` if parsing fails.
    """
    if not vector_string or not isinstance(vector_string, str):
        return None

    try:
        # Strip prefix
        raw = vector_string.upper().strip()
        if raw.startswith("CVSS:3.1/"):
            raw = raw[len("CVSS:3.1/"):]
        elif raw.startswith("CVSS:3.0/"):
            raw = raw[len("CVSS:3.0/"):]

        metrics = {}
        for part in raw.split("/"):
            key, val = part.split(":")
            metrics[key] = val

        # Extract values
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        ui = _UI[metrics["UI"]]
        scope_changed = metrics["S"] == "C"

        pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
        pr = pr_table[metrics["PR"]]

        c = _CIA[metrics["C"]]
        i = _CIA[metrics["I"]]
        a = _CIA[metrics["A"]]

        # Impact Sub Score (ISS)
        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

        # Impact
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        # Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Base Score
        if impact <= 0:
            base_score = 0.0
        elif scope_changed:
            base_score = _roundup(min(1.08 * (impact + exploitability), 10.0))
        else:
            base_score = _roundup(min(impact + exploitability, 10.0))

        severity = _score_to_severity(base_score)

        return {
            "score": base_score,
            "severity": severity,
            "severity_label": severity,
            "vector": vector_string,
        }

    except (KeyError, ValueError, IndexError):
        return None


def _score_to_severity(score):
    """Map a CVSS score to a severity label."""
    if score == 0.0:
        return "None"
    elif score <= 3.9:
        return "Low"
    elif score <= 6.9:
        return "Medium"
    elif score <= 8.9:
        return "High"
    else:
        return "Critical"


# ---------------------------------------------------------------------------
# ICS Finding → CVSS Vector Mapping
# ---------------------------------------------------------------------------
# Pattern-based: keys are lowercase substrings matched against issue
# descriptions.  More specific patterns should appear before generic ones
# (matching picks highest CVSS score among all matches).
# ---------------------------------------------------------------------------

ICS_CVSS_MAPPINGS = {
    # =====================================================================
    # Authentication / Access Control
    # =====================================================================
    "unauthenticated":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "anonymous access":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "anonymous authentication": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "default credentials":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "no authentication":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "no password protection":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "without authentication": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "no password":            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "allows anonymous":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8

    # =====================================================================
    # Write / Control Access
    # =====================================================================
    "write access":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H",  # 10.0
    "writable":               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H",  # 10.0
    "write access to data blocks": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H",  # 10.0
    "control command":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H",  # 10.0
    "control operations":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H",  # 10.0
    "control commands accepted": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H",  # 10.0
    "select/operate":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H",  # 10.0
    "writeproperty":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H",  # 10.0
    "tag write":              "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H",  # 10.0
    "writable coils":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H",  # 10.0
    "writable holding registers": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H",  # 10.0
    "write access to mqtt":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H",  # 10.0
    "pnio write access":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H",  # 10.0
    "ip configuration change": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H",  # 10.0
    "device name change":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H",  # 10.0
    "snmp write access":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H",  # 10.0

    # =====================================================================
    # CPU / Process Control
    # =====================================================================
    "cpu state can be changed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H",  # 10.0
    "plc was stopped":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H",  # 8.6
    "cpu is in stop":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",  # 5.3
    "forwardopen":            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H",  # 10.0

    # =====================================================================
    # Device Restart / Reset
    # =====================================================================
    "restart":                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",  # 7.5
    "reinitialize":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",  # 7.5
    "factory reset":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",  # 9.1
    "devicecommunicationcontrol": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",  # 7.5

    # =====================================================================
    # Encryption / Transport Security
    # =====================================================================
    "unencrypted":            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",  # 7.4
    "plaintext":              "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",  # 7.4
    "no encryption":          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",  # 7.4
    "not available":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",  # 5.3  (e.g. Modbus/TLS not available)
    "no bacnet/sc":           "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",  # 7.4
    "no bacnet secure":       "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",  # 7.4

    # =====================================================================
    # OPC-UA Specific
    # =====================================================================
    "securitymode":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "security mode":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "securitymode 'none'":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "deprecated security policy": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 5.9
    "self-signed certificate": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 5.9
    "certificate has expired": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",  # 7.4
    "methods exposed":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",  # 6.5
    "diagnostics information exposed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "address space browsable": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
    "namespaces enumerated":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3

    # =====================================================================
    # Information Disclosure
    # =====================================================================
    "information disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "version disclosed":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "firmware version":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "information accessible": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "information is exposed": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "device identification":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "device attributes":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "system information":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "order code":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "module/component inventory": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "client information":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "program names accessible": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "program information accessible": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "diagnostic buffer":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "communication setup":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "pdu size":               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "exposes":                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3

    # =====================================================================
    # Read Access (data exfiltration from ICS)
    # =====================================================================
    "read access":            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
    "readable":               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
    "readable holding registers": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
    "readable input registers": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
    "readable discrete inputs": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
    "tag read access":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
    "process data readable":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
    "objects enumerated":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "object enumeration":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "object groups enumerated": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "subscribecov":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
    "readpropertymultiple":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
    "read access to mqtt":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
    "snmp walk":              "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
    "sensitive cip object":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
    "spontaneous data":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "data blocks":            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5

    # =====================================================================
    # Firmware / Known Vulnerabilities
    # =====================================================================
    "known vulnerab":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "vulnerable firmware":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "known vulnerability":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "outdated":               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "cve-":                   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8

    # =====================================================================
    # Weak Security Settings
    # =====================================================================
    "weak":                   "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 5.9
    "deprecated":             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 5.9
    "only password":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",  # 6.5
    "community string":       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
    "security class is 0":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "security class":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "secure authentication (sa) is not": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "cip security":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3 (info)

    # =====================================================================
    # Clock / Time Issues
    # =====================================================================
    "clock":                  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",  # 5.3
    "clock drift":            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",  # 5.3
    "clock synchronization":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",  # 5.3
    "time synchronization":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",  # 5.3

    # =====================================================================
    # Broadcast / Network
    # =====================================================================
    "broadcast":              "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",  # 5.4
    "unsolicited responses":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "broadcast unit id":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",  # 6.5
    "broadcast address":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",  # 6.5

    # =====================================================================
    # Web Interface / Services
    # =====================================================================
    "web server":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "web interface":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "websocket":              "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3

    # =====================================================================
    # DNP3 Specific
    # =====================================================================
    "dnp3 outstation":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "cold restart":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",  # 7.5
    "warm restart":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",  # 7.5
    "disable unsolicited":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",  # 6.5
    "enable unsolicited":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",  # 5.3
    "clear objects":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L",  # 8.2

    # =====================================================================
    # IEC-104 Specific
    # =====================================================================
    "iec-104 communication":  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",  # 7.4
    "interrogation command":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
    "counter interrogation":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
    "station addresses":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "tls detected":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",  # 0.0 (positive)

    # =====================================================================
    # Modbus Specific
    # =====================================================================
    "modbus device found":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "modbus/tls":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "unit ids detected":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "diagnostic function":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",  # 7.3
    "programming function":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H",  # 9.4

    # =====================================================================
    # S7 / Siemens Specific
    # =====================================================================
    "s7 plc found":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "s7 plc identified":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "s7 device detected":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "cpu state":              "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3

    # =====================================================================
    # MQTT Specific
    # =====================================================================
    "mqtt broker found":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "retained messages":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",  # 8.2
    "last will and testament": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",  # 6.5
    "simultaneous connections": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",  # 5.3
    "ics client id":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "qos levels":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",  # 0.0 (info)
    "mqtt v5":                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",  # 0.0 (info)

    # =====================================================================
    # HART-IP Specific
    # =====================================================================
    "hart-ip device":         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "hart device identification": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "hart-ip session":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "device tag":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "additional device status": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "loop current":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",  # 5.3
    "manufacturer-specific":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "supported hart commands": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "field devices":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "write polling address":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L",  # 8.2
    "write message":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",  # 5.3
    "write tag/descriptor":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",  # 5.3

    # =====================================================================
    # EtherNet/IP Specific
    # =====================================================================
    "ethernet/ip device":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "cip session":            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8
    "cip objects enumerated": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "services enumerated":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "device status":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3

    # =====================================================================
    # BACnet Specific
    # =====================================================================
    "bacnet device detected":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "whois":                   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "readproperty":            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5
    "bacnet/sc":               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",  # 0.0 (info — positive)

    # =====================================================================
    # Profinet Specific
    # =====================================================================
    "profinet device":         "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 4.3
    "dcp identify":            "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 4.3
    "dcp get":                 "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 4.3
    "dcp set":                 "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",  # 8.1
    "rpc connection":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",  # 6.5
    "rpc ports open":          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3

    # =====================================================================
    # SNMP Specific
    # =====================================================================
    "snmp service":            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "snmpv3 supported":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",  # 0.0 (positive)
    "traps are disabled":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",  # 5.3
    "trap destination":        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "no snmp trap destination": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",  # 5.3

    # =====================================================================
    # Generic — device found / detected (low priority, matched last)
    # =====================================================================
    "device found":            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "detected":                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "endpoint":                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3
    "session registration":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",  # 6.5
    "session established":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",  # 6.5
}

# Severity-based fallback scores (when no pattern matches)
_SEVERITY_FALLBACK = {
    "critical": 9.5,
    "high":     7.5,
    "medium":   5.0,
    "low":      3.0,
    "info":     0.0,
}

# Pre-compute CVSS scores for all mappings (cached at import time)
_CACHED_SCORES = {}


def _get_mapping_score(vector):
    """Return the numeric score for a vector string (cached)."""
    if vector not in _CACHED_SCORES:
        result = calculate_cvss_base_score(vector)
        _CACHED_SCORES[vector] = result["score"] if result else 0.0
    return _CACHED_SCORES[vector]


def get_cvss_for_issue(issue):
    """
    Get CVSS score for an issue based on its description and severity.

    Matching strategy:
    1. Case-insensitive substring match against ``ICS_CVSS_MAPPINGS``
    2. If multiple patterns match, the one with the **highest** CVSS score wins
    3. If nothing matches, fall back to a severity-based estimate

    Args:
        issue (dict): Issue dict with ``'severity'``, ``'description'``,
                      and optionally ``'details'``.

    Returns:
        dict: ``{'score': float, 'severity_label': str, 'vector': str}``
    """
    description = (issue.get("description", "") or "").lower()
    details = (issue.get("details", "") or "").lower()
    search_text = f"{description} {details}"

    best_score = -1.0
    best_vector = None

    for pattern, vector in ICS_CVSS_MAPPINGS.items():
        if pattern in search_text:
            score = _get_mapping_score(vector)
            if score > best_score:
                best_score = score
                best_vector = vector

    if best_vector is not None:
        result = calculate_cvss_base_score(best_vector)
        if result:
            result["severity_label"] = result["severity"]
            return result

    # Fallback to severity-based estimate
    severity = (issue.get("severity", "") or "").lower()
    fallback_score = _SEVERITY_FALLBACK.get(severity, 0.0)
    fallback_severity = _score_to_severity(fallback_score)

    return {
        "score": fallback_score,
        "severity": fallback_severity,
        "severity_label": fallback_severity,
        "vector": f"ESTIMATED (from severity={severity})",
    }


# ---------------------------------------------------------------------------
# Risk Score Calculator
# ---------------------------------------------------------------------------

# Protocol criticality weights
PROTOCOL_WEIGHTS = {
    # Control protocols — full weight
    "modbus":     1.0,
    "s7":         1.0,
    "dnp3":       1.0,
    "iec104":     1.0,
    "ethernetip": 1.0,
    "profinet":   1.0,
    "hart":       1.0,
    "bacnet":     1.0,
    # Data / monitoring protocols
    "opcua":      0.7,
    "mqtt":       0.7,
    "snmp":       0.7,
}


def calculate_risk_score(scan_results):
    """
    Calculate an overall risk score (0-100) for aggregate scan results.

    Args:
        scan_results (dict): Mapping of
            ``{protocol: {target: scan_result_dict, ...}, ...}``
            where each ``scan_result_dict`` has ``'issues'`` (list) and
            optionally ``'device_info'``.

            Also accepts a flat list of issues via key ``'all_issues'`` and
            metadata via ``'meta'``.

    Returns:
        dict: ``{'score': int, 'rating': str, 'breakdown': {...}}``
    """
    all_cvss_weighted = []
    hosts_with_findings = set()
    all_hosts = set()
    protocols_with_findings = set()
    protocols_scanned = set()

    for protocol, targets in scan_results.items():
        if protocol in ("meta", "all_issues", "summary"):
            continue

        proto_key = protocol.lower().replace("-", "").replace("_", "")
        weight = PROTOCOL_WEIGHTS.get(proto_key, 0.7)
        protocols_scanned.add(proto_key)

        if not isinstance(targets, dict):
            continue

        for host, result in targets.items():
            if not isinstance(result, dict):
                continue

            all_hosts.add(host)
            issues = result.get("issues", [])

            if issues:
                hosts_with_findings.add(host)
                protocols_with_findings.add(proto_key)

            for issue in issues:
                # Get CVSS score
                cvss = None
                if "cvss_score" in issue:
                    cvss_score = issue["cvss_score"]
                else:
                    cvss_result = get_cvss_for_issue(issue)
                    cvss_score = cvss_result["score"] if cvss_result else 0.0

                all_cvss_weighted.append(cvss_score * weight)

    # Calculate sub-scores
    total_hosts = max(len(all_hosts), 1)
    total_protocols = max(len(protocols_scanned), 1)

    # Finding score: sum of weighted CVSS / theoretical max × 50
    # Theoretical max = 10.0 * 1.0 * num_findings (all critical, control protocol)
    max_possible = max(len(all_cvss_weighted) * 10.0, 1.0)
    finding_score = (sum(all_cvss_weighted) / max_possible) * 50.0

    # Exposure score
    exposure_score = (len(hosts_with_findings) / total_hosts) * 25.0

    # Protocol breadth score
    protocol_score = (len(protocols_with_findings) / total_protocols) * 25.0

    total = min(100, int(round(finding_score + exposure_score + protocol_score)))

    # Rating
    if total <= 20:
        rating = "Informational"
    elif total <= 40:
        rating = "Low"
    elif total <= 60:
        rating = "Medium"
    elif total <= 80:
        rating = "High"
    else:
        rating = "Critical"

    return {
        "score": total,
        "rating": rating,
        "breakdown": {
            "finding_score": round(finding_score, 2),
            "exposure_score": round(exposure_score, 2),
            "protocol_score": round(protocol_score, 2),
        },
        "stats": {
            "total_findings": len(all_cvss_weighted),
            "hosts_affected": len(hosts_with_findings),
            "total_hosts": len(all_hosts),
            "protocols_with_findings": len(protocols_with_findings),
            "protocols_scanned": len(protocols_scanned),
        },
    }
