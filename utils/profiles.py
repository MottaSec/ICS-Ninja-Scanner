#!/usr/bin/env python3
"""
Scan Profiles for MottaSec ICS Ninja Scanner.

Pre-built scan configurations optimised for common ICS environments.
Each profile defines which protocols to scan, recommended intensity,
relevant ports, and environment-specific operational notes.
"""

from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Profile definitions
# ---------------------------------------------------------------------------

SCAN_PROFILES: Dict[str, dict] = {
    "siemens-plant": {
        "name": "Siemens Manufacturing Plant",
        "description": (
            "Optimized for Siemens-dominant environments "
            "(S7 PLCs, Profinet, OPC-UA)"
        ),
        "protocols": ["s7", "profinet", "opcua", "modbus", "snmp", "mqtt"],
        "intensity": "medium",
        "extra_ports": [102, 34962, 34963, 34964, 4840, 502, 161, 80, 443],
        "notes": "Includes web server detection for Siemens HMI panels",
    },
    "rockwell-plant": {
        "name": "Rockwell/Allen-Bradley Plant",
        "description": (
            "Optimized for Rockwell-dominant environments "
            "(EtherNet/IP, ControlLogix)"
        ),
        "protocols": ["ethernet-ip", "modbus", "snmp", "opcua", "mqtt"],
        "intensity": "medium",
        "extra_ports": [44818, 502, 161, 4840, 2222, 80, 443],
        "notes": "Includes Rockwell-specific EtherNet/IP and CIP testing",
    },
    "substation": {
        "name": "Electrical Substation / Power Grid",
        "description": "IEC 61850/104 focused for power utility environments",
        "protocols": ["iec104", "dnp3", "modbus", "snmp", "mqtt"],
        "intensity": "low",
        "extra_ports": [2404, 20000, 502, 161, 102],
        "notes": "Conservative intensity — substations are critical infrastructure",
    },
    "bms": {
        "name": "Building Management System",
        "description": "BACnet/IP focused for building automation",
        "protocols": ["bacnet", "modbus", "snmp", "mqtt", "opcua"],
        "intensity": "medium",
        "extra_ports": [47808, 502, 161, 1883, 4840],
        "notes": "UDP-heavy — includes BACnet broadcast discovery",
    },
    "water-treatment": {
        "name": "Water/Wastewater Treatment",
        "description": "DNP3 and Modbus focused for water utilities",
        "protocols": ["dnp3", "modbus", "snmp", "mqtt", "opcua"],
        "intensity": "low",
        "extra_ports": [20000, 502, 161, 1883],
        "notes": "Conservative — water systems are safety-critical",
    },
    "oil-gas": {
        "name": "Oil & Gas / Process Industry",
        "description": "HART-IP and Modbus focused for process automation",
        "protocols": ["hart", "modbus", "opcua", "snmp", "mqtt", "profinet"],
        "intensity": "medium",
        "extra_ports": [5094, 502, 4840, 161, 34962],
        "notes": "Includes HART-IP for field device assessment",
    },
    "quick": {
        "name": "Quick Scan",
        "description": "Fast discovery scan — all protocols, low intensity",
        "protocols": ["all"],
        "intensity": "low",
        "extra_ports": [],
        "notes": "Good for initial reconnaissance",
    },
    "full": {
        "name": "Full Assessment",
        "description": "Complete assessment — all protocols, high intensity",
        "protocols": ["all"],
        "intensity": "high",
        "extra_ports": [],
        "notes": "WARNING: High intensity may affect device operation",
    },
}

# Convenience list for CLI choices
PROFILE_NAMES: List[str] = sorted(SCAN_PROFILES.keys())


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def get_profile(name: str) -> Optional[dict]:
    """Return a profile dict by name, or ``None`` if not found.

    Parameters
    ----------
    name:
        Profile key (e.g. ``"siemens-plant"``).

    Returns
    -------
    dict or None
        The profile dictionary, or *None* when the key is unknown.
    """
    return SCAN_PROFILES.get(name)


def list_profiles() -> List[Dict[str, str]]:
    """Return a list of dicts summarising every available profile.

    Each dict contains:

    * ``key`` – profile identifier used on the CLI
    * ``name`` – human-readable name
    * ``description`` – short description
    * ``intensity`` – default intensity level
    * ``protocols`` – comma-separated protocol list
    * ``notes`` – operational notes
    """
    summaries = []
    for key in PROFILE_NAMES:
        p = SCAN_PROFILES[key]
        summaries.append({
            "key": key,
            "name": p["name"],
            "description": p["description"],
            "intensity": p["intensity"],
            "protocols": ", ".join(p["protocols"]),
            "notes": p.get("notes", ""),
        })
    return summaries


def apply_profile(profile_name: str) -> Tuple[List[str], str, List[int]]:
    """Unpack a profile into CLI-ready values.

    Parameters
    ----------
    profile_name:
        A valid profile key.

    Returns
    -------
    tuple[list[str], str, list[int]]
        ``(protocols, intensity, extra_ports)``

    Raises
    ------
    KeyError
        If *profile_name* is not a known profile.
    """
    profile = SCAN_PROFILES.get(profile_name)
    if profile is None:
        raise KeyError(
            f"Unknown profile '{profile_name}'. "
            f"Available: {', '.join(PROFILE_NAMES)}"
        )
    return (
        list(profile["protocols"]),
        profile["intensity"],
        list(profile.get("extra_ports", [])),
    )


def ports_to_range_string(ports: List[int]) -> str:
    """Convert a list of port numbers to a comma-separated string suitable for
    ``--port-range``.

    Example::

        >>> ports_to_range_string([80, 102, 443])
        '80,102,443'
    """
    if not ports:
        return ""
    return ",".join(str(p) for p in sorted(set(ports)))


def get_profile_protocols_csv(profile_name: str) -> str:
    """Return comma-separated protocol string for a profile (CLI-ready).

    Falls back to ``'all'`` for unknown profiles.
    """
    profile = SCAN_PROFILES.get(profile_name)
    if profile is None:
        return "all"
    return ",".join(profile["protocols"])


# ---------------------------------------------------------------------------
# Pretty-print (used by the CLI ``profiles`` command)
# ---------------------------------------------------------------------------

def format_profiles_table() -> str:
    """Return a human-readable multi-line string listing all profiles."""
    lines = []
    for key in PROFILE_NAMES:
        p = SCAN_PROFILES[key]
        lines.append(f"  {key:<20s} {p['name']}")
        lines.append(f"  {'':20s} {p['description']}")
        lines.append(
            f"  {'':20s} Protocols : {', '.join(p['protocols'])}"
        )
        lines.append(
            f"  {'':20s} Intensity : {p['intensity']}"
        )
        if p.get("extra_ports"):
            lines.append(
                f"  {'':20s} Ports     : "
                f"{', '.join(str(pt) for pt in p['extra_ports'])}"
            )
        if p.get("notes"):
            lines.append(f"  {'':20s} Notes     : {p['notes']}")
        lines.append("")
    return "\n".join(lines)
