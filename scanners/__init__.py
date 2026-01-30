"""
Scanner modules for ICS Ninja Scanner.
Handles graceful import fallback when protocol-specific dependencies are missing.
"""

import logging

logger = logging.getLogger("ICSNinja.scanners")

# All protocol scanner mappings
_SCANNER_REGISTRY = {
    "modbus": ("scanners.modbus_scanner", "ModbusScanner"),
    "dnp3": ("scanners.dnp3_scanner", "DNP3Scanner"),
    "bacnet": ("scanners.bacnet_scanner", "BACnetScanner"),
    "s7": ("scanners.s7_scanner", "S7Scanner"),
    "ethernet-ip": ("scanners.ethernet_ip_scanner", "EtherNetIPScanner"),
    "opcua": ("scanners.opcua_scanner", "OPCUAScanner"),
    "profinet": ("scanners.profinet_scanner", "ProfinetScanner"),
    "iec104": ("scanners.iec104_scanner", "IEC104Scanner"),
    "hart": ("scanners.hart_scanner", "HARTScanner"),
    "snmp": ("scanners.snmp_scanner", "SNMPScanner"),
    "mqtt": ("scanners.mqtt_scanner", "MQTTScanner"),
}

AVAILABLE_SCANNERS = {}
UNAVAILABLE_SCANNERS = {}
ALL_SCANNER_NAMES = list(_SCANNER_REGISTRY.keys())

for _name, (_module, _class) in _SCANNER_REGISTRY.items():
    try:
        _mod = __import__(_module, fromlist=[_class])
        AVAILABLE_SCANNERS[_name] = getattr(_mod, _class)
    except ImportError as e:
        UNAVAILABLE_SCANNERS[_name] = str(e)
        logger.warning(f"Scanner '{_name}' unavailable: {e}")
    except Exception as e:
        UNAVAILABLE_SCANNERS[_name] = str(e)
        logger.warning(f"Scanner '{_name}' failed to load: {e}")
