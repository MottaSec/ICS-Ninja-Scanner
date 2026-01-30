# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-01-29

### Added
- Full implementation of all 11 ICS protocol scanners:
  - Modbus TCP (with device identification, Modbus/TLS detection)
  - Siemens S7 (with real CVE database, CPU state checks, module inventory)
  - IEC 60870-5-104 (with IEC 62351 detection, multi-station testing)
  - MQTT (with v5 detection, WebSocket, QoS testing, client impersonation)
  - SNMP (with proper BER encoding, SNMPv3 detection, walk capability)
  - OPC-UA (with security mode analysis, anonymous access, node browsing)
  - BACnet (with WhoIs discovery, WriteProperty testing, ReinitializeDevice)
  - EtherNet/IP (with CIP session testing, tag read/write, ForwardOpen)
  - DNP3 (with Secure Authentication detection, control command testing)
  - Profinet (with DCP discovery, security class detection, RPC testing)
  - HART-IP (with session testing, command enumeration, sub-device discovery)
- Cross-protocol intelligence (detects multi-protocol attack surfaces)
- Rate limiting for safe scanning of fragile ICS devices
- High-intensity scan confirmation prompt
- Graceful dependency handling (missing libraries don't crash the tool)
- HTML, JSON, CSV, and TXT report formats
- Docker support
- PolyForm Noncommercial 1.0.0 license

### Security
- Safe-by-default write testing with automatic restore and verification
- Consistent timeout handling across all scanners
