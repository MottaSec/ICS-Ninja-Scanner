# Changelog

All notable changes to this project will be documented in this file.

## [2.0.0] - 2026-01-30

### Added
- **CVE Correlation Engine** — embedded ICS CVE database covering Siemens, Rockwell, Schneider, ABB, and other major vendors. Auto-matches device fingerprints against known vulnerabilities with CVSS scores and affected version ranges. Enable with `--cve-check`. View database stats with `ics-ninja cve-db`.
- **Compliance Mapping** — auto-maps findings to IEC 62443, NIST 800-82, and NERC CIP frameworks. Generate compliance gap reports with `--compliance iec62443|nist80082|nerccip|all`.
- **Scan Diffing** — compare two JSON scan reports to track new/resolved/persistent issues, severity changes, host-level risk deltas, and remediation progress. `ics-ninja diff old.json new.json`. Auto-diff against previous baseline with `--diff-baseline`.
- **Risk Trend Analysis** — analyze risk trajectory across multiple scans over time. `ics-ninja trend scan1.json scan2.json scan3.json`.
- **Scan Profiles** — 8 pre-built configurations for common ICS environments: `siemens-plant`, `rockwell-plant`, `substation`, `bms`, `water-treatment`, `oil-gas`, `quick`, `full`. Apply with `--profile <name>`.
- **CVSS 3.1 Scoring** — full base score calculator with 130+ ICS finding-to-CVSS mappings. Every finding gets an auto-calculated CVSS score.
- **HTML Reports** — styled assessment reports with executive summary, severity distribution charts, findings tables, remediation priorities, and configurable branding.
- **Cross-protocol intelligence** — detects multi-protocol attack surfaces (e.g., same device exposing Modbus + S7 + SNMP with inconsistent authentication).

### Protocol Scanners (all 11)
- **Modbus TCP** — device identification (FC 43/14), register read/write, Modbus/TLS detection, broadcast testing, smart unit ID scanning
- **Siemens S7** — real CVE database, CPU state check, module inventory, web server detection, PLC clock, protection level analysis
- **IEC 60870-5-104** — IEC 62351 detection, 5 control command types, sequence tracking, multi-station testing, unsolicited data monitoring
- **MQTT** — callback-based fast detection, MQTT v5, WebSocket, retained messages, QoS testing, client ID impersonation
- **SNMP** — proper BER encoding (fixed for non-"public" community strings), SNMPv3 detection, write testing, SNMP walk
- **OPC-UA** — security mode analysis, anonymous access detection, certificate analysis, node browsing
- **BACnet** — WhoIs discovery, WriteProperty testing, ReinitializeDevice, device enumeration
- **EtherNet/IP** — CIP session testing, tag read/write, ForwardOpen, identity enumeration
- **DNP3** — Secure Authentication detection, control command testing, outstation enumeration
- **Profinet** — DCP discovery, security class detection, RPC testing
- **HART-IP** — session management, command enumeration, sub-device discovery

### Infrastructure
- Rate limiting for safe scanning of fragile ICS devices (`--rate-limit`)
- High-intensity scan confirmation prompt (bypass with `--yes`)
- Graceful dependency handling (missing protocol libraries don't crash the tool)
- Docker support
- JSON, CSV, TXT, and HTML report formats
- Safe-by-default write testing with automatic restore and verification
- Consistent timeout handling across all scanners
- PolyForm Noncommercial 1.0.0 license

## [1.0.0] - 2026-01-29

Initial release with core scanning framework and basic protocol support.
