# ICS Ninja Scanner

<p align="center">
<img src="images/logo.png" alt="ICS Ninja Scanner Logo" width="300px">
</p>

**Multi-protocol Industrial Control System security assessment platform.**

ICS Ninja Scanner is a comprehensive security assessment tool purpose-built for industrial environments. It discovers, fingerprints, and tests ICS/SCADA devices across **11 protocols**, correlates findings against a built-in **CVE database**, maps results to **ICS compliance frameworks** (IEC 62443, NIST 800-82, NERC CIP), and tracks your security posture over time with **scan diffing and trend analysis**.

Designed by penetration testers who actually assess OT environments — not another IT scanner bolted onto port 502.

> ⚖️ Licensed under [PolyForm Noncommercial 1.0.0](LICENSE) — free for research, education, and non-commercial use.

---

## Why ICS Ninja?

Most security scanners treat ICS as an afterthought. ICS Ninja was built ICS-first:

- **Safe by default** — passive discovery at low intensity, write tests auto-restore original values
- **Protocol-native** — speaks Modbus, S7, IEC 104, DNP3, BACnet, etc. natively (no generic TCP probing)
- **Cross-protocol intelligence** — detects multi-protocol attack surfaces (e.g., same device on Modbus + S7 + SNMP with inconsistent auth)
- **Built-in CVE correlation** — embedded database of ICS-specific CVEs, matched against discovered device info
- **Compliance mapping** — auto-maps findings to IEC 62443, NIST 800-82, and NERC CIP requirements
- **Scan diffing** — compare assessments over time, track remediation, detect regression
- **Rate limiting** — millisecond-level request throttling for fragile PLCs and RTUs
- **Industry scan profiles** — pre-built configs for Siemens plants, substations, BMS, water treatment, oil & gas, and more

---

## Installation

```bash
# Core only (no protocol libraries)
pip install ics-ninja

# With all protocol libraries
pip install ics-ninja[all]

# Specific protocols only
pip install ics-ninja[modbus,s7,mqtt]

# Development
pip install ics-ninja[all,dev]
```

### Docker

```bash
docker build -t ics-ninja .
docker run --rm ics-ninja scan --target 192.168.1.100 --protocols modbus --intensity low
```

### From Source

```bash
git clone https://github.com/mottasec/ics-ninja-scanner.git
cd ics-ninja-scanner
pip install -e ".[all]"
```

---

## Quick Start

### Basic Scanning

```bash
# Discover ICS devices on a subnet (passive, safe for production)
ics-ninja scan --target 192.168.1.0/24 --protocols all --intensity low

# Deep scan a specific PLC
ics-ninja scan --target 192.168.1.100 --protocols s7,modbus --intensity medium

# Full security assessment with rate limiting (for fragile devices)
ics-ninja scan --target 192.168.1.100 --protocols all --intensity high --rate-limit 0.5 --yes
```

### Using Scan Profiles

Skip manual protocol selection — use industry-specific profiles:

```bash
# Siemens manufacturing plant (S7 + Profinet + OPC-UA + Modbus + SNMP + MQTT)
ics-ninja scan --target 10.0.0.0/24 --protocols all --profile siemens-plant

# Electrical substation (IEC 104 + DNP3 + Modbus, conservative intensity)
ics-ninja scan --target 10.0.0.0/24 --protocols all --profile substation

# Quick recon across all protocols
ics-ninja scan --target 192.168.1.0/24 --protocols all --profile quick
```

Available profiles: `siemens-plant`, `rockwell-plant`, `substation`, `bms`, `water-treatment`, `oil-gas`, `quick`, `full`

### CVE Correlation

Cross-reference scan findings against the embedded ICS CVE database:

```bash
# Scan with CVE correlation enabled
ics-ninja scan --target 192.168.1.100 --protocols s7,modbus --intensity medium --cve-check

# View CVE database statistics
ics-ninja cve-db
```

The CVE database includes vendor-specific entries for Siemens, Rockwell, Schneider, ABB, and other major ICS vendors, with CVSS scores and affected version ranges.

### Compliance Mapping

Map findings to ICS security frameworks:

```bash
# Map against IEC 62443
ics-ninja scan --target 192.168.1.0/24 --protocols all --intensity medium \
    --compliance iec62443

# Map against all frameworks (IEC 62443 + NIST 800-82 + NERC CIP)
ics-ninja scan --target 192.168.1.0/24 --protocols all --intensity medium \
    --compliance all
```

### Scan Diffing & Trend Analysis

Track your security posture over time:

```bash
# Compare two scan reports
ics-ninja diff old_scan.json new_scan.json --format html --output delta.html

# Auto-diff against the most recent previous scan for the same target
ics-ninja scan --target 192.168.1.0/24 --protocols all --intensity medium \
    --output-format json --output-file scan_q1 --diff-baseline

# Analyze risk trend across multiple scans (oldest first)
ics-ninja trend scan_q1.json scan_q2.json scan_q3.json scan_q4.json --output trend.txt
```

### Reporting

```bash
# Generate HTML report for stakeholders
ics-ninja scan --target 192.168.1.0/24 --protocols all --intensity medium \
    --output-format html --output-file assessment_report

# Export all formats at once (TXT + JSON + CSV + HTML)
ics-ninja scan --target 192.168.1.0/24 --protocols all --intensity medium \
    --output-format all --output-file full_assessment

# Combine everything: CVE check + compliance + HTML report + auto-diff
ics-ninja scan --target 192.168.1.0/24 --protocols all --intensity medium \
    --cve-check --compliance all --output-format json,html \
    --output-file assessment --diff-baseline
```

---

## Supported Protocols

| Protocol | Port | What It Tests |
|----------|------|---------------|
| **Modbus TCP** | 502 | Device ID (FC 43/14), register read/write, Modbus/TLS, broadcast detection |
| **Siemens S7** | 102 | CPU state, module inventory, CVE checks, protection levels, PLC clock, web server |
| **IEC 60870-5-104** | 2404 | Multi-station testing, IEC 62351 security, 5 control command types, sequence tracking |
| **MQTT** | 1883/8883 | Broker auth, MQTT v5, WebSocket, QoS, retained messages, client ID impersonation |
| **SNMP** | 161 | Community strings, SNMPv3, BER-encoded walk, write testing |
| **OPC-UA** | 4840 | Security modes, anonymous access, certificate analysis, node browsing |
| **BACnet** | 47808 | WhoIs discovery, WriteProperty testing, ReinitializeDevice, device enumeration |
| **EtherNet/IP** | 44818 | CIP sessions, tag read/write, ForwardOpen, identity enumeration |
| **DNP3** | 20000 | Secure Authentication, control commands, outstation enumeration |
| **Profinet** | 34964 | DCP discovery, security class detection, RPC testing |
| **HART-IP** | 5094 | Session management, command enumeration, sub-device discovery |

## Scan Intensity Levels

| Level | What It Does | Safe for Production? |
|-------|-------------|---------------------|
| 🟢 **Low** | Passive discovery — version detection, banner grabbing, protocol fingerprinting | ✅ Yes |
| 🟡 **Medium** | Active queries — read registers, check auth, enumerate security settings | ⚠️ Generally safe |
| 🔴 **High** | Write tests — unauthenticated control attempts, write verification with auto-restore | ❌ Maintenance window only |

High-intensity scans prompt for confirmation (bypass with `--yes`). Write tests automatically restore original values and verify restoration.

---

## Scan Profiles

Pre-built configurations for common ICS environments:

| Profile | Environment | Protocols | Default Intensity |
|---------|------------|-----------|-------------------|
| `siemens-plant` | Siemens manufacturing | S7, Profinet, OPC-UA, Modbus, SNMP, MQTT | Medium |
| `rockwell-plant` | Rockwell/Allen-Bradley | EtherNet/IP, Modbus, SNMP, OPC-UA, MQTT | Medium |
| `substation` | Electrical substation | IEC 104, DNP3, Modbus, SNMP, MQTT | Low |
| `bms` | Building management | BACnet, Modbus, SNMP, MQTT, OPC-UA | Medium |
| `water-treatment` | Water/wastewater | DNP3, Modbus, SNMP, MQTT, OPC-UA | Low |
| `oil-gas` | Oil & gas / process | HART-IP, Modbus, OPC-UA, SNMP, MQTT, Profinet | Medium |
| `quick` | Any — fast recon | All | Low |
| `full` | Any — full assessment | All | High |

---

## CLI Reference

```
ics-ninja scan [OPTIONS]
  --target TEXT                    Target IP, range, or CIDR  [required]
  --protocols TEXT                 Comma-separated protocols or 'all'  [required]
  --intensity [low|medium|high]   Scan intensity  [default: low]
  --profile TEXT                   Apply a scan profile (overrides protocols/intensity)
  --cve-check                     Enable CVE correlation
  --compliance [iec62443|nist80082|nerccip|all]  Compliance framework mapping
  --diff-baseline                 Auto-compare with most recent previous scan
  --output-format [txt|json|csv|html|all]  Output format  [default: txt]
  --output-file TEXT              Output filename (without extension)
  --rate-limit FLOAT              Delay between requests in seconds
  --timeout INTEGER               Connection timeout in seconds  [default: 5]
  --threads INTEGER               Parallel scan threads  [default: 10]
  --no-verify                     Disable TLS verification
  --yes / -y                      Skip confirmation for high intensity
  --debug                         Enable debug logging

ics-ninja list                    List available protocols and scanner status
ics-ninja version                 Show version
ics-ninja profiles                List available scan profiles
ics-ninja cve-db                  Show CVE database statistics
ics-ninja diff OLD NEW [--format txt|json|html] [--output FILE]
                                  Compare two scan reports
ics-ninja trend FILE1 FILE2 ... [--output FILE]
                                  Risk trend analysis across multiple scans
```

---

## Output Formats

| Format | Use Case |
|--------|----------|
| **TXT** | Terminal output, quick review |
| **JSON** | Integration with SIEM, ticketing, other tools |
| **CSV** | Spreadsheets, bulk analysis |
| **HTML** | Styled report with executive summary, severity charts, and remediation priorities |

HTML reports include CVSS scores (auto-calculated for all findings), severity distribution charts, and compliance mapping when enabled.

---

## Safety

This tool is for **authorized security assessments only**. Always:

1. 🔐 Get written authorization before scanning any ICS environment
2. 🟢 Start with low intensity in production
3. ⏰ Use maintenance windows for high-intensity scans
4. 📊 Monitor target systems during scanning
5. 🐌 Use `--rate-limit` for sensitive/legacy devices

---

## Contributing

We welcome contributions — especially new protocol scanners. See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev setup, scanner checklist, and PR process.

## Security

Found a vulnerability in ICS Ninja Scanner itself? See [SECURITY.md](SECURITY.md) for responsible disclosure.

## License

[PolyForm Noncommercial License 1.0.0](LICENSE) — free for research, education, non-commercial organizations, and personal use. Commercial use requires a separate license from [MottaSec](https://mottasec.com).

---

Built by [MottaSec](https://mottasec.com)
