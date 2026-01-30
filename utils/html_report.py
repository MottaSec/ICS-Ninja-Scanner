#!/usr/bin/env python3
"""
HTML Report Generator for MottaSec ICS Ninja Scanner.
Produces a self-contained, professional, print-ready HTML security assessment report.
"""

import base64
import mimetypes
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from jinja2 import Environment

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {
    "critical": "#8b0000",
    "high": "#dc3545",
    "medium": "#fd7e14",
    "low": "#0d6efd",
    "info": "#6c757d",
}


def _sev_key(issue):
    return SEVERITY_ORDER.get(issue.get("severity", "info").lower(), 5)


# ---------------------------------------------------------------------------
# Data preparation
# ---------------------------------------------------------------------------

def _prepare_data(scan_results):
    """Parse scan_results into structures the template can consume."""
    metadata = scan_results.get("metadata", {})
    results = scan_results.get("results", {})

    # --- per-severity counters ---
    severity_counts = Counter()
    all_issues = []  # (ip, protocol, issue)
    hosts_with_findings = set()
    finding_summary = defaultdict(lambda: {"count": 0, "hosts": set(), "severity": "info", "cvss": None})
    cross_protocol_findings = []

    for ip, protocols in results.items():
        for protocol, findings in protocols.items():
            if protocol.startswith("_"):
                # cross-protocol
                for issue in findings.get("issues", []):
                    sev = issue.get("severity", "info").lower()
                    severity_counts[sev] += 1
                    cross_protocol_findings.append({**issue, "_ip": ip})
                    hosts_with_findings.add(ip)
                continue
            for issue in findings.get("issues", []):
                sev = issue.get("severity", "info").lower()
                severity_counts[sev] += 1
                all_issues.append((ip, protocol, issue))
                hosts_with_findings.add(ip)
                desc = issue.get("description", "N/A")
                finding_summary[desc]["count"] += 1
                finding_summary[desc]["hosts"].add(ip)
                if SEVERITY_ORDER.get(sev, 5) < SEVERITY_ORDER.get(finding_summary[desc]["severity"], 5):
                    finding_summary[desc]["severity"] = sev
                if issue.get("cvss") is not None:
                    finding_summary[desc]["cvss"] = issue["cvss"]

    total_findings = sum(severity_counts.values())
    total_hosts = len(results)
    hosts_with = len(hosts_with_findings)

    # Risk score (0-100)
    risk = min(100, int(
        severity_counts.get("critical", 0) * 25
        + severity_counts.get("high", 0) * 15
        + severity_counts.get("medium", 0) * 7
        + severity_counts.get("low", 0) * 2
        + severity_counts.get("info", 0) * 0.5
    ))

    # Executive summary paragraph
    most_common = severity_counts.most_common()
    common_types = [f"{c} {s}" for s, c in most_common if c > 0]
    summary_text = (
        f"The assessment identified {total_findings} finding(s) across {hosts_with} host(s), "
        f"including {severity_counts.get('critical', 0)} critical and {severity_counts.get('high', 0)} "
        f"high severity issues. "
    )
    if common_types:
        summary_text += f"The severity breakdown is: {', '.join(common_types)}. "
    if severity_counts.get("critical", 0) or severity_counts.get("high", 0):
        summary_text += "Immediate remediation is recommended for all critical and high findings."
    else:
        summary_text += "No critical or high severity issues require immediate action."

    # Bar chart max
    max_sev = max(severity_counts.values()) if severity_counts else 1

    # --- findings summary table ---
    summary_table = sorted(
        [{"description": d, "severity": v["severity"], "cvss": v["cvss"],
          "host_count": v["count"], "hosts": ", ".join(sorted(v["hosts"]))}
         for d, v in finding_summary.items()],
        key=lambda x: (SEVERITY_ORDER.get(x["severity"], 5), -x["host_count"]),
    )

    # --- remediation priority ---
    remed_map = defaultdict(lambda: {"hosts": set(), "protocols": set(), "severity": "info"})
    for ip, proto, issue in all_issues:
        rem = issue.get("remediation")
        if rem:
            sev = issue.get("severity", "info").lower()
            remed_map[rem]["hosts"].add(ip)
            remed_map[rem]["protocols"].add(proto)
            if SEVERITY_ORDER.get(sev, 5) < SEVERITY_ORDER.get(remed_map[rem]["severity"], 5):
                remed_map[rem]["severity"] = sev
    for issue in cross_protocol_findings:
        rem = issue.get("remediation")
        if rem:
            sev = issue.get("severity", "info").lower()
            remed_map[rem]["hosts"].add(issue.get("_ip", ""))
            remed_map[rem]["protocols"].add("cross-protocol")
            if SEVERITY_ORDER.get(sev, 5) < SEVERITY_ORDER.get(remed_map[rem]["severity"], 5):
                remed_map[rem]["severity"] = sev

    remediation_list = sorted(
        [{"description": d, "severity": v["severity"],
          "host_count": len(v["hosts"]),
          "protocols": ", ".join(sorted(v["protocols"]))}
         for d, v in remed_map.items()],
        key=lambda x: (SEVERITY_ORDER.get(x["severity"], 5), -x["host_count"]),
    )[:10]

    # --- hosts detail ---
    hosts_detail = []
    for ip in sorted(results.keys()):
        protocols = results[ip]
        host_findings = 0
        proto_sections = []
        for protocol, findings in sorted(protocols.items()):
            if protocol.startswith("_"):
                continue
            issues = sorted(findings.get("issues", []), key=_sev_key)
            host_findings += len(issues)
            proto_sections.append({
                "name": protocol,
                "device_info": findings.get("device_info", {}),
                "issues": issues,
            })
        hosts_detail.append({"ip": ip, "total": host_findings, "protocols": proto_sections})

    # cross-protocol sorted
    cross_protocol_findings.sort(key=_sev_key)

    return {
        "metadata": metadata,
        "total_hosts": total_hosts,
        "hosts_with_findings": hosts_with,
        "total_findings": total_findings,
        "severity_counts": {s: severity_counts.get(s, 0) for s in SEVERITY_ORDER},
        "risk_score": risk,
        "summary_text": summary_text,
        "max_sev": max_sev or 1,
        "hosts_detail": hosts_detail,
        "cross_protocol": cross_protocol_findings,
        "summary_table": summary_table,
        "remediation_list": remediation_list,
        "sev_colors": SEVERITY_COLORS,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ---------------------------------------------------------------------------
# Logo helper
# ---------------------------------------------------------------------------

def _resolve_logo(branding):
    if not branding:
        return None
    if branding.get("logo_url"):
        return branding["logo_url"]
    logo_path = branding.get("logo_path")
    if logo_path and Path(logo_path).is_file():
        mime = mimetypes.guess_type(logo_path)[0] or "image/png"
        data = Path(logo_path).read_bytes()
        return f"data:{mime};base64,{base64.b64encode(data).decode()}"
    return None


# ---------------------------------------------------------------------------
# Jinja2 HTML template (self-contained)
# ---------------------------------------------------------------------------

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ICS Security Assessment Report</title>
<style>
/* === Reset & Base === */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --navy:#1a1a2e;--accent:{{ accent_color }};--crit:#8b0000;--high:#dc3545;
  --med:#fd7e14;--low:#0d6efd;--info-c:#6c757d;--bg:#f8f9fa;--border:#dee2e6;
}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  color:#212529;background:#fff;font-size:14px;line-height:1.6}
a{color:var(--accent)}

/* === Print === */
@media print{
  .page-break{page-break-before:always}
  body{font-size:11pt}
  .no-print{display:none}
}

/* === Header === */
.report-header{background:var(--navy);color:#fff;padding:48px 40px 36px;text-align:center}
.report-header h1{font-size:28px;font-weight:700;margin-bottom:8px;letter-spacing:.5px}
.report-header .subtitle{font-size:14px;opacity:.85;margin-bottom:18px}
.report-header .meta{display:flex;justify-content:center;gap:32px;flex-wrap:wrap;font-size:13px;opacity:.75}
.logo{max-height:60px;margin-bottom:16px}

/* === Sections === */
.container{max-width:1040px;margin:0 auto;padding:0 28px}
section{margin:36px 0}
section h2{font-size:20px;font-weight:700;color:var(--navy);border-bottom:3px solid var(--accent);
  padding-bottom:6px;margin-bottom:18px}
section h3{font-size:16px;font-weight:600;color:#333;margin:14px 0 8px}

/* === Cards / Badges === */
.badge{display:inline-block;padding:2px 10px;border-radius:4px;font-size:12px;font-weight:600;
  color:#fff;text-transform:uppercase;letter-spacing:.4px}
.badge-critical{background:var(--crit)}.badge-high{background:var(--high)}
.badge-medium{background:var(--med)}.badge-low{background:var(--low)}
.badge-info{background:var(--info-c)}

.proto-badge{background:var(--navy);color:#fff;padding:4px 14px;border-radius:4px;
  font-size:13px;font-weight:600;text-transform:uppercase;display:inline-block;margin:12px 0 6px}

/* === Summary boxes === */
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin:16px 0}
.summary-box{background:var(--bg);border:1px solid var(--border);border-radius:8px;
  padding:18px;text-align:center}
.summary-box .num{font-size:32px;font-weight:700}
.summary-box .label{font-size:12px;color:#666;text-transform:uppercase;letter-spacing:.5px;margin-top:4px}

/* === Risk gauge === */
.risk-bar-outer{background:#e9ecef;border-radius:8px;height:24px;overflow:hidden;margin:8px 0 16px}
.risk-bar-inner{height:100%;border-radius:8px;transition:width .3s}

/* === Bar chart === */
.bar-row{display:flex;align-items:center;margin:4px 0}
.bar-label{width:80px;font-weight:600;font-size:13px;text-transform:capitalize}
.bar-track{flex:1;background:#e9ecef;border-radius:4px;height:22px;overflow:hidden;margin:0 10px}
.bar-fill{height:100%;border-radius:4px;min-width:2px}
.bar-count{width:36px;font-size:13px;font-weight:600;text-align:right}

/* === Tables === */
table{width:100%;border-collapse:collapse;margin:10px 0 20px;font-size:13px}
th{background:var(--navy);color:#fff;padding:10px 12px;text-align:left;font-weight:600;font-size:12px;
  text-transform:uppercase;letter-spacing:.3px}
td{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top}
tr:nth-child(even) td{background:#f8f9fa}
tr:hover td{background:#eef1f5}

/* === Device info === */
.device-table{width:auto;margin:6px 0 14px}
.device-table td{padding:4px 14px 4px 0;border:none;font-size:13px}
.device-table td:first-child{font-weight:600;color:#555}

/* === Host card === */
.host-card{border:1px solid var(--border);border-radius:8px;margin:20px 0;overflow:hidden}
.host-header{background:var(--bg);padding:14px 20px;display:flex;justify-content:space-between;
  align-items:center;border-bottom:1px solid var(--border)}
.host-header h3{margin:0;font-size:16px;color:var(--navy)}
.host-body{padding:8px 20px 20px}

/* === Footer === */
.report-footer{background:var(--navy);color:rgba(255,255,255,.7);text-align:center;
  padding:28px 20px;font-size:12px;margin-top:40px}
.report-footer strong{color:#fff}

/* === Misc === */
.muted{color:#888;font-size:13px}
.text-block{margin:10px 0;line-height:1.7}
.prio-num{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;
  border-radius:50%;background:var(--navy);color:#fff;font-weight:700;font-size:13px;margin-right:10px}
.remed-item{padding:10px 0;border-bottom:1px solid var(--border)}
.remed-item:last-child{border:none}
</style>
</head>
<body>

<!-- ============ HEADER ============ -->
<div class="report-header">
  {% if logo_src %}<img src="{{ logo_src }}" alt="Logo" class="logo"><br>{% endif %}
  <h1>ICS Security Assessment Report</h1>
  <div class="subtitle">{{ company_name }}</div>
  <div class="meta">
    <span>📅 {{ metadata.scan_time[:19] | default(generated_at) }}</span>
    <span>🎯 Target: {{ metadata.target | default('N/A') }}</span>
    <span>🔧 v{{ metadata.version | default('1.0.0') }}{% if metadata.codename %} "{{ metadata.codename }}"{% endif %}</span>
    <span>⚡ Intensity: {{ metadata.intensity | default('N/A') }}</span>
  </div>
</div>

<div class="container">

<!-- ============ EXECUTIVE SUMMARY ============ -->
<section>
  <h2>Executive Summary</h2>
  <div class="summary-grid">
    <div class="summary-box"><div class="num">{{ total_hosts }}</div><div class="label">Hosts Scanned</div></div>
    <div class="summary-box"><div class="num">{{ hosts_with_findings }}</div><div class="label">With Findings</div></div>
    <div class="summary-box"><div class="num">{{ total_findings }}</div><div class="label">Total Findings</div></div>
    <div class="summary-box">
      <div class="num" style="color:{% if risk_score>=75 %}var(--crit){% elif risk_score>=50 %}var(--high){% elif risk_score>=25 %}var(--med){% else %}var(--low){% endif %}">{{ risk_score }}</div>
      <div class="label">Risk Score</div>
    </div>
  </div>

  <div class="risk-bar-outer">
    <div class="risk-bar-inner" style="width:{{ risk_score }}%;background:{% if risk_score>=75 %}var(--crit){% elif risk_score>=50 %}var(--high){% elif risk_score>=25 %}var(--med){% else %}var(--low){% endif %}"></div>
  </div>

  <div class="summary-grid">
    {% for sev in ['critical','high','medium','low','info'] %}
    <div class="summary-box">
      <div class="num" style="color:{{ sev_colors[sev] }}">{{ severity_counts[sev] }}</div>
      <div class="label">{{ sev | capitalize }}</div>
    </div>
    {% endfor %}
  </div>

  <p class="text-block">{{ summary_text }}</p>
</section>

<!-- ============ SEVERITY DISTRIBUTION ============ -->
<section class="page-break">
  <h2>Severity Distribution</h2>
  {% for sev in ['critical','high','medium','low','info'] %}
  <div class="bar-row">
    <span class="bar-label" style="color:{{ sev_colors[sev] }}">{{ sev }}</span>
    <div class="bar-track">
      <div class="bar-fill" style="width:{{ (severity_counts[sev] / max_sev * 100) | round(1) }}%;background:{{ sev_colors[sev] }}"></div>
    </div>
    <span class="bar-count">{{ severity_counts[sev] }}</span>
  </div>
  {% endfor %}
</section>

<!-- ============ FINDINGS BY HOST ============ -->
<section class="page-break">
  <h2>Findings by Host</h2>
  {% for host in hosts_detail %}
  <div class="host-card">
    <div class="host-header">
      <h3>🖥️ {{ host.ip }}</h3>
      <span class="badge badge-{% if host.total >= 5 %}high{% elif host.total >= 2 %}medium{% else %}low{% endif %}">{{ host.total }} finding{{ 's' if host.total != 1 else '' }}</span>
    </div>
    <div class="host-body">
      {% for proto in host.protocols %}
      <div class="proto-badge">{{ proto.name }}</div>

      {% if proto.device_info %}
      <table class="device-table">
        {% for k, v in proto.device_info.items() %}
        <tr><td>{{ k }}</td><td>{{ v }}</td></tr>
        {% endfor %}
      </table>
      {% endif %}

      {% if proto.issues %}
      <table>
        <thead><tr><th style="width:100px">Severity</th><th style="width:70px">CVSS</th><th>Description</th><th>Details</th><th>Remediation</th></tr></thead>
        <tbody>
          {% for issue in proto.issues %}
          <tr>
            <td><span class="badge badge-{{ issue.severity | default('info') | lower }}">{{ issue.severity | default('info') | upper }}</span></td>
            <td>{{ issue.cvss | default('—') }}</td>
            <td>{{ issue.description | default('') }}</td>
            <td>{{ issue.details | default('') }}</td>
            <td>{{ issue.remediation | default('') }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
      <p class="muted" style="margin:6px 0 14px">No issues detected for this protocol.</p>
      {% endif %}
      {% endfor %}
    </div>
  </div>
  {% endfor %}

  {% if not hosts_detail %}
  <p class="muted">No hosts returned results.</p>
  {% endif %}
</section>

<!-- ============ CROSS-PROTOCOL ============ -->
{% if cross_protocol %}
<section class="page-break">
  <h2>🔗 Cross-Protocol Findings</h2>
  <table>
    <thead><tr><th style="width:100px">Severity</th><th>Description</th><th>Details</th><th>Remediation</th></tr></thead>
    <tbody>
      {% for issue in cross_protocol %}
      <tr>
        <td><span class="badge badge-{{ issue.severity | default('info') | lower }}">{{ issue.severity | default('info') | upper }}</span></td>
        <td>{{ issue.description | default('') }}</td>
        <td>{{ issue.details | default('') }}</td>
        <td>{{ issue.remediation | default('') }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</section>
{% endif %}

<!-- ============ FINDINGS SUMMARY TABLE ============ -->
{% if summary_table %}
<section class="page-break">
  <h2>Findings Summary</h2>
  <table>
    <thead><tr><th style="width:100px">Severity</th><th style="width:70px">CVSS</th><th>Description</th><th style="width:60px">Hosts</th></tr></thead>
    <tbody>
      {% for row in summary_table %}
      <tr>
        <td><span class="badge badge-{{ row.severity | lower }}">{{ row.severity | upper }}</span></td>
        <td>{{ row.cvss | default('—') }}</td>
        <td>{{ row.description }}</td>
        <td style="text-align:center">{{ row.host_count }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</section>
{% endif %}

<!-- ============ REMEDIATION PRIORITY ============ -->
{% if remediation_list %}
<section class="page-break">
  <h2>Remediation Priority</h2>
  {% for item in remediation_list %}
  <div class="remed-item">
    <span class="prio-num">{{ loop.index }}</span>
    <span class="badge badge-{{ item.severity | lower }}" style="margin-right:8px">{{ item.severity | upper }}</span>
    <strong>{{ item.description }}</strong>
    <br><span class="muted" style="margin-left:38px">Protocols: {{ item.protocols }} · Affected hosts: {{ item.host_count }}</span>
  </div>
  {% endfor %}
</section>
{% endif %}

</div><!-- .container -->

<!-- ============ FOOTER ============ -->
<div class="report-footer">
  <strong>Generated by MottaSec ICS Ninja Scanner v{{ metadata.version | default('1.0.0') }}</strong><br>
  This report is confidential and intended for authorized personnel only.<br>
  {% if footer_text %}{{ footer_text }}<br>{% endif %}
  <span style="opacity:.5">{{ generated_at }}</span>
</div>

</body>
</html>"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_html_report(scan_results, output_path, branding=None):
    """
    Generate a professional HTML security assessment report.

    Args:
        scan_results (dict): Scan results from the orchestrator.
        output_path (str | Path): Output file path.
        branding (dict, optional): {
            'company_name': str,
            'logo_path': str,
            'logo_url': str,
            'accent_color': str,
            'footer_text': str,
        }

    Returns:
        str: Path to generated report.
    """
    branding = branding or {}
    data = _prepare_data(scan_results)

    env = Environment(autoescape=True)
    template = env.from_string(HTML_TEMPLATE)

    html = template.render(
        **data,
        company_name=branding.get("company_name", "MottaSec ICS Ninja Scanner"),
        logo_src=_resolve_logo(branding),
        accent_color=branding.get("accent_color", "#1a1a2e"),
        footer_text=branding.get("footer_text", ""),
    )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return str(output_path)
