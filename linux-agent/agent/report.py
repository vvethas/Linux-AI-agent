"""
report.py — Standalone HTML report generator from a study JSON.

Dark theme (#0d0d0d), no external dependencies, printable.
"""
import json
from datetime import datetime, timezone


def _esc(val) -> str:
    """HTML-escape a value converted to string."""
    s = str(val) if val is not None else ""
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
    )


def _score_color(score: int) -> str:
    if score >= 80:
        return "#4caf50"
    if score >= 60:
        return "#e5b840"
    if score >= 40:
        return "#e05252"
    return "#b71c1c"


def _severity_badge(sev: str) -> str:
    colors = {
        "critical": "#b71c1c",
        "high": "#e05252",
        "medium": "#e5b840",
        "low": "#5b9bd5",
    }
    color = colors.get(sev.lower(), "#888")
    return f'<span style="background:{color};color:#fff;padding:2px 7px;border-radius:3px;font-size:0.75rem;font-weight:700">{_esc(sev.upper())}</span>'


def _priority_badge(pri: str) -> str:
    return _severity_badge(pri)


def generate_html(study_row: dict) -> str:
    """
    Build a full standalone HTML page from a study_reports DB row.
    study_row must have report_json (string or dict) and metadata fields.
    """
    if isinstance(study_row.get("report_json"), str):
        report = json.loads(study_row["report_json"])
    else:
        report = study_row.get("report_json") or {}

    instance_label = _esc(study_row.get("instance_label") or study_row.get("host") or "Unknown")
    created_at = study_row.get("created_at") or datetime.now(timezone.utc).isoformat()

    summary = report.get("summary", {})
    hardware = report.get("hardware", {})
    os_info = report.get("os", {})
    services = report.get("services", {})
    network = report.get("network", {})
    security = report.get("security", {})
    software = report.get("software", {})
    environment = report.get("environment", {})
    performance = report.get("performance", {})
    recommendations = report.get("recommendations", [])

    health_score = int(summary.get("health_score", 0))
    sec_score = int(security.get("score", 0))
    h_color = _score_color(health_score)
    s_color = _score_color(sec_score)

    # ── Helpers ──────────────────────────────────────────────────────────────

    def card(title, body):
        return f"""
        <div class="card">
          <h2>{_esc(title)}</h2>
          {body}
        </div>"""

    def kv(label, val):
        return f'<div class="kv"><span class="kl">{_esc(label)}</span><span class="kv-val">{_esc(val)}</span></div>'

    def analysis_p(text):
        if not text:
            return ""
        return f'<p class="analysis">{_esc(text)}</p>'

    # ── Metric cards ─────────────────────────────────────────────────────────

    ram_pct = "N/A"
    try:
        ram_gb = float(hardware.get("ram_gb", 0))
        if ram_gb:
            ram_pct = f"{ram_gb} GB"
    except Exception:
        pass

    metric_cards = f"""
    <div class="metrics">
      <div class="metric-card">
        <div class="metric-val" style="color:{h_color}">{health_score}</div>
        <div class="metric-label">Health Score</div>
      </div>
      <div class="metric-card">
        <div class="metric-val">{_esc(ram_pct)}</div>
        <div class="metric-label">RAM</div>
      </div>
      <div class="metric-card">
        <div class="metric-val">{_esc(str(hardware.get("cores","?")))} cores</div>
        <div class="metric-label">CPUs</div>
      </div>
      <div class="metric-card">
        <div class="metric-val" style="color:#4caf50">{_esc(str(services.get("total_running","?")))}</div>
        <div class="metric-label">Running Services</div>
      </div>
      <div class="metric-card">
        <div class="metric-val" style="color:#e05252">{_esc(str(services.get("total_failed","?")))}</div>
        <div class="metric-label">Failed Services</div>
      </div>
      <div class="metric-card">
        <div class="metric-val" style="color:{s_color}">{sec_score}</div>
        <div class="metric-label">Security Score</div>
      </div>
    </div>"""

    # ── Hardware section ──────────────────────────────────────────────────────

    hw_body = (
        kv("CPU", hardware.get("cpu_model", "N/A"))
        + kv("Cores / Threads", f"{hardware.get('cores','?')} / {hardware.get('threads','?')}")
        + kv("RAM", f"{hardware.get('ram_gb','?')} GB")
        + kv("Swap", f"{hardware.get('swap_gb','?')} GB")
        + kv("Disk", hardware.get("disk_summary", "N/A"))
        + kv("Virtualisation", "✓" if hardware.get("virtualization_support") else "✗")
        + kv("AES-NI", "✓" if hardware.get("aes_support") else "✗")
        + analysis_p(hardware.get("analysis"))
    )

    # ── OS section ────────────────────────────────────────────────────────────

    os_body = (
        kv("OS", os_info.get("name", "N/A"))
        + kv("Kernel", os_info.get("kernel", "N/A"))
        + kv("Uptime", os_info.get("uptime", "N/A"))
        + kv("Timezone", os_info.get("timezone", "N/A"))
        + kv("NTP Synced", "✓" if os_info.get("ntp_synced") else "✗")
        + kv("Pending Updates", str(os_info.get("pending_updates", 0)))
        + kv("Security Updates", str(os_info.get("security_updates", 0)))
        + analysis_p(os_info.get("analysis"))
    )

    # ── Services section ──────────────────────────────────────────────────────

    failed_rows = "".join(
        f'<tr style="color:#e05252"><td>{_esc(s)}</td></tr>'
        for s in (services.get("failed") or [])
    ) or '<tr><td style="color:#888">None</td></tr>'

    svc_body = (
        kv("Running", str(services.get("total_running", 0)))
        + kv("Failed", str(services.get("total_failed", 0)))
        + f"""<table><thead><tr><th>Failed Services</th></tr></thead>
              <tbody>{failed_rows}</tbody></table>"""
        + analysis_p(services.get("analysis"))
    )

    # ── Network section ───────────────────────────────────────────────────────

    port_rows = "".join(
        f'<tr><td>{_esc(str(p.get("port","?")))}</td>'
        f'<td>{_esc(p.get("service",""))}</td>'
        f'<td style="color:{"#e05252" if p.get("exposure")=="internet" else "#4caf50"}">'
        f'{_esc(p.get("exposure","local"))}</td></tr>'
        for p in (network.get("open_ports") or [])
    ) or '<tr><td colspan="3" style="color:#888">N/A</td></tr>'

    net_body = (
        kv("Firewall", network.get("firewall", "unknown"))
        + f"""<table>
          <thead><tr><th>Port</th><th>Service</th><th>Exposure</th></tr></thead>
          <tbody>{port_rows}</tbody>
        </table>"""
        + analysis_p(network.get("analysis"))
    )

    # ── Security section ──────────────────────────────────────────────────────

    finding_rows = "".join(
        f'<tr><td>{_severity_badge(f.get("severity","low"))}</td>'
        f'<td>{_esc(f.get("issue",""))}</td>'
        f'<td>{_esc(f.get("recommendation",""))}</td></tr>'
        for f in (security.get("findings") or [])
    ) or '<tr><td colspan="3" style="color:#888">No findings</td></tr>'

    sec_body = (
        kv("Security Score", f'{sec_score} — {security.get("label","N/A")}')
        + kv("SSH Root Login", security.get("ssh_root_login", "unknown"))
        + kv("Password Auth", security.get("password_auth", "unknown"))
        + kv("Firewall Active", "✓" if security.get("firewall_active") else "✗")
        + kv("Pending Security Updates", str(security.get("pending_security_updates", 0)))
        + f"""<table>
          <thead><tr><th>Severity</th><th>Issue</th><th>Recommendation</th></tr></thead>
          <tbody>{finding_rows}</tbody>
        </table>"""
        + analysis_p(security.get("analysis"))
    )

    # ── Software section ──────────────────────────────────────────────────────

    def pill_list(items):
        return "".join(
            f'<span class="pill">{_esc(i)}</span>'
            for i in (items or [])
        )

    sw_body = (
        f'<div class="pill-group">{pill_list(software.get("installed_highlights"))}</div>'
        + kv("Runtimes", ", ".join(software.get("runtimes") or []) or "N/A")
        + kv("Databases", ", ".join(software.get("databases") or []) or "N/A")
        + analysis_p(software.get("analysis"))
    )

    # ── Performance section ───────────────────────────────────────────────────

    perf_body = (
        kv("Load (1m / 5m / 15m)", f'{performance.get("cpu_load_1m","?")} / '
           f'{performance.get("cpu_load_5m","?")} / {performance.get("cpu_load_15m","?")}')
        + f'<div style="margin-top:0.5rem"><strong>Top CPU:</strong><pre class="mono">'
        + _esc("\n".join(performance.get("top_cpu_processes") or []))
        + "</pre></div>"
        + f'<div><strong>Top Memory:</strong><pre class="mono">'
        + _esc("\n".join(performance.get("top_mem_processes") or []))
        + "</pre></div>"
        + analysis_p(performance.get("analysis"))
    )

    # ── Environment section ───────────────────────────────────────────────────

    env_detail_rows = "".join(
        f'<tr><td>{_esc(k)}</td><td>{_esc(str(v))}</td></tr>'
        for k, v in (environment.get("details") or {}).items()
    ) or '<tr><td colspan="2" style="color:#888">None</td></tr>'

    env_body = (
        kv("Type", environment.get("type", "N/A"))
        + f'<table><thead><tr><th>Key</th><th>Value</th></tr></thead>'
        + f'<tbody>{env_detail_rows}</tbody></table>'
        + analysis_p(environment.get("analysis"))
    )

    # ── Recommendations ───────────────────────────────────────────────────────

    rec_rows = "".join(
        f'<tr>'
        f'<td>{_priority_badge(r.get("priority","low"))}</td>'
        f'<td>{_esc(r.get("category",""))}</td>'
        f'<td>{_esc(r.get("title",""))}</td>'
        f'<td>{_esc(r.get("detail",""))}</td>'
        f'<td><code class="mono-sm">{_esc(r.get("command",""))}</code></td>'
        f'</tr>'
        for r in (recommendations or [])
    ) or '<tr><td colspan="5" style="color:#888">No recommendations</td></tr>'

    rec_section = f"""
    <div class="card">
      <h2>Recommendations</h2>
      <table>
        <thead>
          <tr><th>Priority</th><th>Category</th><th>Title</th><th>Detail</th><th>Command</th></tr>
        </thead>
        <tbody>{rec_rows}</tbody>
      </table>
    </div>"""

    # ── Key findings ─────────────────────────────────────────────────────────

    findings_html = "".join(
        f'<li>{_esc(f)}</li>' for f in (summary.get("key_findings") or [])
    )

    # ── Full page ─────────────────────────────────────────────────────────────

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Study Report — {instance_label}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0d0d0d;color:#e0e0e0;font-family:system-ui,-apple-system,sans-serif;padding:1.5rem}}
  h1{{color:#4ec9b0;font-size:1.5rem;margin-bottom:0.25rem}}
  h2{{color:#4ec9b0;font-size:1.1rem;margin-bottom:0.75rem;border-bottom:1px solid #2a2a2a;padding-bottom:0.3rem}}
  .subtitle{{color:#888;font-size:0.85rem;margin-bottom:1.5rem}}
  .metrics{{display:flex;flex-wrap:wrap;gap:1rem;margin-bottom:1.5rem}}
  .metric-card{{background:#141414;border:1px solid #222;border-radius:6px;padding:0.75rem 1.25rem;min-width:120px;text-align:center}}
  .metric-val{{font-size:1.6rem;font-weight:700;color:#e0e0e0}}
  .metric-label{{font-size:0.75rem;color:#888;margin-top:0.2rem}}
  .card{{background:#141414;border:1px solid #222;border-radius:6px;padding:1.25rem;margin-bottom:1rem}}
  .kv{{display:flex;gap:0.5rem;padding:0.2rem 0;font-size:0.88rem;border-bottom:1px solid #1c1c1c}}
  .kv:last-of-type{{border-bottom:none}}
  .kl{{color:#888;min-width:160px;flex-shrink:0}}
  .kv-val{{color:#e0e0e0}}
  table{{width:100%;border-collapse:collapse;font-size:0.85rem;margin-top:0.5rem}}
  th{{background:#1c1c1c;color:#888;text-align:left;padding:0.4rem 0.6rem}}
  td{{padding:0.35rem 0.6rem;border-bottom:1px solid #1c1c1c;vertical-align:top}}
  pre.mono{{background:#0d0d0d;border:1px solid #222;padding:0.5rem;border-radius:4px;
            overflow-x:auto;font-size:0.78rem;font-family:monospace;margin-top:0.3rem;white-space:pre-wrap}}
  code.mono-sm{{font-size:0.78rem;font-family:monospace;color:#4ec9b0}}
  .analysis{{margin-top:0.75rem;color:#ccc;font-size:0.88rem;line-height:1.5}}
  .pill-group{{display:flex;flex-wrap:wrap;gap:0.4rem;margin-bottom:0.75rem}}
  .pill{{background:#1c1c1c;border:1px solid #333;padding:2px 10px;border-radius:99px;font-size:0.8rem;color:#4ec9b0}}
  .findings-list{{margin-left:1.2rem;color:#ccc;font-size:0.88rem;line-height:1.8}}
  .header-bar{{display:flex;align-items:center;gap:1.5rem;margin-bottom:1.5rem}}
  .score-ring{{width:64px;height:64px;border-radius:50%;display:flex;align-items:center;
               justify-content:center;font-size:1.2rem;font-weight:700;flex-shrink:0;
               border:4px solid {h_color};color:{h_color}}}
  @media print{{body{{background:#fff;color:#000}}.card,.metric-card{{background:#f5f5f5;border-color:#ccc}}}}
</style>
</head>
<body>
<div class="header-bar">
  <div class="score-ring">{health_score}</div>
  <div>
    <h1>{instance_label}</h1>
    <div class="subtitle">Role: {_esc(summary.get("role","Unknown"))} &nbsp;|&nbsp; {_esc(created_at)}</div>
    <div class="subtitle">{_esc(summary.get("headline",""))}</div>
  </div>
</div>

{metric_cards}

<div class="card">
  <h2>Key Findings</h2>
  <ul class="findings-list">{findings_html}</ul>
</div>

{card("Hardware", hw_body)}
{card("Operating System", os_body)}
{card("Services", svc_body)}
{card("Network", net_body)}
{card("Security", sec_body)}
{card("Software Stack", sw_body)}
{card("Performance", perf_body)}
{card("Environment", env_body)}
{rec_section}
</body>
</html>"""
