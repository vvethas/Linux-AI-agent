import json
from html import escape
from typing import Any, Dict, List


def _list_items(items: List[Any]) -> str:
    if not items:
        return "<div class='muted'>None</div>"
    return "<ul>" + "".join(f"<li>{escape(str(i))}</li>" for i in items) + "</ul>"


def _kv_table(data: Dict[str, Any]) -> str:
    if not data:
        return "<div class='muted'>No data</div>"
    rows = []
    for k, v in data.items():
        if isinstance(v, (dict, list)):
            val = f"<pre>{escape(json.dumps(v, indent=2, default=str))}</pre>"
        else:
            val = f"<pre>{escape(str(v))}</pre>"
        rows.append(f"<tr><td class='kv-key'>{escape(str(k))}</td><td>{val}</td></tr>")
    return "<table class='kv-table'>" + "".join(rows) + "</table>"


def _severity_badge(severity: str) -> str:
    colors = {"high": "#e05252", "medium": "#e5b840", "low": "#4caf50"}
    color = colors.get(str(severity).lower(), "#9ca3af")
    return f"<span class='badge' style='border-color:{color};color:{color}'>{escape(str(severity).upper())}</span>"


def generate_study_html(
    instance_label: str,
    report: Dict[str, Any],
    created_at: str = "",
) -> str:
    summary = report.get("summary", {})
    security = report.get("security", {})
    services = report.get("services", {})
    perf = report.get("performance", {})

    score = int(summary.get("health_score", 0) or 0)
    ring_color = (
        "#4caf50" if score >= 80
        else "#e5b840" if score >= 60
        else "#e05252"
    )
    security_score = int(security.get("score", 0) or 0)
    sec_color = (
        "#4caf50" if security_score >= 80
        else "#e5b840" if security_score >= 60
        else "#e05252"
    )

    # Build security findings rows
    findings_rows = ""
    for f in security.get("findings", []):
        findings_rows += (
            f"<tr>"
            f"<td>{_severity_badge(f.get('severity','?'))}</td>"
            f"<td>{escape(str(f.get('issue','')))}</td>"
            f"<td>{escape(str(f.get('recommendation','')))}</td>"
            f"</tr>"
        )

    # Build recommendations rows
    recs_rows = ""
    for r in report.get("recommendations", []):
        prio_colors = {"high": "#e05252", "medium": "#e5b840", "low": "#4caf50"}
        prio = str(r.get("priority", "low")).lower()
        pc = prio_colors.get(prio, "#9ca3af")
        cmd = r.get("command", "")
        cmd_html = f"<code>{escape(cmd)}</code>" if cmd else ""
        recs_rows += (
            f"<tr>"
            f"<td><span class='badge' style='border-color:{pc};color:{pc}'>{escape(prio.upper())}</span></td>"
            f"<td>{escape(str(r.get('category','')))}</td>"
            f"<td>{escape(str(r.get('title','')))}</td>"
            f"<td>{escape(str(r.get('detail','')))}</td>"
            f"<td>{cmd_html}</td>"
            f"</tr>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Study Report — {escape(instance_label)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0d0d0d;color:#d4d4d4;font-family:system-ui,-apple-system,sans-serif;padding:24px}}
.wrap{{max-width:1280px;margin:0 auto}}
h1{{color:#4ec9b0;margin-bottom:4px}}
h2{{color:#4ec9b0;font-size:1.1rem;margin-bottom:12px}}
.panel{{background:#141414;border:1px solid #2a2a2a;border-radius:12px;padding:20px;margin-bottom:16px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}}
.card{{background:#1c1c1c;padding:14px;border-radius:10px}}
.card .val{{font-size:1.5rem;font-weight:700;color:#e0e0e0;margin-top:6px}}
.card .lbl{{font-size:.8rem;color:#9ca3af;margin-bottom:4px}}
.ring{{width:88px;height:88px;border-radius:50%;border:8px solid {ring_color};
       display:grid;place-items:center;font-size:1.6rem;font-weight:800;color:#e0e0e0}}
.muted{{color:#9ca3af;font-size:.9rem}}
pre{{white-space:pre-wrap;font-family:ui-monospace,Menlo,monospace;
     background:#111;padding:8px;border-radius:6px;font-size:.82rem;overflow-x:auto}}
code{{font-family:ui-monospace,Menlo,monospace;background:#111;
      padding:2px 6px;border-radius:4px;font-size:.82rem}}
table{{width:100%;border-collapse:collapse}}
td,th{{border-bottom:1px solid #2a2a2a;padding:8px 10px;vertical-align:top;text-align:left}}
th{{color:#9ca3af;font-weight:600;font-size:.8rem;text-transform:uppercase}}
.kv-table .kv-key{{color:#9ca3af;width:220px;font-size:.85rem;white-space:nowrap}}
.badge{{display:inline-block;padding:2px 8px;border-radius:999px;
        background:#1c1c1c;border:1px solid #444;font-size:.75rem;font-weight:600}}
ul{{padding-left:20px;line-height:1.7}}
.meta{{color:#9ca3af;font-size:.85rem;margin-top:2px}}
@media print{{body{{background:#fff;color:#111}}.panel{{background:#f5f5f5}}}}
</style>
</head>
<body>
<div class="wrap">

  <!-- Header -->
  <div class="panel">
    <div style="display:flex;align-items:flex-start;gap:24px;flex-wrap:wrap">
      <div class="ring">{score}</div>
      <div style="flex:1">
        <h1>{escape(instance_label)}</h1>
        <div class="meta">{escape(str(summary.get("role","unknown")))} &bull; Generated: {escape(created_at)}</div>
        <div style="margin-top:10px">{escape(str(summary.get("headline","No summary")))}</div>
      </div>
    </div>
  </div>

  <!-- Metric cards -->
  <div class="panel">
    <div class="grid">
      <div class="card"><div class="lbl">Health Score</div><div class="val">{score}/100</div></div>
      <div class="card"><div class="lbl">Security Score</div><div class="val" style="color:{sec_color}">{security_score}/100</div></div>
      <div class="card"><div class="lbl">Running Services</div><div class="val">{services.get("total_running",0)}</div></div>
      <div class="card"><div class="lbl">Failed Services</div><div class="val" style="color:#e05252">{services.get("total_failed",0)}</div></div>
      <div class="card"><div class="lbl">CPU Load (1m)</div><div class="val">{perf.get("cpu_load_1m","—")}</div></div>
      <div class="card"><div class="lbl">CPU Load (5m)</div><div class="val">{perf.get("cpu_load_5m","—")}</div></div>
    </div>
  </div>

  <!-- Key findings -->
  <div class="panel">
    <h2>Key Findings</h2>
    {_list_items(summary.get("key_findings", []))}
  </div>

  <!-- Hardware -->
  <div class="panel"><h2>Hardware</h2>{_kv_table(report.get("hardware", {}))}</div>

  <!-- OS -->
  <div class="panel"><h2>Operating System</h2>{_kv_table(report.get("os", {}))}</div>

  <!-- Services -->
  <div class="panel">
    <h2>Services</h2>
    <div class="grid" style="margin-bottom:12px">
      <div class="card"><div class="lbl">Running</div><div class="val">{services.get("total_running",0)}</div></div>
      <div class="card"><div class="lbl">Failed</div><div class="val" style="color:#e05252">{services.get("total_failed",0)}</div></div>
    </div>
    <div style="margin-bottom:8px"><strong>Critical:</strong> {_list_items(services.get("critical",[]))}</div>
    <div style="margin-bottom:8px"><strong>Failed:</strong> {_list_items(services.get("failed",[]))}</div>
    <div class="muted">{escape(str(services.get("analysis","")))}</div>
  </div>

  <!-- Network -->
  <div class="panel">
    <h2>Network</h2>
    <div style="margin-bottom:8px"><strong>Interfaces:</strong> {_list_items(report.get("network",{}).get("interfaces",[]))}</div>
    <div style="margin-bottom:8px">
      <strong>Open Ports:</strong>
      <table><thead><tr><th>Port/Protocol</th></tr></thead><tbody>
      {"".join(f"<tr><td>{escape(str(p))}</td></tr>" for p in report.get("network",{}).get("open_ports",[]))}
      </tbody></table>
    </div>
    <div style="margin-bottom:8px"><strong>Firewall:</strong> <span class="muted">{escape(str(report.get("network",{}).get("firewall","—")))}</span></div>
    <div class="muted">{escape(str(report.get("network",{}).get("analysis","")))}</div>
  </div>

  <!-- Security -->
  <div class="panel">
    <h2>Security</h2>
    <div class="grid" style="margin-bottom:16px">
      <div class="card"><div class="lbl">Score</div><div class="val" style="color:{sec_color}">{security_score}/100</div></div>
      <div class="card"><div class="lbl">Root Login</div><div class="val">{escape(str(security.get("ssh_root_login","?")))}</div></div>
      <div class="card"><div class="lbl">Password Auth</div><div class="val">{escape(str(security.get("password_auth","?")))}</div></div>
      <div class="card"><div class="lbl">Pending Security Updates</div><div class="val">{security.get("pending_security_updates",0)}</div></div>
    </div>
    {'<table><thead><tr><th>Severity</th><th>Issue</th><th>Recommendation</th></tr></thead><tbody>' + findings_rows + '</tbody></table>' if findings_rows else '<div class="muted">No findings</div>'}
  </div>

  <!-- Software -->
  <div class="panel"><h2>Software Stack</h2>
    <div style="margin-bottom:8px"><strong>Highlights:</strong> {_list_items(report.get("software",{}).get("installed_highlights",[]))}</div>
    <div style="margin-bottom:8px"><strong>Runtimes:</strong> {_list_items(report.get("software",{}).get("runtimes",[]))}</div>
    <div style="margin-bottom:8px"><strong>Databases:</strong> {_list_items(report.get("software",{}).get("databases",[]))}</div>
    <div class="muted">{escape(str(report.get("software",{}).get("analysis","")))}</div>
  </div>

  <!-- Performance -->
  <div class="panel">
    <h2>Performance</h2>
    <div class="grid" style="margin-bottom:12px">
      <div class="card"><div class="lbl">Load 1m</div><div class="val">{perf.get("cpu_load_1m","—")}</div></div>
      <div class="card"><div class="lbl">Load 5m</div><div class="val">{perf.get("cpu_load_5m","—")}</div></div>
      <div class="card"><div class="lbl">Load 15m</div><div class="val">{perf.get("cpu_load_15m","—")}</div></div>
    </div>
    <div style="margin-bottom:8px"><strong>Top CPU processes:</strong> {_list_items(perf.get("top_cpu_processes",[]))}</div>
    <div style="margin-bottom:8px"><strong>Top MEM processes:</strong> {_list_items(perf.get("top_mem_processes",[]))}</div>
    <div class="muted">{escape(str(perf.get("analysis","")))}</div>
  </div>

  <!-- Environment -->
  <div class="panel"><h2>Environment</h2>
    <div style="margin-bottom:8px"><strong>Type:</strong> {escape(str(report.get("environment",{}).get("type","generic")))}</div>
    {_kv_table(report.get("environment",{}).get("details",{}))}
    <div class="muted" style="margin-top:8px">{escape(str(report.get("environment",{}).get("analysis","")))}</div>
  </div>

  <!-- Recommendations -->
  <div class="panel">
    <h2>Recommendations</h2>
    {'<table><thead><tr><th>Priority</th><th>Category</th><th>Title</th><th>Detail</th><th>Command</th></tr></thead><tbody>' + recs_rows + '</tbody></table>' if recs_rows else '<div class="muted">No recommendations</div>'}
  </div>

</div>
</body>
</html>
"""
