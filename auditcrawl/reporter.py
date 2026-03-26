from __future__ import annotations
import json
import os
from pathlib import Path
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import ScanConfig
    from .models import ScanResult

from jinja2 import Environment, BaseLoader

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AuditCrawl Report — {{ config.base_url }}</title>
<style>
  :root { --bg:#f8fafc;--card:#fff;--border:#e2e8f0;--text:#1e293b;--muted:#64748b;
          --critical:#dc2626;--high:#ea580c;--medium:#d97706;--low:#16a34a;--info:#2563eb; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
         background:var(--bg);color:var(--text);line-height:1.6;padding:2rem; }
  h1 { font-size:1.8rem;margin-bottom:.25rem; }
  .meta { color:var(--muted);font-size:.9rem;margin-bottom:2rem; }
  .summary { display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));
             gap:1rem;margin-bottom:2rem; }
  .stat { background:var(--card);border:1px solid var(--border);border-radius:8px;
          padding:1rem;text-align:center; }
  .stat .num { font-size:2rem;font-weight:700; }
  .stat .label { font-size:.8rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em; }
  .critical .num { color:var(--critical); }
  .high .num { color:var(--high); }
  .medium .num { color:var(--medium); }
  .low .num { color:var(--low); }
  .info .num { color:var(--info); }
  .finding { background:var(--card);border:1px solid var(--border);border-radius:8px;
             margin-bottom:1rem;overflow:hidden; }
  .finding-header { padding:.75rem 1rem;display:flex;align-items:center;gap:.75rem;
                    cursor:pointer;user-select:none; }
  .finding-header:hover { background:#f1f5f9; }
  .badge { padding:.2rem .6rem;border-radius:4px;font-size:.75rem;font-weight:600;
           text-transform:uppercase;color:#fff;white-space:nowrap; }
  .badge-critical { background:var(--critical); }
  .badge-high { background:var(--high); }
  .badge-medium { background:var(--medium); }
  .badge-low { background:var(--low); }
  .badge-info { background:var(--info); }
  .finding-title { font-weight:600;flex:1; }
  .finding-url { font-size:.8rem;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:40%; }
  .finding-body { padding:1rem;border-top:1px solid var(--border);display:none; }
  .finding-body.open { display:block; }
  .finding-body table { width:100%;border-collapse:collapse;margin-bottom:1rem; }
  .finding-body td { padding:.4rem .6rem;border-bottom:1px solid var(--border);vertical-align:top; }
  .finding-body td:first-child { font-weight:600;width:160px;color:var(--muted);font-size:.85rem; }
  pre { background:#f1f5f9;border-radius:6px;padding:.75rem;font-size:.82rem;
        overflow-x:auto;white-space:pre-wrap;word-break:break-all; }
  .section-title { font-size:1.2rem;font-weight:600;margin:2rem 0 1rem; }
  .filter-bar { display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:1rem; }
  .filter-btn { padding:.35rem .8rem;border-radius:6px;border:1px solid var(--border);
                background:var(--card);cursor:pointer;font-size:.85rem; }
  .filter-btn.active { background:var(--text);color:#fff; }
  footer { margin-top:3rem;text-align:center;font-size:.8rem;color:var(--muted); }
</style>
</head>
<body>
<h1>&#x1F50D; AuditCrawl Report</h1>
<div class="meta">Target: <strong>{{ config.base_url }}</strong> &nbsp;|&nbsp;
  Scanned: {{ timestamp }} &nbsp;|&nbsp;
  Duration: {{ "%.1f"|format(result.duration_seconds) }}s &nbsp;|&nbsp;
  Endpoints: {{ result.endpoints|length }}
</div>

<div class="summary">
  {% set sev = result.summary_by_severity() %}
  <div class="stat critical"><div class="num">{{ sev.critical }}</div><div class="label">Critical</div></div>
  <div class="stat high"><div class="num">{{ sev.high }}</div><div class="label">High</div></div>
  <div class="stat medium"><div class="num">{{ sev.medium }}</div><div class="label">Medium</div></div>
  <div class="stat low"><div class="num">{{ sev.low }}</div><div class="label">Low</div></div>
  <div class="stat info"><div class="num">{{ sev.info }}</div><div class="label">Info</div></div>
  <div class="stat"><div class="num">{{ result.findings|length }}</div><div class="label">Total</div></div>
</div>

<div class="section-title">Findings</div>
<div class="filter-bar">
  <button class="filter-btn active" onclick="filter(this,'all')">All</button>
  <button class="filter-btn" onclick="filter(this,'critical')">Critical</button>
  <button class="filter-btn" onclick="filter(this,'high')">High</button>
  <button class="filter-btn" onclick="filter(this,'medium')">Medium</button>
  <button class="filter-btn" onclick="filter(this,'low')">Low</button>
  <button class="filter-btn" onclick="filter(this,'info')">Info</button>
</div>

{% if result.findings %}
  {% for f in result.findings %}
  <div class="finding" data-sev="{{ f.severity.value }}">
    <div class="finding-header" onclick="toggle(this)">
      <span class="badge badge-{{ f.severity.value }}">{{ f.severity.value }}</span>
      <span class="finding-title">{{ f.vuln_type }}</span>
      <span class="finding-url" title="{{ f.url }}">{{ f.url }}</span>
    </div>
    <div class="finding-body">
      <table>
        <tr><td>URL</td><td><code>{{ f.url }}</code></td></tr>
        <tr><td>Method</td><td>{{ f.method }}</td></tr>
        <tr><td>Parameter</td><td><code>{{ f.parameter }}</code></td></tr>
        <tr><td>CVSS Score</td><td>{{ f.cvss_score }}</td></tr>
        <tr><td>Confidence</td><td>{{ f.confidence }}</td></tr>
        <tr><td>Description</td><td>{{ f.description }}</td></tr>
        <tr><td>Remediation</td><td>{{ f.remediation }}</td></tr>
      </table>
      <strong>Payload:</strong><pre>{{ f.payload }}</pre>
      {% if f.evidence %}<strong>Evidence:</strong><pre>{{ f.evidence[:500] }}</pre>{% endif %}
      {% if f.poc %}<strong>PoC (educational only):</strong><pre>{{ f.poc }}</pre>{% endif %}
    </div>
  </div>
  {% endfor %}
{% else %}
  <p style="color:var(--muted)">No findings.</p>
{% endif %}

<footer>AuditCrawl — for educational use only. Only scan systems you own or have explicit permission to test.</footer>

<script>
function toggle(header) {
  const body = header.nextElementSibling;
  body.classList.toggle('open');
}
function filter(btn, sev) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.finding').forEach(f => {
    f.style.display = (sev === 'all' || f.dataset.sev === sev) ? '' : 'none';
  });
}
</script>
</body>
</html>"""


class Reporter:
    def __init__(self, config, result) -> None:
        self.config = config
        self.result = result
        self.ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        os.makedirs(config.output_dir, exist_ok=True)

    def write_json(self) -> str:
        path = Path(self.config.output_dir) / "findings.json"
        data = {
            "meta": {
                "tool": "AuditCrawl",
                "target": self.config.base_url,
                "timestamp": self.ts,
                "duration_seconds": round(self.result.duration_seconds, 2),
                "endpoints_crawled": len(self.result.endpoints),
            },
            "summary": self.result.summary_by_severity(),
            "findings": [f.to_dict() for f in self.result.findings],
        }
        path.write_text(json.dumps(data, indent=2))
        return str(path)

    def write_html(self) -> str:
        path = Path(self.config.output_dir) / "report.html"
        env = Environment(loader=BaseLoader())
        tmpl = env.from_string(HTML_TEMPLATE)
        html = tmpl.render(config=self.config, result=self.result, timestamp=self.ts)
        path.write_text(html)
        return str(path)

    def write_markdown(self) -> str:
        path = Path(self.config.output_dir) / "report.md"
        lines = [
            f"# AuditCrawl Report",
            f"",
            f"**Target:** {self.config.base_url}  ",
            f"**Scanned:** {self.ts}  ",
            f"**Duration:** {self.result.duration_seconds:.1f}s  ",
            f"**Endpoints:** {len(self.result.endpoints)}  ",
            f"",
            "## Summary",
            "",
        ]
        sev = self.result.summary_by_severity()
        lines += [
            f"| Severity | Count |",
            f"|----------|-------|",
        ]
        for s, c in sev.items():
            lines.append(f"| {s.capitalize()} | {c} |")
        lines += ["", "## Findings", ""]

        for f in self.result.findings:
            lines += [
                f"### [{f.severity.value.upper()}] {f.vuln_type}",
                f"",
                f"- **URL:** `{f.url}`",
                f"- **Method:** {f.method}",
                f"- **Parameter:** `{f.parameter}`",
                f"- **CVSS:** {f.cvss_score}",
                f"- **Confidence:** {f.confidence}",
                f"",
                f"**Description:** {f.description}",
                f"",
                f"**Remediation:** {f.remediation}",
                f"",
                f"**Payload:**",
                f"```",
                f"{f.payload}",
                f"```",
                f"",
            ]
            if f.evidence:
                lines += [f"**Evidence:**", f"```", f"{f.evidence[:400]}", f"```", ""]

        lines += [
            "---",
            "_AuditCrawl — educational use only. Only scan systems you own or have explicit permission to test._",
        ]
        path.write_text("\n".join(lines))
        return str(path)