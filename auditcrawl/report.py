from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .models import Finding


class ReportGenerator:
    def __init__(self, output_dir: str, templates_dir: str) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.env = Environment(
            loader=FileSystemLoader(templates_dir),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def generate_json(self, findings: List[Finding], pocs: List[Dict[str, str]]) -> Path:
        data = {
            "summary": {
                "total_findings": len(findings),
                "high": sum(1 for f in findings if f.risk == "High"),
                "medium": sum(1 for f in findings if f.risk == "Medium"),
                "low": sum(1 for f in findings if f.risk == "Low"),
            },
            "findings": [f.to_dict() for f in findings],
            "pocs": pocs,
        }
        out = self.output_dir / "findings.json"
        out.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return out

    def generate_html(self, findings: List[Finding], pocs: List[Dict[str, str]]) -> Path:
        template = self.env.get_template("report.html.j2")
        html = template.render(findings=findings, pocs=pocs)
        out = self.output_dir / "report.html"
        out.write_text(html, encoding="utf-8")
        return out

    def generate_markdown(self, findings: List[Finding], pocs: List[Dict[str, str]]) -> Path:
        lines: List[str] = []
        lines.append("# AuditCrawl Security Scan Report")
        lines.append("")
        lines.append("Generated for educational, authorized security testing only.")
        lines.append("")
        lines.append("This POC is for educational use; do not run on real systems without permission.")
        lines.append("")
        lines.append(f"## Findings ({len(findings)})")
        lines.append("")

        for idx, finding in enumerate(findings, start=1):
            lines.append(f"### {idx}. {finding.vulnerability}")
            lines.append(f"- Risk: {finding.risk}")
            lines.append(f"- Endpoint: {finding.endpoint}")
            lines.append(f"- Method: {finding.method}")
            lines.append(f"- Parameter: {finding.parameter or 'N/A'}")
            lines.append(f"- Evidence: {finding.evidence}")
            lines.append(f"- Remediation: {finding.remediation or 'N/A'}")
            if finding.payload:
                lines.append(f"- Payload: {finding.payload}")
            lines.append("")

        lines.append("## Safe PoCs")
        lines.append("")
        for idx, poc in enumerate(pocs, start=1):
            lines.append(f"### {idx}. {poc.get('vulnerability', 'Unknown')}")
            lines.append(f"- Endpoint: {poc.get('endpoint', '')}")
            lines.append(f"- Method: {poc.get('method', '')}")
            lines.append(f"- Payload: {poc.get('payload', '')}")
            lines.append("- Reproduction steps:")
            lines.append("")
            lines.append(poc.get("reproduction_steps", ""))
            lines.append("")

        out = self.output_dir / "report.md"
        out.write_text("\n".join(lines), encoding="utf-8")
        return out
