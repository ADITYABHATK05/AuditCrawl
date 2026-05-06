from __future__ import annotations

from email.message import EmailMessage
from typing import Iterable

import aiosmtplib

from app.core.config import settings


def _smtp_configured() -> bool:
    return bool(settings.smtp_host and settings.smtp_from)


def build_scan_report_email_html(
    *,
    target_url: str,
    run_id: int,
    severity_counts: dict[str, int],
    vuln_type_counts: dict[str, int],
    top_findings: list[dict],
    detailed_findings: list[dict],
    dashboard_url: str,
) -> str:
    def badge(label: str, value: int, color: str) -> str:
        return f"""
        <div style="display:inline-block;margin:0 10px 10px 0;padding:10px 12px;border-radius:10px;background:{color};color:#0b1220;">
          <div style="font-size:12px;opacity:.9">{label}</div>
          <div style="font-size:18px;font-weight:700">{value}</div>
        </div>
        """

    sev = {k.lower(): int(v) for k, v in (severity_counts or {}).items()}
    critical = sev.get("critical", 0)
    high = sev.get("high", 0)
    medium = sev.get("medium", 0)
    low = sev.get("low", 0)

    # Keep it email-client safe: inline CSS, tables, no external assets.
    top_rows = ""
    for f in (top_findings or [])[:8]:
        vtype = (f.get("vulnerability_type") or f.get("type") or "Finding").strip()
        severity = (f.get("severity") or "info").strip()
        endpoint = (f.get("endpoint") or f.get("url") or "").strip()
        evidence = (f.get("evidence") or "").strip()
        top_rows += f"""
          <tr>
            <td style="padding:10px 12px;border-bottom:1px solid #243045;">
              <div style="font-weight:700;color:#e8eefc">{vtype}</div>
              <div style="font-size:12px;color:#a9b7d0;margin-top:2px">{endpoint}</div>
              <div style="font-size:12px;color:#a9b7d0;margin-top:6px">{evidence[:220]}</div>
            </td>
            <td style="padding:10px 12px;border-bottom:1px solid #243045;text-align:right;color:#e8eefc;white-space:nowrap;">
              {severity}
            </td>
          </tr>
        """

    detailed_rows = ""
    for f in (detailed_findings or [])[:30]:
        vtype = (f.get("vulnerability_type") or f.get("type") or "Finding").strip()
        severity = (f.get("severity") or "Info").strip().title()
        endpoint = (f.get("endpoint") or f.get("url") or "N/A").strip()
        evidence = (f.get("evidence") or "N/A").strip()
        remediation = (f.get("remediation") or f.get("fix_snippet") or "Review and remediate manually.").strip()
        detailed_rows += f"""
          <tr>
            <td style="padding:10px 12px;border-bottom:1px solid #243045;vertical-align:top;">
              <div style="font-weight:700;color:#e8eefc">{vtype}</div>
              <div style="font-size:12px;color:#a9b7d0;margin-top:4px">{endpoint}</div>
            </td>
            <td style="padding:10px 12px;border-bottom:1px solid #243045;vertical-align:top;color:#e8eefc;">
              {severity}
            </td>
            <td style="padding:10px 12px;border-bottom:1px solid #243045;vertical-align:top;font-size:12px;color:#a9b7d0;">
              {evidence[:220]}
            </td>
            <td style="padding:10px 12px;border-bottom:1px solid #243045;vertical-align:top;font-size:12px;color:#a9b7d0;">
              {remediation[:220]}
            </td>
          </tr>
        """

    type_pills = ""
    for k, v in sorted((vuln_type_counts or {}).items(), key=lambda x: (-x[1], x[0]))[:10]:
        type_pills += f"""
        <span style="display:inline-block;margin:0 8px 8px 0;padding:6px 10px;border-radius:999px;background:#182235;border:1px solid #243045;color:#d7e3ff;font-size:12px;">
          {k}: <b>{int(v)}</b>
        </span>
        """

    return f"""
<!doctype html>
<html>
  <body style="margin:0;padding:0;background:#0b1220;font-family:Inter,Segoe UI,Roboto,Arial,sans-serif;color:#e8eefc;">
    <div style="max-width:720px;margin:0 auto;padding:24px;">
      <div style="padding:18px 18px;border:1px solid #243045;border-radius:14px;background:#0f172a;">
        <div style="font-size:12px;color:#9fb0ce;letter-spacing:.08em;text-transform:uppercase;">AuditCrawl Security Report</div>
        <div style="font-size:22px;font-weight:800;margin-top:6px;">Scan completed</div>
        <div style="margin-top:8px;color:#b9c7e2;font-size:13px;line-height:1.4;">
          <div><b>Target:</b> {target_url}</div>
          <div><b>Run ID:</b> {run_id}</div>
        </div>

        <div style="margin-top:14px;">
          {badge("Critical", critical, "#ff5a7a")}
          {badge("High", high, "#ffb020")}
          {badge("Medium", medium, "#ffe16a")}
          {badge("Low", low, "#68b6ff")}
        </div>

        <div style="margin-top:14px;">
          <a href="{dashboard_url}" style="display:inline-block;padding:10px 14px;border-radius:10px;background:#2b6cff;color:white;text-decoration:none;font-weight:700;">
            View full dashboard →
          </a>
          <span style="display:inline-block;margin-left:10px;color:#9fb0ce;font-size:12px;">
            (opens scan results page)
          </span>
        </div>
      </div>

      <div style="margin-top:16px;padding:18px;border:1px solid #243045;border-radius:14px;background:#0f172a;">
        <div style="font-size:14px;font-weight:800;margin-bottom:10px;">Vulnerability summary</div>
        <div>{type_pills or '<span style="color:#9fb0ce;font-size:13px;">No categorized findings found.</span>'}</div>
      </div>

      <div style="margin-top:16px;padding:18px;border:1px solid #243045;border-radius:14px;background:#0f172a;">
        <div style="font-size:14px;font-weight:800;margin-bottom:10px;">Top findings</div>
        <table style="width:100%;border-collapse:collapse;border:1px solid #243045;border-radius:12px;overflow:hidden;">
          <thead>
            <tr style="background:#111c33;">
              <th style="text-align:left;padding:10px 12px;color:#9fb0ce;font-size:12px;">Finding</th>
              <th style="text-align:right;padding:10px 12px;color:#9fb0ce;font-size:12px;">Severity</th>
            </tr>
          </thead>
          <tbody>
            {top_rows or '<tr><td style="padding:12px;color:#9fb0ce;">No findings.</td><td></td></tr>'}
          </tbody>
        </table>
      </div>

      <div style="margin-top:16px;padding:18px;border:1px solid #243045;border-radius:14px;background:#0f172a;">
        <div style="font-size:14px;font-weight:800;margin-bottom:10px;">Detailed findings</div>
        <table style="width:100%;border-collapse:collapse;border:1px solid #243045;border-radius:12px;overflow:hidden;">
          <thead>
            <tr style="background:#111c33;">
              <th style="text-align:left;padding:10px 12px;color:#9fb0ce;font-size:12px;">Type / Endpoint</th>
              <th style="text-align:left;padding:10px 12px;color:#9fb0ce;font-size:12px;">Severity</th>
              <th style="text-align:left;padding:10px 12px;color:#9fb0ce;font-size:12px;">Evidence</th>
              <th style="text-align:left;padding:10px 12px;color:#9fb0ce;font-size:12px;">Remediation</th>
            </tr>
          </thead>
          <tbody>
            {detailed_rows or '<tr><td style="padding:12px;color:#9fb0ce;">No detailed findings.</td><td></td><td></td><td></td></tr>'}
          </tbody>
        </table>
        <div style="margin-top:8px;font-size:12px;color:#7f93b6;">
          Showing up to 30 findings in email. Use dashboard for full interactive analysis.
        </div>
      </div>

      <div style="margin-top:14px;color:#7f93b6;font-size:12px;line-height:1.5;">
        You are receiving this email because an AuditCrawl scan was run with this address attached.
        Only scan systems you own or have explicit written authorization to test.
      </div>
    </div>
  </body>
</html>
""".strip()


async def send_html_email(*, to_email: str, subject: str, html_body: str) -> None:
    if not _smtp_configured():
        raise RuntimeError("SMTP is not configured (set SMTP_HOST and SMTP_FROM at minimum).")

    msg = EmailMessage()
    msg["From"] = settings.smtp_from
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content("Your email client does not support HTML emails.")
    msg.add_alternative(html_body, subtype="html")

    await aiosmtplib.send(
        msg,
        hostname=settings.smtp_host,
        port=settings.smtp_port,
        username=settings.smtp_user or None,
        password=settings.smtp_password or None,
        start_tls=settings.smtp_starttls,
        timeout=20,
    )

