from __future__ import annotations
import os
import html
import re
from pathlib import Path
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import ScanConfig
    from .models import ScanResult

def sanitize_text_for_pdf(text: str) -> str:
    """Remove all HTML tags and escape special characters for safe PDF rendering."""
    if not text:
        return ""
    # Remove all HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    # Escape HTML entities
    text = html.escape(text)
    return text

class Reporter:
    def __init__(self, config, result) -> None:
        self.config = config
        self.result = result
        self.ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        os.makedirs(config.output_dir, exist_ok=True)

    def write_pdf(self) -> str:
        """
        Generate a PDF report inspired by typical vuln scanner reports:
        cover page, executive summary, vulnerabilities by target, details, glossary.
        """
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import LETTER
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle,
            PageBreak,
        )

        path = Path(self.config.output_dir) / "report.pdf"

        doc = SimpleDocTemplate(
            str(path),
            pagesize=LETTER,
            leftMargin=0.8 * inch,
            rightMargin=0.8 * inch,
            topMargin=0.8 * inch,
            bottomMargin=0.8 * inch,
            title="AuditCrawl Vulnerability Scan Report",
        )

        styles = getSampleStyleSheet()
        title = ParagraphStyle(
            "TitleBig",
            parent=styles["Title"],
            fontSize=26,
            leading=30,
            textColor=colors.HexColor("#0B1F3A"),
            spaceAfter=20,
        )
        h1 = ParagraphStyle(
            "H1",
            parent=styles["Heading1"],
            textColor=colors.HexColor("#0B1F3A"),
            spaceBefore=10,
            spaceAfter=8,
        )
        h2 = ParagraphStyle(
            "H2",
            parent=styles["Heading2"],
            textColor=colors.HexColor("#1E3A5F"),
            spaceBefore=10,
            spaceAfter=6,
        )
        small = ParagraphStyle("Small", parent=styles["BodyText"], fontSize=9, leading=12, textColor=colors.HexColor("#374151"))
        mono = ParagraphStyle("Mono", parent=styles["BodyText"], fontName="Courier", fontSize=9, leading=11)
        badge = ParagraphStyle("Badge", parent=styles["BodyText"], fontSize=8, leading=9, textColor=colors.white)

        def sev_bg(severity: str):
            s = (severity or "").lower()
            if s == "critical":
                return colors.HexColor("#7F1D1D")
            if s == "high":
                return colors.HexColor("#B91C1C")
            if s == "medium":
                return colors.HexColor("#B45309")
            if s == "low":
                return colors.HexColor("#1D4ED8")
            return colors.HexColor("#4B5563")

        sev = self.result.summary_by_severity()
        findings = self.result.findings

        story = []

        # Cover
        story.append(Paragraph(datetime.utcnow().strftime("%B %d, %Y"), styles["Normal"]))
        story.append(Spacer(1, 18))
        story.append(Paragraph("Vulnerability Scan<br/>Report", title))
        story.append(Spacer(1, 10))
        story.append(Paragraph("Automated security assessment for authorized testing", small))
        story.append(Spacer(1, 16))
        story.append(Paragraph("<b>Prepared By</b><br/>AuditCrawl Security", styles["Normal"]))
        story.append(Spacer(1, 6))
        story.append(Paragraph(f"<b>Target</b><br/>{sanitize_text_for_pdf(self.config.base_url)}", styles["Normal"]))
        story.append(Spacer(1, 6))
        story.append(Paragraph(f"<b>Generated At</b><br/>{self.ts}", styles["Normal"]))
        story.append(PageBreak())

        # Table of Contents (static)
        story.append(Paragraph("Table of Contents", h1))
        toc_data = [
            ["1", "Executive Summary"],
            ["2", "Vulnerabilities By Target"],
            ["3", "Vulnerability Details"],
            ["4", "Glossary"],
        ]
        toc_table = Table(toc_data, colWidths=[0.4 * inch, 5.8 * inch])
        toc_table.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 11),
                    ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#F3F4F6"), colors.white]),
                    ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                    ("PADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(toc_table)
        story.append(PageBreak())

        # Executive Summary
        story.append(Paragraph("1 Executive Summary", h1))
        story.append(
            Paragraph(
                "This report contains the discovered potential vulnerabilities from the scan. "
                "Vulnerabilities are classified by severity; higher severity indicates greater risk.",
                styles["BodyText"],
            )
        )
        story.append(Spacer(1, 10))
        story.append(Paragraph("1.1 Total Vulnerabilities", h2))
        summary_table = Table(
            [
                ["Critical", sev.get("critical", 0), "High", sev.get("high", 0), "Medium", sev.get("medium", 0)],
                ["Low", sev.get("low", 0), "Info", sev.get("info", 0), "Total", len(findings)],
            ],
            # 6.6in total width to fit within page frame and avoid overlap.
            colWidths=[1.2 * inch, 1.0 * inch, 1.0 * inch, 1.0 * inch, 1.0 * inch, 1.4 * inch],
        )
        summary_table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E5E7EB")),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("PADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(summary_table)
        story.append(Spacer(1, 10))
        story.append(Paragraph("1.2 Report Coverage", h2))
        story.append(Paragraph(f"This report includes findings for 1 target scanned.", styles["BodyText"]))
        story.append(Paragraph(f"<b>Total Targets:</b> 1", styles["BodyText"]))
        story.append(PageBreak())

        # Vulnerabilities by Target
        story.append(Paragraph("2 Vulnerabilities By Target", h1))
        story.append(
            Paragraph(
                "Summary of vulnerability findings for the scanned target.",
                styles["BodyText"],
            )
        )
        by_target = Table(
            [
                ["Target", "Critical", "High", "Medium", "Low", "Info"],
                [
                    Paragraph(sanitize_text_for_pdf(self.config.base_url), small),
                    sev.get("critical", 0),
                    sev.get("high", 0),
                    sev.get("medium", 0),
                    sev.get("low", 0),
                    sev.get("info", 0),
                ],
            ],
            # 6.7in total width so long URLs wrap cleanly.
            colWidths=[3.0 * inch, 0.72 * inch, 0.72 * inch, 0.82 * inch, 0.72 * inch, 0.72 * inch],
        )
        by_target.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E5E7EB")),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(by_target)
        story.append(PageBreak())

        # Vulnerability breakdown
        story.append(Paragraph("3 Vulnerability Details", h1))
        if not findings:
            story.append(Paragraph("No findings detected.", styles["BodyText"]))
        else:
            story.append(Paragraph("3.1 Vulnerabilities Breakdown", h2))
            breakdown_rows = [["Title", "Severity", "CVSS", "URL"]]
            for f in findings:
                breakdown_rows.append(
                    [
                        Paragraph(sanitize_text_for_pdf(f.vuln_type), small),
                        f"{f.severity.value}".title(),
                        f"{f.cvss_score:.1f}",
                        Paragraph(sanitize_text_for_pdf(f.url), small),
                    ]
                )
            # 6.8in total width to avoid clipping on Letter with 0.8in margins.
            breakdown = Table(breakdown_rows, colWidths=[2.2 * inch, 1.0 * inch, 0.6 * inch, 3.0 * inch], repeatRows=1)
            breakdown.setStyle(
                TableStyle(
                    [
                        ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E5E7EB")),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
                        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("PADDING", (0, 0), (-1, -1), 5),
                    ]
                )
            )
            story.append(breakdown)
            story.append(Spacer(1, 12))

            story.append(Paragraph("3.2 Detailed Findings", h2))
            for idx, f in enumerate(findings, start=1):
                story.append(Paragraph(f"{idx}. {sanitize_text_for_pdf(f.vuln_type)}", styles["Heading3"]))
                sev_chip = Table([[Paragraph(f"{f.severity.value.upper()}", badge)]], colWidths=[0.95 * inch], rowHeights=[0.24 * inch])
                sev_chip.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (0, 0), sev_bg(f.severity.value)),
                            ("ALIGN", (0, 0), (0, 0), "CENTER"),
                            ("VALIGN", (0, 0), (0, 0), "MIDDLE"),
                            ("BOX", (0, 0), (0, 0), 0, colors.white),
                            ("LEFTPADDING", (0, 0), (0, 0), 3),
                            ("RIGHTPADDING", (0, 0), (0, 0), 3),
                            ("TOPPADDING", (0, 0), (0, 0), 2),
                            ("BOTTOMPADDING", (0, 0), (0, 0), 2),
                        ]
                    )
                )
                story.append(sev_chip)
                story.append(Spacer(1, 4))
                story.append(
                    Paragraph(
                        f"<b>CVSS:</b> {f.cvss_score:.1f} &nbsp;&nbsp; "
                        f"<b>Confidence:</b> {f.confidence}",
                        styles["BodyText"],
                    )
                )
                story.append(Paragraph(f"<b>URL:</b> {sanitize_text_for_pdf(f.url)}", small))
                story.append(Paragraph(f"<b>Method:</b> {sanitize_text_for_pdf(f.method)} &nbsp;&nbsp; <b>Parameter:</b> {sanitize_text_for_pdf(f.parameter or '')}", small))
                story.append(Spacer(1, 6))
                story.append(Paragraph("<b>Description</b>", small))
                story.append(Paragraph(sanitize_text_for_pdf(f.description), styles["BodyText"]))
                story.append(Spacer(1, 4))
                story.append(Paragraph("<b>Remediation</b>", small))
                story.append(Paragraph(sanitize_text_for_pdf(f.remediation), styles["BodyText"]))
                story.append(Spacer(1, 4))
                story.append(Paragraph("<b>Payload</b>", small))
                payload_text = sanitize_text_for_pdf((f.payload or "")[:900]).replace("\n", "<br/>")
                story.append(Paragraph(payload_text, mono))
                if f.evidence:
                    story.append(Spacer(1, 4))
                    story.append(Paragraph("<b>Evidence</b>", small))
                    evidence_text = sanitize_text_for_pdf(f.evidence[:1200]).replace("\n", "<br/>")
                    story.append(Paragraph(evidence_text, mono))
                story.append(Spacer(1, 12))
                divider = Table([[""]], colWidths=[6.9 * inch], rowHeights=[0.02 * inch])
                divider.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#E5E7EB"))]))
                story.append(divider)
                story.append(Spacer(1, 8))

        story.append(PageBreak())

        # Glossary
        story.append(Paragraph("4 Glossary", h1))
        story.append(
            Paragraph(
                "<b>CVSS Score</b><br/>"
                "CVSS is a standard for scoring vulnerabilities from 0.0 to 10.0.<br/>"
                "0.1-3.9 = Low, 4.0-6.9 = Medium, 7.0-8.9 = High, 9.0-10.0 = Critical",
                styles["BodyText"],
            )
        )
        story.append(Spacer(1, 10))
        story.append(
            Paragraph(
                "AuditCrawl is an educational scanner. Only scan systems you own or have explicit written permission to test.",
                small,
            )
        )

        def _footer(canvas, _doc):
            canvas.saveState()
            canvas.setFont("Helvetica", 9)
            canvas.setFillGray(0.4)
            canvas.drawString(0.8 * inch, 0.55 * inch, "AuditCrawl Security Report")
            canvas.drawRightString(7.9 * inch, 0.55 * inch, str(canvas.getPageNumber()))
            canvas.restoreState()

        doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
        return str(path)