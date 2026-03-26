from __future__ import annotations
import os
from pathlib import Path
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import ScanConfig
    from .models import ScanResult

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
            fontSize=24,
            leading=28,
            spaceAfter=18,
        )
        h1 = ParagraphStyle("H1", parent=styles["Heading1"], spaceBefore=10, spaceAfter=8)
        h2 = ParagraphStyle("H2", parent=styles["Heading2"], spaceBefore=10, spaceAfter=6)
        small = ParagraphStyle("Small", parent=styles["BodyText"], fontSize=9, leading=12)
        mono = ParagraphStyle("Mono", parent=styles["BodyText"], fontName="Courier", fontSize=9, leading=11)

        sev = self.result.summary_by_severity()
        findings = self.result.findings

        story = []

        # Cover
        story.append(Paragraph(datetime.utcnow().strftime("%B %d, %Y"), styles["Normal"]))
        story.append(Spacer(1, 18))
        story.append(Paragraph("Vulnerability Scan<br/>Report", title))
        story.append(Spacer(1, 18))
        story.append(Paragraph("<b>Prepared By</b><br/>AuditCrawl Security", styles["Normal"]))
        story.append(Spacer(1, 6))
        story.append(Paragraph(f"<b>Target</b><br/>{self.config.base_url}", styles["Normal"]))
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
                    ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.whitesmoke, colors.white]),
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
                ["Low", sev.get("low", 0), "Info", sev.get("info", 0), "Total", len(findings), "", ""],
            ],
            colWidths=[0.9 * inch, 0.6 * inch, 0.7 * inch, 0.6 * inch, 0.9 * inch, 0.6 * inch],
        )
        summary_table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
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
                    self.config.base_url,
                    sev.get("critical", 0),
                    sev.get("high", 0),
                    sev.get("medium", 0),
                    sev.get("low", 0),
                    sev.get("info", 0),
                ],
            ],
            colWidths=[3.7 * inch, 0.7 * inch, 0.6 * inch, 0.8 * inch, 0.6 * inch, 0.6 * inch],
        )
        by_target.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
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
                breakdown_rows.append([f.vuln_type, f"{f.severity.value}".title(), f"{f.cvss_score:.1f}", f.url])
            breakdown = Table(breakdown_rows, colWidths=[2.5 * inch, 0.9 * inch, 0.6 * inch, 3.1 * inch])
            breakdown.setStyle(
                TableStyle(
                    [
                        ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                        ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
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
                story.append(Paragraph(f"{idx}. {f.vuln_type}", styles["Heading3"]))
                story.append(
                    Paragraph(
                        f"<b>Severity:</b> {f.severity.value.title()} &nbsp;&nbsp; "
                        f"<b>CVSS:</b> {f.cvss_score:.1f} &nbsp;&nbsp; "
                        f"<b>Confidence:</b> {f.confidence}",
                        styles["BodyText"],
                    )
                )
                story.append(Paragraph(f"<b>URL:</b> {f.url}", small))
                story.append(Paragraph(f"<b>Method:</b> {f.method} &nbsp;&nbsp; <b>Parameter:</b> {f.parameter}", small))
                story.append(Spacer(1, 6))
                story.append(Paragraph("<b>Description</b>", small))
                story.append(Paragraph(f.description, styles["BodyText"]))
                story.append(Spacer(1, 4))
                story.append(Paragraph("<b>Remediation</b>", small))
                story.append(Paragraph(f.remediation, styles["BodyText"]))
                story.append(Spacer(1, 4))
                story.append(Paragraph("<b>Payload</b>", small))
                story.append(Paragraph((f.payload or "")[:900].replace("\n", "<br/>"), mono))
                if f.evidence:
                    story.append(Spacer(1, 4))
                    story.append(Paragraph("<b>Evidence</b>", small))
                    story.append(Paragraph(f.evidence[:1200].replace("\n", "<br/>"), mono))
                story.append(Spacer(1, 10))

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
            canvas.drawRightString(7.9 * inch, 0.55 * inch, str(canvas.getPageNumber()))
            canvas.restoreState()

        doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
        return str(path)