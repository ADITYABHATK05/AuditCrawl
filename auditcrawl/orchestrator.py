from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List

from .audit_logger import AuditLogger
from .config import ScanConfig
from .crawler import WebCrawler
from .models import Endpoint, Finding
from .poc import SafePoCGenerator
from .report import ReportGenerator
from .scanners import AuthScanner, RCEPatternScanner, SQLiScanner, SSRFScanner, XSSScanner


@dataclass
class ScanResult:
    endpoints: List[Endpoint]
    findings: List[Finding]
    findings_json_path: str
    report_html_path: str
    report_markdown_path: str


class Scanner:
    def __init__(self, config: ScanConfig) -> None:
        config.validate()
        self.config = config
        self.logger = AuditLogger(output_dir=self.config.output_dir, use_sqlite=False)
        self.crawler = WebCrawler(self.config)

    def run(self) -> ScanResult:
        endpoints = self.crawler.crawl()
        findings: List[Finding] = []

        if self.config.enable_xss:
            findings.extend(XSSScanner(self.config, self.logger).scan(endpoints))
        if self.config.enable_sqli:
            findings.extend(SQLiScanner(self.config, self.logger).scan(endpoints))
        if self.config.enable_ssrf:
            findings.extend(SSRFScanner(self.config, self.logger).scan(endpoints))
        if self.config.enable_auth:
            findings.extend(AuthScanner(self.config, self.logger).scan(endpoints))
        if self.config.enable_rce:
            findings.extend(RCEPatternScanner(self.config, self.logger).scan(endpoints))

        poc_data = SafePoCGenerator().generate(findings)
        templates_dir = str(Path(__file__).resolve().parent.parent / "templates")
        reporter = ReportGenerator(output_dir=self.config.output_dir, templates_dir=templates_dir)
        findings_json = reporter.generate_json(findings, poc_data)
        report_html = reporter.generate_html(findings, poc_data)
        report_markdown = reporter.generate_markdown(findings, poc_data)

        return ScanResult(
            endpoints=endpoints,
            findings=findings,
            findings_json_path=str(findings_json),
            report_html_path=str(report_html),
            report_markdown_path=str(report_markdown),
        )
