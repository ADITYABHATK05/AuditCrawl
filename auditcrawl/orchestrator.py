from __future__ import annotations
import logging
import time
import json
import os
from pathlib import Path
from typing import List, Optional

from .config import ScanConfig
from .http_client import HttpClient
from .crawler import Crawler
from .models import Endpoint, Finding, ScanResult
from .modules import xss, sqli, ssrf, idor, csrf, headers, open_redirect, auth, rce
from .reporter import Reporter

logger = logging.getLogger("auditcrawl.orchestrator")


class Scanner:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.client = HttpClient(config)
        self._progress_callback = None  # optional callable(stage, message, pct)

    def set_progress_callback(self, cb):
        """Register a callback(stage, message, percent) for live UI updates."""
        self._progress_callback = cb

    def _emit(self, stage: str, message: str, pct: int = 0) -> None:
        logger.info("[%s] %s", stage, message)
        if self._progress_callback:
            self._progress_callback(stage, message, pct)

    def run(self) -> ScanResult:
        cfg = self.config
        result = ScanResult()
        start = time.monotonic()

        os.makedirs(cfg.output_dir, exist_ok=True)
        _setup_logging(cfg.output_dir)

        # Login if configured
        if cfg.auth_login_url and cfg.auth_username:
            self._emit("auth", "Performing login...", 2)
            self.client.login()

        # Crawl
        self._emit("crawl", f"Starting crawl from {cfg.base_url}", 5)
        crawler = Crawler(cfg, self.client)
        endpoints = crawler.crawl()
        result.endpoints = endpoints
        self._emit("crawl", f"Discovered {len(endpoints)} endpoints", 25)

        # De-duplicate endpoints for scanning
        scan_targets = _deduplicate_endpoints(endpoints)
        total = len(scan_targets)
        findings: List[Finding] = []

        for i, ep in enumerate(scan_targets):
            pct = 25 + int(70 * i / max(total, 1))
            self._emit("scan", f"[{i+1}/{total}] Scanning {ep.url}", pct)

            if cfg.enable_xss:
                findings += _safe_run(xss.scan, ep, self.client, cfg.lab_mode, "xss")
            if cfg.enable_sqli:
                findings += _safe_run(sqli.scan, ep, self.client, cfg.lab_mode, "sqli")
            if cfg.enable_ssrf:
                findings += _safe_run(ssrf.scan, ep, self.client, cfg.lab_mode, "ssrf")
            if cfg.enable_idor:
                findings += _safe_run(idor.scan, ep, self.client, cfg.lab_mode, "idor")
            if cfg.enable_csrf:
                findings += _safe_run(csrf.scan, ep, self.client, cfg.lab_mode, "csrf")
            if cfg.enable_headers:
                findings += _safe_run(headers.scan, ep, self.client, cfg.lab_mode, "headers")
            if cfg.enable_open_redirect:
                findings += _safe_run(open_redirect.scan, ep, self.client, cfg.lab_mode, "open_redirect")
            if cfg.enable_auth:
                findings += _safe_run(auth.scan, ep, self.client, cfg.lab_mode, "auth")
            if cfg.enable_rce:
                findings += _safe_run(rce.scan, ep, self.client, cfg.lab_mode, "rce")

        result.findings = _deduplicate_findings(findings)
        result.duration_seconds = time.monotonic() - start

        # Report
        self._emit("report", "Generating reports...", 96)
        reporter = Reporter(cfg, result)
        # Only generate the PDF report for users to download.
        result.report_pdf_path = reporter.write_pdf()
        result.scan_log_path = str(Path(cfg.output_dir) / "scan.log")

        self._emit("done", f"Scan complete. {len(result.findings)} findings.", 100)
        # Be tolerant if an older/alternate HttpClient implementation is used.
        close_fn = getattr(self.client, "close", None)
        if callable(close_fn):
            close_fn()
        return result


def _safe_run(fn, endpoint: Endpoint, client: HttpClient, lab_mode: bool, name: str) -> List[Finding]:
    try:
        return fn(endpoint, client, lab_mode)
    except Exception as exc:
        logger.warning("Module %s failed on %s: %s", name, endpoint.url, exc)
        return []


def _deduplicate_endpoints(endpoints: List[Endpoint]) -> List[Endpoint]:
    seen = set()
    result = []
    for ep in endpoints:
        # FIX: Include parameter keys in deduplication so endpoints with different params are scanned
        param_keys = tuple(sorted(ep.params.keys()))
        key = (ep.url.split("?")[0], ep.method, param_keys)
        if key not in seen:
            seen.add(key)
            result.append(ep)
    return result


def _deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    seen = set()
    result = []
    for f in findings:
        # FIX: Ensure payload is converted to string to avoid slicing errors on None
        safe_payload = str(f.payload)[:50] if f.payload else ""
        key = (f.vuln_type, f.url, f.parameter, safe_payload)
        if key not in seen:
            seen.add(key)
            result.append(f)
            
    # Sort: critical first
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    # FIX: Handle cases where f.severity might be a raw string instead of the Enum object
    result.sort(key=lambda f: severity_order.get(getattr(f.severity, "value", str(f.severity)), 5))
    return result


def _setup_logging(output_dir: str) -> None:
    log_path = Path(output_dir) / "scan.log"
    fh = logging.FileHandler(log_path, mode="w")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s"))
    logging.getLogger("auditcrawl").addHandler(fh)
    logging.getLogger("auditcrawl").setLevel(logging.DEBUG)