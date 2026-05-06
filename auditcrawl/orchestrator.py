from __future__ import annotations
import asyncio
import logging
import time
import json
import os
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

import requests

from .config import ScanConfig
from .http_client import HttpClient
from .crawler import Crawler
from .models import Endpoint, Finding, ScanResult, Severity
from .modules import xss, sqli, ssrf, idor, csrf, headers, open_redirect, auth, rce, leaked_assets
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
        return asyncio.run(self.run_async())

    async def run_async(self) -> ScanResult:
        cfg = self.config
        result = ScanResult()
        start = time.monotonic()

        os.makedirs(cfg.output_dir, exist_ok=True)
        _setup_logging(cfg.output_dir)

        async with self.client:
            # Login if configured
            if cfg.auth_login_url and cfg.auth_username:
                self._emit("auth", "Performing login...", 2)
                await self.client.login_async()

            # Crawl
            self._emit("crawl", f"Starting crawl from {cfg.base_url}", 5)
            crawler = Crawler(cfg, self.client)
            endpoints = await crawler.crawl_async()
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
                    findings += await _safe_run_async(xss.scan_async, ep, self.client, cfg.lab_mode, "xss")
                if cfg.enable_sqli:
                    findings += await _safe_run_async(sqli.scan_async, ep, self.client, cfg.lab_mode, "sqli")
                if cfg.enable_ssrf:
                    findings += await _safe_run_async(ssrf.scan_async, ep, self.client, cfg.lab_mode, "ssrf")
                if cfg.enable_idor:
                    findings += await _safe_run_async(idor.scan_async, ep, self.client, cfg.lab_mode, "idor")
                if cfg.enable_csrf:
                    findings += await _safe_run_async(csrf.scan_async, ep, self.client, cfg.lab_mode, "csrf")
                if cfg.enable_headers:
                    findings += await _safe_run_async(headers.scan_async, ep, self.client, cfg.lab_mode, "headers")
                if cfg.enable_open_redirect:
                    findings += await _safe_run_async(open_redirect.scan_async, ep, self.client, cfg.lab_mode, "open_redirect")
                if cfg.enable_auth:
                    findings += await _safe_run_async(auth.scan_async, ep, self.client, cfg.lab_mode, "auth")
                if cfg.enable_rce:
                    findings += await _safe_run_async(rce.scan_async, ep, self.client, cfg.lab_mode, "rce")
                if cfg.enable_leaked_assets:
                    findings += await _safe_run_async(leaked_assets.scan_async, ep, self.client, cfg.lab_mode, "leaked_assets")

            result.findings = _deduplicate_findings(findings)
            result.duration_seconds = time.monotonic() - start

            # Report
            self._emit("report", "Generating reports...", 96)
            reporter = Reporter(cfg, result)
            # Only generate the PDF report for users to download.
            result.report_pdf_path = reporter.write_pdf()
            result.scan_log_path = str(Path(cfg.output_dir) / "scan.log")

        _maybe_send_webhook_alert(self, result)

        self._emit("done", f"Scan complete. {len(result.findings)} findings.", 100)
        return result


async def _safe_run_async(fn, endpoint: Endpoint, client: HttpClient, lab_mode: bool, name: str) -> List[Finding]:
    try:
        result = fn(endpoint, client, lab_mode)
        if asyncio.iscoroutine(result):
            return await result
        return result
    except Exception as exc:
        logger.warning("Module %s failed on %s: %s", name, endpoint.url, exc)
        return []


def _severity_value(finding: Finding) -> str:
    return getattr(finding.severity, "value", str(finding.severity)).lower()


def _format_webhook_message(result: ScanResult, config: ScanConfig) -> str:
    sev = result.summary_by_severity()
    critical = sev.get("critical", 0)
    high = sev.get("high", 0)
    medium = sev.get("medium", 0)
    low = sev.get("low", 0)

    lines = [
        "AuditCrawl scan completed.",
        f"Target: {config.base_url}",
        f"Findings: critical={critical}, high={high}, medium={medium}, low={low}",
    ]

    notable = [f for f in result.findings if _severity_value(f) in {"critical", "high"}]
    for finding in notable[:3]:
        lines.append(f"- {finding.vuln_type} at {finding.url}")

    if len(notable) > 3:
        lines.append(f"- ...and {len(notable) - 3} more high-severity finding(s)")

    return "\n".join(lines)


def _webhook_payload(webhook_url: str, message: str) -> dict:
    host = urlparse(webhook_url).netloc.lower()
    if "slack.com" in host:
        return {"text": message}
    return {"content": message}


def _send_webhook_alert(webhook_url: str, message: str) -> None:
    try:
        requests.post(webhook_url, json=_webhook_payload(webhook_url, message), timeout=10)
    except requests.RequestException as exc:
        logger.warning("Webhook alert failed: %s", exc)


def _has_high_severity_findings(result: ScanResult) -> bool:
    return any(_severity_value(f) in {"critical", "high"} for f in result.findings)


def _maybe_send_webhook_alert(self, result: ScanResult) -> None:
    webhook_url = getattr(self.config, "webhook_url", None)
    if not webhook_url or not _has_high_severity_findings(result):
        return

    message = _format_webhook_message(result, self.config)
    _send_webhook_alert(webhook_url, message)


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