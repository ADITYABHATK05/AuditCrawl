from __future__ import annotations

import re
import time
import uuid
from typing import Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from .audit_logger import AuditLogger
from .config import ScanConfig
from .models import Endpoint, Finding
from .utils import response_fingerprint

EDU_POC_NOTE = "This POC is for educational use; do not run on real systems without permission."


class BaseScanner:
    module_name = "BaseScanner"

    def __init__(self, config: ScanConfig, logger: AuditLogger, session: Optional[requests.Session] = None) -> None:
        self.config = config
        self.logger = logger
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": self.config.user_agent})

    def _request(self, method: str, url: str, data: Optional[Dict[str, str]] = None) -> requests.Response:
        if method.upper() == "POST":
            return self.session.post(url, data=data or {}, timeout=self.config.timeout_seconds)

        parsed = urlparse(url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query.update(data or {})
        merged_url = urlunparse(parsed._replace(query=urlencode(query)))
        return self.session.get(merged_url, timeout=self.config.timeout_seconds)


class XSSScanner(BaseScanner):
    module_name = "XSSScanner"

    PAYLOAD_TEMPLATES = [
        "<script>console.log('{marker}')</script>",
        "\"'><img src=x onerror=console.log('{marker}')>",
    ]

    def _new_marker(self) -> str:
        return f"AUDITCRAWL_XSS_{uuid.uuid4().hex[:10]}"

    def _is_html_response(self, response: requests.Response) -> bool:
        content_type = response.headers.get("Content-Type", "").lower()
        return "html" in content_type or content_type == ""

    def _appears_in_sensitive_context(self, html_text: str, marker: str) -> bool:
        if marker not in html_text:
            return False

        patterns = [
            rf"<script[^>]*>[^<]*{re.escape(marker)}[^<]*</script>",
            rf"on\w+\s*=\s*['\"][^'\"]*{re.escape(marker)}[^'\"]*['\"]",
            rf"on\w+\s*=\s*[^\s>]*{re.escape(marker)}[^\s>]*",
            rf"javascript:[^'\"\s>]*{re.escape(marker)}",
            rf">[^<]*{re.escape(marker)}[^<]*<",
        ]
        return any(re.search(pattern, html_text, flags=re.IGNORECASE) for pattern in patterns)

    def _follow_up_targets(self, endpoint: Endpoint, endpoints: List[Endpoint]) -> List[str]:
        candidates: List[str] = []
        for url in [endpoint.source_url, endpoint.url]:
            if url:
                candidates.append(url)

        # Add nearby GET endpoints as potential render pages for stored content.
        for ep in endpoints:
            if ep.method == "GET" and ep.url not in candidates:
                candidates.append(ep.url)
            if len(candidates) >= 6:
                break

        unique: List[str] = []
        seen = set()
        for url in candidates:
            if url in seen:
                continue
            seen.add(url)
            unique.append(url)
        return unique[:6]

    def _fetch_page_text(self, url: str) -> str:
        try:
            resp = self.session.get(url, timeout=self.config.timeout_seconds)
        except requests.RequestException:
            return ""
        if resp.status_code >= 400 or not self._is_html_response(resp):
            return ""
        return resp.text

    def _scan_reflected_xss(self, endpoint: Endpoint, parameter: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            baseline = self._request(endpoint.method, endpoint.url, {parameter: "baseline"})
        except requests.RequestException:
            return findings

        if baseline.status_code >= 400 or not self._is_html_response(baseline):
            return findings

        baseline_text = baseline.text
        marker = self._new_marker()
        payloads = [template.format(marker=marker) for template in self.PAYLOAD_TEMPLATES]

        for payload in payloads:
            try:
                test = self._request(endpoint.method, endpoint.url, {parameter: payload})
            except requests.RequestException:
                continue

            reflected = (
                test.status_code < 400
                and self._is_html_response(test)
                and payload in test.text
                and payload not in baseline_text
                and marker not in baseline_text
                and self._appears_in_sensitive_context(test.text, marker)
            )
            notes = "reflected context + baseline delta" if reflected else "no strong reflection signal"
            self.logger.log_event(
                module=self.module_name,
                url=endpoint.url,
                method=endpoint.method,
                payload=f"{parameter}={payload}",
                response_status=test.status_code,
                response_hash=response_fingerprint(test.text),
                confirmed=reflected,
                notes=notes,
            )
            if reflected:
                findings.append(
                    Finding(
                        vulnerability="Reflected XSS",
                        risk="Medium",
                        endpoint=endpoint.url,
                        method=endpoint.method,
                        parameter=parameter,
                        payload=payload,
                        evidence=(
                            f"Unique marker reflected in sensitive rendering context for parameter '{parameter}'. "
                            "Baseline comparison confirms marker absence before injection."
                        ),
                        remediation="Apply context-aware output encoding, validate input, and enforce CSP.",
                        confidence="high",
                        module=self.module_name,
                    )
                )
                break

        return findings

    def _scan_stored_xss(self, endpoint: Endpoint, parameter: str, endpoints: List[Endpoint]) -> List[Finding]:
        findings: List[Finding] = []
        if endpoint.method != "POST":
            return findings

        marker = self._new_marker()
        stored_payload = self.PAYLOAD_TEMPLATES[1].format(marker=marker)
        targets = self._follow_up_targets(endpoint, endpoints)
        baseline_pages = {url: self._fetch_page_text(url) for url in targets}

        submit_data = {field: "safe" for field in (endpoint.form_fields or endpoint.parameters)}
        submit_data[parameter] = stored_payload
        try:
            submit_resp = self._request("POST", endpoint.url, submit_data)
        except requests.RequestException:
            return findings

        # Two follow-up fetch rounds reduce transient false positives.
        time.sleep(self.config.delay_seconds)
        round_one = {url: self._fetch_page_text(url) for url in targets}
        time.sleep(self.config.delay_seconds)
        round_two = {url: self._fetch_page_text(url) for url in targets}

        confirmed_target = None
        for url in targets:
            base_text = baseline_pages.get(url, "")
            first_text = round_one.get(url, "")
            second_text = round_two.get(url, "")
            newly_present = marker not in base_text and marker in first_text and marker in second_text
            context_match = self._appears_in_sensitive_context(first_text + "\n" + second_text, marker)
            if newly_present and context_match:
                confirmed_target = url
                break

        self.logger.log_event(
            module=self.module_name,
            url=endpoint.url,
            method="POST",
            payload=f"{parameter}={stored_payload}",
            response_status=submit_resp.status_code,
            response_hash=response_fingerprint(submit_resp.text),
            confirmed=confirmed_target is not None,
            notes="stored XSS submit-then-fetch correlation",
        )

        if confirmed_target:
            findings.append(
                Finding(
                    vulnerability="Stored XSS",
                    risk="High",
                    endpoint=endpoint.url,
                    method="POST",
                    parameter=parameter,
                    payload=stored_payload,
                    evidence=(
                        f"Unique marker persisted after POST and reappeared on follow-up GET page {confirmed_target} "
                        "in two consecutive fetches; absent in baseline capture."
                    ),
                    remediation="Sanitize and encode untrusted input before storage/output; deploy strict CSP.",
                    confidence="high",
                    module=self.module_name,
                )
            )

        return findings

    def scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings: List[Finding] = []
        for ep in endpoints:
            if not ep.parameters:
                continue
            for param in ep.parameters:
                findings.extend(self._scan_reflected_xss(ep, param))
                findings.extend(self._scan_stored_xss(ep, param, endpoints))

        return findings


class SQLiScanner(BaseScanner):
    module_name = "SQLiScanner"

    ERROR_PAYLOADS = [
        "'",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
    ]
    ERROR_MARKERS = [
        "sql syntax",
        "mysql",
        "sqlite",
        "postgresql",
        "syntax error",
        "unclosed quotation mark",
        "odbc",
    ]

    TIME_PAYLOAD = "' AND SLEEP(1)--"

    def scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings: List[Finding] = []
        for ep in endpoints:
            if not ep.parameters:
                continue

            for param in ep.parameters:
                try:
                    baseline_start = time.perf_counter()
                    baseline = self._request(ep.method, ep.url, {param: "1"})
                    baseline_elapsed = time.perf_counter() - baseline_start
                except requests.RequestException:
                    continue

                base_len = len(baseline.text)
                base_text_lower = baseline.text.lower()

                for payload in self.ERROR_PAYLOADS:
                    try:
                        test = self._request(ep.method, ep.url, {param: payload})
                    except requests.RequestException:
                        continue
                    test_lower = test.text.lower()
                    marker_hit = any(m in test_lower and m not in base_text_lower for m in self.ERROR_MARKERS)
                    length_delta = abs(len(test.text) - base_len) > max(120, int(base_len * 0.25))
                    confirmed = marker_hit or (test.status_code >= 500 and length_delta)

                    self.logger.log_event(
                        module=self.module_name,
                        url=ep.url,
                        method=ep.method,
                        payload=f"{param}={payload}",
                        response_status=test.status_code,
                        response_hash=response_fingerprint(test.text),
                        confirmed=confirmed,
                        notes="error-based SQLi check",
                    )

                    if confirmed:
                        findings.append(
                            Finding(
                                vulnerability="SQL Injection (error-based symptom)",
                                risk="High",
                                endpoint=ep.url,
                                method=ep.method,
                                parameter=param,
                                payload=payload,
                                evidence="Response contains SQL error indicators or abnormal server error behavior.",
                                remediation="Use parameterized queries/ORM, strict input validation, and least-privileged DB accounts.",
                                confidence="medium",
                                module=self.module_name,
                            )
                        )
                        break

                if self.config.enable_time_based_sqli and self.config.lab_mode and not self.config.safe_mode:
                    try:
                        t0 = time.perf_counter()
                        test = self._request(ep.method, ep.url, {param: self.TIME_PAYLOAD})
                        elapsed = time.perf_counter() - t0
                        delayed = elapsed > baseline_elapsed + 0.8
                        self.logger.log_event(
                            module=self.module_name,
                            url=ep.url,
                            method=ep.method,
                            payload=f"{param}={self.TIME_PAYLOAD}",
                            response_status=test.status_code,
                            response_hash=response_fingerprint(test.text),
                            confirmed=delayed,
                            notes="time-based SQLi check (lab-only)",
                        )
                        if delayed:
                            findings.append(
                                Finding(
                                    vulnerability="SQL Injection (time-based symptom)",
                                    risk="High",
                                    endpoint=ep.url,
                                    method=ep.method,
                                    parameter=param,
                                    payload=self.TIME_PAYLOAD,
                                    evidence="Injected request showed consistent latency increase versus baseline.",
                                    remediation="Use prepared statements and avoid dynamic SQL string concatenation.",
                                    confidence="low",
                                    module=self.module_name,
                                )
                            )
                    except requests.RequestException:
                        continue

        return findings


class SSRFScanner(BaseScanner):
    module_name = "SSRFScanner"
    URL_HINTS = ["url", "uri", "link", "image", "callback", "redirect", "feed", "next"]

    def scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings: List[Finding] = []
        for ep in endpoints:
            if not ep.parameters:
                continue
            for param in ep.parameters:
                if not any(h in param.lower() for h in self.URL_HINTS):
                    continue

                if self.config.lab_mode:
                    payload = "http://127.0.0.1/health"
                    try:
                        resp = self._request(ep.method, ep.url, {param: payload})
                    except requests.RequestException:
                        continue
                    signal = "127.0.0.1" in resp.text or "health" in resp.text.lower()
                    self.logger.log_event(
                        module=self.module_name,
                        url=ep.url,
                        method=ep.method,
                        payload=f"{param}={payload}",
                        response_status=resp.status_code,
                        response_hash=response_fingerprint(resp.text),
                        confirmed=signal,
                        notes="lab SSRF simulation",
                    )
                    if signal:
                        findings.append(
                            Finding(
                                vulnerability="Potential SSRF",
                                risk="High",
                                endpoint=ep.url,
                                method=ep.method,
                                parameter=param,
                                payload=payload,
                                evidence="Application appears to fetch user-provided URL and include result in response.",
                                remediation="Enforce strict outbound URL allow-list and block private/internal address ranges.",
                                confidence="medium",
                                module=self.module_name,
                            )
                        )
                else:
                    warning_payload = "https://example.com/safe-check"
                    self.logger.log_event(
                        module=self.module_name,
                        url=ep.url,
                        method=ep.method,
                        payload=f"{param}={warning_payload}",
                        response_status=0,
                        response_hash="",
                        confirmed=False,
                        notes="real-world mode warning only; no internal SSRF probe executed",
                    )
                    findings.append(
                        Finding(
                            vulnerability="Potential SSRF exposure (warning)",
                            risk="Medium",
                            endpoint=ep.url,
                            method=ep.method,
                            parameter=param,
                            payload=warning_payload,
                            evidence=(
                                "Parameter appears to accept URLs. In production this can be risky if internal addresses are reachable."
                            ),
                            remediation="Apply URL scheme/domain allow-list and deny localhost, RFC1918, and metadata endpoints.",
                            confidence="low",
                            module=self.module_name,
                        )
                    )

        return findings


class AuthScanner(BaseScanner):
    module_name = "AuthScanner"

    def scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings: List[Finding] = []
        sensitive = [
            ep
            for ep in endpoints
            if any(k in (urlparse(ep.url).path or "").lower() for k in self.config.auth_protected_keywords)
        ]

        for ep in sensitive:
            try:
                resp = self._request("GET", ep.url)
            except requests.RequestException:
                continue

            looks_open = resp.status_code == 200 and "login" not in resp.url.lower()
            self.logger.log_event(
                module=self.module_name,
                url=ep.url,
                method="GET",
                payload="unauthenticated-request",
                response_status=resp.status_code,
                response_hash=response_fingerprint(resp.text),
                confirmed=looks_open,
                notes="missing auth check",
            )

            if looks_open:
                findings.append(
                    Finding(
                        vulnerability="Missing authentication on sensitive endpoint",
                        risk="High",
                        endpoint=ep.url,
                        method="GET",
                        parameter=None,
                        evidence="Sensitive-looking path was accessible without authentication context.",
                        remediation="Require server-side authentication and role checks for all sensitive routes.",
                        confidence="low",
                        module=self.module_name,
                    )
                )

        if self.config.auth_logout_url and self.config.auth_login_url:
            try:
                login_resp = self._request("GET", self.config.auth_login_url)
                cookie_before = dict(self.session.cookies)
                logout_resp = self._request("GET", self.config.auth_logout_url)
                cookie_after = dict(self.session.cookies)
                still_same = bool(cookie_before) and cookie_before == cookie_after

                self.logger.log_event(
                    module=self.module_name,
                    url=self.config.auth_logout_url,
                    method="GET",
                    payload="logout-reuse-check",
                    response_status=logout_resp.status_code,
                    response_hash=response_fingerprint(logout_resp.text),
                    confirmed=still_same,
                    notes="session invalidation check",
                )

                if still_same:
                    findings.append(
                        Finding(
                            vulnerability="Incomplete session invalidation",
                            risk="Medium",
                            endpoint=self.config.auth_logout_url,
                            method="GET",
                            parameter=None,
                            evidence="Session cookie remained unchanged after logout flow check.",
                            remediation="Invalidate server-side sessions and rotate session identifiers after logout/login.",
                            confidence="low",
                            module=self.module_name,
                        )
                    )
            except requests.RequestException:
                pass

        return findings


class RCEPatternScanner(BaseScanner):
    module_name = "RCEPatternScanner"
    PARAM_HINTS = ["cmd", "command", "exec", "run", "file", "path"]
    META_CHARS = [";", "|", "&", "$(", "`"]

    def scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings: List[Finding] = []
        for ep in endpoints:
            for param in ep.parameters:
                if not any(h in param.lower() for h in self.PARAM_HINTS):
                    continue

                # Pattern-only, no command execution payloads.
                payload = "echo_SAFE_TEST"
                try:
                    resp = self._request(ep.method, ep.url, {param: payload})
                except requests.RequestException:
                    continue

                body = resp.text.lower()
                signal = any(token in body for token in ["command", "shell", "execution", "process"])
                confirmed = signal
                self.logger.log_event(
                    module=self.module_name,
                    url=ep.url,
                    method=ep.method,
                    payload=f"{param}={payload}",
                    response_status=resp.status_code,
                    response_hash=response_fingerprint(resp.text),
                    confirmed=confirmed,
                    notes="pattern-only RCE surface probe",
                )

                if confirmed:
                    findings.append(
                        Finding(
                            vulnerability="Potential command injection / RCE surface",
                            risk="High",
                            endpoint=ep.url,
                            method=ep.method,
                            parameter=param,
                            payload=payload,
                            evidence=(
                                "Endpoint parameter naming and response patterns suggest possible command execution pathway."
                            ),
                            remediation="Avoid OS command execution with user input; use allow-lists and safe library APIs.",
                            confidence="low",
                            module=self.module_name,
                        )
                    )

        return findings
