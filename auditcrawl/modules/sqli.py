from __future__ import annotations
import asyncio
import logging
import time
import re
from typing import List
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from ..http_client import HttpClient
from ..models import Endpoint, Finding, Severity

logger = logging.getLogger("auditcrawl.sqli")

# Error-based payloads
ERROR_PAYLOADS = [
    "'",
    '"',
    "';--",
    '" OR "1"="1',
    "' OR '1'='1",
    "1' AND '1'='2",
    "' OR 1=1--",
    "') OR ('1'='1",
    "1; SELECT SLEEP(0)--",
    "\\",
    "1'",
]

# Boolean payloads: (true_payload, false_payload)
BOOLEAN_PAIRS = [
    ("' OR '1'='1", "' OR '1'='2"),
    ("1' OR '1'='1'--", "1' OR '1'='2'--"),
    ("1 OR 1=1", "1 OR 1=2"),
]

# Time-based payloads (lab mode only) — sleep 3s
TIME_PAYLOADS = [
    ("' OR SLEEP(3)--", 3.0),
    ("1; WAITFOR DELAY '0:0:3'--", 3.0),
    ("' OR pg_sleep(3)--", 3.0),
    ("' OR 1=1 AND SLEEP(3)--", 3.0),
]

DB_ERROR_PATTERNS = re.compile(
    r"(sql syntax|mysql_fetch|ORA-\d+|pg_query|SQLite3::|"
    r"unclosed quotation|ODBC.*error|syntax error.*SQL|"
    r"Microsoft.*ODBC|JET Database|Warning.*mysql_|"
    r"supplied argument is not a valid MySQL|"
    r"Division by zero|Column count doesn't match|"
    r"You have an error in your SQL syntax)",
    re.IGNORECASE,
)


def scan(endpoint: Endpoint, client: HttpClient, lab_mode: bool = False) -> List[Finding]:
    return asyncio.run(scan_async(endpoint, client, lab_mode))


async def scan_async(endpoint: Endpoint, client: HttpClient, lab_mode: bool = False) -> List[Finding]:
    findings: List[Finding] = []
    findings += await _error_based(endpoint, client)
    findings += await _boolean_based(endpoint, client)
    if lab_mode:
        findings += await _time_based(endpoint, client)
    return _deduplicate(findings)


def _param_variants(endpoint: Endpoint):
    """Yield (url, method, param_name, all_params, form) for every testable parameter."""
    parsed = urlparse(endpoint.url)
    url_params = {k: v[0] if isinstance(v, list) else v
                  for k, v in parse_qs(parsed.query).items()}

    for param in url_params:
        yield endpoint.url, "GET", param, url_params, None

    for form in endpoint.forms:
        for inp in form.get("inputs", []):
            if inp.get("type") in ("submit", "button", "file"):
                continue
            data = {i["name"]: i["value"] for i in form["inputs"]}
            yield form["action"], form["method"], inp["name"], data, form


def _inject_param(url: str, params: dict, name: str, value: str) -> str:
    parsed = urlparse(url)
    new_params = dict(params)
    new_params[name] = value
    return urlunparse(parsed._replace(query=urlencode(new_params)))


async def _send(client: HttpClient, url: str, method: str, params: dict, name: str, payload: str):
    new_params = dict(params)
    new_params[name] = payload
    if method == "POST":
        return await client.post_async(url, data=new_params)
    test_url = _inject_param(url, params, name, payload)
    return await client.get_async(test_url)


async def _error_based(endpoint: Endpoint, client: HttpClient) -> List[Finding]:
    findings = []
    for url, method, param, params, form in _param_variants(endpoint):
        baseline_resp = await client.get_async(url) if method == "GET" else None
        baseline_text = baseline_resp.text if baseline_resp else ""

        for payload in ERROR_PAYLOADS:
            resp = await _send(client, url, method, params, param, payload)
            if resp is None:
                continue
            if DB_ERROR_PATTERNS.search(resp.text) and not DB_ERROR_PATTERNS.search(baseline_text):
                match = DB_ERROR_PATTERNS.search(resp.text)
                findings.append(Finding(
                    vuln_type="SQL Injection (Error-based)",
                    severity=Severity.CRITICAL,
                    url=url,
                    method=method,
                    parameter=param,
                    payload=payload,
                    evidence=_extract_error(resp.text, match.group()),
                    description=f"Error-based SQL injection in parameter '{param}'. "
                                "The server returned a database error message revealing the SQL query structure.",
                    remediation="Use parameterized queries / prepared statements. "
                                "Never concatenate user input into SQL. "
                                "Suppress detailed database error messages in production.",
                    cvss_score=9.8,
                    confidence="high",
                    false_positive_risk="low",
                    poc=f"{method} {url} with {param}={payload}",
                ))
                break
    return findings


async def _boolean_based(endpoint: Endpoint, client: HttpClient) -> List[Finding]:
    findings = []
    for url, method, param, params, form in _param_variants(endpoint):
        baseline_resp = await _send(client, url, method, params, param, params.get(param, "1"))
        if baseline_resp is None:
            continue
        baseline_text = baseline_resp.text

        for true_pay, false_pay in BOOLEAN_PAIRS:
            resp_true = await _send(client, url, method, params, param, true_pay)
            resp_false = await _send(client, url, method, params, param, false_pay)
            if resp_true is None or resp_false is None:
                continue

            # Significant difference between true/false but true ≈ baseline
            true_diff = _diff_ratio(baseline_text, resp_true.text)
            false_diff = _diff_ratio(baseline_text, resp_false.text)

            if true_diff < 0.15 and false_diff > 0.25:
                findings.append(Finding(
                    vuln_type="SQL Injection (Boolean-based blind)",
                    severity=Severity.CRITICAL,
                    url=url,
                    method=method,
                    parameter=param,
                    payload=true_pay,
                    evidence=f"True payload response length: {len(resp_true.text)}, "
                             f"False payload length: {len(resp_false.text)}, "
                             f"Baseline length: {len(baseline_text)}",
                    description=f"Boolean-based blind SQL injection in parameter '{param}'. "
                                "The application returns different responses depending on the truth value of the injected condition.",
                    remediation="Use parameterized queries / prepared statements. "
                                "Never concatenate user input into SQL.",
                    cvss_score=9.8,
                    confidence="medium",
                    false_positive_risk="medium",
                    poc=f"{method} {url} — compare {param}={true_pay} vs {param}={false_pay}",
                ))
                break
    return findings


async def _time_based(endpoint: Endpoint, client: HttpClient) -> List[Finding]:
    findings = []
    for url, method, param, params, form in _param_variants(endpoint):
        for payload, expected_delay in TIME_PAYLOADS:
            t0 = time.monotonic()
            resp = await _send(client, url, method, params, param, payload)
            elapsed = time.monotonic() - t0
            if resp is None:
                continue
            if elapsed >= expected_delay * 0.8:
                findings.append(Finding(
                    vuln_type="SQL Injection (Time-based blind)",
                    severity=Severity.CRITICAL,
                    url=url,
                    method=method,
                    parameter=param,
                    payload=payload,
                    evidence=f"Response delay: {elapsed:.2f}s (expected ≥{expected_delay}s)",
                    description=f"Time-based blind SQL injection in parameter '{param}'. "
                                "The database executed a sleep/delay function, confirming injection.",
                    remediation="Use parameterized queries / prepared statements. "
                                "Never concatenate user input into SQL.",
                    cvss_score=9.8,
                    confidence="high",
                    false_positive_risk="low",
                    poc=f"{method} {url} with {param}={payload} — observe {elapsed:.1f}s delay",
                ))
                break
    return findings


def _diff_ratio(a: str, b: str) -> float:
    if not a and not b:
        return 0.0
    longer = max(len(a), len(b))
    if longer == 0:
        return 0.0
    return abs(len(a) - len(b)) / longer


def _deduplicate(findings: List[Finding]) -> List[Finding]:
    seen = set()
    result = []
    for f in findings:
        key = (f.vuln_type, f.url, f.parameter)
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result


def _extract_error(text: str, pattern: str, window: int = 300) -> str:
    idx = text.lower().find(pattern.lower())
    if idx == -1:
        return text[:300]
    return text[max(0, idx - 50):idx + window]