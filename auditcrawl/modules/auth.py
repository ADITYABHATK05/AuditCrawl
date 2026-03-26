from __future__ import annotations
import logging
import re
from typing import List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ..http_client import HttpClient
from ..models import Endpoint, Finding, Severity

logger = logging.getLogger("auditcrawl.rce")

# Parameter names that suggest OS command execution
CMD_PARAM_PATTERN = re.compile(
    r"(cmd|command|exec|execute|shell|run|ping|ip|host|query|"
    r"system|process|eval|code|script|payload|input|data)",
    re.IGNORECASE,
)

# Payloads that trigger observable output (no real harm)
CMD_DETECTION_PAYLOADS = [
    # Command separators + benign echo
    (";echo AUDITCRAWL_RCE_MARKER", "AUDITCRAWL_RCE_MARKER"),
    ("&&echo AUDITCRAWL_RCE_MARKER", "AUDITCRAWL_RCE_MARKER"),
    ("|echo AUDITCRAWL_RCE_MARKER", "AUDITCRAWL_RCE_MARKER"),
    ("`echo AUDITCRAWL_RCE_MARKER`", "AUDITCRAWL_RCE_MARKER"),
    ("$(echo AUDITCRAWL_RCE_MARKER)", "AUDITCRAWL_RCE_MARKER"),
    # Windows
    ("&echo AUDITCRAWL_RCE_MARKER", "AUDITCRAWL_RCE_MARKER"),
    # SSTI (template injection → RCE)
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("#{7*7}", "49"),
]

# Patterns in responses that suggest RCE is happening
RCE_RESPONSE_PATTERNS = re.compile(
    r"(root:x:0:|/bin/bash|/usr/bin|uid=\d+|Windows NT|"
    r"Microsoft Windows \[Version|Directory of C:\\|"
    r"AUDITCRAWL_RCE_MARKER)",
    re.IGNORECASE,
)


def scan(endpoint: Endpoint, client: HttpClient, lab_mode: bool = False) -> List[Finding]:
    findings = []
    findings += _command_injection(endpoint, client, lab_mode)
    findings += _ssti(endpoint, client)
    return findings


def _collect_params(endpoint: Endpoint):
    parsed = urlparse(endpoint.url)
    url_params = {k: v[0] if isinstance(v, list) else v
                  for k, v in parse_qs(parsed.query).items()}
    for name in url_params:
        yield endpoint.url, "GET", name, url_params

    for form in endpoint.forms:
        data = {i["name"]: i["value"] for i in form.get("inputs", [])}
        for inp in form.get("inputs", []):
            if inp.get("type") in ("submit", "button"):
                continue
            yield form["action"], form["method"], inp["name"], data


def _inject(client, url, method, params, param_name, payload):
    new_params = dict(params)
    new_params[param_name] = payload
    if method == "POST":
        return client.post(url, data=new_params)
    parsed = urlparse(url)
    test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
    return client.get(test_url)


def _command_injection(endpoint: Endpoint, client: HttpClient, lab_mode: bool) -> List[Finding]:
    findings = []
    for url, method, param, params in _collect_params(endpoint):
        if not CMD_PARAM_PATTERN.search(param) and not lab_mode:
            continue

        baseline_resp = client.get(url) if method == "GET" else None
        baseline_text = baseline_resp.text if baseline_resp else ""

        for payload, marker in CMD_DETECTION_PAYLOADS:
            if "49" in marker:
                continue  # Skip SSTI payloads here
            resp = _inject(client, url, method, params, param, params.get(param, "127.0.0.1") + payload)
            if resp is None:
                continue

            if marker in resp.text and marker not in baseline_text:
                findings.append(Finding(
                    vuln_type="Command Injection (RCE)",
                    severity=Severity.CRITICAL,
                    url=url,
                    method=method,
                    parameter=param,
                    payload=payload,
                    evidence=f"Marker '{marker}' appeared in response after injection. "
                             + _extract_context(resp.text, marker),
                    description=f"Command injection confirmed in parameter '{param}'. "
                                "The server executed a system command containing "
                                "user-supplied input. Full remote code execution is possible.",
                    remediation="Never pass user input to system commands. "
                                "Use language-native APIs instead (e.g., Python subprocess with list args). "
                                "Validate and whitelist all inputs. Run the process with minimal privileges.",
                    cvss_score=10.0,
                    confidence="high",
                    false_positive_risk="low",
                    poc=f"{method} {url} with {param}=<value>{payload}",
                ))
                break
    return findings


def _ssti(endpoint: Endpoint, client: HttpClient) -> List[Finding]:
    """Server-Side Template Injection detection."""
    findings = []
    for url, method, param, params in _collect_params(endpoint):
        baseline_resp = client.get(url) if method == "GET" else None
        baseline_text = baseline_resp.text if baseline_resp else ""

        for payload, expected in [("{{7*7}}", "49"), ("${7*7}", "49"), ("<%= 7*7 %>", "49")]:
            resp = _inject(client, url, method, params, param, payload)
            if resp is None:
                continue
            if expected in resp.text and expected not in baseline_text:
                findings.append(Finding(
                    vuln_type="SSTI (Server-Side Template Injection)",
                    severity=Severity.CRITICAL,
                    url=url,
                    method=method,
                    parameter=param,
                    payload=payload,
                    evidence=f"Payload {payload} evaluated to '{expected}' in response.",
                    description=f"Server-Side Template Injection in parameter '{param}'. "
                                "The template engine evaluated an arithmetic expression from "
                                "user input. This can lead to full remote code execution.",
                    remediation="Never render user input directly in template strings. "
                                "Pass user data as template variables, not as template source. "
                                "Use sandboxed template environments.",
                    cvss_score=10.0,
                    confidence="high",
                    false_positive_risk="low",
                    poc=f"{method} {url} with {param}={payload} — response contains '{expected}'",
                ))
                break
    return findings


def _extract_context(text: str, marker: str, window: int = 200) -> str:
    idx = text.find(marker)
    if idx == -1:
        return text[:200]
    return text[max(0, idx - 50):idx + window]