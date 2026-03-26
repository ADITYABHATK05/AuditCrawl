from __future__ import annotations
import logging
from typing import List
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from ..http_client import HttpClient
from ..models import Endpoint, Finding, Severity

logger = logging.getLogger("auditcrawl.xss")

XSS_PAYLOADS = [
    '<script>alert("AUDITCRAWL_XSS")</script>',
    '"><script>alert("AUDITCRAWL_XSS")</script>',
    "'><script>alert('AUDITCRAWL_XSS')</script>",
    '<img src=x onerror=alert("AUDITCRAWL_XSS")>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert("AUDITCRAWL_XSS")>',
    'javascript:alert("AUDITCRAWL_XSS")',
    '"><details open ontoggle=alert(1)>',
]

STORED_XSS_MARKER = "AUDITCRAWL_STORED_XSS_"


def scan(endpoint: Endpoint, client: HttpClient, lab_mode: bool = False) -> List[Finding]:
    findings: List[Finding] = []
    findings += _reflected_xss(endpoint, client)
    findings += _stored_xss(endpoint, client)
    return findings


def _get_baseline(url: str, client: HttpClient) -> str:
    resp = client.get(url)
    return resp.text if resp else ""


def _reflected_xss(endpoint: Endpoint, client: HttpClient) -> List[Finding]:
    findings = []

    # Test URL query params
    parsed = urlparse(endpoint.url)
    params = {k: v[0] if isinstance(v, list) else v
              for k, v in parse_qs(parsed.query).items()}

    if not params and not endpoint.forms:
        return findings

    baseline = _get_baseline(endpoint.url, client)

    for param, orig_val in params.items():
        for payload in XSS_PAYLOADS:
            test_params = dict(params)
            test_params[param] = payload
            new_query = urlencode(test_params)
            test_url = urlunparse(parsed._replace(query=new_query))

            resp = client.get(test_url)
            if resp is None:
                continue

            # Verify payload is reflected unencoded
            if payload in resp.text and payload not in baseline:
                findings.append(Finding(
                    vuln_type="Reflected XSS",
                    severity=Severity.HIGH,
                    url=endpoint.url,
                    method="GET",
                    parameter=param,
                    payload=payload,
                    evidence=_extract_context(resp.text, payload),
                    description=f"Reflected XSS in GET parameter '{param}'. "
                                "User-supplied input is returned unencoded in the response.",
                    remediation="HTML-encode all output. Use Content-Security-Policy header. "
                                "Validate and sanitize input server-side.",
                    cvss_score=7.4,
                    confidence="high",
                    poc=f"curl '{test_url}'",
                ))
                break  # one confirmed finding per param is enough

    # Test form inputs
    for form in endpoint.forms:
        form_baseline = ""
        form_resp = client.get(form["action"])
        if form_resp:
            form_baseline = form_resp.text

        for inp in form.get("inputs", []):
            if inp.get("type") in ("submit", "hidden", "button"):
                continue
            name = inp["name"]
            for payload in XSS_PAYLOADS:
                data = {i["name"]: i["value"] for i in form["inputs"]}
                data[name] = payload

                if form["method"] == "POST":
                    resp = client.post(form["action"], data=data)
                else:
                    resp = client.get(form["action"], params=data)

                if resp is None:
                    continue
                if payload in resp.text and payload not in form_baseline:
                    findings.append(Finding(
                        vuln_type="Reflected XSS",
                        severity=Severity.HIGH,
                        url=form["action"],
                        method=form["method"],
                        parameter=name,
                        payload=payload,
                        evidence=_extract_context(resp.text, payload),
                        description=f"Reflected XSS in form field '{name}' "
                                    f"({form['method']} {form['action']}).",
                        remediation="HTML-encode all output. Use Content-Security-Policy. "
                                    "Validate input server-side.",
                        cvss_score=7.4,
                        confidence="high",
                        poc=f"Submit form at {form['action']} with {name}={payload}",
                    ))
                    break
    return findings


def _stored_xss(endpoint: Endpoint, client: HttpClient) -> List[Finding]:
    """
    Submit a unique marker via each form input, then re-fetch the page
    to check if it appears unencoded (stored XSS).
    """
    findings = []
    import uuid

    for form in endpoint.forms:
        if form["method"] != "POST":
            continue
        for inp in form.get("inputs", []):
            if inp.get("type") in ("submit", "hidden", "button", "password"):
                continue
            name = inp["name"]
            marker = f'{STORED_XSS_MARKER}{uuid.uuid4().hex[:8]}'
            payload = f'<script>/*{marker}*/</script>'

            data = {i["name"]: i["value"] for i in form["inputs"]}
            data[name] = payload

            submit_resp = client.post(form["action"], data=data)
            if submit_resp is None:
                continue

            # Re-fetch to check persistence
            check_resp = client.get(endpoint.url)
            if check_resp is None:
                continue

            if marker in check_resp.text:
                findings.append(Finding(
                    vuln_type="Stored XSS",
                    severity=Severity.CRITICAL,
                    url=form["action"],
                    method="POST",
                    parameter=name,
                    payload=payload,
                    evidence=_extract_context(check_resp.text, marker),
                    description=f"Stored XSS in form field '{name}'. "
                                "The payload is persisted and returned to other users.",
                    remediation="HTML-encode stored content on output. "
                                "Never trust stored user input. Use a Content-Security-Policy.",
                    cvss_score=9.0,
                    confidence="high",
                    false_positive_risk="low",
                    poc=f"POST to {form['action']} with {name}={payload}, "
                        f"then visit {endpoint.url}",
                ))
    return findings


def _extract_context(html: str, marker: str, window: int = 200) -> str:
    idx = html.find(marker)
    if idx == -1:
        return ""
    return html[max(0, idx - 80):idx + window]