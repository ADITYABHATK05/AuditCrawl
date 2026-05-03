from __future__ import annotations
import asyncio
import logging
import re
from typing import List
from urllib.parse import urlparse
import ipaddress

from ..http_client import HttpClient
from ..models import Endpoint, Finding, Severity

logger = logging.getLogger("auditcrawl.headers")


HEADER_CHECKS = [
    {
        "header": "Strict-Transport-Security",
        "missing_severity": Severity.MEDIUM,
        "description": "Missing HSTS header. The browser may connect over HTTP instead of HTTPS.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "cvss": 5.9,
        "check_value": None,
    },
    {
        "header": "X-Frame-Options",
        "missing_severity": Severity.MEDIUM,
        "description": "Missing X-Frame-Options header. The page can be embedded in an iframe, enabling clickjacking attacks.",
        "remediation": "Add: X-Frame-Options: DENY  (or SAMEORIGIN if framing is required)",
        "cvss": 6.5,
        "check_value": None,
    },
    {
        "header": "X-Content-Type-Options",
        "missing_severity": Severity.LOW,
        "description": "Missing X-Content-Type-Options header. Browsers may MIME-sniff responses, potentially executing malicious content.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
        "cvss": 4.3,
        "check_value": None,
    },
    {
        "header": "Content-Security-Policy",
        "missing_severity": Severity.MEDIUM,
        "description": "Missing Content-Security-Policy header. No CSP means no defence-in-depth against XSS.",
        "remediation": "Add a strict CSP: Content-Security-Policy: default-src 'self'; script-src 'self'",
        "cvss": 6.1,
        "check_value": None,
    },
    {
        "header": "Referrer-Policy",
        "missing_severity": Severity.LOW,
        "description": "Missing Referrer-Policy header. The full URL may be sent in the Referer header to third parties.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "cvss": 3.1,
        "check_value": None,
    },
    {
        "header": "Permissions-Policy",
        "missing_severity": Severity.LOW,
        "description": "Missing Permissions-Policy (Feature-Policy) header. Browser features are unrestricted.",
        "remediation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        "cvss": 3.1,
        "check_value": None,
    },
]

# Dangerous values in headers
DANGEROUS_CSP_PATTERNS = [
    (re.compile(r"'unsafe-inline'", re.I), "CSP contains 'unsafe-inline' which allows inline scripts (XSS risk)"),
    (re.compile(r"'unsafe-eval'", re.I), "CSP contains 'unsafe-eval' which allows eval() (XSS risk)"),
    (re.compile(r"\bdata:\b", re.I), "CSP allows data: URIs (XSS risk in some browsers)"),
    (re.compile(r"\*", re.I), "CSP uses wildcard (*) which undermines the policy"),
]


def scan(endpoint: Endpoint, client: HttpClient, lab_mode: bool = False) -> List[Finding]:
    return asyncio.run(scan_async(endpoint, client, lab_mode))


async def scan_async(endpoint: Endpoint, client: HttpClient, lab_mode: bool = False) -> List[Finding]:
    findings = []
    resp = await client.get_async(endpoint.url)
    if resp is None:
        return findings

    headers = {k.lower(): v for k, v in resp.headers.items()}
    findings += _check_missing_headers(endpoint.url, headers)
    findings += _check_header_values(endpoint.url, headers)
    findings += await _check_cors(endpoint.url, headers, client)
    findings += _check_csp_quality(endpoint.url, headers)
    findings += _check_server_disclosure(endpoint.url, headers)
    findings += _check_cookies(endpoint.url, resp)
    return findings


def _check_missing_headers(url: str, headers: dict) -> List[Finding]:
    findings = []
    for check in HEADER_CHECKS:
        hname = check["header"].lower()
        if hname not in headers:
            findings.append(Finding(
                vuln_type=f"Missing Security Header: {check['header']}",
                severity=check["missing_severity"],
                url=url,
                method="GET",
                parameter=check["header"],
                payload="(header absent)",
                evidence=f"Response does not include the {check['header']} header.",
                description=check["description"],
                remediation=check["remediation"],
                cvss_score=check["cvss"],
                confidence="high",
                false_positive_risk="low",
                poc=f"curl -I '{url}' | grep -i {check['header']}",
            ))
    return findings


def _check_header_values(url: str, headers: dict) -> List[Finding]:
    findings = []
    csp = headers.get("content-security-policy", "")
    if csp:
        csp_lower = csp.lower()
        for pattern, desc in DANGEROUS_CSP_PATTERNS:
            if pattern.search(csp):
                findings.append(Finding(
                    vuln_type="Weak Content-Security-Policy",
                    severity=Severity.LOW,
                    url=url,
                    method="GET",
                    parameter="Content-Security-Policy",
                    payload=pattern.pattern,
                    evidence=f"CSP: {csp[:300]}",
                    description=desc,
                    remediation="Review and tighten the CSP. Remove unsafe-inline and unsafe-eval. "
                                "Use nonces or hashes for inline scripts instead.",
                    cvss_score=4.3,
                    confidence="high",
                    false_positive_risk="low",
                    poc=f"curl -I '{url}' | grep -i content-security-policy",
                ))
                break
    xfo = headers.get("x-frame-options", "").strip().upper()
    if xfo and xfo not in {"DENY", "SAMEORIGIN"}:
        findings.append(Finding(
            vuln_type="Weak X-Frame-Options",
            severity=Severity.LOW,
            url=url,
            method="GET",
            parameter="X-Frame-Options",
            payload=xfo,
            evidence=f"Unexpected X-Frame-Options value: {xfo}",
            description="X-Frame-Options is present but not set to a safe value.",
            remediation="Set X-Frame-Options to DENY or SAMEORIGIN.",
            cvss_score=4.3,
            confidence="high",
            false_positive_risk="low",
            poc=f"curl -I '{url}' | grep -i x-frame-options",
        ))
    xcto = headers.get("x-content-type-options", "").strip().lower()
    if xcto and xcto != "nosniff":
        findings.append(Finding(
            vuln_type="Weak X-Content-Type-Options",
            severity=Severity.LOW,
            url=url,
            method="GET",
            parameter="X-Content-Type-Options",
            payload=xcto,
            evidence=f"Unexpected X-Content-Type-Options value: {xcto}",
            description="X-Content-Type-Options is present but not set to nosniff.",
            remediation="Set X-Content-Type-Options to nosniff.",
            cvss_score=4.3,
            confidence="high",
            false_positive_risk="low",
            poc=f"curl -I '{url}' | grep -i x-content-type-options",
        ))
    if url.startswith("https://"):
        hsts = headers.get("strict-transport-security", "")
        if hsts:
            hsts_lower = hsts.lower()
            max_age_match = re.search(r"max-age=(\d+)", hsts_lower)
            max_age = int(max_age_match.group(1)) if max_age_match else 0
            if max_age < 15552000:
                findings.append(Finding(
                    vuln_type="Weak HSTS Policy",
                    severity=Severity.LOW,
                    url=url,
                    method="GET",
                    parameter="Strict-Transport-Security",
                    payload=hsts,
                    evidence=f"HSTS max-age is too low or missing: {hsts}",
                    description="HSTS is present but the max-age value is too low to provide durable protection.",
                    remediation="Use a long HSTS max-age such as max-age=31536000 and includeSubDomains when appropriate.",
                    cvss_score=4.3,
                    confidence="high",
                    false_positive_risk="low",
                    poc=f"curl -I '{url}' | grep -i strict-transport-security",
                ))
    return findings


async def _check_cors(url: str, headers: dict, client: HttpClient) -> List[Finding]:
    findings = []
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")

    if acao == "*" and acac.lower() == "true":
        findings.append(Finding(
            vuln_type="Misconfigured CORS",
            severity=Severity.HIGH,
            url=url,
            method="GET",
            parameter="Access-Control-Allow-Origin",
            payload="Origin: https://evil.com",
            evidence=f"Access-Control-Allow-Origin: {acao}\n"
                     f"Access-Control-Allow-Credentials: {acac}",
            description="CORS is configured with a wildcard origin AND credentials allowed. "
                        "An attacker can make cross-origin authenticated requests from any domain.",
            remediation="Never combine Access-Control-Allow-Origin: * with "
                        "Access-Control-Allow-Credentials: true. "
                        "Whitelist specific trusted origins.",
            cvss_score=8.1,
            confidence="high",
            false_positive_risk="low",
            poc=f"fetch('{url}', {{credentials:'include',headers:{{Origin:'https://evil.com'}}}})",
        ))

    # Test for origin reflection
    test_resp = await client.get_async(url, headers={"Origin": "https://evil-audit-test.com"})
    if test_resp:
        reflected_acao = test_resp.headers.get("Access-Control-Allow-Origin", "")
        if reflected_acao == "https://evil-audit-test.com":
            findings.append(Finding(
                vuln_type="CORS Origin Reflection",
                severity=Severity.HIGH,
                url=url,
                method="GET",
                parameter="Access-Control-Allow-Origin",
                payload="Origin: https://evil-audit-test.com",
                evidence=f"Reflected origin in response: {reflected_acao}",
                description="The server reflects arbitrary Origin headers back in "
                            "Access-Control-Allow-Origin. Combined with credentials, "
                            "an attacker can steal authenticated data cross-origin.",
                remediation="Validate the Origin header against a strict whitelist. "
                            "Never reflect user-supplied Origin values.",
                cvss_score=8.1,
                confidence="high",
                false_positive_risk="low",
                poc=f"curl -H 'Origin: https://evil.com' '{url}'",
            ))
    return findings


def _check_csp_quality(url: str, headers: dict) -> List[Finding]:
    findings = []
    csp = headers.get("content-security-policy", "")
    if not csp:
        return findings
    for pattern, desc in DANGEROUS_CSP_PATTERNS:
        if pattern.search(csp):
            findings.append(Finding(
                vuln_type="Weak Content-Security-Policy",
                severity=Severity.LOW,
                url=url,
                method="GET",
                parameter="Content-Security-Policy",
                payload=pattern.pattern,
                evidence=f"CSP: {csp[:300]}",
                description=desc,
                remediation="Review and tighten the CSP. Remove unsafe-inline and unsafe-eval. "
                            "Use nonces or hashes for inline scripts instead.",
                cvss_score=4.3,
                confidence="high",
                false_positive_risk="low",
                poc=f"curl -I '{url}' | grep -i content-security-policy",
            ))
    return findings


def _check_server_disclosure(url: str, headers: dict) -> List[Finding]:
    # For localhost/private lab targets, "Server" disclosure is usually just the dev server
    # (Werkzeug/uvicorn/etc.) and is not a meaningful vulnerability signal. Keep this check
    # for real external targets.
    try:
        host = (urlparse(url).hostname or "").lower()
        if host in {"localhost", "127.0.0.1"}:
            return []
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback:
                return []
        except ValueError:
            # not an IP literal
            pass
    except Exception:
        # If parsing fails, fall back to reporting normally.
        pass

    findings = []
    for hdr in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        val = headers.get(hdr, "")
        if val:
            findings.append(Finding(
                vuln_type="Server Version Disclosure",
                severity=Severity.INFO,
                url=url,
                method="GET",
                parameter=hdr,
                payload="(read from response header)",
                evidence=f"{hdr}: {val}",
                description=f"The '{hdr}' header discloses server software and version information. "
                            "This aids attackers in fingerprinting the stack.",
                remediation=f"Remove or obscure the '{hdr}' header in your web server configuration.",
                cvss_score=2.0,
                confidence="high",
                false_positive_risk="low",
            ))
    return findings


def _check_cookies(url: str, resp) -> List[Finding]:
    findings = []
    for cookie in resp.cookies:
        issues = []
        if not cookie.secure:
            issues.append("missing Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append("missing HttpOnly flag")
        same_site = cookie._rest.get("SameSite", "").lower()
        if same_site not in ("strict", "lax"):
            issues.append(f"SameSite={same_site or 'not set'}")

        if issues:
            severity = Severity.MEDIUM if "missing Secure flag" in issues else Severity.LOW
            findings.append(Finding(
                vuln_type="Insecure Cookie Attributes",
                severity=severity,
                url=url,
                method="GET",
                parameter=f"Cookie: {cookie.name}",
                payload="(read from Set-Cookie header)",
                evidence=f"Cookie '{cookie.name}' issues: {', '.join(issues)}",
                description=f"The cookie '{cookie.name}' has insecure attributes: {', '.join(issues)}. "
                            "This can allow cookie theft or CSRF.",
                remediation="Set Secure, HttpOnly, and SameSite=Strict (or Lax) on all cookies. "
                            "Especially on session cookies.",
                cvss_score=5.9 if "missing Secure flag" in issues else 4.3,
                confidence="high",
                false_positive_risk="low",
            ))
    return findings