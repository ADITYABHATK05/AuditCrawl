from __future__ import annotations
import asyncio
import logging
import re
from typing import List

from ..http_client import HttpClient
from ..models import Endpoint, Finding, Severity

logger = logging.getLogger("auditcrawl.csrf")

# Common CSRF token field name patterns
CSRF_TOKEN_PATTERNS = re.compile(
    r"(csrf|xsrf|_token|authenticity_token|__requestverificationtoken|"
    r"nonce|anti.?forgery|csrfmiddlewaretoken|_wpnonce)",
    re.IGNORECASE,
)

# Patterns in meta tags
CSRF_META_PATTERNS = re.compile(
    r'<meta[^>]+(csrf|xsrf)[^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


def scan(endpoint: Endpoint, client: HttpClient, lab_mode: bool = False) -> List[Finding]:
    return asyncio.run(scan_async(endpoint, client, lab_mode))


async def scan_async(endpoint: Endpoint, client: HttpClient, lab_mode: bool = False) -> List[Finding]:
    findings = []
    for form in endpoint.forms:
        if form["method"] != "POST":
            continue
        finding = await _check_form_csrf(endpoint, form, client)
        if finding:
            findings.append(finding)
    return findings


async def _check_form_csrf(endpoint: Endpoint, form: dict, client: HttpClient) -> Finding | None:
    inputs = form.get("inputs", [])
    input_names = [i["name"] for i in inputs]

    # Check if any input looks like a CSRF token
    has_token_field = any(CSRF_TOKEN_PATTERNS.search(name) for name in input_names)

    # Also check the page source for CSRF meta tags
    resp = await client.get_async(endpoint.url)
    has_meta_token = False
    if resp:
        has_meta_token = bool(CSRF_META_PATTERNS.search(resp.text))

    if has_token_field or has_meta_token:
        # CSRF protection present — now check if it's actually enforced
        finding = await _verify_token_enforcement(endpoint, form, client)
        return finding  # returns None if enforced, Finding if bypassable

    # No token found at all — missing CSRF protection
    return Finding(
        vuln_type="CSRF (Missing Token)",
        severity=Severity.HIGH,
        url=form["action"],
        method="POST",
        parameter="(form)",
        payload="(no CSRF token present)",
        evidence=f"Form at {form['action']} has no CSRF token. "
                 f"Fields: {', '.join(input_names[:10])}",
        description=f"The POST form at '{form['action']}' has no CSRF token. "
                    "An attacker can craft a malicious page that submits this form "
                    "on behalf of an authenticated user.",
        remediation="Add a per-session, per-form CSRF token to all state-changing forms. "
                    "Validate the token server-side on every POST. "
                    "Use the SameSite=Strict or SameSite=Lax cookie attribute.",
        cvss_score=6.5,
        confidence="high",
        false_positive_risk="low",
        poc=f'<form method="POST" action="{form["action"]}">'
            + "".join(f'<input name="{i["name"]}" value="{i["value"]}">'
                      for i in inputs if i.get("type") != "submit")
            + '<input type="submit"></form>',
    )


async def _verify_token_enforcement(endpoint: Endpoint, form: dict, client: HttpClient) -> Finding | None:
    """
    Try submitting the form without the CSRF token (or with a tampered token).
    If it succeeds (200/302 and similar response body), the token is not enforced.
    """
    inputs = form.get("inputs", [])
    data_with_token = {i["name"]: i["value"] for i in inputs}

    # Submit with token for baseline
    baseline = await client.post_async(form["action"], data=data_with_token)
    if baseline is None:
        return None

    # Remove CSRF token fields and try again
    data_without_token = {
        k: v for k, v in data_with_token.items()
        if not CSRF_TOKEN_PATTERNS.search(k)
    }
    if data_without_token == data_with_token:
        return None  # No token was present to remove

    tampered = await client.post_async(form["action"], data=data_without_token)
    if tampered is None:
        return None

    # If both return 200 and similar content — token not enforced
    if (tampered.status_code in (200, 302)
            and baseline.status_code in (200, 302)
            and _similarity(baseline.text, tampered.text) > 0.7):
        return Finding(
            vuln_type="CSRF (Token Not Enforced)",
            severity=Severity.HIGH,
            url=form["action"],
            method="POST",
            parameter="csrf_token",
            payload="(token omitted)",
            evidence=f"Form submitted without CSRF token: HTTP {tampered.status_code}. "
                     "Response was similar to the legitimate submission.",
            description=f"The CSRF token in the form at '{form['action']}' is not properly validated. "
                        "Submitting the form without the token succeeds, making it vulnerable to CSRF.",
            remediation="Validate the CSRF token on every POST request server-side. "
                        "Reject requests with missing or invalid tokens with HTTP 403.",
            cvss_score=6.5,
            confidence="medium",
            false_positive_risk="medium",
            poc=f"POST to {form['action']} without CSRF token — receives {tampered.status_code}",
        )
    return None


def _similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    longer = max(len(a), len(b))
    shorter = min(len(a), len(b))
    return shorter / longer