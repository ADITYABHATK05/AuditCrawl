from __future__ import annotations
import asyncio
import logging
import re
from typing import List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ..http_client import HttpClient
from ..models import Endpoint, Finding, Severity

logger = logging.getLogger("auditcrawl.open_redirect")

REDIRECT_PARAM_PATTERN = re.compile(
    r"^(redirect|return|next|goto|url|continue|forward|dest|"
    r"destination|redir|redirect_uri|redirect_url|return_url|"
    r"back|callback|target|to|location|ref|source|r|u)$",
    re.IGNORECASE,
)

REDIRECT_PAYLOADS = [
    "https://evil.example.com",
    "//evil.example.com",
    "/\\evil.example.com",
    "https:evil.example.com",
    "https://evil.example.com%2F@legitimate.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]


def scan(endpoint: Endpoint, client: HttpClient, lab_mode: bool = False) -> List[Finding]:
    return asyncio.run(scan_async(endpoint, client, lab_mode))


async def scan_async(endpoint: Endpoint, client: HttpClient, lab_mode: bool = False) -> List[Finding]:
    findings = []
    parsed = urlparse(endpoint.url)
    params = {k: v[0] if isinstance(v, list) else v
              for k, v in parse_qs(parsed.query).items()}

    redirect_params = [p for p in params if REDIRECT_PARAM_PATTERN.match(p)]
    if not redirect_params:
        return findings

    for param in redirect_params:
        for payload in REDIRECT_PAYLOADS:
            new_params = dict(params)
            new_params[param] = payload
            test_url = urlunparse(parsed._replace(query=urlencode(new_params)))

            resp = await client.get_async(test_url, allow_redirects=False)
            if resp is None:
                continue

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if "evil.example.com" in location or location == payload:
                    severity = Severity.HIGH if "javascript:" in payload else Severity.MEDIUM
                    findings.append(Finding(
                        vuln_type="Open Redirect",
                        severity=severity,
                        url=endpoint.url,
                        method="GET",
                        parameter=param,
                        payload=payload,
                        evidence=f"HTTP {resp.status_code} Location: {location}",
                        description=f"Open redirect via parameter '{param}'. "
                                    "An attacker can redirect users to a malicious site, "
                                    "enabling phishing or token theft.",
                        remediation="Validate redirect targets against a strict whitelist. "
                                    "Use relative paths instead of full URLs. "
                                    "Never pass user-controlled redirect destinations directly.",
                        cvss_score=6.1,
                        confidence="high",
                        false_positive_risk="low",
                        poc=f"GET {test_url}",
                    ))
                    break
    return findings