from __future__ import annotations
import logging
import re
from typing import List
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from ..http_client import HttpClient
from ..models import Endpoint, Finding, Severity

logger = logging.getLogger("auditcrawl.ssrf")

# SSRF probe targets — internal services likely to give distinctive responses
SSRF_PROBES = [
    # AWS metadata
    ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "hostname"]),
    ("http://169.254.169.254/latest/user-data", ["#!/bin", "cloud-init", "MIME"]),
    # GCP metadata
    ("http://metadata.google.internal/computeMetadata/v1/", ["404", "instance"]),
    # Azure metadata
    ("http://169.254.169.254/metadata/v1/", ["subscriptionId", "resourceGroupName"]),
    # localhost services
    ("http://localhost/", ["Apache", "nginx", "IIS", "Welcome"]),
    ("http://127.0.0.1/", ["Apache", "nginx", "IIS", "Welcome"]),
    ("http://127.0.0.1:8080/", ["Tomcat", "Jetty", "Spring"]),
    ("http://0.0.0.0/", ["Apache", "nginx"]),
    ("http://[::1]/", ["Apache", "nginx"]),
    # Internal network ranges
    ("http://10.0.0.1/", ["Router", "Admin", "Login"]),
    ("http://192.168.1.1/", ["Router", "Admin", "Login"]),
]

# Parameters commonly used for URLs — high-value SSRF targets
URL_PARAM_NAMES = re.compile(
    r"(url|uri|href|src|redirect|return|next|goto|path|file|"
    r"load|fetch|callback|webhook|endpoint|host|resource|link|"
    r"image|img|page|view|include|dest|destination|target)",
    re.IGNORECASE,
)


def scan(endpoint: Endpoint, client: HttpClient, lab_mode: bool = False) -> List[Finding]:
    findings = []
    findings += _probe_ssrf(endpoint, client, lab_mode)
    return findings


def _probe_ssrf(endpoint: Endpoint, client: HttpClient, lab_mode: bool) -> List[Finding]:
    findings = []
    all_params = _collect_params(endpoint)

    for param_name, context_url, method, all_data, form in all_params:
        if not URL_PARAM_NAMES.search(param_name):
            continue  # Only test URL-like parameters to reduce noise

        for probe_url, indicators in SSRF_PROBES:
            data = dict(all_data)
            data[param_name] = probe_url

            if method == "POST":
                resp = client.post(context_url, data=data)
            else:
                parsed = urlparse(context_url)
                new_q = urlencode(data)
                test_url = urlunparse(parsed._replace(query=new_q))
                resp = client.get(test_url)

            if resp is None:
                continue

            matched = [ind for ind in indicators if ind.lower() in resp.text.lower()]
            if matched:
                severity = Severity.CRITICAL if "169.254" in probe_url or "metadata" in probe_url else Severity.HIGH
                findings.append(Finding(
                    vuln_type="SSRF (Server-Side Request Forgery)",
                    severity=severity,
                    url=context_url,
                    method=method,
                    parameter=param_name,
                    payload=probe_url,
                    evidence=f"Response contained indicators: {matched}. "
                             + _extract_context(resp.text, matched[0]),
                    description=f"SSRF confirmed in parameter '{param_name}'. "
                                f"The server made a request to {probe_url} and returned "
                                f"internal content. This can expose cloud metadata, "
                                "internal services, and sensitive credentials.",
                    remediation="Validate and whitelist allowed URLs. "
                                "Block requests to internal IP ranges (169.254.x.x, 10.x, 172.16-31.x, 192.168.x). "
                                "Use a network-level egress firewall. "
                                "Never pass user-controlled URLs to server-side HTTP clients.",
                    cvss_score=9.8 if severity == Severity.CRITICAL else 8.6,
                    confidence="high",
                    false_positive_risk="low",
                    poc=f"{method} {context_url} with {param_name}={probe_url}",
                ))
                break  # One confirmed finding per parameter

    return findings


def _collect_params(endpoint: Endpoint):
    """Yield (param_name, url, method, all_params_dict, form_or_None)."""
    parsed = urlparse(endpoint.url)
    url_params = {k: v[0] if isinstance(v, list) else v
                  for k, v in parse_qs(parsed.query).items()}

    for name in url_params:
        yield name, endpoint.url, "GET", url_params, None

    for form in endpoint.forms:
        data = {i["name"]: i["value"] for i in form.get("inputs", [])}
        for inp in form.get("inputs", []):
            if inp.get("type") in ("submit", "button"):
                continue
            yield inp["name"], form["action"], form["method"], data, form


def _extract_context(text: str, marker: str, window: int = 200) -> str:
    idx = text.lower().find(marker.lower())
    if idx == -1:
        return text[:200]
    return text[max(0, idx - 50):idx + window]