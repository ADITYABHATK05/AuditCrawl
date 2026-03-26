from __future__ import annotations
import logging
import re
from typing import List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ..http_client import HttpClient
from ..models import Endpoint, Finding, Severity

logger = logging.getLogger("auditcrawl.idor")

# Parameter names typically used for object IDs
ID_PARAM_PATTERN = re.compile(
    r"^(id|user_?id|account_?id|order_?id|item_?id|doc_?id|file_?id|"
    r"record_?id|profile_?id|invoice_?id|message_?id|post_?id|"
    r"customer_?id|employee_?id|product_?id|num|no|ref|uid|pid|"
    r"uuid|guid|oid|nid|tid)$",
    re.IGNORECASE,
)

# Numeric ID probe strategy: try original, original+1, original-1, 0, 1, 9999
def _neighboring_ids(val: str) -> List[str]:
    try:
        n = int(val)
        return [str(n + 1), str(n - 1), str(n + 100), "1", "0"]
    except ValueError:
        pass
    # UUIDs / slugs — try swapping last character
    if len(val) > 4:
        return [val[:-1] + "1", val[:-1] + "2", val[:-1] + "9"]
    return []


def scan(endpoint: Endpoint, client: HttpClient, lab_mode: bool = False) -> List[Finding]:
    findings = []
    parsed = urlparse(endpoint.url)
    params = {k: v[0] if isinstance(v, list) else v
              for k, v in parse_qs(parsed.query).items()}

    for param, value in params.items():
        if not ID_PARAM_PATTERN.match(param):
            continue
        if not value:
            continue

        baseline_resp = client.get(endpoint.url)
        if baseline_resp is None or baseline_resp.status_code in (401, 403, 404):
            continue
        baseline_text = baseline_resp.text
        baseline_len = len(baseline_text)

        for alt_id in _neighboring_ids(value):
            if alt_id == value:
                continue
            new_params = dict(params)
            new_params[param] = alt_id
            test_url = urlunparse(parsed._replace(query=urlencode(new_params)))

            resp = client.get(test_url)
            if resp is None:
                continue

            # If response is 200 and contains different content with similar length
            # (indicating a different record, not an error page)
            if (resp.status_code == 200
                    and baseline_resp.status_code == 200
                    and _significant_difference(baseline_text, resp.text)
                    and _looks_like_data_not_error(resp.text)):

                findings.append(Finding(
                    vuln_type="IDOR (Insecure Direct Object Reference)",
                    severity=Severity.HIGH,
                    url=endpoint.url,
                    method="GET",
                    parameter=param,
                    payload=alt_id,
                    evidence=f"Original ID {value} → response length {baseline_len}. "
                             f"Modified to {alt_id} → response length {len(resp.text)}, "
                             f"status {resp.status_code}. Different data returned.",
                    description=f"Potential IDOR in parameter '{param}'. "
                                f"Changing the object ID from '{value}' to '{alt_id}' "
                                "returned a successful response with different content, "
                                "suggesting access to other users' data.",
                    remediation="Implement object-level authorization checks for every "
                                "data retrieval. Verify the authenticated user owns/has "
                                "access to the requested object. Consider using "
                                "unpredictable UUIDs instead of sequential IDs.",
                    cvss_score=7.5,
                    confidence="medium",
                    false_positive_risk="medium",
                    poc=f"GET {test_url}",
                ))
                break  # One finding per parameter

    return findings


def _significant_difference(a: str, b: str) -> bool:
    """True if the two responses are materially different."""
    if not a or not b:
        return False
    # Different length is suspicious
    ratio = abs(len(a) - len(b)) / max(len(a), len(b), 1)
    return ratio > 0.05  # 5% difference threshold


def _looks_like_data_not_error(text: str) -> bool:
    """Heuristic: not a generic 404/403/500 page."""
    error_keywords = [
        "not found", "page not found", "404", "forbidden", "403",
        "access denied", "unauthorized", "500", "internal server error",
        "error", "invalid", "does not exist",
    ]
    lower = text.lower()
    error_count = sum(1 for kw in error_keywords if kw in lower)
    return error_count < 2