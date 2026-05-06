from __future__ import annotations
import asyncio
import logging
from typing import List

from ..http_client import HttpClient
from ..models import Endpoint, Finding, Severity

logger = logging.getLogger("auditcrawl.leaked_assets")


def scan(endpoint: Endpoint, client: HttpClient, lab_mode: bool = False) -> List[Finding]:
    return asyncio.run(scan_async(endpoint, client, lab_mode))


async def scan_async(endpoint: Endpoint, client: HttpClient, lab_mode: bool = False) -> List[Finding]:
    """Scan for leaked sensitive information in endpoint response."""
    findings: List[Finding] = []

    if not endpoint.response_text:
        return findings

    # Import here to avoid circular imports
    from ..leaked_asset_detector import LeakedAssetDetector

    leaked_assets = LeakedAssetDetector.detect_leaked_assets(endpoint.response_text, endpoint.url)

    for asset in leaked_assets:
        findings.append(Finding(
            vuln_type=f"Leaked {asset['type']}",
            severity=Severity(asset["severity"].lower()),
            url=asset["url"],
            method=endpoint.method,
            parameter=asset["value"],  # Store the actual leaked value here
            payload="",
            evidence=f"Potentially leaked {asset['type']}: {asset['value'][:100]}{'...' if len(asset['value']) > 100 else ''}",
            description=f"Detected potentially leaked {asset['type']} in response body",
            remediation=f"Remove exposed {asset['type'].lower()} from public pages. Store sensitive data securely and never expose in client-side code or responses."
        ))

    return findings