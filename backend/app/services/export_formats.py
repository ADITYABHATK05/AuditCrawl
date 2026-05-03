"""Export findings in standard security tool formats (Burp, ZAP)."""

from __future__ import annotations
import json
from datetime import datetime
from typing import Any


def export_to_burp_json(findings: list[dict], target_url: str, scan_name: str = "AuditCrawl Scan") -> str:
    """
    Export findings in Burp Suite JSON format.
    Burp Enterprise format: issues array with specific field structure.
    """
    burp_issues = []
    severity_to_confidence = {
        "Critical": {"severity": "high", "confidence": "certain"},
        "High": {"severity": "high", "confidence": "firm"},
        "Medium": {"severity": "medium", "confidence": "firm"},
        "Low": {"severity": "low", "confidence": "tentative"},
    }

    for idx, finding in enumerate(findings):
        severity = finding.get("severity", "Low")
        severity_map = severity_to_confidence.get(severity, {"severity": "info", "confidence": "tentative"})

        # Burp issue item
        issue = {
            "type": 0,  # User-defined issue type
            "name": finding.get("vulnerability_type", "Unknown Vulnerability"),
            "detail": finding.get("evidence", ""),
            "background": finding.get("fix_snippet", "No remediation provided"),
            "remediation": finding.get("fix_snippet", ""),
            "remediationBackground": finding.get("fix_snippet", ""),
            "severity": severity_map["severity"],
            "confidence": severity_map["confidence"],
            "issueBackground": f"Vulnerability Type: {finding.get('vulnerability_type', 'Unknown')}",
            "vulnerabilityClassifications": ["PCI DSS sensitive data exposure", "CWE-79"],
            "httpService": {
                "host": target_url.split("://")[-1].split("/")[0],
                "port": 443 if "https" in target_url else 80,
                "protocol": "https" if "https" in target_url else "http",
            },
            "httpMessages": [
                {
                    "request": {
                        "method": "GET",
                        "url": finding.get("endpoint", target_url),
                        "httpVersion": "HTTP/1.1",
                        "headers": [],
                        "body": "",
                    },
                    "response": {
                        "httpVersion": "HTTP/1.1",
                        "statusCode": 200,
                        "reasonPhrase": "OK",
                        "headers": [],
                        "body": finding.get("vulnerable_snippet", ""),
                    },
                    "note": finding.get("evidence", ""),
                }
            ],
        }
        burp_issues.append(issue)

    burp_report = {
        "burpVersion": "2024.1.1",
        "exportTime": datetime.utcnow().isoformat() + "Z",
        "issues": burp_issues,
    }

    return burp_report


def export_to_zap_json(findings: list[dict], target_url: str, scan_name: str = "AuditCrawl Scan") -> str:
    """
    Export findings in OWASP ZAP JSON format.
    ZAP JSON includes summary stats and alert details.
    """
    severity_to_riskcode = {
        "Critical": 3,
        "High": 2,
        "Medium": 1,
        "Low": 0,
    }
    confidence_map = {
        "Critical": 3,
        "High": 3,
        "Medium": 2,
        "Low": 1,
    }

    alerts = []
    for idx, finding in enumerate(findings):
        severity = finding.get("severity", "Low")
        risk_code = severity_to_riskcode.get(severity, 0)
        confidence = confidence_map.get(severity, 1)

        alert = {
            "pluginId": 1000 + idx,  # Custom plugin ID
            "alertRef": f"{1000+idx}",
            "alert": finding.get("vulnerability_type", "Unknown Vulnerability"),
            "name": finding.get("vulnerability_type", "Unknown Vulnerability"),
            "riskcode": str(risk_code),
            "confidence": str(confidence),
            "riskdesc": f"{['Low', 'Medium', 'High', 'Critical'][risk_code]} risk",
            "desc": finding.get("evidence", ""),
            "instances": [
                {
                    "uri": finding.get("endpoint", target_url),
                    "method": "GET",
                    "param": "",
                    "attack": "",
                    "evidence": finding.get("vulnerable_snippet", ""),
                    "description": finding.get("evidence", ""),
                }
            ],
            "count": 1,
            "solution": finding.get("fix_snippet", ""),
            "otherinfo": "",
            "reference": "",
            "cweid": "0",
            "wascid": "0",
            "sourceid": "1",
        }
        alerts.append(alert)

    # Statistics
    risk_stats = {"0": 0, "1": 0, "2": 0, "3": 0}
    for finding in findings:
        severity = finding.get("severity", "Low")
        risk_code = severity_to_riskcode.get(severity, 0)
        risk_stats[str(risk_code)] += 1

    zap_report = {
        "@version": "2.12.0",
        "@generated": datetime.utcnow().isoformat() + "Z",
        "site": [
            {
                "host": target_url.split("://")[-1].split("/")[0],
                "name": target_url,
                "port": 443 if "https" in target_url else 80,
                "ssl": "https" in target_url,
                "@name": target_url,
                "@host": target_url.split("://")[-1].split("/")[0],
                "@port": 443 if "https" in target_url else 80,
                "@basehref": target_url,
                "alerts": alerts,
                "stats": {
                    "high": risk_stats["2"] + risk_stats["3"],
                    "medium": risk_stats["1"],
                    "low": risk_stats["0"],
                    "informational": 0,
                },
            }
        ],
    }

    return zap_report


def export_to_sarif(findings: list[dict], target_url: str, scan_name: str = "AuditCrawl Scan") -> str:
    """
    Export findings in SARIF (Static Analysis Results Interchange Format).
    SARIF is an open, vendor-neutral format for tool outputs.
    """
    severity_to_level = {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "note",
    }

    results = []
    for idx, finding in enumerate(findings):
        severity = finding.get("severity", "Low")
        level = severity_to_level.get(severity, "note")

        result = {
            "ruleId": f"AUDITCRAWL-{idx+1:04d}",
            "ruleIndex": idx,
            "level": level,
            "message": {
                "text": finding.get("evidence", "A vulnerability was detected"),
                "markdown": f"**{finding.get('vulnerability_type', 'Unknown')}**\n\n{finding.get('evidence', '')}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "address": {"relativeUrl": finding.get("endpoint", target_url).replace(target_url, "")},
                        "region": {"startLine": 1},
                    }
                }
            ],
            "fix": {"artifactChanges": [{"replacement": {"text": finding.get("fix_snippet", "")}}]},
            "properties": {
                "vulnerability_type": finding.get("vulnerability_type", ""),
                "severity": finding.get("severity", ""),
                "endpoint": finding.get("endpoint", ""),
            },
        }
        results.append(result)

    sarif_report = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AuditCrawl",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/aditya-sec/AuditCrawl",
                        "rules": [
                            {
                                "id": f"AUDITCRAWL-{idx+1:04d}",
                                "name": f.get("vulnerability_type", "Unknown"),
                                "shortDescription": {"text": f.get("evidence", "")},
                                "help": {"text": f.get("fix_snippet", "")},
                            }
                            for idx, f in enumerate(findings)
                        ],
                    }
                },
                "results": results,
            }
        ],
    }

    return sarif_report
