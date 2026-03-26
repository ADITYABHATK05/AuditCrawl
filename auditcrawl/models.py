from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_SCORE = {
    Severity.CRITICAL: 9.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 3.0,
    Severity.INFO: 1.0,
}


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    depth: int = 0
    content_type: str = ""
    status_code: int = 0

    def __hash__(self):
        return hash((self.url, self.method))

    def __eq__(self, other):
        return self.url == other.url and self.method == other.method


@dataclass
class Finding:
    vuln_type: str
    severity: Severity
    url: str
    method: str
    parameter: str
    payload: str
    evidence: str
    description: str
    remediation: str
    cvss_score: float = 0.0
    confidence: str = "medium"   # low | medium | high
    false_positive_risk: str = "low"
    poc: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_type": self.vuln_type,
            "severity": self.severity.value,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence[:500],
            "description": self.description,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "confidence": self.confidence,
            "false_positive_risk": self.false_positive_risk,
            "poc": self.poc,
        }


@dataclass
class ScanResult:
    endpoints: List[Endpoint] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    findings_json_path: str = ""
    report_html_path: str = ""
    report_markdown_path: str = ""
    scan_log_path: str = ""
    duration_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)

    def summary_by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts