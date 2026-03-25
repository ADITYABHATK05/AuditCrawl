from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    form_fields: List[str] = field(default_factory=list)
    form_action: Optional[str] = None
    depth: int = 0
    source_url: Optional[str] = None
    content_type: Optional[str] = None


@dataclass
class Finding:
    vulnerability: str
    risk: str
    endpoint: str
    method: str
    parameter: Optional[str]
    evidence: str
    payload: Optional[str] = None
    remediation: Optional[str] = None
    confidence: str = "medium"
    module: Optional[str] = None

    def to_dict(self) -> Dict[str, str]:
        return {
            "vulnerability": self.vulnerability,
            "risk": self.risk,
            "endpoint": self.endpoint,
            "method": self.method,
            "parameter": self.parameter or "",
            "evidence": self.evidence,
            "payload": self.payload or "",
            "remediation": self.remediation or "",
            "confidence": self.confidence,
            "module": self.module or "",
        }
