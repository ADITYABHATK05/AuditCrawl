from __future__ import annotations

from typing import Dict, List

from .models import Finding

DISCLAIMER = "This POC is for educational use; do not run on real systems without permission."


class SafePoCGenerator:
    def generate(self, findings: List[Finding]) -> List[Dict[str, str]]:
        pocs: List[Dict[str, str]] = []
        for f in findings:
            steps = [
                "Use a test environment or authorized target only.",
                f"Send a {f.method} request to {f.endpoint}.",
                f"Set parameter '{f.parameter or 'N/A'}' to payload: {f.payload or '(see evidence)'}.",
                "Observe the behavior described in evidence.",
                DISCLAIMER,
            ]
            pocs.append(
                {
                    "vulnerability": f.vulnerability,
                    "endpoint": f.endpoint,
                    "method": f.method,
                    "payload": f.payload or "",
                    "reproduction_steps": "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps)),
                    "evidence": f.evidence,
                    "disclaimer": DISCLAIMER,
                }
            )
        return pocs
