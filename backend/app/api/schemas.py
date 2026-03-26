from __future__ import annotations

from pydantic import BaseModel, Field, HttpUrl
from typing import Literal


class ScanRequest(BaseModel):
    target_url: HttpUrl
    scan_level: Literal["1", "2", "3"] = "2"
    use_selenium: bool = False


class FindingOut(BaseModel):
    type: str  # vulnerability_type
    severity: str
    url: str  # endpoint
    evidence: str
    param: str = ""  # parameter name if applicable
    description: str = ""  # detailed description
    poc: str = ""  # proof of concept
    vulnerable_snippet: str
    fix_snippet: str


class ScanResponse(BaseModel):
    run_id: int
    target_url: str
    base_url: str = ""  # same as target_url
    target_domain: str = ""  # domain extracted from target_url
    scan_level: str
    status: str = "completed"
    findings_count: int
    endpoints_count: int = 0
    findings: list[FindingOut]
    pdf_path: str


class ScanEnqueueResponse(BaseModel):
    job_id: str
    status: str
    progress: int
    message: str


class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    progress: int
    message: str
    run_id: int | None = None
    error: str | None = None
    result: ScanResponse | None = None
