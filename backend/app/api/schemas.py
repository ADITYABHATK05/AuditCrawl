from __future__ import annotations

from pydantic import BaseModel, Field, HttpUrl
from typing import Literal


class ScanRequest(BaseModel):
    target_url: HttpUrl
    scan_level: Literal["1", "2", "3"] = "2"
    use_selenium: bool = False


class FindingOut(BaseModel):
    vulnerability_type: str
    severity: str
    endpoint: str
    evidence: str
    vulnerable_snippet: str
    fix_snippet: str


class ScanResponse(BaseModel):
    run_id: int
    target_url: str
    scan_level: str
    findings_count: int
    findings: list[FindingOut]
    json_path: str
    xml_path: str


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
