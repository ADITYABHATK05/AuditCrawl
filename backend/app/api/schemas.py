from __future__ import annotations

from pydantic import BaseModel, Field, HttpUrl
from typing import Literal, Optional


class ScanRequest(BaseModel):
    target_url: HttpUrl
    scan_level: Literal["1", "2", "3"] = "2"
    use_selenium: bool = False
    # Authentication fields
    login_url: Optional[str] = None  # URL to perform login
    username: Optional[str] = None  # Username for authentication
    password: Optional[str] = None  # Password for authentication
    auth_method: Optional[Literal["form", "basic", "bearer", "custom"]] = None  # Authentication method
    auth_headers: Optional[dict[str, str]] = None  # Custom headers for auth (e.g., {"Authorization": "Bearer token"})
    cookies: Optional[dict[str, str]] = None  # Pre-populated cookies for session


class BatchScanTarget(BaseModel):
    """Individual target in a batch scan."""
    url: str
    scan_level: Literal["1", "2", "3"] = "2"
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    auth_method: Optional[Literal["form", "basic", "bearer", "custom"]] = None
    tags: Optional[list[str]] = None


class BatchScanRequest(BaseModel):
    """Request for distributed batch scanning."""
    targets: list[BatchScanTarget]
    max_workers: int = 3  # Number of parallel workers


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
