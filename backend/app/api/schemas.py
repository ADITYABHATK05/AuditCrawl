from __future__ import annotations

from pydantic import BaseModel, Field, HttpUrl
from typing import Literal, Optional


class ScanRequest(BaseModel):
    target_url: HttpUrl
    scan_level: Literal["1", "2", "3"] = "2"
    use_selenium: bool = False
    # Keep this as a plain string to avoid hard dependency on `email-validator`.
    # Basic validation is enforced by a regex (good enough for UI + SMTP usage).
    email: Optional[str] = Field(
        default=None,
        pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        description="Optional email to receive a scan summary report",
    )
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


class LeakedAssetOut(BaseModel):
    id: int
    asset_type: str
    value: str
    severity: str
    endpoint: str


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
    leaked_assets: list[LeakedAssetOut] = []
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


class RepoScanRequest(BaseModel):
    github_url: str = Field(..., description="Public GitHub repository URL (e.g. https://github.com/owner/repo)")


class RepoLeakedAssetOut(BaseModel):
    asset_type: str
    value: str
    severity: str
    endpoint: str


class RepoScanResponse(BaseModel):
    repo_url: str
    status: Literal["completed"]
    findings_count: int
    findings: list[FindingOut]
    leaked_assets: list[RepoLeakedAssetOut] = []
