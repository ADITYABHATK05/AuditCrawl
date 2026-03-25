from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ScanConfig:
    base_url: str
    target_domain: str
    allowed_subdomains: bool = False
    max_depth: int = 4
    max_pages: int = 500
    timeout_seconds: int = 12
    delay_seconds: float = 0.4
    user_agent: str = "AuditCrawl/0.1 (educational scanner)"
    ignore_paths: List[str] = field(default_factory=list)
    respect_robots_txt: bool = True
    safe_mode: bool = True
    enable_xss: bool = True
    enable_sqli: bool = True
    enable_ssrf: bool = True
    enable_auth: bool = True
    enable_rce: bool = True
    enable_time_based_sqli: bool = False
    lab_mode: bool = False
    output_dir: str = "."
    auth_login_url: Optional[str] = None
    auth_logout_url: Optional[str] = None
    auth_protected_keywords: List[str] = field(
        default_factory=lambda: ["admin", "dashboard", "profile", "account", "settings"]
    )

    def validate(self) -> None:
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must start with http:// or https://")
        if not self.target_domain:
            raise ValueError("target_domain is required")
        if self.max_depth < 1:
            raise ValueError("max_depth must be >= 1")
        if self.max_pages < 1:
            raise ValueError("max_pages must be >= 1")
