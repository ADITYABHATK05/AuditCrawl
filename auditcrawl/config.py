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
    output_dir: str = "output"
    ignore_paths: List[str] = field(default_factory=list)
    safe_mode: bool = True
    lab_mode: bool = False

    # modules
    enable_xss: bool = True
    enable_sqli: bool = True
    enable_ssrf: bool = True
    enable_auth: bool = True
    enable_rce: bool = True
    enable_idor: bool = True
    enable_csrf: bool = True
    enable_headers: bool = True
    enable_open_redirect: bool = True
    enable_time_based_sqli: bool = False

    # auth
    auth_login_url: Optional[str] = None
    auth_logout_url: Optional[str] = None
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    auth_username_field: str = "username"
    auth_password_field: str = "password"

    # alerts
    webhook_url: Optional[str] = None

    # rate limiting
    request_delay: float = 0.1
    max_concurrent: int = 5
    request_timeout: int = 10

    # canary for SSRF (use a safe OOB domain you control or a local listener)
    ssrf_canary_url: str = "http://169.254.169.254/latest/meta-data/"