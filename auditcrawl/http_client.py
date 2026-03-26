from __future__ import annotations
import time
import logging
from typing import Any, Dict, Optional
from urllib.parse import urljoin, urlparse

import requests
from requests import Session, Response
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import ScanConfig

logger = logging.getLogger("auditcrawl.http")


class HttpClient:
    """Thread-safe HTTP client with rate-limiting, session management, and helpers."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._session = self._build_session()
        self._last_request_time: float = 0.0
        self.is_authenticated = False

    def _build_session(self) -> Session:
        s = Session()
        s.headers.update({
            "User-Agent": "AuditCrawl/1.0 (educational scanner; not for production)",
            "Accept": "text/html,application/xhtml+xml,application/json,*/*",
            "Accept-Language": "en-US,en;q=0.9",
        })
        retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        return s

    def _rate_limit(self) -> None:
        elapsed = time.time() - self._last_request_time
        if elapsed < self.config.request_delay:
            time.sleep(self.config.request_delay - elapsed)
        self._last_request_time = time.time()

    def get(self, url: str, **kwargs) -> Optional[Response]:
        return self._request("GET", url, **kwargs)

    def post(self, url: str, data: Optional[Dict] = None, **kwargs) -> Optional[Response]:
        return self._request("POST", url, data=data, **kwargs)

    def _request(self, method: str, url: str, **kwargs) -> Optional[Response]:
        self._rate_limit()
        kwargs.setdefault("timeout", self.config.request_timeout)
        kwargs.setdefault("allow_redirects", True)
        kwargs.setdefault("verify", False)
        try:
            resp = self._session.request(method, url, **kwargs)
            return resp
        except requests.exceptions.Timeout:
            logger.debug("Timeout: %s %s", method, url)
        except requests.exceptions.ConnectionError:
            logger.debug("ConnectionError: %s %s", method, url)
        except Exception as exc:
            logger.debug("Request error %s %s: %s", method, url, exc)
        return None

    def login(self) -> bool:
        """Perform form-based login if configured."""
        cfg = self.config
        if not cfg.auth_login_url or not cfg.auth_username:
            return False
        data = {
            cfg.auth_username_field: cfg.auth_username,
            cfg.auth_password_field: cfg.auth_password or "",
        }
        resp = self.post(cfg.auth_login_url, data=data, allow_redirects=True)
        if resp and resp.status_code in (200, 302):
            self.is_authenticated = True
            logger.info("Login succeeded (%s)", resp.status_code)
            return True
        logger.warning("Login failed")
        return False

    def is_in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        target = self.config.target_domain.lower()
        if self.config.allowed_subdomains:
            return domain == target or domain.endswith("." + target)
        return domain == target or domain == "www." + target

    def close(self) -> None:
        self._session.close()