from __future__ import annotations
import asyncio
import time
import logging
from typing import Any, Dict, Optional
from urllib.parse import urljoin, urlparse

import aiohttp
import requests
from requests import Session, Response
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import ScanConfig

logger = logging.getLogger("auditcrawl.http")


class _AsyncResponse:
    def __init__(self, status_code: int, text: str, headers: Dict[str, str]) -> None:
        self.status_code = status_code
        self.text = text
        self.headers = headers


class HttpClient:
    """Thread-safe HTTP client with rate-limiting, session management, and helpers."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._session = self._build_session()
        self._async_session: aiohttp.ClientSession | None = None
        self._async_last_request_time: float = 0.0
        self._async_request_lock = asyncio.Lock()
        self._last_request_time: float = 0.0
        self.is_authenticated = False

    async def __aenter__(self) -> "HttpClient":
        await self._ensure_async_session()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close_async()

    def _build_session(self) -> Session:
        s = Session()
        s.headers.update({
            "User-Agent": "AuditCrawl/1.0 (educational scanner; not for production)",
            "Accept": "text/html,application/xhtml+xml,application/json,*/*",
            "Accept-Language": "en-US,en;q=0.9",
        })
        # Important: do not raise on HTTP 500 responses. For scanners, an application error page
        # can still contain useful evidence (stack traces, debug info, headers, etc.).
        # We retry on a subset of transient server errors but keep the final response.
        retry = Retry(
            total=2,
            backoff_factor=0.3,
            status_forcelist=[502, 503, 504],
            raise_on_status=False,
        )
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

    async def get_async(self, url: str, **kwargs) -> Optional[_AsyncResponse]:
        return await self._request_async("GET", url, **kwargs)

    async def post_async(self, url: str, data: Optional[Dict] = None, **kwargs) -> Optional[_AsyncResponse]:
        return await self._request_async("POST", url, data=data, **kwargs)

    def _request(self, method: str, url: str, **kwargs) -> Optional[Response]:
        self._rate_limit()
        kwargs.setdefault("timeout", self.config.request_timeout)
        kwargs.setdefault("allow_redirects", True)
        kwargs.setdefault("verify", False)
        try:
            resp = self._session.request(method, url, **kwargs)
            return resp
        except requests.exceptions.Timeout:
            print(f"[ERROR] Timeout: {method} {url}")
            logger.debug("Timeout: %s %s", method, url)
        except requests.exceptions.ConnectionError as e:
            print(f"[ERROR] ConnectionError: {method} {url} - {e}")
            logger.debug("ConnectionError: %s %s", method, url)
        except Exception as exc:
            print(f"[ERROR] Request error {method} {url}: {exc}")
            logger.debug("Request error %s %s: %s", method, url, exc)
        return None

    async def _ensure_async_session(self) -> aiohttp.ClientSession:
        if self._async_session is None or self._async_session.closed:
            timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
            connector = aiohttp.TCPConnector(ssl=False)
            self._async_session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers={
                    "User-Agent": "AuditCrawl/1.0 (educational scanner; not for production)",
                    "Accept": "text/html,application/xhtml+xml,application/json,*/*",
                    "Accept-Language": "en-US,en;q=0.9",
                },
            )
        return self._async_session

    async def _request_async(self, method: str, url: str, **kwargs) -> Optional[_AsyncResponse]:
        session = await self._ensure_async_session()
        kwargs.pop("timeout", None)
        kwargs.pop("verify", None)
        allow_redirects = kwargs.pop("allow_redirects", True)
        data = kwargs.pop("data", None)
        params = kwargs.pop("params", None)
        headers = kwargs.pop("headers", None)
        if kwargs:
            logger.debug("Ignoring unsupported aiohttp kwargs on %s %s: %s", method, url, sorted(kwargs.keys()))

        async with self._async_request_lock:
            elapsed = time.time() - self._async_last_request_time
            if elapsed < self.config.request_delay:
                await asyncio.sleep(self.config.request_delay - elapsed)
            self._async_last_request_time = time.time()

            try:
                async with session.request(
                    method,
                    url,
                    data=data,
                    params=params,
                    headers=headers,
                    allow_redirects=allow_redirects,
                ) as resp:
                    text = await resp.text()
                    return _AsyncResponse(resp.status, text, {k: v for k, v in resp.headers.items()})
            except asyncio.TimeoutError:
                print(f"[ERROR] Timeout: {method} {url}")
                logger.debug("Timeout: %s %s", method, url)
            except aiohttp.ClientError as e:
                print(f"[ERROR] ConnectionError: {method} {url} - {e}")
                logger.debug("ConnectionError: %s %s", method, url)
            except Exception as exc:
                print(f"[ERROR] Request error {method} {url}: {exc}")
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

    async def login_async(self) -> bool:
        cfg = self.config
        if not cfg.auth_login_url or not cfg.auth_username:
            return False
        data = {
            cfg.auth_username_field: cfg.auth_username,
            cfg.auth_password_field: cfg.auth_password or "",
        }
        resp = await self.post_async(cfg.auth_login_url, data=data, allow_redirects=True)
        if resp and resp.status in (200, 302):
            self.is_authenticated = True
            logger.info("Login succeeded (%s)", resp.status)
            return True
        logger.warning("Login failed")
        return False

    def is_in_scope(self, url: str) -> bool:
        """
        Decide whether a URL is within scan scope.

        Important: callers often provide `target_domain` without a port (e.g. "127.0.0.1"),
        while URLs may include one (e.g. "127.0.0.1:5000"). We therefore match primarily
        on hostname, and only enforce port equality when the configured target includes a port.
        """
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        port = parsed.port

        target_raw = (self.config.target_domain or "").strip().lower()
        target_host, target_port = _parse_target_host_port(target_raw)

        if not host or not target_host:
            return False

        def host_matches(h: str) -> bool:
            if self.config.allowed_subdomains:
                return h == target_host or h.endswith("." + target_host)
            return h == target_host or h == "www." + target_host

        if not host_matches(host):
            return False

        # If user specified a port in target_domain, enforce it; otherwise ignore ports.
        if target_port is not None:
            return port == target_port
        return True

    async def close_async(self) -> None:
        if self._async_session is not None:
            await self._async_session.close()
            self._async_session = None

    def close(self) -> None:
        self._session.close()
def _parse_target_host_port(target: str) -> tuple[str, int | None]:
    """
    Parse config.target_domain into (host, port?).

    Accepts:
    - "localhost"
    - "localhost:5000"
    - "http://localhost:5000" (some callers accidentally pass full URLs)
    """
    if not target:
        return "", None

    # If a full URL was provided, use urlparse.
    if "://" in target:
        p = urlparse(target)
        return (p.hostname or "").lower(), p.port

    # Handle simple host[:port] (IPv4/hostname). (IPv6 not supported by this split.)
    if ":" in target and target.count(":") == 1:
        h, p = target.split(":", 1)
        try:
            return h.lower(), int(p)
        except ValueError:
            return target.lower(), None

    return target.lower(), None