from __future__ import annotations

import asyncio
from difflib import SequenceMatcher
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
import re
from typing import Awaitable, Callable, Optional

import aiohttp
from bs4 import BeautifulSoup

from .snippet_library import fix_snippet_for
from .payload_generator import detect_input_type, get_contextual_payloads
from .leaked_asset_detector import LeakedAssetDetector


@dataclass
class _ResponseData:
    status_code: int
    text: str
    headers: dict[str, str]
    set_cookie_headers: list[str] = field(default_factory=list)


class _AioHttpClient:
    def __init__(self, timeout: float = 12.0, verify: bool = False) -> None:
        self._timeout = timeout
        self._verify = verify
        self._session: aiohttp.ClientSession | None = None
        self._cookies: dict[str, str] = {}
        self._auth_headers: dict[str, str] = {}

    async def __aenter__(self) -> "_AioHttpClient":
        connector = aiohttp.TCPConnector(ssl=self._verify if self._verify else False)
        timeout = aiohttp.ClientTimeout(total=self._timeout)
        self._session = aiohttp.ClientSession(timeout=timeout, connector=connector)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._session is not None:
            await self._session.close()

    def set_cookies(self, cookies: dict[str, str]) -> None:
        """Set session cookies for authenticated requests."""
        self._cookies.update(cookies)

    def set_auth_headers(self, headers: dict[str, str]) -> None:
        """Set custom authentication headers."""
        self._auth_headers.update(headers)

    async def login(self, login_url: str, username: str, password: str, auth_method: str = "form") -> bool:
        """Attempt to authenticate and store session cookies."""
        try:
            if auth_method == "form":
                # Form-based login
                login_data = {"username": username, "password": password}
                resp = await self.post(login_url, data=login_data, follow_redirects=True)
                # Extract and store cookies from response
                if resp.set_cookie_headers:
                    for cookie_header in resp.set_cookie_headers:
                        # Parse "name=value; Path=/; ..."
                        cookie_parts = cookie_header.split(";")[0]
                        if "=" in cookie_parts:
                            name, value = cookie_parts.split("=", 1)
                            self._cookies[name.strip()] = value.strip()
                return resp.status_code == 200
            elif auth_method == "basic":
                # HTTP Basic Auth
                import base64
                credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                self._auth_headers["Authorization"] = f"Basic {credentials}"
                # Test the auth
                resp = await self.get(login_url)
                return resp.status_code == 200
            else:
                return False
        except Exception:
            return False

    async def request(
        self,
        method: str,
        url: str,
        *,
        data: Optional[dict[str, str]] = None,
        params: Optional[dict[str, str]] = None,
        follow_redirects: bool = True,
        headers: Optional[dict[str, str]] = None,
        content: Optional[str] = None,
    ) -> _ResponseData:
        if self._session is None:
            raise RuntimeError("HTTP client session is not initialized")

        # Merge headers
        req_headers = {**self._auth_headers}
        if headers:
            req_headers.update(headers)

        # Merge cookies into session
        if self._cookies:
            for name, value in self._cookies.items():
                self._session.cookie_jar.update_cookies({name: value})

        async with self._session.request(
            method,
            url,
            data=data,
            params=params,
            allow_redirects=follow_redirects,
            headers=req_headers if req_headers else None,
            content=content.encode() if content else None,
        ) as resp:
            text = await resp.text()
            return _ResponseData(
                status_code=resp.status,
                text=text,
                headers={k: v for k, v in resp.headers.items()},
                set_cookie_headers=list(resp.headers.getall("Set-Cookie", [])),
            )

    async def get(self, url: str, **kwargs) -> _ResponseData:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, data: Optional[dict[str, str]] = None, **kwargs) -> _ResponseData:
        return await self.request("POST", url, data=data, **kwargs)


class WebScanner:
    """Safe heuristic scanner: non-destructive checks only."""

    PROFILE = {
        "1": {"max_pages": 20, "max_depth": 1},
        "2": {"max_pages": 80, "max_depth": 3},
        "3": {"max_pages": 200, "max_depth": 5},
    }

    XSS_PAYLOAD = "<script>console.log('AUDITCRAWL_TEST')</script>"
    SQLI_PAYLOADS = ["'", "' OR '1'='1", '" OR "1"="1']

    async def scan(
        self,
        target_url: str,
        scan_level: str,
        use_selenium: bool = False,
        progress_cb: Optional[Callable[[int, str], Awaitable[None]]] = None,
        login_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        auth_method: Optional[str] = None,
        auth_headers: Optional[dict[str, str]] = None,
        cookies: Optional[dict[str, str]] = None,
    ) -> list[dict]:
        profile = self.PROFILE.get(scan_level, self.PROFILE["2"])
        if progress_cb:
            await progress_cb(5, "Initializing crawler")

        async def crawl_progress_cb(crawled_count: int, max_pages: int) -> None:
            if not progress_cb:
                return
            ratio = min(1.0, crawled_count / max(1, max_pages))
            pct = 5 + int(ratio * 20)
            await progress_cb(min(pct, 24), f"Crawled {crawled_count} page(s)")

        pages = await self._crawl(
            target_url,
            profile["max_pages"],
            profile["max_depth"],
            crawl_progress_cb=crawl_progress_cb,
            login_url=login_url,
            username=username,
            password=password,
            auth_method=auth_method,
            auth_headers=auth_headers,
            cookies=cookies,
        )
        if progress_cb:
            await progress_cb(25, f"Crawl complete. {len(pages)} pages discovered")

        findings: list[dict] = []
        async with _AioHttpClient(timeout=12, verify=False) as client:
            # Apply authentication to the scanning client
            if cookies:
                client.set_cookies(cookies)
            if auth_headers:
                client.set_auth_headers(auth_headers)
            if login_url and username and password and auth_method:
                if progress_cb:
                    await progress_cb(26, "Authenticating...")
                success = await client.login(login_url, username, password, auth_method)
                if not success and progress_cb:
                    await progress_cb(27, "Authentication failed, continuing without auth")
                elif progress_cb:
                    await progress_cb(27, "Authentication successful")

            total_pages = max(1, len(pages))

            async def analyze_page(page: dict) -> list[dict]:
                page_findings: list[dict] = []
                page_findings.extend(await self._check_reflected_xss(client, page))
                page_findings.extend(await self._check_sqli_symptoms(client, page))
                page_findings.extend(await self._check_idor(client, page))
                page_findings.extend(self._check_ssrf_surface(page))
                page_findings.extend(await self._check_open_redirect(client, page))
                page_findings.extend(self._check_security_misconfig(page))
                page_findings.extend(await self._check_cors_misconfig(client, page))
                page_findings.extend(await self._check_path_traversal(client, page))
                page_findings.extend(await self._check_xxe_injection(client, page))
                page_findings.extend(self._check_jwt_vulnerabilities(page))
                page_findings.extend(self._check_dom_xss(page))
                page_findings.extend(self._check_api_misconfig(page))
                page_findings.extend(self._check_leaked_assets(page))
                return page_findings

            tasks = [asyncio.create_task(analyze_page(page)) for page in pages]
            completed = 0
            for task in asyncio.as_completed(tasks):
                findings.extend(await task)
                completed += 1
                if progress_cb:
                    progress = 25 + int((completed / total_pages) * 60)
                    await progress_cb(min(progress, 90), f"Analyzed {completed}/{total_pages} pages")

        deduped = []
        seen = set()
        for f in findings:
            key = (f["vulnerability_type"], f["endpoint"], f["evidence"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(f)
        if progress_cb:
            await progress_cb(95, f"Correlated findings. {len(deduped)} potential issues")
        return deduped

    def compare_scans(self, current_findings: list[dict], previous_findings: list[dict]) -> dict:
        """Compare two scan results and categorize findings as new, fixed, recurring, etc."""
        result = {
            "new": [],
            "fixed": [],
            "recurring": [],
            "improved": [],  # Same vuln but with lower severity
            "worsened": [],  # Same vuln but with higher severity
            "summary": {},
        }

        # Create lookup keys for efficient comparison
        prev_keys = {}
        for finding in previous_findings:
            key = (finding["vulnerability_type"], finding["endpoint"])
            if key not in prev_keys:
                prev_keys[key] = []
            prev_keys[key].append(finding)

        current_keys = {}
        for finding in current_findings:
            key = (finding["vulnerability_type"], finding["endpoint"])
            if key not in current_keys:
                current_keys[key] = []
            current_keys[key].append(finding)

        # Categorize vulnerabilities
        severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

        for key in current_keys:
            current_vulns = current_keys[key]
            prev_vulns = prev_keys.get(key, [])

            if not prev_vulns:
                # No previous finding with this type+endpoint = new
                result["new"].extend(current_vulns)
            else:
                # Compare severities
                current_severity = max(severity_order.get(v.get("severity", "Low"), 0) for v in current_vulns)
                prev_severity = max(severity_order.get(v.get("severity", "Low"), 0) for v in prev_vulns)

                if current_severity > prev_severity:
                    result["worsened"].extend(current_vulns)
                elif current_severity < prev_severity:
                    result["improved"].extend(current_vulns)
                else:
                    # Same severity = recurring
                    result["recurring"].extend(current_vulns)

        # Find fixed vulnerabilities (in previous but not in current)
        for key in prev_keys:
            if key not in current_keys:
                result["fixed"].extend(prev_keys[key])

        # Generate summary statistics
        result["summary"] = {
            "new_count": len(result["new"]),
            "fixed_count": len(result["fixed"]),
            "recurring_count": len(result["recurring"]),
            "improved_count": len(result["improved"]),
            "worsened_count": len(result["worsened"]),
            "total_current": len(current_findings),
            "total_previous": len(previous_findings),
        }

        return result

    async def _crawl(
        self,
        base_url: str,
        max_pages: int,
        max_depth: int,
        crawl_progress_cb: Optional[Callable[[int, int], Awaitable[None]]] = None,
        login_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        auth_method: Optional[str] = None,
        auth_headers: Optional[dict[str, str]] = None,
        cookies: Optional[dict[str, str]] = None,
    ) -> list[dict]:
        pages: list[dict] = []
        seen = set()
        queue = [(base_url, 0)]
        origin = urlparse(base_url).netloc

        async with _AioHttpClient(timeout=12, verify=False) as client:
            # Apply authentication to the crawl client
            if cookies:
                client.set_cookies(cookies)
            if auth_headers:
                client.set_auth_headers(auth_headers)
            if login_url and username and password and auth_method:
                await client.login(login_url, username, password, auth_method)

            while queue and len(pages) < max_pages:
                url, depth = queue.pop(0)
                if url in seen:
                    continue
                if depth > max_depth:
                    continue
                seen.add(url)
                try:
                    resp = await client.get(url)
                except Exception:
                    continue
                if resp.status_code >= 400:
                    continue

                html = resp.text
                soup = BeautifulSoup(html, "lxml")
                forms = []
                for form in soup.find_all("form"):
                    method = (form.get("method") or "GET").upper()
                    action = form.get("action") or url
                    form_url = urljoin(url, action)
                    fields = []
                    inputs = []
                    for elem in form.find_all(["input", "textarea", "select"]):
                        name = elem.get("name")
                        if name:
                            fields.append(name)
                            inputs.append(
                                {
                                    "name": name,
                                    "type": (elem.get("type") or "text").lower(),
                                    "value": elem.get("value") or "",
                                }
                            )
                    if fields:
                        forms.append({"url": form_url, "method": method, "fields": fields, "inputs": inputs})

                page = {
                    "url": url,
                    "html": html,
                    "soup": soup,
                    "forms": forms,
                    "headers": dict(resp.headers),
                    "set_cookie_headers": resp.set_cookie_headers,
                    "status_code": resp.status_code,
                }
                pages.append(page)
                if crawl_progress_cb:
                    await crawl_progress_cb(len(pages), max_pages)

                for a in soup.find_all("a", href=True):
                    nxt = urljoin(url, a["href"])
                    if urlparse(nxt).netloc == origin and nxt not in seen:
                        queue.append((nxt, depth + 1))

        return pages

    def _replace_query_param(self, url: str, key: str, value: str) -> str:
        parsed = urlparse(url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query[key] = value
        return urlunparse(parsed._replace(query=urlencode(query, doseq=False)))

    async def _check_reflected_xss(self, client: httpx.AsyncClient, page: dict) -> list[dict]:
        url = page["url"]
        parsed = urlparse(url)
        findings = []

        query_keys = [x.split("=")[0] for x in parsed.query.split("&") if "=" in x]
        for key in query_keys:
            payload_url = self._replace_query_param(url, key, self.XSS_PAYLOAD)
            try:
                resp = await client.get(payload_url)
            except Exception:
                continue
            if self.XSS_PAYLOAD in resp.text:
                snippet = self._snippet(resp.text, "AUDITCRAWL_TEST")
                vuln = "Reflected XSS"
                findings.append(
                    {
                        "vulnerability_type": vuln,
                        "severity": "Medium",
                        "endpoint": url,
                        "evidence": f"Payload reflected via query parameter '{key}'.",
                        "vulnerable_snippet": snippet,
                        "fix_snippet": fix_snippet_for(vuln),
                    }
                )

        # Form-based reflected checks catch common login/search flows with POST bodies.
        for form in page.get("forms", []):
            for key in form["fields"]:
                body = {field: "auditcrawl_test" for field in form["fields"]}
                body[key] = self.XSS_PAYLOAD
                try:
                    if form["method"] == "POST":
                        resp = await client.post(form["url"], data=body)
                    else:
                        resp = await client.get(form["url"], params=body)
                except Exception:
                    continue

                if self.XSS_PAYLOAD in resp.text:
                    vuln = "Reflected XSS"
                    findings.append(
                        {
                            "vulnerability_type": vuln,
                            "severity": "Medium",
                            "endpoint": form["url"],
                            "evidence": f"Payload reflected from form field '{key}' ({form['method']}).",
                            "vulnerable_snippet": self._snippet(resp.text, "AUDITCRAWL_TEST"),
                            "fix_snippet": fix_snippet_for(vuln),
                        }
                    )
        return findings

    async def _check_contextual_xss(self, client: httpx.AsyncClient, page: dict) -> list[dict]:
        """Enhanced XSS detection using context-aware payloads based on input type."""
        url = page["url"]
        findings = []

        # Check forms with input type detection
        for form in page.get("forms", []):
            for input_field in form.get("inputs", []):
                field_name = input_field.get("name", "")
                field_type = input_field.get("type", "text")

                # Detect input type
                detected_type = detect_input_type(field_name, field_type, input_field.get("value", ""))

                # Get context-aware payloads
                payloads = get_contextual_payloads(detected_type, "xss")

                body = {f["name"]: "test" for f in form.get("inputs", []) if f.get("name")}
                form_url = form.get("url", url)

                for payload in payloads:
                    if not field_name:
                        continue

                    body[field_name] = payload
                    try:
                        if form.get("method", "GET").upper() == "POST":
                            resp = await client.post(form_url, data=body, follow_redirects=False)
                        else:
                            query_str = urlencode(body)
                            resp = await client.get(f"{form_url}?{query_str}", follow_redirects=False)
                    except Exception:
                        continue

                    # Check if payload was reflected
                    if payload in resp.text or payload.replace("'", '"') in resp.text:
                        findings.append(
                            {
                                "vulnerability_type": "Contextual Reflected XSS",
                                "severity": "Medium",
                                "endpoint": form_url,
                                "evidence": f"Field '{field_name}' (type: {detected_type.value}) vulnerable to XSS.",
                                "vulnerable_snippet": self._snippet(resp.text, payload[:30]),
                                "fix_snippet": fix_snippet_for("Reflected XSS"),
                            }
                        )
                        break

        return findings

    async def _check_sqli_symptoms(self, client: httpx.AsyncClient, page: dict) -> list[dict]:
        url = page["url"]
        markers = [
            "sql syntax",
            "sqlite",
            "mysql",
            "unclosed quotation",
            "syntax error",
            "java.sql",
            "sqlexception",
            "sqlstate",
            "odbc",
            "ora-",
        ]
        parsed = urlparse(url)
        query_keys = [x.split("=")[0] for x in parsed.query.split("&") if "=" in x]
        findings = []

        for key in query_keys:
            for payload in self.SQLI_PAYLOADS:
                payload_url = self._replace_query_param(url, key, payload)
                try:
                    resp = await client.get(payload_url)
                except Exception:
                    continue

                text_l = resp.text.lower()
                if any(m in text_l for m in markers) or resp.status_code >= 500:
                    vuln = "SQL Injection"
                    findings.append(
                        {
                            "vulnerability_type": vuln,
                            "severity": "High",
                            "endpoint": url,
                            "evidence": f"SQL error marker observed when testing parameter '{key}'.",
                            "vulnerable_snippet": self._snippet(resp.text, "sql"),
                            "fix_snippet": fix_snippet_for(vuln),
                        }
                    )
                    break

        for form in page.get("forms", []):
            for key in form["fields"]:
                for payload in self.SQLI_PAYLOADS:
                    body = {field: "auditcrawl_test" for field in form["fields"]}
                    body[key] = payload
                    try:
                        if form["method"] == "POST":
                            resp = await client.post(form["url"], data=body)
                        else:
                            resp = await client.get(form["url"], params=body)
                    except Exception:
                        continue

                    text_l = resp.text.lower()
                    if any(m in text_l for m in markers) or resp.status_code >= 500:
                        vuln = "SQL Injection"
                        findings.append(
                            {
                                "vulnerability_type": vuln,
                                "severity": "High",
                                "endpoint": form["url"],
                                "evidence": f"SQL-like server error observed for form field '{key}'.",
                                "vulnerable_snippet": self._snippet(resp.text, "sql"),
                                "fix_snippet": fix_snippet_for(vuln),
                            }
                        )
                        break
        return findings

    def _check_ssrf_surface(self, page: dict) -> list[dict]:
        url = page["url"]
        q = urlparse(url).query.lower()
        hints = ["url=", "uri=", "redirect=", "callback=", "next="]
        if any(h in q for h in hints):
            vuln = "Potential SSRF"
            return [
                {
                    "vulnerability_type": vuln,
                    "severity": "Medium",
                    "endpoint": url,
                    "evidence": "URL-like parameter accepted; backend URL fetching should be allow-listed.",
                    "vulnerable_snippet": "GET /endpoint?url=http://user-controlled.example",
                    "fix_snippet": fix_snippet_for(vuln),
                }
            ]
        return []

    async def _check_open_redirect(self, client: httpx.AsyncClient, page: dict) -> list[dict]:
        url = page["url"]
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        redirect_keys = {
            "next",
            "url",
            "redirect",
            "return",
            "continue",
            "dest",
            "destination",
            "redirect_uri",
            "redirect_url",
            "return_url",
            "goto",
            "to",
            "target",
        }
        active_keys = [key for key in params if key.lower() in redirect_keys]
        if not active_keys:
            return []

        payloads = [
            "https://evil.example.com",
            "//evil.example.com",
            "https://evil.example.com/landing",
            "/%2F%2Fevil.example.com",
            "https://evil.example.com%2F@legitimate.example",
        ]
        findings: list[dict] = []

        for key in active_keys:
            for payload in payloads:
                test_url = self._replace_query_param(url, key, payload)
                try:
                    resp = await client.get(test_url, follow_redirects=False)
                except Exception:
                    continue

                location = resp.headers.get("Location", "")
                if resp.status_code not in {301, 302, 303, 307, 308}:
                    continue

                if self._is_open_redirect_target(url, location, payload):
                    findings.append(
                        {
                            "vulnerability_type": "Open Redirect",
                            "severity": "Medium",
                            "endpoint": url,
                            "evidence": f"HTTP {resp.status_code} Location: {location}",
                            "vulnerable_snippet": f"GET {test_url}",
                            "fix_snippet": fix_snippet_for("Open Redirect"),
                        }
                    )
                    break

        return findings

    async def _check_cors_misconfig(self, client: httpx.AsyncClient, page: dict) -> list[dict]:
        """Test for CORS misconfiguration via wildcard and origin reflection."""
        url = page["url"]
        headers = {k.lower(): v for k, v in page.get("headers", {}).items()}
        findings: list[dict] = []

        # Check for wildcard CORS policy in response headers
        acao = headers.get("access-control-allow-origin", "").strip()
        if acao == "*":
            findings.append(
                {
                    "vulnerability_type": "CORS Misconfiguration (Wildcard)",
                    "severity": "Medium",
                    "endpoint": url,
                    "evidence": "Access-Control-Allow-Origin: *",
                    "vulnerable_snippet": "Access-Control-Allow-Origin: *",
                    "fix_snippet": fix_snippet_for("CORS Misconfiguration"),
                }
            )
            return findings

        # Test for origin reflection vulnerability
        test_origins = [
            "https://evil.example.com",
            "https://attacker.local",
            "http://localhost:9999",
        ]
        for test_origin in test_origins:
            try:
                resp = await client.get(url, params={}, headers={"Origin": test_origin}, follow_redirects=False)
            except Exception:
                continue

            reflected_acao = resp.headers.get("access-control-allow-origin", "").strip()
            if reflected_acao == test_origin:
                findings.append(
                    {
                        "vulnerability_type": "CORS Misconfiguration (Origin Reflection)",
                        "severity": "Medium",
                        "endpoint": url,
                        "evidence": f"Server reflected arbitrary Origin header: {reflected_acao}",
                        "vulnerable_snippet": f"GET {url}\nOrigin: {test_origin}\nResponse: Access-Control-Allow-Origin: {reflected_acao}",
                        "fix_snippet": fix_snippet_for("CORS Misconfiguration"),
                    }
                )
                break

        return findings

    async def _check_path_traversal(self, client: httpx.AsyncClient, page: dict) -> list[dict]:
        """Test for Path Traversal and Local File Inclusion vulnerabilities."""
        url = page["url"]
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        forms = page.get("forms", [])
        findings: list[dict] = []

        # Keywords that suggest file path parameters
        file_keywords = {"file", "path", "include", "load", "page", "document", "dir", "directory", "url", "template"}
        payloads = [
            "../../etc/passwd",
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/passwd",
            "C:\\windows\\system32\\config\\sam",
        ]
        suspicious_content = ["root:", "Administrator", "System", "daemon:"]

        # Check query parameters
        for param_name in params:
            if any(keyword in param_name.lower() for keyword in file_keywords):
                for payload in payloads:
                    test_url = self._replace_query_param(url, param_name, payload)
                    try:
                        resp = await client.get(test_url, follow_redirects=False)
                    except Exception:
                        continue
                    resp_lower = resp.text.lower()
                    if any(content.lower() in resp_lower for content in suspicious_content) or payload in resp.text:
                        findings.append(
                            {
                                "vulnerability_type": "Path Traversal / LFI",
                                "severity": "High",
                                "endpoint": url,
                                "evidence": f"Parameter '{param_name}' appears vulnerable to path traversal.",
                                "vulnerable_snippet": f"GET {test_url}",
                                "fix_snippet": fix_snippet_for("Path Traversal / LFI"),
                            }
                        )
                        break
                if findings:
                    break

        # Check form fields
        if not findings:
            for form in forms:
                for input_field in form.get("inputs", []):
                    field_name = input_field.get("name", "")
                    if any(keyword in field_name.lower() for keyword in file_keywords):
                        form_url = form.get("url", url)
                        form_method = form.get("method", "GET").upper()
                        for payload in payloads:
                            test_data = {field_name: payload}
                            try:
                                if form_method == "GET":
                                    test_url = f"{form_url}?{urlencode(test_data)}"
                                    resp = await client.get(test_url, follow_redirects=False)
                                else:
                                    resp = await client.post(form_url, data=test_data, follow_redirects=False)
                            except Exception:
                                continue
                            resp_lower = resp.text.lower()
                            if any(content.lower() in resp_lower for content in suspicious_content) or payload in resp.text:
                                findings.append(
                                    {
                                        "vulnerability_type": "Path Traversal / LFI",
                                        "severity": "High",
                                        "endpoint": form_url,
                                        "evidence": f"Form field '{field_name}' appears vulnerable to path traversal.",
                                        "vulnerable_snippet": f"{form_method} {form_url}\n{field_name}={payload}",
                                        "fix_snippet": fix_snippet_for("Path Traversal / LFI"),
                                    }
                                )
                                break
                        if findings:
                            break
                if findings:
                    break

        return findings

    async def _check_xxe_injection(self, client: httpx.AsyncClient, page: dict) -> list[dict]:
        """Test for XML External Entity (XXE) injection vulnerabilities."""
        url = page["url"]
        forms = page.get("forms", [])
        findings: list[dict] = []

        # XXE payloads designed to test entity expansion and external entity loading
        xxe_payloads = [
            # Basic entity expansion test
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test123">]><foo>&xxe;</foo>',
            # External entity loading attempt (file:// protocol)
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            # Blind XXE with potential out-of-band detection
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.local/xxe">]><foo>&xxe;</foo>',
            # Parameter entity variation
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo></foo>',
        ]

        # Look for forms that might accept XML
        for form in forms:
            form_url = form.get("url", url)
            form_method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])

            # Skip if form has no inputs or is purely GET
            if not inputs and form_method == "GET":
                continue

            for payload in xxe_payloads:
                try:
                    # Try to submit as XML POST with first input field as the XML body
                    if form_method == "POST" and inputs:
                        field_name = inputs[0].get("name", "xml")
                        headers = {"Content-Type": "application/xml"}
                        # Send payload as raw XML body
                        resp = await client.post(
                            form_url,
                            content=payload,
                            headers=headers,
                            follow_redirects=False,
                        )
                    else:
                        # Try as form field
                        test_data = {inputs[0].get("name", "data"): payload} if inputs else {}
                        if not test_data:
                            continue
                        resp = await client.post(form_url, data=test_data, follow_redirects=False)
                except Exception:
                    continue

                resp_lower = resp.text.lower()
                # Check for XXE indicators
                xxe_indicators = [
                    "test123",  # Basic entity expansion marker
                    "root:",  # /etc/passwd content
                    "daemon:",  # /etc/passwd content
                    "<!entity",  # Entity definition echo
                    "xml.etree",  # Parser error messages
                    "expat",  # XML parser name
                    "entity",  # Generic entity reference
                ]

                if any(indicator.lower() in resp_lower for indicator in xxe_indicators):
                    findings.append(
                        {
                            "vulnerability_type": "XXE Injection",
                            "severity": "High",
                            "endpoint": form_url,
                            "evidence": f"Form appears to process XML entities.",
                            "vulnerable_snippet": f"POST {form_url}\nContent-Type: application/xml\n{payload[:100]}...",
                            "fix_snippet": fix_snippet_for("XXE Injection"),
                        }
                    )
                    break

            if findings:
                break

        return findings

    def _check_jwt_vulnerabilities(self, page: dict) -> list[dict]:
        """Test for JWT vulnerabilities including alg:none bypass and weak secrets."""
        url = page["url"]
        headers = page.get("headers", {})
        soup = page.get("soup")
        findings: list[dict] = []

        # Extract potential JWT tokens
        tokens = []

        # Check Authorization header
        auth_header = headers.get("Authorization") or headers.get("authorization") or ""
        if auth_header.startswith("Bearer "):
            tokens.append(auth_header.split(" ")[1])

        # Check cookies for common JWT names
        set_cookie_headers = page.get("set_cookie_headers", [])
        for cookie_header in set_cookie_headers:
            if any(jwt_name in cookie_header.lower() for jwt_name in ["token", "jwt", "auth", "access"]):
                # Extract cookie value
                cookie_parts = cookie_header.split(";")[0].split("=")
                if len(cookie_parts) == 2:
                    tokens.append(cookie_parts[1])

        # Check for JWT patterns in HTML (script tags, data attributes)
        if soup:
            for script in soup.find_all("script"):
                text = script.string or ""
                # Look for JWT-like patterns: three base64 parts separated by dots
                import re as regex_module
                jwt_pattern = r"([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)"
                matches = regex_module.findall(jwt_pattern, text)
                tokens.extend(matches)

        # Analyze tokens
        for token in tokens:
            try:
                parts = token.split(".")
                if len(parts) != 3:
                    continue

                # Decode header (add padding if needed)
                header_b64 = parts[0]
                header_b64 += "=" * (4 - len(header_b64) % 4)
                import base64
                header_json = base64.urlsafe_b64decode(header_b64)
                import json
                header = json.loads(header_json)

                # Check for alg:none
                if header.get("alg", "").lower() == "none":
                    findings.append(
                        {
                            "vulnerability_type": "JWT - Algorithm None (alg:none)",
                            "severity": "Critical",
                            "endpoint": url,
                            "evidence": "JWT token uses 'none' algorithm, disabling signature verification.",
                            "vulnerable_snippet": f"JWT Header: {json.dumps(header)}",
                            "fix_snippet": fix_snippet_for("JWT Vulnerabilities"),
                        }
                    )
                    continue

                # Test weak secrets
                weak_secrets = [
                    "secret",
                    "123456",
                    "password",
                    "admin",
                    "test",
                    "key",
                    "jwt_secret",
                    "",  # Empty secret
                ]

                for weak_secret in weak_secrets:
                    try:
                        import hmac
                        import hashlib

                        # Recreate signature with weak secret
                        message = f"{parts[0]}.{parts[1]}".encode()
                        expected_sig = base64.urlsafe_b64encode(
                            hmac.new(weak_secret.encode(), message, hashlib.sha256).digest()
                        ).decode().rstrip("=")

                        if expected_sig == parts[2]:
                            findings.append(
                                {
                                    "vulnerability_type": "JWT - Weak Secret",
                                    "severity": "High",
                                    "endpoint": url,
                                    "evidence": f"JWT signed with weak secret: '{weak_secret}'",
                                    "vulnerable_snippet": f"JWT Token (truncated): {token[:50]}...",
                                    "fix_snippet": fix_snippet_for("JWT Vulnerabilities"),
                                }
                            )
                            break
                    except Exception:
                        continue

            except Exception:
                continue

        return findings

    def _check_dom_xss(self, page: dict) -> list[dict]:
        """Test for DOM-based XSS vulnerabilities by analyzing JavaScript."""
        url = page["url"]
        soup = page.get("soup")
        findings: list[dict] = []

        if not soup:
            return findings

        # Dangerous DOM sinks that can execute JavaScript
        dangerous_sinks = {
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "eval",
            "Function",
            "setTimeout",
            "setInterval",
            "document.write",
        }

        # Dangerous DOM sources (user input entry points)
        dangerous_sources = {
            "location.hash",
            "location.search",
            "location.href",
            "window.name",
            "document.referrer",
            "history.go",
            "location.pathname",
        }

        # Collect all JavaScript code from script tags
        script_code = ""
        for script in soup.find_all("script"):
            if script.string:
                script_code += script.string + "\n"

        if not script_code:
            return findings

        script_lower = script_code.lower()

        # Check for dangerous sink usage
        for sink in dangerous_sinks:
            sink_lower = sink.lower()
            if sink_lower not in script_lower:
                continue

            # Check for dangerous source usage
            for source in dangerous_sources:
                source_lower = source.lower()
                if source_lower not in script_lower:
                    continue

                # Check if source and sink are in proximity (simple heuristic)
                source_idx = script_lower.find(source_lower)
                sink_idx = script_lower.find(sink_lower)

                # If both exist and sink comes after source, flag it
                if source_idx >= 0 and sink_idx > source_idx:
                    # Check if there's any sanitization in between (naive check)
                    between = script_code[source_idx : sink_idx].lower()
                    sanitization_keywords = {
                        "encodeuri",
                        "encodeuricomponent",
                        "htmlescape",
                        "escape",
                        "sanitize",
                        "dompurify",
                    }
                    has_sanitization = any(keyword in between for keyword in sanitization_keywords)

                    if not has_sanitization:
                        # Extract snippet of vulnerable code
                        snippet_start = max(0, source_idx - 100)
                        snippet_end = min(len(script_code), sink_idx + 100)
                        vulnerable_snippet = script_code[snippet_start:snippet_end]

                        findings.append(
                            {
                                "vulnerability_type": "DOM-based XSS",
                                "severity": "High",
                                "endpoint": url,
                                "evidence": f"Unsanitized user input from '{source}' flows to dangerous sink '{sink}'.",
                                "vulnerable_snippet": vulnerable_snippet.strip()[:200],
                                "fix_snippet": fix_snippet_for("DOM-based XSS"),
                            }
                        )
                        break

            if findings:
                break

        return findings

    def _check_api_misconfig(self, page: dict) -> list[dict]:
        """Test for API misconfiguration and security issues."""
        url = page["url"]
        headers = page.get("headers", {})
        body = page.get("text", "")
        findings: list[dict] = []

        # Check if this looks like an API endpoint
        api_indicators = {"/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql"}
        is_api = any(indicator in url.lower() for indicator in api_indicators)

        if not is_api:
            return findings

        # Check for missing or weak authentication
        auth_headers = ["authorization", "x-api-key", "x-auth-token", "api-key"]
        has_auth = any(h.lower() in {k.lower() for k in headers.keys()} for h in auth_headers)

        if not has_auth and (page.get("status_code") == 200 or page.get("status_code") == 401):
            findings.append(
                {
                    "vulnerability_type": "API - Missing Authentication",
                    "severity": "High",
                    "endpoint": url,
                    "evidence": f"API endpoint accessible without authentication headers.",
                    "vulnerable_snippet": f"GET {url}\nStatus: {page.get('status_code')}",
                    "fix_snippet": fix_snippet_for("API Misconfiguration"),
                }
            )

        # Check for verbose error messages in response
        body_lower = body.lower()
        error_keywords = {
            "stacktrace",
            "traceback",
            "exception",
            "error_code",
            "sql syntax",
            "mysql",
            "postgresql",
            "oracle database",
            "java.lang",
            "at line",
            "debug information",
        }

        if any(keyword in body_lower for keyword in error_keywords):
            findings.append(
                {
                    "vulnerability_type": "API - Verbose Error Messages",
                    "severity": "Medium",
                    "endpoint": url,
                    "evidence": f"API returns detailed error information that could aid attackers.",
                    "vulnerable_snippet": body[: min(200, len(body))],
                    "fix_snippet": fix_snippet_for("API Misconfiguration"),
                }
            )

        # Check for exposed internal IP addresses or hostnames
        internal_patterns = {
            "192.168.",
            "10.0.",
            "172.16.",
            "localhost",
            "127.0.0.1",
            "internal",
            ".local",
            ".corp",
        }
        if any(pattern in body.lower() for pattern in internal_patterns):
            findings.append(
                {
                    "vulnerability_type": "API - Information Disclosure",
                    "severity": "Medium",
                    "endpoint": url,
                    "evidence": f"API response contains internal network information.",
                    "vulnerable_snippet": body[: min(200, len(body))],
                    "fix_snippet": fix_snippet_for("API Misconfiguration"),
                }
            )

        # Check for missing security headers
        required_headers = {
            "x-content-type-options": "nosniff",
            "x-frame-options": "deny",
            "x-xss-protection": "1",
            "strict-transport-security": "max-age",
        }
        missing_headers = []
        for header, value in required_headers.items():
            if header.lower() not in {k.lower() for k in headers.keys()}:
                missing_headers.append(header)

        if missing_headers:
            findings.append(
                {
                    "vulnerability_type": "API - Missing Security Headers",
                    "severity": "Medium",
                    "endpoint": url,
                    "evidence": f"API missing security headers: {', '.join(missing_headers)}",
                    "vulnerable_snippet": "Missing headers: " + ", ".join(missing_headers),
                    "fix_snippet": fix_snippet_for("API Misconfiguration"),
                }
            )

        return findings

    def _is_open_redirect_target(self, base_url: str, location: str, payload: str) -> bool:
        if not location:
            return False

        normalized_location = location.strip()
        resolved = urljoin(base_url, normalized_location)
        resolved_parsed = urlparse(resolved)
        base_parsed = urlparse(base_url)
        location_lower = normalized_location.lower()
        payload_lower = payload.lower()

        if "evil.example.com" in location_lower or "evil.example.com" in resolved_parsed.netloc.lower():
            return True
        if normalized_location == payload or location_lower == payload_lower:
            return True
        if resolved_parsed.netloc and resolved_parsed.netloc.lower() != base_parsed.netloc.lower():
            return True
        if normalized_location.startswith(("//", "http://", "https://", "javascript:", "data:")):
            return True
        return False

    async def _check_idor(self, client: httpx.AsyncClient, page: dict) -> list[dict]:
        findings: list[dict] = []
        url = page["url"]
        parsed = urlparse(url)
        clean_url = parsed._replace(query="").geturl()
        base_query = dict(parse_qsl(parsed.query, keep_blank_values=True))

        candidates = self._idor_candidates_from_params(base_query, source_url=clean_url)
        for form in page.get("forms", []):
            form_inputs = form.get("inputs", [])
            form_data = {field.get("name"): field.get("value", "") for field in form_inputs if field.get("name")}
            candidates.extend(self._idor_candidates_from_params(form_data, source_url=form["url"], method=form["method"], is_form=True))

        seen = set()
        unique_candidates = []
        for candidate in candidates:
            key = (candidate["source_url"], candidate["method"], candidate["param"])
            if key in seen:
                continue
            seen.add(key)
            unique_candidates.append(candidate)

        for candidate in unique_candidates:
            baseline = await self._idor_request(client, candidate["source_url"], candidate["method"], candidate["data"])
            if baseline is None or baseline.status_code >= 400:
                continue

            baseline_text = self._normalize_for_diff(baseline.text)
            if not baseline_text:
                continue

            for alt_value in self._idor_alternatives(candidate["value"]):
                if alt_value == candidate["value"]:
                    continue

                test_data = dict(candidate["data"])
                test_data[candidate["param"]] = alt_value
                test_resp = await self._idor_request(client, candidate["source_url"], candidate["method"], test_data)
                if test_resp is None or test_resp.status_code >= 400:
                    continue

                test_text = self._normalize_for_diff(test_resp.text)
                if not self._idor_should_flag(baseline_text, test_text):
                    continue

                vuln = "IDOR (Insecure Direct Object Reference)"
                findings.append(
                    {
                        "vulnerability_type": vuln,
                        "severity": "High",
                        "endpoint": candidate["source_url"],
                        "evidence": (
                            f"Parameter '{candidate['param']}' returned materially different content when changed from "
                            f"'{candidate['value']}' to '{alt_value}'."
                        ),
                        "vulnerable_snippet": f"{candidate['method']} {candidate['source_url']}?{candidate['param']}={candidate['value']}",
                        "fix_snippet": fix_snippet_for(vuln),
                    }
                )
                break

        return findings

    def _idor_candidates_from_params(
        self,
        params: dict[str, str],
        *,
        source_url: Optional[str] = None,
        method: str = "GET",
        is_form: bool = False,
    ) -> list[dict]:
        source_url = source_url or ""
        candidates = []
        for key, value in params.items():
            if not self._looks_like_idor_key(key, value):
                continue
            if not value:
                continue
            candidates.append(
                {
                    "source_url": source_url,
                    "method": method,
                    "param": key,
                    "value": value,
                    "data": dict(params),
                    "is_form": is_form,
                }
            )
        return candidates

    async def _idor_request(self, client: httpx.AsyncClient, url: str, method: str, data: dict[str, str]):
        if method.upper() == "POST":
            return await client.post(url, data=data)
        return await client.get(url, params=data)

    def _looks_like_idor_key(self, key: str, value: str) -> bool:
        key_l = key.lower()
        if re.search(r"(^|_)(id|uid|uuid|guid|pk|user_id|account_id|order_id|record_id|doc_id|file_id)$", key_l):
            return True
        if value.isdigit() and re.search(r"(id|uid|guid|num|no|ref|oid|pid)$", key_l):
            return True
        if re.fullmatch(r"[0-9a-fA-F-]{8,36}", value) and re.search(r"(id|uid|uuid|guid)$", key_l):
            return True
        return False

    def _idor_alternatives(self, value: str) -> list[str]:
        if value.isdigit():
            n = int(value)
            return [str(n + 1), str(max(n - 1, 0)), str(n + 10), "1", "0"]
        if re.fullmatch(r"[0-9a-fA-F-]{8,36}", value):
            return [value[:-1] + "0", value[:-1] + "1", value[:-1] + "2"]
        if len(value) > 4:
            return [value[:-1] + "1", value[:-1] + "2", value[:-1] + "9"]
        return []

    def _idor_should_flag(self, baseline_text: str, test_text: str) -> bool:
        if not baseline_text or not test_text:
            return False
        if self._looks_like_error_page(test_text):
            return False
        ratio = SequenceMatcher(None, baseline_text, test_text).ratio()
        if ratio < 0.78:
            return True
        baseline_tokens = set(re.findall(r"[A-Za-z0-9_]{4,}", baseline_text.lower()))
        test_tokens = set(re.findall(r"[A-Za-z0-9_]{4,}", test_text.lower()))
        token_delta = len(test_tokens.symmetric_difference(baseline_tokens))
        return token_delta >= 8 and abs(len(baseline_text) - len(test_text)) > 40

    def _looks_like_error_page(self, text: str) -> bool:
        lower = text.lower()
        markers = ["not found", "forbidden", "unauthorized", "access denied", "error", "exception", "invalid"]
        return sum(1 for marker in markers if marker in lower) >= 2

    def _normalize_for_diff(self, text: str) -> str:
        return re.sub(r"\s+", " ", text).strip()

    def _check_security_misconfig(self, page: dict) -> list[dict]:
        findings: list[dict] = []
        url = page["url"]
        headers = {k.lower(): v for k, v in page.get("headers", {}).items()}

        csp = headers.get("content-security-policy", "")
        if not csp:
            findings.append(
                {
                    "vulnerability_type": "Security Misconfiguration",
                    "severity": "Medium",
                    "endpoint": url,
                    "evidence": "Missing Content-Security-Policy header.",
                    "vulnerable_snippet": "Content-Security-Policy header not present.",
                    "fix_snippet": "response.headers['Content-Security-Policy'] = \"default-src 'self'\"",
                }
            )
        else:
            csp_lower = csp.lower()
            for needle, evidence in [
                ("'unsafe-inline'", "CSP allows unsafe-inline, which weakens XSS protection."),
                ("'unsafe-eval'", "CSP allows unsafe-eval, which weakens XSS protection."),
                ("data:", "CSP allows data: URIs, which can weaken script restrictions."),
                ("*", "CSP uses a wildcard source, which weakens the policy."),
            ]:
                if needle in csp_lower:
                    findings.append(
                        {
                            "vulnerability_type": "Weak Content-Security-Policy",
                            "severity": "Low",
                            "endpoint": url,
                            "evidence": evidence,
                            "vulnerable_snippet": csp[:300],
                            "fix_snippet": "Remove unsafe-inline/unsafe-eval, avoid wildcards, and prefer self-hosted sources or nonces.",
                        }
                    )
                    break

        xfo = headers.get("x-frame-options", "").strip().upper()
        if not xfo:
            findings.append(
                {
                    "vulnerability_type": "Security Misconfiguration",
                    "severity": "Medium",
                    "endpoint": url,
                    "evidence": "Missing X-Frame-Options header.",
                    "vulnerable_snippet": "X-Frame-Options header not present.",
                    "fix_snippet": "response.headers['X-Frame-Options'] = 'DENY'",
                }
            )
        elif xfo not in {"DENY", "SAMEORIGIN"}:
            findings.append(
                {
                    "vulnerability_type": "Weak X-Frame-Options",
                    "severity": "Low",
                    "endpoint": url,
                    "evidence": f"Unexpected X-Frame-Options value: {xfo}",
                    "vulnerable_snippet": f"X-Frame-Options: {xfo}",
                    "fix_snippet": "Set X-Frame-Options to DENY or SAMEORIGIN.",
                }
            )

        xcto = headers.get("x-content-type-options", "").strip().lower()
        if not xcto:
            findings.append(
                {
                    "vulnerability_type": "Security Misconfiguration",
                    "severity": "Low",
                    "endpoint": url,
                    "evidence": "Missing X-Content-Type-Options header.",
                    "vulnerable_snippet": "X-Content-Type-Options header not present.",
                    "fix_snippet": "response.headers['X-Content-Type-Options'] = 'nosniff'",
                }
            )
        elif xcto != "nosniff":
            findings.append(
                {
                    "vulnerability_type": "Weak X-Content-Type-Options",
                    "severity": "Low",
                    "endpoint": url,
                    "evidence": f"Unexpected X-Content-Type-Options value: {xcto}",
                    "vulnerable_snippet": f"X-Content-Type-Options: {xcto}",
                    "fix_snippet": "Set X-Content-Type-Options to nosniff.",
                }
            )

        if url.startswith("https://"):
            hsts = headers.get("strict-transport-security", "")
            if not hsts:
                findings.append(
                    {
                        "vulnerability_type": "Security Misconfiguration",
                        "severity": "Medium",
                        "endpoint": url,
                        "evidence": "Missing Strict-Transport-Security header on HTTPS response.",
                        "vulnerable_snippet": "Strict-Transport-Security header not present.",
                        "fix_snippet": "response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'",
                    }
                )
            else:
                hsts_lower = hsts.lower()
                max_age_match = re.search(r"max-age=(\d+)", hsts_lower)
                max_age = int(max_age_match.group(1)) if max_age_match else 0
                if max_age < 15552000:
                    findings.append(
                        {
                            "vulnerability_type": "Weak HSTS Policy",
                            "severity": "Low",
                            "endpoint": url,
                            "evidence": f"HSTS max-age is too low or missing: {hsts}",
                            "vulnerable_snippet": hsts[:300],
                            "fix_snippet": "Use a long HSTS max-age such as max-age=31536000 and includeSubDomains when appropriate.",
                        }
                    )

        findings.extend(self._check_cookie_flags(url, page.get("set_cookie_headers", [])))
        return findings

    def _check_cookie_flags(self, url: str, set_cookie_headers: list[str]) -> list[dict]:
        findings: list[dict] = []
        for raw_cookie in set_cookie_headers:
            if not raw_cookie:
                continue

            cookie = SimpleCookie()
            try:
                cookie.load(raw_cookie)
            except Exception:
                continue

            attrs = [part.strip().lower() for part in raw_cookie.split(";")[1:]]
            for name in cookie.keys():
                secure = "secure" in attrs
                httponly = "httponly" in attrs
                samesite = ""
                for attr in attrs:
                    if attr.startswith("samesite="):
                        samesite = attr.split("=", 1)[1].strip()
                        break

                issues = []
                if not secure:
                    issues.append("missing Secure flag")
                if not httponly:
                    issues.append("missing HttpOnly flag")
                if not samesite or samesite == "none":
                    issues.append("missing or weak SameSite attribute")

                if issues:
                    findings.append(
                        {
                            "vulnerability_type": "Insecure Cookie Attributes",
                            "severity": "Medium" if "missing Secure flag" in issues else "Low",
                            "endpoint": url,
                            "evidence": f"Cookie '{name}' issues: {', '.join(issues)}",
                            "vulnerable_snippet": raw_cookie[:300],
                            "fix_snippet": "Set Secure, HttpOnly, and SameSite=Strict (or Lax) on session cookies.",
                        }
                    )

        return findings

    def _check_leaked_assets(self, page: dict) -> list[dict]:
        """Check for leaked sensitive information in page content."""
        url = page["url"]
        body = page.get("text", "")

        if not body:
            return []

        findings = []
        leaked_assets = LeakedAssetDetector.detect_leaked_assets(body, url)

        for asset in leaked_assets:
            findings.append({
                "vulnerability_type": f"Leaked {asset['type']}",
                "severity": asset["severity"],
                "endpoint": asset["url"],
                "evidence": f"Potentially leaked {asset['type']}: {asset['value'][:50]}{'...' if len(asset['value']) > 50 else ''}",
                "vulnerable_snippet": self._snippet(body, asset["value"]),
                "fix_snippet": f"Remove exposed {asset['type'].lower()} from public pages. Store sensitive data securely and never expose in client-side code or responses.",
            })

        return findings

    def _snippet(self, text: str, needle: str, radius: int = 140) -> str:
        idx = text.lower().find(needle.lower())
        if idx == -1:
            return text[: radius * 2]
        start = max(0, idx - radius)
        end = min(len(text), idx + radius)
        return text[start:end]
