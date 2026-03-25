from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
import re
from typing import Awaitable, Callable, Optional

import httpx
from bs4 import BeautifulSoup

from app.services.snippet_library import fix_snippet_for


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
        )
        if progress_cb:
            await progress_cb(25, f"Crawl complete. {len(pages)} pages discovered")

        findings: list[dict] = []
        async with httpx.AsyncClient(timeout=12, follow_redirects=True, verify=False) as client:
            total_pages = max(1, len(pages))
            for idx, page in enumerate(pages, start=1):
                findings.extend(await self._check_reflected_xss(client, page))
                findings.extend(await self._check_sqli_symptoms(client, page))
                findings.extend(self._check_ssrf_surface(page))
                findings.extend(self._check_security_misconfig(page))
                if progress_cb:
                    progress = 25 + int((idx / total_pages) * 60)
                    await progress_cb(min(progress, 90), f"Analyzed {idx}/{total_pages} pages")

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

    async def _crawl(
        self,
        base_url: str,
        max_pages: int,
        max_depth: int,
        crawl_progress_cb: Optional[Callable[[int, int], Awaitable[None]]] = None,
    ) -> list[dict]:
        pages: list[dict] = []
        seen = set()
        queue = [(base_url, 0)]
        origin = urlparse(base_url).netloc

        async with httpx.AsyncClient(timeout=12, follow_redirects=True, verify=False) as client:
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
                    for elem in form.find_all(["input", "textarea", "select"]):
                        name = elem.get("name")
                        if name:
                            fields.append(name)
                    if fields:
                        forms.append({"url": form_url, "method": method, "fields": fields})

                page = {
                    "url": url,
                    "html": html,
                    "soup": soup,
                    "forms": forms,
                    "headers": dict(resp.headers),
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

    def _check_security_misconfig(self, page: dict) -> list[dict]:
        findings: list[dict] = []
        url = page["url"]
        headers = {k.lower(): v for k, v in page.get("headers", {}).items()}

        missing_headers = [
            ("content-security-policy", "Missing Content-Security-Policy header", "Low"),
            ("x-frame-options", "Missing X-Frame-Options header", "Low"),
            ("x-content-type-options", "Missing X-Content-Type-Options header", "Low"),
        ]
        for header_name, evidence, severity in missing_headers:
            if header_name not in headers:
                findings.append(
                    {
                        "vulnerability_type": "Security Misconfiguration",
                        "severity": severity,
                        "endpoint": url,
                        "evidence": evidence,
                        "vulnerable_snippet": f"Response header '{header_name}' is missing.",
                        "fix_snippet": (
                            "# Example secure headers\n"
                            "response.headers['Content-Security-Policy'] = \"default-src 'self'\"\n"
                            "response.headers['X-Frame-Options'] = 'DENY'\n"
                            "response.headers['X-Content-Type-Options'] = 'nosniff'\n"
                        ),
                    }
                )

        if url.startswith("https://") and "strict-transport-security" not in headers:
            findings.append(
                {
                    "vulnerability_type": "Security Misconfiguration",
                    "severity": "Medium",
                    "endpoint": url,
                    "evidence": "Missing HSTS header on HTTPS response.",
                    "vulnerable_snippet": "Strict-Transport-Security header not present.",
                    "fix_snippet": (
                        "response.headers['Strict-Transport-Security'] = "
                        "'max-age=31536000; includeSubDomains'"
                    ),
                }
            )

        return findings

    def _snippet(self, text: str, needle: str, radius: int = 140) -> str:
        idx = text.lower().find(needle.lower())
        if idx == -1:
            return text[: radius * 2]
        start = max(0, idx - radius)
        end = min(len(text), idx + radius)
        return text[start:end]
