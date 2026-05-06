from __future__ import annotations
import asyncio
import logging
import re
from typing import List, Set
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from .config import ScanConfig
from .http_client import HttpClient
from .models import Endpoint

logger = logging.getLogger("auditcrawl.crawler")


class Crawler:
    """Discovers endpoints and forms within the target scope."""

    def __init__(self, config: ScanConfig, client: HttpClient) -> None:
        self.config = config
        self.client = client
        self.visited: Set[str] = set()
        self.endpoints: List[Endpoint] = []
        self._ignore_patterns = [re.compile(p) for p in config.ignore_paths]

    def _should_ignore(self, url: str) -> bool:
        path = urlparse(url).path
        for pattern in self._ignore_patterns:
            if pattern.search(path):
                return True
        # Ignore common static files by default
        ext = path.split('.')[-1].lower()
        if ext in ('png', 'jpg', 'jpeg', 'gif', 'svg', 'css', 'js', 'ico', 'woff', 'woff2', 'ttf'):
            return True
        return False

    def crawl(self) -> List[Endpoint]:
        return asyncio.run(self.crawl_async())

    async def crawl_async(self) -> List[Endpoint]:
        start_url = self.config.base_url
        queue = [(start_url, 0)]
        
        print(f"\n{'='*60}")
        print(f"CRAWLER STARTING")
        print(f"  Base URL: {start_url}")
        print(f"  Target Domain: {self.config.target_domain}")
        print(f"  Max Depth: {self.config.max_depth}")
        print(f"  Max Pages: {self.config.max_pages}")
        print(f"{'='*60}\n")

        while queue and len(self.visited) < self.config.max_pages:
            url, depth = queue.pop(0)

            # Strip fragments for deduplication
            clean_url = url.split('#')[0]

            if clean_url in self.visited:
                print(f"[SKIP] Already visited: {clean_url}")
                continue
            if not self.client.is_in_scope(clean_url):
                print(f"[SKIP] Out of scope: {clean_url}")
                continue
            if self._should_ignore(clean_url):
                print(f"[SKIP] Ignored pattern: {clean_url}")
                continue
            if depth > self.config.max_depth:
                print(f"[SKIP] Over max depth ({depth}): {clean_url}")
                continue

            self.visited.add(clean_url)
            logger.debug(f"Crawling [{depth}]: {clean_url}")
            print(f"[CRAWL] Fetching [{depth}]: {clean_url}")

            resp = await self.client.get_async(clean_url)
            # requests.Response is falsy for HTTP >= 400; we still want to record/scan it.
            if resp is None:
                print(f"[ERROR] No response from {clean_url}")
                continue
            
            print(f"[SUCCESS] {resp.status_code} from {clean_url}")

            content_type = resp.headers.get("Content-Type", "")
            print(f"  Content-Type: {content_type}")
            
            endpoint = Endpoint(
                url=clean_url,
                method="GET",
                depth=depth,
                content_type=content_type,
                status_code=resp.status_code,
                response_text=resp.text
            )

            # Only parse HTML for links and forms
            if "text/html" in content_type:
                try:
                    soup = BeautifulSoup(resp.text, "html.parser")
                    
                    # Extract links
                    links = soup.find_all("a", href=True)
                    print(f"  Found {len(links)} links")
                    for a in links:
                        href = a["href"]
                        full_url = urljoin(clean_url, href)
                        if self.client.is_in_scope(full_url) and not self._should_ignore(full_url):
                            queue.append((full_url, depth + 1))
                            print(f"    > Added to queue: {full_url}")
                        
                    # Extract forms
                    forms = []
                    for form_tag in soup.find_all("form"):
                        action = form_tag.get("action", "")
                        method = form_tag.get("method", "GET").upper()
                        full_action = urljoin(clean_url, action)
                        
                        inputs = []
                        for inp in form_tag.find_all(["input", "select", "textarea"]):
                            name = inp.get("name")
                            if not name:
                                continue
                            inp_type = inp.get("type", "text").lower()
                            value = inp.get("value", "")
                            inputs.append({"name": name, "type": inp_type, "value": value})
                            
                        forms.append({
                            "action": full_action,
                            "method": method,
                            "inputs": inputs
                        })
                    print(f"  Found {len(forms)} forms")
                    endpoint.forms = forms
                except Exception as e:
                    print(f"  [PARSE ERROR] {e}")

            self.endpoints.append(endpoint)
            print(f"  OK Added endpoint #{len(self.endpoints)}")

        print(f"\n{'='*60}")
        print(f"CRAWLER COMPLETE: {len(self.endpoints)} endpoints discovered")
        print(f"{'='*60}\n")
        return self.endpoints