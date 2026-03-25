from __future__ import annotations

import time
from collections import deque
from typing import Dict, List, Set, Tuple
from urllib import robotparser
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from .config import ScanConfig
from .models import Endpoint
from .utils import belongs_to_domain, get_query_params, is_static_path, normalize_url


class WebCrawler:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.config.user_agent})
        self.seen_pages: Set[str] = set()
        self.seen_testables: Set[Tuple[str, str]] = set()
        self.robots = robotparser.RobotFileParser()
        if self.config.respect_robots_txt:
            robots_url = normalize_url(self.config.base_url, "/robots.txt")
            self.robots.set_url(robots_url)
            try:
                self.robots.read()
            except Exception:
                pass

    def _is_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        if not belongs_to_domain(parsed.hostname or "", self.config.target_domain, self.config.allowed_subdomains):
            return False
        if is_static_path(parsed.path):
            return False
        for ignored in self.config.ignore_paths:
            if parsed.path.startswith(ignored):
                return False
        if self.config.respect_robots_txt:
            try:
                if not self.robots.can_fetch(self.config.user_agent, url):
                    return False
            except Exception:
                return False
        return True

    def _extract_form_endpoint(self, page_url: str, form, depth: int) -> Endpoint:
        method = (form.get("method") or "GET").upper()
        action = form.get("action") or page_url
        form_url = normalize_url(page_url, action)

        fields: List[str] = []
        for tag in form.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if name:
                fields.append(name)

        return Endpoint(
            url=form_url,
            method=method,
            parameters=fields,
            form_fields=fields,
            form_action=action,
            depth=depth,
            source_url=page_url,
            content_type="text/html",
        )

    def crawl(self) -> List[Endpoint]:
        queue = deque([(self.config.base_url, 0)])
        testable: List[Endpoint] = []

        while queue and len(self.seen_pages) < self.config.max_pages:
            current_url, depth = queue.popleft()
            if depth > self.config.max_depth:
                continue
            if current_url in self.seen_pages:
                continue
            if not self._is_allowed(current_url):
                continue

            self.seen_pages.add(current_url)
            try:
                resp = self.session.get(current_url, timeout=self.config.timeout_seconds)
            except requests.RequestException:
                continue

            content_type = resp.headers.get("Content-Type", "")
            params = list(get_query_params(current_url).keys())
            key = (current_url, "GET")
            if key not in self.seen_testables:
                self.seen_testables.add(key)
                testable.append(
                    Endpoint(
                        url=current_url,
                        method="GET",
                        parameters=params,
                        depth=depth,
                        source_url=current_url,
                        content_type=content_type,
                    )
                )

            if "json" in content_type.lower():
                # JSON endpoint discovered via content type.
                time.sleep(self.config.delay_seconds)
                continue

            soup = BeautifulSoup(resp.text, "lxml")

            for form in soup.find_all("form"):
                endpoint = self._extract_form_endpoint(current_url, form, depth)
                key = (endpoint.url, endpoint.method)
                if key not in self.seen_testables and self._is_allowed(endpoint.url):
                    self.seen_testables.add(key)
                    testable.append(endpoint)

            for a_tag in soup.find_all("a", href=True):
                candidate = normalize_url(current_url, a_tag["href"])
                if candidate not in self.seen_pages and self._is_allowed(candidate):
                    queue.append((candidate, depth + 1))

            time.sleep(self.config.delay_seconds)

        return testable
