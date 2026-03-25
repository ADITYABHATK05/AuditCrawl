from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from auditcrawl.config import ScanConfig
from auditcrawl.crawler import WebCrawler


def make_response(url: str, text: str, content_type: str = "text/html", status_code: int = 200):
    return SimpleNamespace(
        url=url,
        text=text,
        status_code=status_code,
        headers={"Content-Type": content_type},
    )


class CrawlerScopeTests(unittest.TestCase):
    def test_crawler_stays_in_scope_and_skips_static(self) -> None:
        config = ScanConfig(
            base_url="http://example.com",
            target_domain="example.com",
            max_depth=2,
            max_pages=10,
            respect_robots_txt=False,
            delay_seconds=0,
        )

        with patch("auditcrawl.crawler.requests.Session") as session_cls:
            session = MagicMock()
            session.headers = {}
            session_cls.return_value = session

            def fake_get(url, timeout=12):
                if url == "http://example.com":
                    return make_response(
                        url,
                        """
                        <a href='/page2'>internal</a>
                        <a href='http://outside.com/p'>external</a>
                        <a href='/assets/app.js'>static-js</a>
                        <form method='post' action='/submit'>
                          <input name='comment'/>
                        </form>
                        """,
                    )
                if url == "http://example.com/page2":
                    return make_response(url, "<p>ok</p>")
                raise RuntimeError(f"unexpected URL: {url}")

            session.get.side_effect = fake_get

            crawler = WebCrawler(config)
            endpoints = crawler.crawl()

        urls = {ep.url for ep in endpoints}
        self.assertIn("http://example.com", urls)
        self.assertIn("http://example.com/page2", urls)
        self.assertIn("http://example.com/submit", urls)
        self.assertNotIn("http://outside.com/p", urls)
        self.assertNotIn("http://example.com/assets/app.js", urls)

    def test_crawler_respects_max_depth(self) -> None:
        config = ScanConfig(
            base_url="http://example.com",
            target_domain="example.com",
            max_depth=1,
            max_pages=10,
            respect_robots_txt=False,
            delay_seconds=0,
        )

        with patch("auditcrawl.crawler.requests.Session") as session_cls:
            session = MagicMock()
            session.headers = {}
            session_cls.return_value = session

            def fake_get(url, timeout=12):
                if url == "http://example.com":
                    return make_response(url, "<a href='/l1'>l1</a>")
                if url == "http://example.com/l1":
                    return make_response(url, "<a href='/l2'>l2</a>")
                if url == "http://example.com/l2":
                    return make_response(url, "<p>too deep</p>")
                raise RuntimeError(f"unexpected URL: {url}")

            session.get.side_effect = fake_get

            crawler = WebCrawler(config)
            endpoints = crawler.crawl()

        urls = {ep.url for ep in endpoints}
        self.assertIn("http://example.com", urls)
        self.assertIn("http://example.com/l1", urls)
        self.assertNotIn("http://example.com/l2", urls)


if __name__ == "__main__":
    unittest.main()
