from __future__ import annotations

import unittest
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from auditcrawl.audit_logger import AuditLogger
from auditcrawl.config import ScanConfig
from auditcrawl.models import Endpoint
from auditcrawl.scanners import SQLiScanner, XSSScanner


def make_response(url: str, text: str, status_code: int = 200, content_type: str = "text/html"):
    return SimpleNamespace(
        url=url,
        text=text,
        status_code=status_code,
        headers={"Content-Type": content_type},
    )


class FakeSession:
    def __init__(self) -> None:
        self.headers = {}
        self.stored_marker = ""

    def get(self, url, params=None, timeout=12):
        params = params or {}
        if url == "http://test.local/search":
            q = params.get("q", "")
            if q == "baseline":
                return make_response(url, "<html><body>clean baseline</body></html>")
            return make_response(url, f"<html><body><script>{q}</script></body></html>")

        if url == "http://test.local/guestbook":
            if self.stored_marker:
                return make_response(url, f"<html><div class='entry'>{self.stored_marker}</div></html>")
            return make_response(url, "<html><div class='entry'>empty</div></html>")

        if url == "http://test.local/item":
            item_id = params.get("id", "")
            if item_id == "1":
                return make_response(url, "<html>normal item page</html>")
            if item_id == "'":
                return make_response(url, "<html>SQL syntax error near ' at line 1</html>", status_code=500)
            return make_response(url, "<html>generic</html>")

        return make_response(url, "<html>ok</html>")

    def post(self, url, data=None, timeout=12):
        data = data or {}
        if url == "http://test.local/submit":
            comment = data.get("comment", "")
            if "AUDITCRAWL_XSS_" in comment:
                self.stored_marker = comment
            return make_response(url, "<html>submitted</html>")
        return make_response(url, "<html>posted</html>")


class ScannerHeuristicTests(unittest.TestCase):
    def _config(self) -> ScanConfig:
        return ScanConfig(
            base_url="http://test.local",
            target_domain="test.local",
            respect_robots_txt=False,
            delay_seconds=0,
            safe_mode=True,
            lab_mode=True,
        )

    def test_reflected_xss_detected_with_baseline_delta(self) -> None:
        with TemporaryDirectory() as tmp:
            logger = AuditLogger(output_dir=tmp, use_sqlite=False)
            scanner = XSSScanner(self._config(), logger, session=FakeSession())
            endpoints = [
                Endpoint(url="http://test.local/search", method="GET", parameters=["q"]),
            ]

            findings = scanner.scan(endpoints)

        reflected = [f for f in findings if f.vulnerability == "Reflected XSS"]
        self.assertTrue(reflected, "Expected reflected XSS finding")

    def test_stored_xss_requires_submit_then_fetch_correlation(self) -> None:
        with TemporaryDirectory() as tmp:
            logger = AuditLogger(output_dir=tmp, use_sqlite=False)
            scanner = XSSScanner(self._config(), logger, session=FakeSession())
            endpoints = [
                Endpoint(url="http://test.local/submit", method="POST", parameters=["comment"], form_fields=["comment"], source_url="http://test.local/guestbook"),
                Endpoint(url="http://test.local/guestbook", method="GET", parameters=[]),
            ]

            findings = scanner.scan(endpoints)

        stored = [f for f in findings if f.vulnerability == "Stored XSS"]
        self.assertTrue(stored, "Expected stored XSS finding")
        self.assertEqual("High", stored[0].risk)

    def test_sqli_error_based_marker_detection(self) -> None:
        with TemporaryDirectory() as tmp:
            logger = AuditLogger(output_dir=tmp, use_sqlite=False)
            scanner = SQLiScanner(self._config(), logger, session=FakeSession())
            endpoints = [
                Endpoint(url="http://test.local/item", method="GET", parameters=["id"]),
            ]

            findings = scanner.scan(endpoints)

        sqli = [f for f in findings if "SQL Injection" in f.vulnerability]
        self.assertTrue(sqli, "Expected SQLi finding")
        self.assertEqual("High", sqli[0].risk)


if __name__ == "__main__":
    unittest.main()
