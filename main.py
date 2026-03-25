from __future__ import annotations

import argparse
from pathlib import Path

from auditcrawl.config import ScanConfig
from auditcrawl.orchestrator import Scanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auditcrawl",
        description="Educational web app security scanner (safe and non-destructive by default).",
    )
    parser.add_argument("--base-url", required=True, help="Start URL for crawling")
    parser.add_argument("--target-domain", required=True, help="Target domain scope (e.g., example.com)")
    parser.add_argument("--allowed-subdomains", action="store_true", help="Allow crawling *.target-domain")
    parser.add_argument("--max-depth", type=int, default=4)
    parser.add_argument("--max-pages", type=int, default=500)
    parser.add_argument("--output-dir", default="output")
    parser.add_argument("--ignore-path", action="append", default=[])
    parser.add_argument("--safe-mode", action="store_true", default=True)
    parser.add_argument("--lab-mode", action="store_true")

    parser.add_argument("--xss", action="store_true")
    parser.add_argument("--sqli", action="store_true")
    parser.add_argument("--ssrf", action="store_true")
    parser.add_argument("--auth", action="store_true")
    parser.add_argument("--rce", action="store_true")

    parser.add_argument("--auth-login-url", default=None)
    parser.add_argument("--auth-logout-url", default=None)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    any_module_flag = any([args.xss, args.sqli, args.ssrf, args.auth, args.rce])

    config = ScanConfig(
        base_url=args.base_url,
        target_domain=args.target_domain,
        allowed_subdomains=args.allowed_subdomains,
        max_depth=args.max_depth,
        max_pages=args.max_pages,
        output_dir=args.output_dir,
        ignore_paths=args.ignore_path,
        safe_mode=args.safe_mode,
        lab_mode=args.lab_mode,
        enable_xss=args.xss if any_module_flag else True,
        enable_sqli=args.sqli if any_module_flag else True,
        enable_ssrf=args.ssrf if any_module_flag else True,
        enable_auth=args.auth if any_module_flag else True,
        enable_rce=args.rce if any_module_flag else True,
        enable_time_based_sqli=False,
        auth_login_url=args.auth_login_url,
        auth_logout_url=args.auth_logout_url,
    )

    scanner = Scanner(config)
    result = scanner.run()

    print("=== AuditCrawl Scan Complete ===")
    print(f"Endpoints discovered: {len(result.endpoints)}")
    print(f"Findings: {len(result.findings)}")
    print(f"JSON report: {result.findings_json_path}")
    print(f"HTML report: {result.report_html_path}")
    print(f"Markdown report: {result.report_markdown_path}")
    print("Educational-only: scan only systems you own or are explicitly authorized to test.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
