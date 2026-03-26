from __future__ import annotations

import argparse
import sys
from pathlib import Path

from auditcrawl.config import ScanConfig
from auditcrawl.orchestrator import Scanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auditcrawl",
        description="AuditCrawl — educational web application security scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py --base-url http://localhost:5000 --target-domain localhost --lab-mode\n"
            "  python main.py --base-url http://localhost:5000 --target-domain localhost --xss --sqli\n"
            "\n"
            "IMPORTANT: Only scan systems you own or have explicit written permission to test."
        ),
    )

    # Target
    parser.add_argument("--base-url", required=True, help="Start URL for crawling")
    parser.add_argument("--target-domain", required=True, help="Target domain scope (e.g., localhost)")
    parser.add_argument("--allowed-subdomains", action="store_true", help="Allow *.target-domain")

    # Crawl limits
    parser.add_argument("--max-depth", type=int, default=4, help="Max crawl depth (default: 4)")
    parser.add_argument("--max-pages", type=int, default=500, help="Max pages to crawl (default: 500)")
    parser.add_argument("--ignore-path", action="append", default=[], metavar="REGEX",
                        help="Regex patterns for paths to skip (repeatable)")
    parser.add_argument("--delay", type=float, default=0.1, metavar="SECONDS",
                        help="Delay between requests in seconds (default: 0.1)")

    # Mode
    parser.add_argument("--safe-mode", action="store_true", default=True,
                        help="Safe mode — no destructive actions (default: on)")
    parser.add_argument("--lab-mode", action="store_true",
                        help="Lab mode — enables time-based SQLi, default creds, aggressive checks")

    # Module selection (if none given, all are enabled)
    parser.add_argument("--xss", action="store_true", help="Enable XSS module")
    parser.add_argument("--sqli", action="store_true", help="Enable SQLi module")
    parser.add_argument("--ssrf", action="store_true", help="Enable SSRF module")
    parser.add_argument("--auth", action="store_true", help="Enable auth/session module")
    parser.add_argument("--rce", action="store_true", help="Enable RCE surface module")
    parser.add_argument("--idor", action="store_true", help="Enable IDOR module")
    parser.add_argument("--csrf", action="store_true", help="Enable CSRF module")
    parser.add_argument("--headers", action="store_true", help="Enable security headers module")
    parser.add_argument("--open-redirect", action="store_true", help="Enable open redirect module")

    # Auth
    parser.add_argument("--auth-login-url", default=None, help="Login form URL")
    parser.add_argument("--auth-logout-url", default=None, help="Logout URL")
    parser.add_argument("--auth-username", default=None, help="Login username")
    parser.add_argument("--auth-password", default=None, help="Login password")
    parser.add_argument("--auth-username-field", default="username", help="Username field name")
    parser.add_argument("--auth-password-field", default="password", help="Password field name")

    # Output
    parser.add_argument("--output-dir", default="output", help="Output directory (default: output)")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    any_module = any([
        args.xss, args.sqli, args.ssrf, args.auth, args.rce,
        args.idor, args.csrf, args.headers, args.open_redirect,
    ])

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
        request_delay=args.delay,

        # If no module flag given → enable all
        enable_xss=args.xss if any_module else True,
        enable_sqli=args.sqli if any_module else True,
        enable_ssrf=args.ssrf if any_module else True,
        enable_auth=args.auth if any_module else True,
        enable_rce=args.rce if any_module else True,
        enable_idor=args.idor if any_module else True,
        enable_csrf=args.csrf if any_module else True,
        enable_headers=args.headers if any_module else True,
        enable_open_redirect=args.open_redirect if any_module else True,
        enable_time_based_sqli=args.lab_mode,

        auth_login_url=args.auth_login_url,
        auth_logout_url=args.auth_logout_url,
        auth_username=args.auth_username,
        auth_password=args.auth_password,
        auth_username_field=args.auth_username_field,
        auth_password_field=args.auth_password_field,
    )

    print("=" * 60)
    print("  AuditCrawl — Educational Web Security Scanner")
    print("=" * 60)
    print(f"  Target   : {config.base_url}")
    print(f"  Domain   : {config.target_domain}")
    print(f"  Lab mode : {'yes' if config.lab_mode else 'no'}")
    print(f"  Output   : {config.output_dir}/")
    print("=" * 60)
    print("  WARNING: Only scan systems you own or have")
    print("           explicit written permission to test.")
    print("=" * 60)
    print()

    scanner = Scanner(config)

    def on_progress(stage, message, pct):
        bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
        print(f"  [{bar}] {pct:3d}%  {message}")

    scanner.set_progress_callback(on_progress)
    result = scanner.run()

    print()
    print("=" * 60)
    print("  Scan Complete")
    print("=" * 60)
    sev = result.summary_by_severity()
    print(f"  Endpoints : {len(result.endpoints)}")
    print(f"  Findings  : {len(result.findings)}")
    print(f"    Critical: {sev['critical']}")
    print(f"    High    : {sev['high']}")
    print(f"    Medium  : {sev['medium']}")
    print(f"    Low     : {sev['low']}")
    print(f"    Info    : {sev['info']}")
    print(f"  Duration  : {result.duration_seconds:.1f}s")
    print()
    print(f"  JSON    → {result.findings_json_path}")
    print(f"  HTML    → {result.report_html_path}")
    print(f"  Markdown→ {result.report_markdown_path}")
    print(f"  Log     → {result.scan_log_path}")
    print("=" * 60)
    print("  Educational use only — PoCs require explicit permission.")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())