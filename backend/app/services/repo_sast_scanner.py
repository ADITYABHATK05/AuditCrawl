from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from app.services.leaked_asset_detector import LeakedAssetDetector


_DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    "coverage",
    ".idea",
    ".vscode",
}

_DEFAULT_EXCLUDE_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".7z",
    ".rar",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".class",
    ".jar",
    ".pyc",
    ".pyo",
    ".wasm",
    ".mp4",
    ".mp3",
}


@dataclass(frozen=True)
class RepoFinding:
    type: str
    severity: str
    url: str
    evidence: str
    vulnerable_snippet: str
    fix_snippet: str


def _is_binary_bytes(chunk: bytes) -> bool:
    # Simple heuristic: NUL byte => likely binary
    return b"\x00" in chunk


def iter_repo_files(root_dir: Path) -> Iterable[Path]:
    for base, dirs, files in os.walk(root_dir):
        base_path = Path(base)

        # prune excluded dirs in-place
        dirs[:] = [d for d in dirs if d not in _DEFAULT_EXCLUDE_DIRS and not d.startswith(".git")]

        for name in files:
            path = base_path / name
            yield path


def scan_repo_for_secrets_and_misconfig(root_dir: Path) -> tuple[list[RepoFinding], list[dict[str, str]]]:
    """
    Lightweight SAST pass:
    - hardcoded secrets / keys via regex
    - insecure config flags via regex
    - leaked assets via existing LeakedAssetDetector patterns
    """
    root_dir = root_dir.resolve()
    findings: list[RepoFinding] = []
    leaked_assets_out: list[dict[str, str]] = []

    insecure_config_rules: list[tuple[str, str, re.Pattern[str], str]] = [
        (
            "Debug mode enabled",
            "Medium",
            re.compile(r"(?i)\bdebug\s*[:=]\s*(true|1)\b"),
            "Disable debug mode in production builds and ensure it is controlled via environment configuration.",
        ),
        (
            "Insecure CORS wildcard",
            "Medium",
            re.compile(r"(?i)\baccess-control-allow-origin\b.*\*|\ballow_origins\b.*\*|\bcors\b.*\*"),
            "Avoid permissive CORS. Use an allow-list of trusted origins.",
        ),
        (
            "TLS/SSL verification disabled",
            "High",
            re.compile(r"(?i)\bverify\s*=\s*False\b|\bssl_verify\s*[:=]\s*false\b|\brejectUnauthorized\s*:\s*false\b"),
            "Do not disable TLS verification. If needed for dev, gate it behind a development-only setting.",
        ),
        (
            "Hardcoded application secret",
            "High",
            re.compile(r"(?i)\b(secret_key|flask_secret_key|django_secret_key|jwt_secret|session_secret)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
            "Move secrets into environment variables or a secret manager; rotate the exposed secret immediately.",
        ),
        (
            "Use of eval/Function",
            "High",
            re.compile(r"(?i)\beval\s*\(|\bnew\s+Function\s*\("),
            "Avoid eval/Function. Use safe parsers or strict allow-lists; treat evaluated input as untrusted.",
        ),
        (
            "Potential command injection (shell=True)",
            "High",
            re.compile(r"(?i)\bshell\s*=\s*True\b"),
            "Avoid `shell=True` and pass command args as a list. Validate/allow-list any user-influenced input.",
        ),
        (
            "Insecure deserialization (pickle/yaml.load)",
            "High",
            re.compile(r"(?i)\bpickle\.loads?\s*\(|\byaml\.load\s*\("),
            "Avoid unsafe deserialization. Use `yaml.safe_load` and never unpickle untrusted data.",
        ),
        (
            "Weak TLS settings (TLSv1/SSLv3)",
            "High",
            re.compile(r"(?i)\bTLSv1\b|\bSSLv3\b"),
            "Disable legacy TLS versions; enforce TLS 1.2+ (ideally TLS 1.3).",
        ),
        (
            "Insecure randomness (Math.random)",
            "Medium",
            re.compile(r"(?i)\bMath\.random\s*\("),
            "Do not use Math.random() for secrets/tokens. Use a cryptographically secure RNG.",
        ),
    ]

    # Generic “password/token/key = …” assignments (broad, but useful)
    generic_secret_assignment = re.compile(
        r"(?i)\b(password|passwd|pwd|api[_-]?key|secret|token|auth[_-]?token|access[_-]?token)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"
    )

    # Heuristic sinks/sources for common vulns (regex-only, best-effort)
    sql_concat = re.compile(r"(?i)\b(select|update|insert|delete)\b.*(['\"][^'\"]*['\"]\s*\+\s*|\%\s*\(|f['\"])")
    xss_sink_js = re.compile(r"(?i)\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write)\b")
    flask_debug_run = re.compile(r"(?i)\bapp\.run\s*\(.*debug\s*=\s*True")
    jwt_none_alg = re.compile(r"(?i)alg['\"]?\s*[:=]\s*['\"]none['\"]")

    for path in iter_repo_files(root_dir):
        try:
            if path.suffix.lower() in _DEFAULT_EXCLUDE_SUFFIXES:
                continue
            if not path.is_file():
                continue

            # Size guard (avoid huge files)
            try:
                if path.stat().st_size > 1_000_000:
                    continue
            except OSError:
                continue

            with path.open("rb") as f:
                head = f.read(4096)
                if _is_binary_bytes(head):
                    continue
                rest = f.read()
            raw = head + rest
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            continue

        rel = str(path.relative_to(root_dir)).replace("\\", "/")

        # Leaked asset detector (returns {type,value,url,severity})
        for asset in LeakedAssetDetector.detect_leaked_assets(text, rel):
            leaked_assets_out.append(
                {
                    "asset_type": asset["type"],
                    "value": asset["value"],
                    "severity": asset["severity"],
                    "endpoint": rel,
                }
            )

        # Line-based regex scanning
        for i, line in enumerate(text.splitlines(), start=1):
            line_stripped = line.strip()
            if not line_stripped:
                continue

            if generic_secret_assignment.search(line_stripped):
                findings.append(
                    RepoFinding(
                        type="Hardcoded secret assignment",
                        severity="High",
                        url=rel,
                        evidence=f"{rel}:{i} suspicious credential-like assignment",
                        vulnerable_snippet=line_stripped[:300],
                        fix_snippet="Replace hardcoded secrets with environment variables or a secrets manager; rotate any exposed credentials.",
                    )
                )

            for rule_name, sev, pattern, remediation in insecure_config_rules:
                if pattern.search(line_stripped):
                    findings.append(
                        RepoFinding(
                            type=rule_name,
                            severity=sev,
                            url=rel,
                            evidence=f"{rel}:{i} matched insecure configuration pattern",
                            vulnerable_snippet=line_stripped[:300],
                            fix_snippet=remediation,
                        )
                    )

            # Additional “actual vulnerability” heuristics (best-effort)
            if flask_debug_run.search(line_stripped):
                findings.append(
                    RepoFinding(
                        type="Flask debug server enabled",
                        severity="High",
                        url=rel,
                        evidence=f"{rel}:{i} Flask app.run(debug=True) detected",
                        vulnerable_snippet=line_stripped[:300],
                        fix_snippet="Never run Flask with debug=True in production. Use a production WSGI server and disable debug.",
                    )
                )

            if jwt_none_alg.search(line_stripped):
                findings.append(
                    RepoFinding(
                        type="JWT alg=none usage",
                        severity="Critical",
                        url=rel,
                        evidence=f"{rel}:{i} JWT header indicates alg=none",
                        vulnerable_snippet=line_stripped[:300],
                        fix_snippet="Disallow alg=none; enforce a signed JWT algorithm and verify signatures server-side.",
                    )
                )

            if sql_concat.search(line_stripped):
                findings.append(
                    RepoFinding(
                        type="Potential SQL injection (string-built query)",
                        severity="High",
                        url=rel,
                        evidence=f"{rel}:{i} query appears to be constructed via string concatenation/interpolation",
                        vulnerable_snippet=line_stripped[:300],
                        fix_snippet="Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
                    )
                )

            if xss_sink_js.search(line_stripped) and ("sanitize" not in line_stripped.lower()):
                findings.append(
                    RepoFinding(
                        type="Potential XSS sink usage (dangerous DOM APIs)",
                        severity="Medium",
                        url=rel,
                        evidence=f"{rel}:{i} dangerous DOM sink used; ensure input is sanitized/escaped",
                        vulnerable_snippet=line_stripped[:300],
                        fix_snippet="Avoid dangerous sinks or sanitize with a proven library (e.g., DOMPurify) and prefer textContent.",
                    )
                )

    # De-dup findings
    seen = set()
    deduped: list[RepoFinding] = []
    for f in findings:
        key = (f.type, f.url, f.vulnerable_snippet)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)

    # De-dup leaked assets
    seen_assets = set()
    deduped_assets: list[dict[str, str]] = []
    for a in leaked_assets_out:
        key = (a["asset_type"], a["endpoint"], a["value"])
        if key in seen_assets:
            continue
        seen_assets.add(key)
        deduped_assets.append(a)

    return deduped, deduped_assets

