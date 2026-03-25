from __future__ import annotations

import hashlib
from typing import Dict
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse


STATIC_EXTENSIONS = {
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".pdf",
    ".zip",
    ".rar",
    ".7z",
    ".mp4",
    ".mp3",
}


def normalize_url(base: str, href: str) -> str:
    joined = urljoin(base, href)
    parsed = urlparse(joined)
    normalized = parsed._replace(fragment="")
    clean = urlunparse(normalized)
    return clean


def get_query_params(url: str) -> Dict[str, str]:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    return {k: v[0] if v else "" for k, v in qs.items()}


def response_fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:16]


def is_static_path(path: str) -> bool:
    lower = path.lower()
    return any(lower.endswith(ext) for ext in STATIC_EXTENSIONS)


def belongs_to_domain(hostname: str, target_domain: str, allowed_subdomains: bool) -> bool:
    if hostname is None:
        return False
    if hostname == target_domain:
        return True
    if allowed_subdomains and hostname.endswith("." + target_domain):
        return True
    return False
