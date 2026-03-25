from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os


@dataclass
class Settings:
    app_name: str = "AuditCrawl API"
    db_url: str = "sqlite+aiosqlite:///./auditcrawl_scans.db"
    output_dir: str = str(Path(__file__).resolve().parents[2] / "output")
    allowed_origins: tuple[str, ...] = ("http://localhost:5173", "http://127.0.0.1:5173")
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")


settings = Settings()
