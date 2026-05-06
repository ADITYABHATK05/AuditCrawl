from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os


@dataclass
class Settings:
    app_name: str = "AuditCrawl API"
    db_url: str = "sqlite+aiosqlite:///./auditcrawl_scans.db"
    output_dir: str = str(Path(__file__).resolve().parents[2] / "output")
    # CORS origins - can be overridden with ALLOWED_ORIGINS env var (comma-separated)
    allowed_origins: list[str] = None
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    backend_url: str = os.getenv("BACKEND_URL", "http://localhost:8000")
    
    def __post_init__(self):
        if self.allowed_origins is None:
            # Default origins if not specified
            allowed_env = os.getenv("ALLOWED_ORIGINS")
            if allowed_env:
                self.allowed_origins = [origin.strip() for origin in allowed_env.split(",")]
            else:
                self.allowed_origins = [
                    "http://localhost:5173",
                    "http://127.0.0.1:5173",
                    "http://localhost:3000",
                    "http://127.0.0.1:3000",
                ]
        # Always allow requests from same origin (dynamic localhost detection)
        if "*" not in self.allowed_origins:
            self.allowed_origins = list(set(self.allowed_origins))  # Remove duplicates


settings = Settings()
