from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os


def _load_backend_env() -> None:
    """
    Load key=value pairs from backend/.env into process env.
    Existing environment variables are not overridden.
    """
    env_path = Path(__file__).resolve().parents[2] / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if key and key not in os.environ:
            os.environ[key] = value


_load_backend_env()


@dataclass
class Settings:
    app_name: str = "AuditCrawl API"
    db_url: str = "sqlite+aiosqlite:///./auditcrawl_scans.db"
    output_dir: str = str(Path(__file__).resolve().parents[2] / "output")
    # CORS origins - can be overridden with ALLOWED_ORIGINS env var (comma-separated)
    allowed_origins: list[str] = None
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    backend_url: str = os.getenv("BACKEND_URL", "http://localhost:8000")
    frontend_url: str = os.getenv("FRONTEND_URL", "http://localhost:5173")

    # SMTP settings for email reports
    smtp_host: str = os.getenv("SMTP_HOST", "")
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    smtp_user: str = os.getenv("SMTP_USER", "")
    smtp_password: str = os.getenv("SMTP_PASSWORD", "")
    smtp_from: str = os.getenv("SMTP_FROM", "auditcrawl@localhost")
    smtp_starttls: bool = os.getenv("SMTP_STARTTLS", "true").lower() in {"1", "true", "yes", "on"}
    
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
