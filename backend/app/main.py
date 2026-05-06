from __future__ import annotations
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api.routes import router as api_router
from app.core.config import settings
from app.db.database import engine
from app.db.models import Base
from app.services.job_queue import job_manager


app = FastAPI(title=settings.app_name)

# Use allowed origins from settings (respects ALLOWED_ORIGINS env var)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    # Vite often auto-increments ports (5173, 5174, ...). Allow localhost/127.0.0.1 on 5170-5179 by regex.
    allow_origin_regex=r"^http://(localhost|127\.0\.0\.1):517\d$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

# Ensure the directory exists before mounting StaticFiles to prevent startup crash
os.makedirs(settings.output_dir, exist_ok=True)
app.mount("/output", StaticFiles(directory=settings.output_dir), name="output")


@app.on_event("startup")
async def startup_event() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await job_manager.start()
    # Non-fatal startup hint for email configuration
    if not settings.smtp_host:
        print("Email reports: SMTP_HOST not set (email sending disabled).")


@app.on_event("shutdown")
async def shutdown_event() -> None:
    await job_manager.shutdown()


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}