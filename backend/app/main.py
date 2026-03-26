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

# Define allowed origins to include both standard ports and your current Vite port
origins = [
    "http://localhost:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
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


@app.on_event("shutdown")
async def shutdown_event() -> None:
    await job_manager.shutdown()


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}