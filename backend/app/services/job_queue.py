from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from uuid import uuid4

from app.api.schemas import ScanRequest, ScanResponse
from app.core.config import settings
from app.db.database import SessionLocal
from app.db.models import ScanRun, VulnerabilityFinding
from app.services.ai_helper import generate_summary_with_gemini
from app.services.exporter import export_findings
from app.services.scanner import WebScanner


@dataclass
class JobState:
    job_id: str
    payload: dict[str, Any]
    status: str = "queued"
    progress: int = 0
    message: str = "Queued"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    run_id: Optional[int] = None
    result: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    cancel_requested: bool = False


class ScanJobManager:
    def __init__(self) -> None:
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._jobs: dict[str, JobState] = {}
        self._worker_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        if self._worker_task and not self._worker_task.done():
            return
        self._worker_task = asyncio.create_task(self._worker_loop(), name="scan-job-worker")

    async def shutdown(self) -> None:
        if self._worker_task and not self._worker_task.done():
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass

    async def enqueue(self, payload: ScanRequest) -> JobState:
        await self.start()
        job_id = uuid4().hex
        job = JobState(job_id=job_id, payload=payload.model_dump())
        self._jobs[job_id] = job
        await self._queue.put(job_id)
        return job

    def get(self, job_id: str) -> Optional[JobState]:
        return self._jobs.get(job_id)

    def cancel(self, job_id: str) -> Optional[JobState]:
        job = self._jobs.get(job_id)
        if not job:
            return None
        if job.status in {"completed", "failed", "cancelled"}:
            return job
        job.cancel_requested = True
        if job.status == "queued":
            job.status = "cancelled"
            job.progress = 100
            job.message = "Scan cancelled"
            job.completed_at = datetime.utcnow().isoformat()
        else:
            job.message = "Cancellation requested"
        return job

    async def _worker_loop(self) -> None:
        while True:
            job_id = await self._queue.get()
            job = self._jobs.get(job_id)
            if not job:
                self._queue.task_done()
                continue

            if job.status == "cancelled" or job.cancel_requested:
                job.status = "cancelled"
                job.progress = 100
                job.message = "Scan cancelled"
                job.completed_at = datetime.utcnow().isoformat()
                self._queue.task_done()
                continue

            try:
                await self._run_job(job)
            except asyncio.CancelledError:
                job.status = "cancelled"
                job.progress = 100
                job.message = "Scan cancelled"
                job.completed_at = datetime.utcnow().isoformat()
            except Exception as exc:
                job.status = "failed"
                job.error = str(exc)
                job.progress = 100
                job.message = "Scan failed"
                job.completed_at = datetime.utcnow().isoformat()
            finally:
                self._queue.task_done()

    async def _run_job(self, job: JobState) -> None:
        payload = ScanRequest(**job.payload)

        if job.cancel_requested:
            raise asyncio.CancelledError()

        job.status = "running"
        job.started_at = datetime.utcnow().isoformat()
        job.progress = 2
        job.message = "Starting scan"

        async def on_progress(progress: int, message: str) -> None:
            if job.cancel_requested:
                raise asyncio.CancelledError()
            job.progress = max(job.progress, min(progress, 99))
            job.message = message

        scanner = WebScanner()
        findings = await scanner.scan(
            str(payload.target_url),
            payload.scan_level,
            payload.use_selenium,
            progress_cb=on_progress,
        )

        if job.cancel_requested:
            raise asyncio.CancelledError()

        job.message = "Persisting findings"
        async with SessionLocal() as session:
            run = ScanRun(target_url=str(payload.target_url), scan_level=payload.scan_level, status="completed")
            session.add(run)
            await session.flush()

            for f in findings:
                session.add(
                    VulnerabilityFinding(
                        scan_run_id=run.id,
                        vulnerability_type=f["vulnerability_type"],
                        severity=f["severity"],
                        endpoint=f["endpoint"],
                        evidence=f["evidence"],
                        vulnerable_snippet=f["vulnerable_snippet"],
                        fix_snippet=f["fix_snippet"],
                    )
                )

            await session.commit()

        payload_for_export = {
            "run_id": run.id,
            "target_url": str(payload.target_url),
            "scan_level": payload.scan_level,
            "findings": findings,
            "ai_summary": generate_summary_with_gemini(findings),
        }
        json_path, xml_path = export_findings(run.id, payload_for_export, settings.output_dir)

        response = ScanResponse(
            run_id=run.id,
            target_url=str(payload.target_url),
            scan_level=payload.scan_level,
            findings_count=len(findings),
            findings=findings,
            json_path=json_path,
            xml_path=xml_path,
        )

        job.run_id = run.id
        job.result = response.model_dump()
        job.status = "completed"
        job.progress = 100
        job.message = "Scan completed"
        job.completed_at = datetime.utcnow().isoformat()


job_manager = ScanJobManager()
