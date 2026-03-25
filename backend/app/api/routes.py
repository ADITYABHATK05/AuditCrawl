from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import (
    FindingOut,
    JobStatusResponse,
    ScanEnqueueResponse,
    ScanRequest,
    ScanResponse,
)
from app.core.config import settings
from app.db.database import get_session
from app.db.models import ScanRun, VulnerabilityFinding
from app.services.job_queue import job_manager


router = APIRouter(prefix="/api", tags=["scanner"])


@router.post("/scan", response_model=ScanEnqueueResponse)
async def enqueue_scan(payload: ScanRequest) -> ScanEnqueueResponse:
    job = await job_manager.enqueue(payload)
    return ScanEnqueueResponse(
        job_id=job.job_id,
        status=job.status,
        progress=job.progress,
        message=job.message,
    )


@router.get("/jobs/{job_id}", response_model=JobStatusResponse)
async def get_job_status(job_id: str) -> JobStatusResponse:
    job = job_manager.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    result = ScanResponse(**job.result) if job.result else None
    return JobStatusResponse(
        job_id=job.job_id,
        status=job.status,
        progress=job.progress,
        message=job.message,
        run_id=job.run_id,
        error=job.error,
        result=result,
    )


@router.post("/jobs/{job_id}/cancel", response_model=JobStatusResponse)
async def cancel_job(job_id: str) -> JobStatusResponse:
    job = job_manager.cancel(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    result = ScanResponse(**job.result) if job.result else None
    return JobStatusResponse(
        job_id=job.job_id,
        status=job.status,
        progress=job.progress,
        message=job.message,
        run_id=job.run_id,
        error=job.error,
        result=result,
    )


@router.get("/scan/{run_id}", response_model=ScanResponse)
async def get_scan(run_id: int, session: AsyncSession = Depends(get_session)) -> ScanResponse:
    run = await session.get(ScanRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Scan run not found")

    rows = await session.execute(select(VulnerabilityFinding).where(VulnerabilityFinding.scan_run_id == run_id))
    findings = rows.scalars().all()
    findings_payload = [
        {
            "vulnerability_type": f.vulnerability_type,
            "severity": f.severity,
            "endpoint": f.endpoint,
            "evidence": f.evidence,
            "vulnerable_snippet": f.vulnerable_snippet,
            "fix_snippet": f.fix_snippet,
        }
        for f in findings
    ]

    return ScanResponse(
        run_id=run.id,
        target_url=run.target_url,
        scan_level=run.scan_level,
        findings_count=len(findings_payload),
        findings=[FindingOut(**x) for x in findings_payload],
        json_path=str(Path(settings.output_dir) / f"run_{run_id}.json"),
        xml_path=str(Path(settings.output_dir) / f"run_{run_id}.xml"),
    )
