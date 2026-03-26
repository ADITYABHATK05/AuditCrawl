from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
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
    
    # Extract domain from target URL
    from urllib.parse import urlparse
    parsed = urlparse(run.target_url)
    domain = parsed.netloc or run.target_url
    
    findings_payload = [
        {
            "type": f.vulnerability_type,
            "severity": f.severity,
            "url": f.endpoint,
            "evidence": f.evidence,
            "param": "",
            "description": "",
            "poc": "",
            "vulnerable_snippet": f.vulnerable_snippet,
            "fix_snippet": f.fix_snippet,
        }
        for f in findings
    ]

    # Count unique endpoints
    unique_endpoints = len(set(f.endpoint for f in findings))

    return ScanResponse(
        run_id=run.id,
        target_url=run.target_url,
        base_url=run.target_url,
        target_domain=domain,
        scan_level=run.scan_level,
        status="completed",
        findings_count=len(findings_payload),
        endpoints_count=unique_endpoints,
        findings=[FindingOut(**x) for x in findings_payload],
        pdf_path=str(Path(settings.output_dir) / f"run_{run_id}.pdf"),
    )

@router.get("/scans")
async def get_all_scans(session: AsyncSession = Depends(get_session)):
    """Fetch scan history for the frontend archive."""
    rows = await session.execute(
        select(ScanRun).order_by(ScanRun.id.desc())
    )
    scans = rows.scalars().all()

    run_ids = [s.id for s in scans]
    sev_counts_by_run: dict[int, dict[str, int]] = {
        run_id: {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for run_id in run_ids
    }
    findings_count_by_run: dict[int, int] = {run_id: 0 for run_id in run_ids}

    if run_ids:
        sev_rows = await session.execute(
            select(
                VulnerabilityFinding.scan_run_id,
                func.lower(VulnerabilityFinding.severity).label("severity"),
                func.count(VulnerabilityFinding.id).label("count"),
            )
            .where(VulnerabilityFinding.scan_run_id.in_(run_ids))
            .group_by(VulnerabilityFinding.scan_run_id, func.lower(VulnerabilityFinding.severity))
        )

        for run_id, severity, count in sev_rows.all():
            sev = severity or ""
            if sev in sev_counts_by_run[run_id]:
                sev_counts_by_run[run_id][sev] = count
            findings_count_by_run[run_id] += count

    return [
        {
            "id": s.id,
            "target_url": s.target_url,
            "scan_level": s.scan_level,
            "status": s.status or "completed",
            "started_at": getattr(s, "created_at", None),
            "findings_count": findings_count_by_run.get(s.id, 0),
            "severity_counts": sev_counts_by_run.get(
                s.id, {"critical": 0, "high": 0, "medium": 0, "low": 0}
            ),
        }
        for s in scans
    ]