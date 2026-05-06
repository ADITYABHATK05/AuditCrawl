from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import (
    BatchScanRequest,
    FindingOut,
    LeakedAssetOut,
    JobStatusResponse,
    RepoScanRequest,
    RepoScanResponse,
    RepoLeakedAssetOut,
    ScanEnqueueResponse,
    ScanRequest,
    ScanResponse,
)
from app.core.config import settings
from app.db.database import get_session
from app.db.models import ScanRun, VulnerabilityFinding, LeakedAsset
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


@router.post("/scan-repo", response_model=RepoScanResponse)
async def scan_github_repo(payload: RepoScanRequest) -> RepoScanResponse:
    """
    Clone a *public* GitHub repo into a temp dir, run a lightweight SAST pass,
    then delete the clone automatically.
    """
    from urllib.parse import urlparse
    import tempfile

    from fastapi import HTTPException
    from fastapi.concurrency import run_in_threadpool

    parsed = urlparse(payload.github_url.strip())
    if parsed.scheme not in {"https"}:
        raise HTTPException(status_code=400, detail="Only https GitHub URLs are allowed")
    if parsed.netloc.lower() != "github.com":
        raise HTTPException(status_code=400, detail="Only github.com repository URLs are allowed")
    if parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="Credentials in URL are not allowed")

    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        raise HTTPException(status_code=400, detail="Expected URL like https://github.com/owner/repo")

    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[: -len(".git")]
    if not owner or not repo:
        raise HTTPException(status_code=400, detail="Invalid GitHub repository URL")

    clone_url = f"https://github.com/{owner}/{repo}.git"

    def _clone_and_scan() -> tuple[list[dict], list[dict]]:
        try:
            from git import Repo  # GitPython
        except Exception as e:
            raise RuntimeError("GitPython is not installed. Add GitPython to requirements.txt") from e

        from pathlib import Path
        from app.services.repo_sast_scanner import scan_repo_for_secrets_and_misconfig

        with tempfile.TemporaryDirectory(prefix="auditcrawl_repo_") as tmp:
            dst = Path(tmp) / "repo"
            Repo.clone_from(
                clone_url,
                str(dst),
                depth=1,
                single_branch=True,
            )
            findings, leaked_assets = scan_repo_for_secrets_and_misconfig(dst)
            # TemporaryDirectory context guarantees cleanup.
            return (
                [
                    {
                        "type": f.type,
                        "severity": f.severity,
                        "url": f.url,
                        "evidence": f.evidence,
                        "param": "",
                        "description": "",
                        "poc": "",
                        "vulnerable_snippet": f.vulnerable_snippet,
                        "fix_snippet": f.fix_snippet,
                    }
                    for f in findings
                ],
                leaked_assets,
            )

    try:
        findings_payload, leaked_assets_payload = await run_in_threadpool(_clone_and_scan)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Repository scan failed: {str(e)}")

    return RepoScanResponse(
        repo_url=payload.github_url,
        status="completed",
        findings_count=len(findings_payload),
        findings=[FindingOut(**x) for x in findings_payload],
        leaked_assets=[RepoLeakedAssetOut(**x) for x in leaked_assets_payload],
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
    
    # Fetch leaked assets
    asset_rows = await session.execute(select(LeakedAsset).where(LeakedAsset.scan_run_id == run_id))
    leaked_assets = asset_rows.scalars().all()
    
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

    leaked_assets_payload = [
        {
            "id": asset.id,
            "asset_type": asset.asset_type,
            "value": asset.value,
            "severity": asset.severity,
            "endpoint": asset.endpoint,
        }
        for asset in leaked_assets
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
        leaked_assets=[LeakedAssetOut(**x) for x in leaked_assets_payload],
        pdf_path=str(Path(settings.output_dir) / f"run_{run_id}.pdf"),
    )

@router.get("/scans/compare/{run_id1}/{run_id2}")
async def compare_scans(run_id1: int, run_id2: int, session: AsyncSession = Depends(get_session)):
    """Compare two scan runs and return differences (new, fixed, recurring, etc.)."""
    from app.services.scanner import WebScanner
    
    # Fetch both scan runs
    run1 = await session.get(ScanRun, run_id1)
    run2 = await session.get(ScanRun, run_id2)
    
    if not run1 or not run2:
        raise HTTPException(status_code=404, detail="One or both scan runs not found")
    
    # Fetch findings for both runs
    rows1 = await session.execute(select(VulnerabilityFinding).where(VulnerabilityFinding.scan_run_id == run_id1))
    rows2 = await session.execute(select(VulnerabilityFinding).where(VulnerabilityFinding.scan_run_id == run_id2))
    
    findings1 = rows1.scalars().all()
    findings2 = rows2.scalars().all()
    
    # Convert to scanner format
    findings_format_1 = [
        {
            "vulnerability_type": f.vulnerability_type,
            "severity": f.severity,
            "endpoint": f.endpoint,
            "evidence": f.evidence,
            "vulnerable_snippet": f.vulnerable_snippet,
            "fix_snippet": f.fix_snippet,
        }
        for f in findings1
    ]
    findings_format_2 = [
        {
            "vulnerability_type": f.vulnerability_type,
            "severity": f.severity,
            "endpoint": f.endpoint,
            "evidence": f.evidence,
            "vulnerable_snippet": f.vulnerable_snippet,
            "fix_snippet": f.fix_snippet,
        }
        for f in findings2
    ]
    
    # Use WebScanner.compare_scans (static method or instantiate)
    scanner = WebScanner()
    comparison = scanner.compare_scans(findings_format_2, findings_format_1)  # Compare run2 against run1 (baseline)
    
    return {
        "run_id_baseline": run_id1,
        "run_id_current": run_id2,
        "baseline_date": run1.created_at.isoformat() if run1.created_at else None,
        "current_date": run2.created_at.isoformat() if run2.created_at else None,
        "comparison": comparison,
    }

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

@router.get("/scan/{run_id}/export/burp")
async def export_scan_burp(run_id: int, session: AsyncSession = Depends(get_session)):
    """Export scan findings in Burp Suite JSON format."""
    from app.services.export_formats import export_to_burp_json
    
    run = await session.get(ScanRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Scan run not found")
    
    rows = await session.execute(select(VulnerabilityFinding).where(VulnerabilityFinding.scan_run_id == run_id))
    findings = rows.scalars().all()
    
    findings_list = [
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
    
    burp_data = export_to_burp_json(findings_list, run.target_url, f"Scan {run_id}")
    return {
        "format": "burp",
        "filename": f"auditcrawl_scan_{run_id}_burp.json",
        "data": json.dumps(burp_data, indent=2),
    }

@router.get("/scan/{run_id}/export/zap")
async def export_scan_zap(run_id: int, session: AsyncSession = Depends(get_session)):
    """Export scan findings in OWASP ZAP JSON format."""
    from app.services.export_formats import export_to_zap_json
    
    run = await session.get(ScanRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Scan run not found")
    
    rows = await session.execute(select(VulnerabilityFinding).where(VulnerabilityFinding.scan_run_id == run_id))
    findings = rows.scalars().all()
    
    findings_list = [
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
    
    zap_data = export_to_zap_json(findings_list, run.target_url, f"Scan {run_id}")
    return {
        "format": "zap",
        "filename": f"auditcrawl_scan_{run_id}_zap.json",
        "data": json.dumps(zap_data, indent=2),
    }

@router.get("/scan/{run_id}/export/sarif")
async def export_scan_sarif(run_id: int, session: AsyncSession = Depends(get_session)):
    """Export scan findings in SARIF format."""
    from app.services.export_formats import export_to_sarif
    
    run = await session.get(ScanRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Scan run not found")
    
    rows = await session.execute(select(VulnerabilityFinding).where(VulnerabilityFinding.scan_run_id == run_id))
    findings = rows.scalars().all()
    
    findings_list = [
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
    
    sarif_data = export_to_sarif(findings_list, run.target_url, f"Scan {run_id}")
    return {
        "format": "sarif",
        "filename": f"auditcrawl_scan_{run_id}_sarif.json",
        "data": json.dumps(sarif_data, indent=2),
    }


# Distributed Scanning Endpoints
@router.post("/batch-scans")
async def create_batch_scan(request: BatchScanRequest):
    """Create a distributed batch scan with multiple targets."""
    from app.services.distributed_scanner import distributed_scan_manager
    
    targets = [t.model_dump() for t in request.targets]
    batch = distributed_scan_manager.create_batch(targets, max_workers=request.max_workers)
    
    return {
        "batch_id": batch.batch_id,
        "target_count": len(batch.targets),
        "status": batch.status.value,
        "max_workers": batch.max_workers,
    }


@router.get("/batch-scans")
async def list_batch_scans(limit: int = 10):
    """List recent batch scans."""
    from app.services.distributed_scanner import distributed_scan_manager
    
    batches = distributed_scan_manager.list_batches(limit=limit)
    return [
        {
            "batch_id": b.batch_id,
            "target_count": len(b.targets),
            "status": b.status.value,
            "created_at": b.created_at.isoformat(),
            "progress": b.get_progress(),
        }
        for b in batches
    ]


@router.get("/batch-scans/{batch_id}")
async def get_batch_progress(batch_id: str):
    """Get progress of a batch scan."""
    from app.services.distributed_scanner import distributed_scan_manager
    
    batch = distributed_scan_manager.get_batch(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")
    
    return {
        "batch_id": batch.batch_id,
        "status": batch.status.value,
        "progress": batch.get_progress(),
        "created_at": batch.created_at.isoformat(),
        "started_at": batch.started_at.isoformat() if batch.started_at else None,
        "completed_at": batch.completed_at.isoformat() if batch.completed_at else None,
        "summary": batch.summary,
    }


@router.get("/batch-scans/{batch_id}/results")
async def get_batch_results(batch_id: str):
    """Get aggregated results for a batch scan."""
    from app.services.distributed_scanner import distributed_scan_manager
    
    results = distributed_scan_manager.get_batch_results(batch_id)
    if not results:
        raise HTTPException(status_code=404, detail="Batch not found")
    
    return results


@router.post("/batch-scans/{batch_id}/cancel")
async def cancel_batch_scan(batch_id: str):
    """Cancel a running batch scan."""
    from app.services.distributed_scanner import distributed_scan_manager
    
    batch = distributed_scan_manager.cancel_batch(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")
    
    return {
        "batch_id": batch.batch_id,
        "status": batch.status.value,
        "message": "Batch cancelled",
    }


@router.post("/batch-scans/{batch_id}/start")
async def start_batch_scan(batch_id: str, session: AsyncSession = Depends(get_session)):
    """Start executing a batch scan."""
    from app.services.distributed_scanner import distributed_scan_manager
    from app.services.scanner import WebScanner
    
    batch = distributed_scan_manager.get_batch(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="Batch not found")
    
    async def scan_target(target):
        """Scan a single target in the batch."""
        scanner = WebScanner()
        findings = await scanner.scan(
            target_url=target.url,
            scan_level=target.scan_level,
            login_url=target.login_url,
            username=target.username,
            password=target.password,
            auth_method=target.auth_method,
        )
        return {
            "target_url": target.url,
            "scan_level": target.scan_level,
            "findings": findings,
            "findings_count": len(findings),
        }
    
    # Start batch scan in background
    async def run_batch():
        await distributed_scan_manager.run_batch(batch_id, scan_target)
    
    # Queue the batch for background execution
    import asyncio
    asyncio.create_task(run_batch())
    
    return {
        "batch_id": batch.batch_id,
        "status": "started",
        "message": f"Batch scan started with {len(batch.targets)} targets",
    }
