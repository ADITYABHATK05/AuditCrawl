"""Distributed scanning support for parallel multi-target scans."""

from __future__ import annotations
import asyncio
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable, Awaitable
from uuid import uuid4


class ScanStatus(Enum):
    """Status of a distributed scan batch."""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TargetStatus(Enum):
    """Status of an individual target scan."""
    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ScanTarget:
    """Individual target for scanning."""
    url: str
    scan_level: str = "2"
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    auth_method: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    status: TargetStatus = TargetStatus.PENDING
    result: Optional[dict] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


@dataclass
class DistributedScanBatch:
    """Batch of targets for distributed scanning."""
    batch_id: str
    targets: list[ScanTarget]
    status: ScanStatus = ScanStatus.QUEUED
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    max_workers: int = 3  # Parallel workers
    results: list[dict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def get_progress(self) -> dict:
        """Get batch progress statistics."""
        total = len(self.targets)
        completed = sum(1 for t in self.targets if t.status == TargetStatus.COMPLETED)
        failed = sum(1 for t in self.targets if t.status == TargetStatus.FAILED)
        scanning = sum(1 for t in self.targets if t.status == TargetStatus.SCANNING)
        
        # Progress includes both completed AND failed (both are "done")
        finished = completed + failed
        
        return {
            "batch_id": self.batch_id,
            "status": self.status.value,
            "total_targets": total,
            "completed": completed,
            "failed": failed,
            "scanning": scanning,
            "pending": total - finished - scanning,
            "progress_percent": int((finished / max(1, total)) * 100),
        }

    def generate_summary(self) -> dict:
        """Generate summary of scan results."""
        total_findings = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for target in self.targets:
            findings = []
            if isinstance(target.result, dict):
                findings = target.result.get("findings", [])
            elif isinstance(target.result, list):
                findings = target.result

            total_findings += len(findings)
            for finding in findings:
                severity = finding.get("severity", "Low").lower()
                if severity == "critical":
                    critical_count += 1
                elif severity == "high":
                    high_count += 1
                elif severity == "medium":
                    medium_count += 1
                elif severity == "low":
                    low_count += 1
        
        return {
            "batch_id": self.batch_id,
            "total_targets": len(self.targets),
            "completed_targets": sum(1 for t in self.targets if t.status == TargetStatus.COMPLETED),
            "failed_targets": sum(1 for t in self.targets if t.status == TargetStatus.FAILED),
            "total_findings": total_findings,
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class DistributedScanManager:
    """Manages distributed scanning across multiple targets."""
    
    def __init__(self):
        self.batches: dict[str, DistributedScanBatch] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def create_batch(self, targets: list[dict], max_workers: int = 3) -> DistributedScanBatch:
        """Create a new scan batch."""
        batch_id = str(uuid4())
        scan_targets = []
        
        for target_config in targets:
            target = ScanTarget(
                url=target_config.get("url"),
                scan_level=target_config.get("scan_level", "2"),
                login_url=target_config.get("login_url"),
                username=target_config.get("username"),
                password=target_config.get("password"),
                auth_method=target_config.get("auth_method"),
                tags=target_config.get("tags", []),
            )
            scan_targets.append(target)
        
        batch = DistributedScanBatch(
            batch_id=batch_id,
            targets=scan_targets,
            max_workers=max_workers,
        )
        
        self.batches[batch_id] = batch
        self._locks[batch_id] = asyncio.Lock()
        
        return batch

    def get_batch(self, batch_id: str) -> Optional[DistributedScanBatch]:
        """Retrieve a batch by ID."""
        return self.batches.get(batch_id)

    def list_batches(self, limit: int = 10) -> list[DistributedScanBatch]:
        """List recent batches."""
        return sorted(
            self.batches.values(),
            key=lambda b: b.created_at,
            reverse=True,
        )[:limit]

    async def run_batch(
        self,
        batch_id: str,
        scan_func: Callable[[ScanTarget], Awaitable[dict]],
        progress_callback: Optional[Callable[[str, dict], Awaitable[None]]] = None,
    ) -> DistributedScanBatch:
        """
        Execute a batch of scans in parallel with worker pool.
        
        Args:
            batch_id: ID of the batch to run
            scan_func: Async function to scan a target; returns findings dict
            progress_callback: Optional callback to report progress
        """
        batch = self.batches.get(batch_id)
        if not batch:
            raise ValueError(f"Batch {batch_id} not found")
        
        async with self._locks[batch_id]:
            batch.status = ScanStatus.RUNNING
            batch.started_at = datetime.utcnow()
        
        if progress_callback:
            await progress_callback(batch_id, batch.get_progress())
        
        # Create worker queue
        queue: asyncio.Queue = asyncio.Queue()
        for target in batch.targets:
            await queue.put(target)
        
        # Create worker coroutines
        async def worker():
            while True:
                try:
                    target = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                
                target.status = TargetStatus.SCANNING
                target.started_at = datetime.utcnow()
                
                try:
                    result = await scan_func(target)
                    target.result = result
                    target.status = TargetStatus.COMPLETED
                except Exception as e:
                    target.error = str(e)
                    target.status = TargetStatus.FAILED
                finally:
                    target.completed_at = datetime.utcnow()
                    if progress_callback:
                        await progress_callback(batch_id, batch.get_progress())
        
        # Run workers in parallel
        workers = [asyncio.create_task(worker()) for _ in range(min(batch.max_workers, len(batch.targets)))]
        await asyncio.gather(*workers)
        
        # Mark batch as complete
        async with self._locks[batch_id]:
            batch.status = ScanStatus.COMPLETED
            batch.completed_at = datetime.utcnow()
            batch.summary = batch.generate_summary()
        
        if progress_callback:
            await progress_callback(batch_id, batch.get_progress())
        
        return batch

    def cancel_batch(self, batch_id: str) -> Optional[DistributedScanBatch]:
        """Cancel a running batch."""
        batch = self.batches.get(batch_id)
        if batch:
            batch.status = ScanStatus.CANCELLED
        return batch

    def get_batch_results(self, batch_id: str) -> Optional[dict]:
        """Get aggregated results for a batch."""
        batch = self.batches.get(batch_id)
        if not batch:
            return None
        
        all_findings = []
        target_results = []
        
        for target in batch.targets:
            target_result = {
                "url": target.url,
                "status": target.status.value,
                "findings_count": 0,
                "error": target.error,
            }
            
            if isinstance(target.result, dict):
                findings = target.result.get("findings", [])
            elif isinstance(target.result, list):
                findings = target.result
            else:
                findings = []

            target_result["findings_count"] = len(findings)
            all_findings.extend(findings)
            
            target_results.append(target_result)
        
        return {
            "batch_id": batch_id,
            "status": batch.status.value,
            "total_findings": len(all_findings),
            "targets": target_results,
            "summary": batch.summary,
        }


# Global instance
distributed_scan_manager = DistributedScanManager()
