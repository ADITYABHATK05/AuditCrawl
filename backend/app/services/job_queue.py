import asyncio
import uuid
from typing import Dict, Any
from app.api.schemas import ScanRequest
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker
from app.db.database import SessionLocal
from app.db.models import ScanRun, VulnerabilityFinding
from urllib.parse import urlparse
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# Import AuditCrawl scanner
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from auditcrawl.orchestrator import Scanner
from auditcrawl.config import ScanConfig

# Thread pool for running sync scanner in async context
_executor = ThreadPoolExecutor(max_workers=2)

class MockJobObj:
    """Helper class to convert dict to object for the router schema validation."""
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class JobManager:
    def __init__(self):
        self.jobs: Dict[str, Dict[str, Any]] = {}

    async def start(self) -> None:
        print("Job Manager started.")

    async def shutdown(self) -> None:
        print("Job Manager shutting down. Cancelling active tasks...")

    async def enqueue(self, payload: ScanRequest):
        job_id = str(uuid.uuid4())
        self.jobs[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "progress": 0,
            "message": "Initializing scan engine...",
            "run_id": None,
            "error": None,
            "result": None,
            "target_url": payload.target_url
        }
        
        # Fire and forget the background task
        asyncio.create_task(self._run_scan_task(job_id, payload))
        return self.get(job_id)

    def get(self, job_id: str):
        job_data = self.jobs.get(job_id)
        return MockJobObj(**job_data) if job_data else None

    def cancel(self, job_id: str):
        if job_id in self.jobs:
            self.jobs[job_id]["status"] = "cancelled"
            self.jobs[job_id]["message"] = "Scan cancelled by user."
        return self.get(job_id)

    async def _run_scan_task(self, job_id: str, payload: ScanRequest):
        """
        Run the actual AuditCrawl scanner against the target.
        """
        job = self.jobs[job_id]
        job["status"] = "running"
        
        try:
            print(f"\n{'='*60}")
            print(f"SCAN INITIATED: {payload.target_url}")
            print(f"{'='*60}\n")
            
            # Parse scan level to config
            scan_level = int(payload.scan_level)
            level_config = {
                1: {"max_depth": 1, "max_pages": 20},
                2: {"max_depth": 3, "max_pages": 80},
                3: {"max_depth": 5, "max_pages": 200},
            }
            config_args = level_config.get(scan_level, level_config[2])
            
            # Extract domain from target URL
            parsed_url = urlparse(str(payload.target_url))
            domain = parsed_url.netloc or str(payload.target_url)
            
            print(f"✓ Parsed URL: {str(payload.target_url)}")
            print(f"✓ Domain: {domain}")
            print(f"✓ Scan Level: {scan_level} ({config_args})\n")
            
            # Create scanner config
            config = ScanConfig(
                base_url=str(payload.target_url),
                target_domain=domain,
                max_depth=config_args["max_depth"],
                max_pages=config_args["max_pages"],
                output_dir="backend/output",
                safe_mode=True,
                lab_mode=False,
                enable_xss=True,
                enable_sqli=True,
                enable_ssrf=True,
                enable_auth=False,
                enable_rce=False,
                enable_idor=True,
                enable_csrf=True,
                enable_headers=True,
                enable_open_redirect=True,
                request_timeout=10,
            )
            
            # Progress callback
            def progress_callback(stage, message, pct):
                job["progress"] = pct
                job["message"] = message
                print(f"[{stage}] {message} - {pct}%")
            
            # Run the scanner in a thread pool to avoid blocking
            def run_scanner():
                try:
                    print(f"\n[SCANNER] Creating Scanner with config:")
                    print(f"  Base URL: {config.base_url}")
                    print(f"  Target domain: {config.target_domain}")
                    print(f"  Max depth: {config.max_depth}")
                    print(f"  Max pages: {config.max_pages}")
                    
                    scanner = Scanner(config)
                    scanner.set_progress_callback(progress_callback)
                    
                    print(f"[SCANNER] Starting scan...")
                    result = scanner.run()
                    print(f"[SCANNER] Scan complete:")
                    print(f"  Endpoints found: {len(result.endpoints)}")
                    print(f"  Vulnerabilities found: {len(result.findings)}")
                    return result
                except Exception as e:
                    print(f"[SCANNER ERROR] {type(e).__name__}: {e}")
                    import traceback
                    traceback.print_exc()
                    raise
            
            loop = asyncio.get_event_loop()
            scan_result = await loop.run_in_executor(_executor, run_scanner)
            
            print(f"Saving {len(scan_result.findings)} findings to database...")
            
            # Save results to database
            async with SessionLocal() as session:
                # Create scan run
                scan_run = ScanRun(
                    target_url=str(payload.target_url),
                    scan_level=payload.scan_level,
                    status="completed"
                )
                session.add(scan_run)
                await session.flush()
                
                # Save each finding
                for finding in scan_result.findings:
                    vuln_finding = VulnerabilityFinding(
                        scan_run_id=scan_run.id,
                        vulnerability_type=finding.vuln_type,
                        severity=finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                        endpoint=finding.url,
                        evidence=finding.evidence[:1000],  # Limit to 1000 chars
                        vulnerable_snippet=f"{finding.method} {finding.parameter}" if finding.parameter else finding.url,
                        fix_snippet=finding.remediation[:500] if finding.remediation else "N/A"
                    )
                    session.add(vuln_finding)
                
                await session.commit()
                job["run_id"] = scan_run.id

            # Write a downloadable PDF report to backend/output for the frontend.
            # The FastAPI app mounts settings.output_dir at /output.
            try:
                out_dir = Path("backend/output")
                out_dir.mkdir(parents=True, exist_ok=True)
                pdf_src = getattr(scan_result, "report_pdf_path", "") or ""
                pdf_dst = out_dir / f"run_{job['run_id']}.pdf"
                if pdf_src:
                    Path(pdf_src).replace(pdf_dst)
                else:
                    # If scanner didn't generate a PDF for some reason, create an empty placeholder.
                    pdf_dst.write_bytes(b"")
            except Exception as _:
                # Don't fail the scan completion if report export fails.
                pass
            
            print(f"Scan {job_id} completed successfully")
            job["status"] = "completed"
            job["progress"] = 100
            job["message"] = f"Scan complete. Found {len(scan_result.findings)} vulnerabilities."
            
        except Exception as e:
            print(f"\n!!! SCAN ERROR: {str(e)}")
            import traceback
            traceback.print_exc()
            job["status"] = "failed"
            job["error"] = f"Scanner error: {str(e)}"

# Global instance imported by routes.py and main.py
job_manager = JobManager()