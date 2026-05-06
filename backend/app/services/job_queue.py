import asyncio
import uuid
from typing import Dict, Any
from app.api.schemas import ScanRequest
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker
from app.db.database import SessionLocal
from app.db.models import ScanRun, VulnerabilityFinding, LeakedAsset
from app.core.config import settings
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
            
            # Extract domain from target URL
            parsed_url = urlparse(str(payload.target_url))
            domain = parsed_url.netloc or str(payload.target_url)
            
            is_github = domain.lower() == "github.com"
            
            # Progress callback
            def progress_callback(stage, message, pct):
                job["progress"] = pct
                job["message"] = message
                print(f"[{stage}] {message} - {pct}%")
            
            if is_github:
                print(f"[SCANNER] Detected GitHub repository URL. Running SAST scanner...")
                parts = [p for p in parsed_url.path.split("/") if p]
                if len(parts) >= 2:
                    owner, repo = parts[0], parts[1]
                    if repo.endswith(".git"):
                        repo = repo[:-len(".git")]
                    clone_url = f"https://github.com/{owner}/{repo}.git"
                else:
                    raise ValueError("Expected GitHub URL like https://github.com/owner/repo")
                
                def run_repo_scanner():
                    import tempfile
                    from git import Repo
                    from app.services.repo_sast_scanner import scan_repo_for_secrets_and_misconfig
                    
                    with tempfile.TemporaryDirectory(prefix="auditcrawl_repo_") as tmp:
                        dst = Path(tmp) / "repo"
                        progress_callback("Setup", f"Cloning {clone_url}...", 10)
                        try:
                            Repo.clone_from(clone_url, str(dst), depth=1, single_branch=True)
                        except Exception as e:
                            raise ValueError(f"Failed to clone repository: {str(e)}. Make sure it is public.")
                        
                        progress_callback("Scanning", "Scanning repository files...", 50)
                        findings, leaked_assets = scan_repo_for_secrets_and_misconfig(dst)
                        
                        class MockFinding:
                            def __init__(self, f):
                                self.vuln_type = getattr(f, 'type', 'Unknown')
                                self.severity = MockJobObj(value=getattr(f, 'severity', 'Medium'))
                                self.url = getattr(f, 'url', '')
                                self.evidence = getattr(f, 'evidence', '')
                                self.method = ""
                                self.parameter = getattr(f, 'vulnerable_snippet', '')
                                self.remediation = getattr(f, 'fix_snippet', '')
                                self.payload = getattr(f, 'vulnerable_snippet', '')
                                
                        class MockLeakedAsset:
                            def __init__(self, a):
                                self.vuln_type = f"Leaked {a.get('asset_type', 'Secret')}"
                                self.severity = MockJobObj(value=a.get('severity', 'High'))
                                self.url = a.get('endpoint', '')
                                self.evidence = "Secret detected in repository file."
                                self.method = ""
                                self.parameter = a.get('value', '')
                                self.remediation = "Rotate the exposed secret immediately and use environment variables."
                                self.payload = a.get('value', '')
                        
                        mock_findings = [MockFinding(f) for f in findings]
                        mock_findings.extend([MockLeakedAsset(a) for a in leaked_assets])
                        
                        scan_res = MockJobObj(
                            endpoints=[],
                            findings=mock_findings,
                            summary_by_severity=lambda: {},
                            report_pdf_path=""
                        )
                        return scan_res
                
                loop = asyncio.get_event_loop()
                scan_result = await loop.run_in_executor(_executor, run_repo_scanner)
                scan_level_db = "repo"
            else:
                # Parse scan level to config
                scan_level = int(payload.scan_level)
                level_config = {
                    1: {"max_depth": 1, "max_pages": 20},
                    2: {"max_depth": 3, "max_pages": 80},
                    3: {"max_depth": 5, "max_pages": 200},
                }
                config_args = level_config.get(scan_level, level_config[2])
                
                print(f"✓ Parsed URL: {str(payload.target_url)}")
                print(f"✓ Domain: {domain}")
                print(f"✓ Scan Level: {scan_level} ({config_args})\n")
                
                # Create scanner config
                config = ScanConfig(
                    base_url=str(payload.target_url),
                    target_domain=domain,
                    max_depth=config_args["max_depth"],
                    max_pages=config_args["max_pages"],
                    output_dir=settings.output_dir,
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
                    enable_leaked_assets=True,
                    request_timeout=10,
                )
                
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
                scan_level_db = str(scan_level)
            
            print(f"Saving {len(scan_result.findings)} findings to database...")
            
            # Save results to database
            async with SessionLocal() as session:
                # Create scan run
                scan_run = ScanRun(
                    target_url=str(payload.target_url),
                    scan_level=scan_level_db,
                    status="completed"
                )
                session.add(scan_run)
                await session.flush()
                
                # Save each finding
                for finding in scan_result.findings:
                    vuln_type_lower = finding.vuln_type.lower()
                    is_leaked = (
                        finding.vuln_type.startswith("Leaked ") or
                        "secret" in vuln_type_lower or
                        "token" in vuln_type_lower or
                        "key" in vuln_type_lower or
                        "credential" in vuln_type_lower or
                        "password" in vuln_type_lower
                    )
                    
                    if is_leaked:
                        # Save as leaked asset
                        asset_type = finding.vuln_type.replace("Leaked ", "")
                        leaked_asset = LeakedAsset(
                            scan_run_id=scan_run.id,
                            asset_type=asset_type,
                            value=finding.payload or finding.parameter or "N/A",  # Try to extract the actual value
                            severity=finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                            endpoint=finding.url
                        )
                        session.add(leaked_asset)
                    else:
                        # Save as vulnerability finding
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
                out_dir = Path(settings.output_dir)
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

            email_note = ""

            # Optional: email the report summary to the user
            if getattr(payload, "email", None):
                try:
                    from app.services.mailer import build_scan_report_email_html, send_html_email

                    # Build summary counts
                    sev_counts = scan_result.summary_by_severity() if hasattr(scan_result, "summary_by_severity") else {}

                    def _bucket(vuln_type: str) -> str:
                        t = (vuln_type or "").lower()
                        if "sql" in t:
                            return "SQLi"
                        if "ssrf" in t:
                            return "SSRF"
                        if "xss" in t:
                            return "XSS"
                        if "csrf" in t:
                            return "CSRF"
                        if "idor" in t:
                            return "IDOR"
                        if "open redirect" in t or "redirect" in t:
                            return "Open Redirect"
                        if "cors" in t:
                            return "CORS"
                        if "security misconfiguration" in t or "misconfig" in t or "header" in t:
                            return "Security Headers/Misconfig"
                        if "leaked" in t or "token" in t or "key" in t:
                            return "Leaked Secrets"
                        return "Other"

                    vuln_type_counts: dict[str, int] = {}
                    for f in getattr(scan_result, "findings", []) or []:
                        vuln_type_counts[_bucket(getattr(f, "vuln_type", ""))] = vuln_type_counts.get(
                            _bucket(getattr(f, "vuln_type", "")), 0
                        ) + 1

                    # Top findings (critical/high first)
                    def _sev_weight(x) -> int:
                        s = getattr(x.severity, "value", str(x.severity)).lower()
                        return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(s, 0)

                    findings_sorted = sorted(getattr(scan_result, "findings", []) or [], key=_sev_weight, reverse=True)
                    top_findings = [
                        {
                            "vulnerability_type": getattr(f, "vuln_type", "Finding"),
                            "severity": getattr(f.severity, "value", str(f.severity)).title(),
                            "endpoint": getattr(f, "url", ""),
                            "evidence": getattr(f, "evidence", "") or "",
                            "remediation": getattr(f, "remediation", "") or "",
                        }
                        for f in findings_sorted[:10]
                    ]
                    detailed_findings = [
                        {
                            "vulnerability_type": getattr(f, "vuln_type", "Finding"),
                            "severity": getattr(f.severity, "value", str(f.severity)).title(),
                            "endpoint": getattr(f, "url", ""),
                            "evidence": getattr(f, "evidence", "") or "",
                            "remediation": getattr(f, "remediation", "") or "",
                        }
                        for f in findings_sorted
                    ]

                    dashboard_url = f"{settings.frontend_url.rstrip('/')}/scan/backend/{job['run_id']}"
                    html_body = build_scan_report_email_html(
                        target_url=str(payload.target_url),
                        run_id=int(job["run_id"]),
                        severity_counts=sev_counts,
                        vuln_type_counts=vuln_type_counts,
                        top_findings=top_findings,
                        detailed_findings=detailed_findings,
                        dashboard_url=dashboard_url,
                    )
                    await send_html_email(
                        to_email=str(payload.email),
                        subject=f"AuditCrawl report — {domain} (run {job['run_id']})",
                        html_body=html_body,
                    )
                    email_note = f" Email sent to {str(payload.email)}."
                except Exception as mail_exc:
                    # Don't fail the scan if email fails; surface info in job message.
                    print(f"[MAIL ERROR] {type(mail_exc).__name__}: {mail_exc}")
                    email_note = f" Email failed: {type(mail_exc).__name__}: {mail_exc}"
            
            print(f"Scan {job_id} completed successfully")
            job["status"] = "completed"
            job["progress"] = 100
            job["message"] = (
                f"Scan complete. Found {len(getattr(scan_result, 'findings', []) or [])} vulnerabilities."
                f"{email_note}"
            )
            
        except Exception as e:
            print(f"\n!!! SCAN ERROR: {str(e)}")
            import traceback
            traceback.print_exc()
            job["status"] = "failed"
            job["error"] = f"Scanner error: {str(e)}"

# Global instance imported by routes.py and main.py
job_manager = JobManager()