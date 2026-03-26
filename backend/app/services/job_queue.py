import asyncio
import uuid
from typing import Dict, Any
from app.api.schemas import ScanRequest

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
        This is where you integrate your actual AuditCrawl engine.
        For now, it simulates progress so your frontend UI works.
        """
        job = self.jobs[job_id]
        job["status"] = "running"
        
        try:
            # --- INTEGRATION POINT ---
            # Instantiate your actual scanner class here:
            # scanner = AuditCrawler(target=payload.target_url)
            
            # Simulated progress loop for frontend testing
            for i in range(1, 11):
                if job["status"] == "cancelled":
                    return
                await asyncio.sleep(1) # Simulating scan time
                job["progress"] = i * 10
                job["message"] = f"Crawling and testing endpoints... (Phase {i}/10)"

            # --- END INTEGRATION POINT ---

            job["status"] = "completed"
            job["progress"] = 100
            job["message"] = "Scan completed successfully."
            
            # Set this to the actual database ID created by your scan engine
            job["run_id"] = 1 
            
        except Exception as e:
            job["status"] = "failed"
            job["error"] = f"Internal scanner error: {str(e)}"

# Global instance imported by routes.py and main.py
job_manager = JobManager()