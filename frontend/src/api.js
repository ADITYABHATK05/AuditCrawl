// Single source of truth for the backend API base URL.
// If you run the FastAPI backend on a different port, set:
//   VITE_API_BASE=http://127.0.0.1:8000/api
const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000/api";

export async function flaskStartScan(payload) {
  const res = await fetch(`${API_BASE}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || "Failed to start scan");
  }
  return res.json();
}

export async function flaskGetJobStatus(jobId) {
  const res = await fetch(`${API_BASE}/jobs/${jobId}`);
  if (!res.ok) {
    throw new Error("Failed to fetch job status");
  }
  return res.json();
}

export async function flaskStopScan(jobId) {
  const res = await fetch(`${API_BASE}/jobs/${jobId}/cancel`, {
    method: "POST",
  });
  if (!res.ok) {
    throw new Error("Failed to cancel scan");
  }
  return res.json();
}

export async function getScanResults(runId) {
  const res = await fetch(`${API_BASE}/scan/${runId}`);
  if (!res.ok) {
    throw new Error("Failed to fetch scan results");
  }
  return res.json();
}

export async function getAllScans() {
  const res = await fetch(`${API_BASE}/scans`);
  if (!res.ok) {
    throw new Error("Failed to fetch scans");
  }
  return res.json();
}