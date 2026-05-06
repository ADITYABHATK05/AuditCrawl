// Single source of truth for the backend API base URL.
// Smart detection: if VITE_API_BASE is set, use it; otherwise try to auto-detect based on hostname
let API_BASE = import.meta.env.VITE_API_BASE;

if (!API_BASE) {
  // Auto-detect backend URL based on current hostname
  const protocol = window.location.protocol;
  const hostname = window.location.hostname;
  const backendPort = import.meta.env.VITE_BACKEND_PORT || "8000";
  API_BASE = `${protocol}//${hostname}:${backendPort}/api`;
}

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

// Batch Scanning API
export async function createBatchScan(targets, maxWorkers = 3) {
  const res = await fetch(`${API_BASE}/batch-scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ targets, max_workers: maxWorkers }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || "Failed to create batch scan");
  }
  return res.json();
}

export async function listBatchScans(limit = 10) {
  const res = await fetch(`${API_BASE}/batch-scans?limit=${limit}`);
  if (!res.ok) {
    throw new Error("Failed to fetch batch scans");
  }
  return res.json();
}

export async function getBatchProgress(batchId) {
  const res = await fetch(`${API_BASE}/batch-scans/${batchId}`);
  if (!res.ok) {
    throw new Error("Failed to fetch batch progress");
  }
  return res.json();
}

export async function startBatchScan(batchId) {
  const res = await fetch(`${API_BASE}/batch-scans/${batchId}/start`, {
    method: "POST",
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || "Failed to start batch scan");
  }
  return res.json();
}

export async function getBatchResults(batchId) {
  const res = await fetch(`${API_BASE}/batch-scans/${batchId}/results`);
  if (!res.ok) {
    throw new Error("Failed to fetch batch results");
  }
  return res.json();
}

export async function cancelBatchScan(batchId) {
  const res = await fetch(`${API_BASE}/batch-scans/${batchId}/cancel`, {
    method: "POST",
  });
  if (!res.ok) {
    throw new Error("Failed to cancel batch scan");
  }
  return res.json();
}

// Export Formats API
export async function exportScanToBurp(runId) {
  const res = await fetch(`${API_BASE}/scan/${runId}/export/burp`);
  if (!res.ok) {
    throw new Error("Failed to export to Burp format");
  }
  return res.json();
}

export async function exportScanToZap(runId) {
  const res = await fetch(`${API_BASE}/scan/${runId}/export/zap`);
  if (!res.ok) {
    throw new Error("Failed to export to ZAP format");
  }
  return res.json();
}

export async function exportScanToSarif(runId) {
  const res = await fetch(`${API_BASE}/scan/${runId}/export/sarif`);
  if (!res.ok) {
    throw new Error("Failed to export to SARIF format");
  }
  return res.json();
}

export async function compareScanRuns(runId1, runId2) {
  const res = await fetch(`${API_BASE}/scans/compare/${runId1}/${runId2}`);
  if (!res.ok) {
    throw new Error("Failed to compare scans");
  }
  return res.json();
}