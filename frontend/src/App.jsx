import { useState, useEffect, useCallback } from "react";
import ScanForm from "./components/ScanForm";
import ScanHistory from "./components/ScanHistory";
import ScanResults from "./components/ScanResults";
import Header from "./components/Header";
import "./App.css";

const API = "http://localhost:8000/api";

export default function App() {
  const [scans, setScans] = useState([]);
  const [activeScan, setActiveScan] = useState(null);
  const [view, setView] = useState("scan"); // "scan" | "history" | "results"
  const [polling, setPolling] = useState(false);

  const fetchScans = useCallback(async () => {
    try {
      const res = await fetch(`${API}/scans`);
      const data = await res.json();
      setScans(data.sort((a, b) => new Date(b.started_at) - new Date(a.started_at)));
    } catch {
      // backend not ready yet
    }
  }, []);

  // Poll for scan updates while one is running
  useEffect(() => {
    if (!polling) return;
    const interval = setInterval(async () => {
      await fetchScans();
      if (activeScan) {
        try {
          const res = await fetch(`${API}/scans/${activeScan.id}`);
          const data = await res.json();
          setActiveScan(data);
          if (data.status === "completed" || data.status === "error") {
            setPolling(false);
          }
        } catch {}
      }
    }, 2000);
    return () => clearInterval(interval);
  }, [polling, activeScan, fetchScans]);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  const handleStartScan = async (formData) => {
    const res = await fetch(`${API}/scans`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(formData),
    });
    const data = await res.json();
    if (res.ok) {
      const newScan = { id: data.scan_id, status: "queued", ...formData, findings: [], started_at: new Date().toISOString() };
      setActiveScan(newScan);
      setPolling(true);
      setView("results");
      fetchScans();
    }
    return data;
  };

  const handleViewScan = (scan) => {
    setActiveScan(scan);
    setView("results");
  };

  const handleDeleteScan = async (scanId) => {
    await fetch(`${API}/scans/${scanId}`, { method: "DELETE" });
    fetchScans();
    if (activeScan?.id === scanId) {
      setActiveScan(null);
      setView("scan");
    }
  };

  return (
    <div className="app">
      <Header view={view} setView={setView} scanCount={scans.length} />
      <main className="main">
        {view === "scan" && (
          <ScanForm onSubmit={handleStartScan} />
        )}
        {view === "history" && (
          <ScanHistory scans={scans} onView={handleViewScan} onDelete={handleDeleteScan} />
        )}
        {view === "results" && (
          <ScanResults scan={activeScan} onBack={() => setView("scan")} />
        )}
      </main>
    </div>
  );
}