import React, { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import { getScanResults } from "../api";
import ScanResults from "./ScanResult";
import { ScanResultsSkeleton } from "./SkeletonLoaders";

export default function ScanResultsPage() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    async function fetchResults() {
      try {
        const data = await getScanResults(id);
        setScan(data);
      } catch (err) {
        setError(err.message || "Failed to fetch scan results");
      } finally {
        setLoading(false);
      }
    }

    fetchResults();
  }, [id]);

  if (loading) {
    return (
      <div className="page fade-in space-y-6">
        <div className="glass-card p-6">
          <h1 className="section-title-clean">Loading scan results</h1>
          <p className="section-sub-clean">Fetching data from FastAPI backend on port 8000...</p>
        </div>
        <ScanResultsSkeleton />
      </div>
    );
  }

  if (error) {
    return (
      <div className="page fade-in">
        <div className="glass-card border border-rose-400/40 p-6">
          <div className="alert alert-error">{error}</div>
          <div className="mt-4">
            <Link to="/scanner" className="btn-ghost-clean">← Back to Scanner</Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="page fade-in">
      <div className="glass-card mb-6 p-6">
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <Link to="/scanner" className="btn-ghost-clean">← Scanner</Link>
          <Link to="/archive" className="btn-ghost-clean">Archive</Link>
        </div>
        <h1 className="section-title-clean">Scan Results</h1>
        <p className="section-sub-clean">Detailed vulnerability intelligence and remediation guidance.</p>
      </div>
      <ScanResults scan={scan} onBack={() => window.history.back()} />
    </div>
  );
}
