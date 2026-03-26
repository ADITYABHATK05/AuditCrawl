import React, { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import { getScanResults } from "../api";
import ScanResults from "./ScanResult";

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
      <div className="page fade-in">
        <div className="empty">
          <div className="empty-icon">⏳</div>
          <div className="empty-text">Loading scan results...</div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="page fade-in">
        <div className="alert alert-error">{error}</div>
        <Link to="/scanner" className="btn btn-ghost btn-sm">← Back to Scanner</Link>
      </div>
    );
  }

  return (
    <div className="page fade-in">
      <div className="page-header">
        <div style={{ display: "flex", gap: "0.5rem", alignItems: "center", marginBottom: "0.5rem" }}>
          <Link to="/scanner" className="btn btn-ghost btn-sm">← Scanner</Link>
          <Link to="/archive" className="btn btn-ghost btn-sm">Archive</Link>
        </div>
        <h1 className="page-title">Scan Results</h1>
      </div>
      <ScanResults scan={scan} onBack={() => window.history.back()} />
    </div>
  );
}
