import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

export default function ScanArchiveTable({ limit }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('http://localhost:8000/api/scans')
      .then(res => res.json())
      .then(data => {
        // Sort newest first
        const sortedData = data.sort((a, b) => b.id - a.id);
        setScans(limit ? sortedData.slice(0, limit) : sortedData);
        setLoading(false);
      })
      .catch(err => {
        console.error("Failed to fetch scans", err);
        setLoading(false);
      });
  }, [limit]);

  if (loading) return <div style={{ padding: '1rem', color: 'var(--muted)' }}>Loading archive...</div>;

  return (
    <div className="table-container">
      <table className="table" style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border)' }}>
            <th style={{ padding: '0.75rem' }}>Run ID</th>
            <th style={{ padding: '0.75rem' }}>Target</th>
            <th style={{ padding: '0.75rem' }}>Level</th>
            <th style={{ padding: '0.75rem' }}>Status</th>
            <th style={{ padding: '0.75rem' }}>Action</th>
          </tr>
        </thead>
        <tbody>
          {scans.length === 0 ? (
            <tr><td colSpan="5" style={{ padding: '1rem', textAlign: 'center' }}>No scans found.</td></tr>
          ) : scans.map(scan => (
            <tr key={scan.id} style={{ borderBottom: '1px solid var(--bg-hover)' }}>
              <td style={{ padding: '0.75rem' }}>#{scan.id}</td>
              <td style={{ padding: '0.75rem', fontFamily: 'var(--mono)' }}>{scan.target_url}</td>
              <td style={{ padding: '0.75rem' }}>Lvl {scan.scan_level}</td>
              <td style={{ padding: '0.75rem', color: scan.status === 'completed' ? 'var(--neon)' : 'inherit' }}>
                {scan.status || 'Unknown'}
              </td>
              <td style={{ padding: '0.75rem' }}>
                <Link to={`/scan/backend/${scan.id}`} className="btn btn-sm btn-ghost">
                  View Report
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}