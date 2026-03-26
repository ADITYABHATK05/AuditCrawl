import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { getAllScans } from '../api';

function ArchiveSeverityDonut({ counts }) {
  const safeCounts = counts || {};
  const critical = safeCounts.critical || 0;
  const high = safeCounts.high || 0;
  const medium = safeCounts.medium || 0;
  const low = safeCounts.low || 0;
  const total = critical + high + medium + low;
  const safeTotal = total > 0 ? total : 1;

  let cursor = 0;
  const segments = [
    ['#ff3355', critical],
    ['#ffa040', high],
    ['#ffb020', medium],
    ['#40aaff', low],
  ].map(([color, value]) => {
    const start = cursor;
    const end = cursor + (value / safeTotal) * 360;
    cursor = end;
    return `${color} ${start}deg ${end}deg`;
  });

  const health =
    critical > 0
      ? 'High'
      : high > 0
        ? 'Elevated'
        : medium > 0
          ? 'Moderate'
          : low > 0
            ? 'Low'
            : 'Clean';

  return (
    <div className="archive-health-cell">
      <div className="archive-donut-wrap">
        <div className="archive-donut" style={{ background: `conic-gradient(${segments.join(', ')})` }} />
        <div className="archive-donut-hole" />
      </div>
      <div className="archive-health-meta">
        <div className="archive-health-label">{health} Risk</div>
        <div className="archive-health-counts">{total} findings</div>
      </div>
    </div>
  );
}

export default function ScanArchiveTable({ limit }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [riskFilter, setRiskFilter] = useState('all');
  const [sortBy, setSortBy] = useState('newest');
  const [compareA, setCompareA] = useState('');
  const [compareB, setCompareB] = useState('');

  useEffect(() => {
    let mounted = true;

    const loadScans = (preserveLoading = false) =>
      getAllScans()
      .then(data => {
        if (!mounted) return;
        const sortedData = data.sort((a, b) => b.id - a.id);
        setScans(limit ? sortedData.slice(0, limit) : sortedData);
      })
      .catch(err => {
        console.error("Failed to fetch scans", err);
      })
      .finally(() => {
        if (mounted && !preserveLoading) setLoading(false);
      });

    loadScans();
    const poll = setInterval(() => loadScans(true), 15000);

    return () => {
      mounted = false;
      clearInterval(poll);
    };
  }, [limit]);

  if (loading) return <div style={{ padding: '1rem', color: 'var(--muted)' }}>Loading archive...</div>;

  const withRisk = scans.map((scan) => {
    const counts = scan.severity_counts || {};
    const critical = counts.critical || 0;
    const high = counts.high || 0;
    const medium = counts.medium || 0;
    const low = counts.low || 0;
    const total = critical + high + medium + low;
    const safe = total > 0 ? total : 1;
    // Keep sorting severity-priority: critical outranks any volume of lower severities.
    const baseBand = critical > 0 ? 400 : high > 0 ? 300 : medium > 0 ? 200 : low > 0 ? 100 : 0;
    const blend = Math.round(((critical * 10 + high * 6 + medium * 3 + low) / safe) * 10);
    const riskScore = baseBand + blend;
    return { ...scan, riskScore, findingsCount: scan.findings_count || total };
  });

  const filteredScans = withRisk
    .filter((scan) => (scan.target_url || '').toLowerCase().includes(query.toLowerCase()))
    .filter((scan) => {
      if (riskFilter === 'critical') return (scan.severity_counts?.critical || 0) > 0;
      if (riskFilter === 'high') return (scan.severity_counts?.high || 0) > 0;
      return true;
    })
    .sort((a, b) => {
      if (sortBy === 'risk') return b.riskScore - a.riskScore;
      if (sortBy === 'findings') return b.findingsCount - a.findingsCount;
      return b.id - a.id;
    });

  const cmpA = withRisk.find((s) => String(s.id) === String(compareA));
  const cmpB = withRisk.find((s) => String(s.id) === String(compareB));
  const diff = cmpA && cmpB ? {
    critical: (cmpB.severity_counts?.critical || 0) - (cmpA.severity_counts?.critical || 0),
    high: (cmpB.severity_counts?.high || 0) - (cmpA.severity_counts?.high || 0),
    medium: (cmpB.severity_counts?.medium || 0) - (cmpA.severity_counts?.medium || 0),
    low: (cmpB.severity_counts?.low || 0) - (cmpA.severity_counts?.low || 0),
    findings: (cmpB.findingsCount || 0) - (cmpA.findingsCount || 0),
  } : null;

  return (
    <div className="table-container">
      <div className="archive-toolbar">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search target URL..."
        />
        <button className={`filter-tab ${riskFilter === 'all' ? 'active' : ''}`} onClick={() => setRiskFilter('all')}>All</button>
        <button className={`filter-tab ${riskFilter === 'critical' ? 'active' : ''}`} onClick={() => setRiskFilter('critical')}>Critical {'>'} 0</button>
        <button className={`filter-tab ${riskFilter === 'high' ? 'active' : ''}`} onClick={() => setRiskFilter('high')}>High {'>'} 0</button>
        <select className="finding-roi-select" value={sortBy} onChange={(e) => setSortBy(e.target.value)}>
          <option value="newest">Newest</option>
          <option value="risk">Highest Risk</option>
          <option value="findings">Most Findings</option>
        </select>
      </div>

      <div className="archive-compare">
        <span className="archive-compare-title">Compare Runs</span>
        <select className="finding-roi-select" value={compareA} onChange={(e) => setCompareA(e.target.value)}>
          <option value="">Base run</option>
          {withRisk.map((scan) => <option key={scan.id} value={scan.id}>#{scan.id}</option>)}
        </select>
        <span style={{ color: 'var(--muted)' }}>vs</span>
        <select className="finding-roi-select" value={compareB} onChange={(e) => setCompareB(e.target.value)}>
          <option value="">Compare run</option>
          {withRisk.map((scan) => <option key={scan.id} value={scan.id}>#{scan.id}</option>)}
        </select>
        {diff && (
          <div className="archive-diff">
            <span>Total {diff.findings >= 0 ? '+' : ''}{diff.findings}</span>
            <span>C {diff.critical >= 0 ? '+' : ''}{diff.critical}</span>
            <span>H {diff.high >= 0 ? '+' : ''}{diff.high}</span>
            <span>M {diff.medium >= 0 ? '+' : ''}{diff.medium}</span>
            <span>L {diff.low >= 0 ? '+' : ''}{diff.low}</span>
          </div>
        )}
      </div>

      <table className="table" style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border)' }}>
            <th style={{ padding: '0.75rem' }}>Run ID</th>
            <th style={{ padding: '0.75rem' }}>Target</th>
            <th style={{ padding: '0.75rem' }}>Health</th>
            <th style={{ padding: '0.75rem' }}>Level</th>
            <th style={{ padding: '0.75rem' }}>Status</th>
            <th style={{ padding: '0.75rem' }}>Action</th>
          </tr>
        </thead>
        <tbody>
          {filteredScans.length === 0 ? (
            <tr><td colSpan="6" style={{ padding: '1rem', textAlign: 'center' }}>No scans found.</td></tr>
          ) : filteredScans.map(scan => (
            <tr key={scan.id} style={{ borderBottom: '1px solid var(--bg-hover)' }}>
              <td style={{ padding: '0.75rem' }}>#{scan.id}</td>
              <td style={{ padding: '0.75rem', fontFamily: 'var(--mono)' }}>{scan.target_url}</td>
              <td style={{ padding: '0.75rem' }}>
                <ArchiveSeverityDonut counts={scan.severity_counts} />
              </td>
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