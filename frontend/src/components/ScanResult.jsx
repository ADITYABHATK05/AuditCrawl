import React, { useState, useEffect, useMemo } from 'react'
import { useParams, Link } from 'react-router-dom'
import { fastApi } from '../api'
import FindingsTable from '../components/FindingsTable'
import VulnChart from '../components/VulnChart'

export default function ScanResult() {
  const { source, itemId } = useParams()
  const [scan,    setScan]    = useState(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState('')

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError('')

    async function load() {
      try {
        // Both "backend" and "legacy" sources can be fetched via FastAPI
        // (legacy scans aren't in FastAPI DB, but backend scans are)
        if (source === 'backend') {
          const { data } = await fastApi.get(`/api/scan/${itemId}`)
          if (!cancelled) setScan(data)
        } else {
          // Legacy scan — read JSON file via Flask static route
          const resp = await fetch(
            `http://127.0.0.1:5000/output/${itemId}/findings.json`
          )
          if (!resp.ok) throw new Error('Legacy scan not found')
          const json = await resp.json()
          // Shape into the same format as FastAPI response
          const findings = (json.findings || []).map(f => ({
            vulnerability_type: f.vulnerability,
            severity: f.risk,
            endpoint: f.endpoint,
            evidence: f.evidence,
            vulnerable_snippet: f.payload || '',
            fix_snippet: f.remediation || '',
          }))
          if (!cancelled) setScan({
            run_id: itemId,
            target_url: json.target_url || 'unknown',
            scan_level: '—',
            findings_count: findings.length,
            findings,
            json_path: `http://127.0.0.1:5000/output/${itemId}/findings.json`,
            xml_path: null,
          })
        }
      } catch (err) {
        if (!cancelled) setError(err.message || 'Failed to load scan result')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    load()
    return () => { cancelled = true }
  }, [source, itemId])

  const summary = useMemo(() => {
    if (!scan) return {}
    const findings = scan.findings || []
    return {
      total:    findings.length,
      high:     findings.filter(f => ['High','Critical'].includes(f.severity)).length,
      medium:   findings.filter(f => f.severity === 'Medium').length,
      low:      findings.filter(f => f.severity === 'Low').length,
    }
  }, [scan])

  if (loading) return (
    <div className="page fade-in">
      <div style={{ color: 'var(--muted)', fontFamily: 'var(--mono)', padding: '2rem 0' }}>
        Loading scan result…
      </div>
    </div>
  )

  if (error) return (
    <div className="page fade-in">
      <div className="alert alert-error">{error}</div>
      <Link to="/archive" className="btn btn-ghost" style={{ marginTop: '1rem' }}>
        ← Back to Archive
      </Link>
    </div>
  )

  const jsonUrl = source === 'backend'
    ? `http://127.0.0.1:8000/output/run_${itemId}.json`
    : `http://127.0.0.1:5000/output/${itemId}/findings.json`

  const xmlUrl = source === 'backend'
    ? `http://127.0.0.1:8000/output/run_${itemId}.xml`
    : null

  return (
    <div className="page fade-in">
      {/* Header */}
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.25rem' }}>
          <Link to="/archive" className="btn btn-ghost btn-sm">← Archive</Link>
          <span className="badge badge-info" style={{ fontFamily: 'var(--mono)' }}>
            {source.toUpperCase()} #{itemId}
          </span>
        </div>
        <h1 className="page-title" style={{ marginTop: '0.5rem' }}>Scan Results</h1>
        <p className="page-sub" style={{ fontFamily: 'var(--mono)', wordBreak: 'break-all' }}>
          {scan.target_url}
        </p>
      </div>

      {/* Stat cards */}
      <div className="stat-grid">
        <div className="stat-card red">
          <div className="stat-label">High / Critical</div>
          <div className="stat-value red">{summary.high}</div>
          <div className="stat-sub">findings</div>
        </div>
        <div className="stat-card orange">
          <div className="stat-label">Medium</div>
          <div className="stat-value orange">{summary.medium}</div>
          <div className="stat-sub">findings</div>
        </div>
        <div className="stat-card green">
          <div className="stat-label">Low</div>
          <div className="stat-value green">{summary.low}</div>
          <div className="stat-sub">findings</div>
        </div>
        <div className="stat-card blue">
          <div className="stat-label">Total</div>
          <div className="stat-value blue">{summary.total}</div>
          <div className="stat-sub">all findings</div>
        </div>
      </div>

      {/* Download links */}
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '1.25rem' }}>
        <Link to={`/report/${source}/${itemId}/json`} className="btn btn-ghost btn-sm">
          📄 View JSON Report
        </Link>
        <a href={jsonUrl} download className="btn btn-ghost btn-sm">
          ⬇ Download JSON
        </a>
        {xmlUrl && (
          <>
            <Link to={`/report/${source}/${itemId}/xml`} className="btn btn-ghost btn-sm">
              📄 View XML Report
            </Link>
            <a href={xmlUrl} download className="btn btn-ghost btn-sm">
              ⬇ Download XML
            </a>
          </>
        )}
      </div>

      {/* Vuln type breakdown */}
      {scan.findings?.length > 0 && (
        <div className="card" style={{ marginBottom: '1rem' }}>
          <div className="card-header">
            <div className="card-title">Vulnerability Type Breakdown</div>
          </div>
          <VulnChart findings={scan.findings} />
        </div>
      )}

      {/* Findings table */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">Findings ({summary.total})</div>
        </div>
        <FindingsTable findings={scan.findings || []} />
      </div>
    </div>
  )
}