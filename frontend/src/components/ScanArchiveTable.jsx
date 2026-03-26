import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { fastApi } from '../api'

function SevBadge({ n, color }) {
  if (!n) return null
  return (
    <span className={`badge badge-${color}`} style={{ marginRight: '0.25rem' }}>
      {n}
    </span>
  )
}

export default function ScanArchiveTable({ limit = 20 }) {
  const [scans,   setScans]   = useState([])
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState('')

  useEffect(() => {
    let cancelled = false

    async function load() {
      setLoading(true)
      try {
        // Probe run IDs 1..40 in parallel
        const ids = Array.from({ length: 40 }, (_, i) => i + 1)
        const results = await Promise.all(
          ids.map(id =>
            fastApi.get(`/api/scan/${id}`, { timeout: 3000 })
              .then(r => ({ ...r.data, _found: true }))
              .catch(() => null)
          )
        )
        const found = results
          .filter(Boolean)
          .sort((a, b) => b.run_id - a.run_id)
          .slice(0, limit)

        if (!cancelled) setScans(found)
      } catch (err) {
        if (!cancelled) setError('Could not load scan history. Is the FastAPI backend running?')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    load()
    return () => { cancelled = true }
  }, [limit])

  if (loading) return (
    <div style={{ color: 'var(--muted)', fontSize: '0.85rem', padding: '0.75rem 0', fontFamily: 'var(--mono)' }}>
      Loading history…
    </div>
  )

  if (error) return (
    <div className="alert alert-warning" style={{ marginTop: '0.5rem' }}>{error}</div>
  )

  if (!scans.length) return (
    <div className="empty-state" style={{ padding: '2rem 0' }}>
      <div className="empty-state-icon">🔍</div>
      <p>No completed scans yet. <Link to="/scanner">Run a scan.</Link></p>
    </div>
  )

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Target URL</th>
            <th>Level</th>
            <th>Findings</th>
            <th>Risk</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {scans.map(scan => {
            const high   = countSev(scan.findings, ['High', 'Critical'])
            const medium = countSev(scan.findings, ['Medium'])
            const low    = countSev(scan.findings, ['Low'])
            return (
              <tr key={scan.run_id}>
                <td style={{ fontFamily: 'var(--mono)', color: 'var(--muted)' }}>
                  #{scan.run_id}
                </td>
                <td title={scan.target_url}
                  style={{ fontFamily: 'var(--mono)', fontSize: '0.8rem', maxWidth: 240 }}>
                  {trunc(scan.target_url, 40)}
                </td>
                <td>
                  <span className="badge badge-info">L{scan.scan_level}</span>
                </td>
                <td style={{ fontWeight: 700, color: scan.findings_count ? 'var(--orange)' : 'var(--neon)' }}>
                  {scan.findings_count}
                </td>
                <td>
                  <SevBadge n={high}   color="high"   />
                  <SevBadge n={medium} color="medium" />
                  <SevBadge n={low}    color="low"    />
                </td>
                <td>
                  <Link to={`/scan/backend/${scan.run_id}`} className="archive-link">
                    View →
                  </Link>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function countSev(findings, sevs) {
  return (findings || []).filter(f => sevs.includes(f.severity)).length
}

function trunc(s, n) {
  if (!s) return '—'
  return s.length > n ? s.slice(0, n) + '…' : s
}