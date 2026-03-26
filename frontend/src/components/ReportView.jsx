import React, { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'

export default function ReportView() {
  const { source, itemId, fmt } = useParams()
  const [content, setContent] = useState('')
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState('')

  const rawUrl = source === 'backend'
    ? `http://127.0.0.1:8000/output/run_${itemId}.${fmt}`
    : fmt === 'json'
      ? `http://127.0.0.1:5000/output/${itemId}/findings.json`
      : `http://127.0.0.1:5000/output/${itemId}/report.xml`

  const downloadUrl = rawUrl

  useEffect(() => {
    let cancelled = false
    setLoading(true)

    fetch(rawUrl)
      .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.text() })
      .then(text => {
        if (cancelled) return
        // Pretty-print
        try {
          if (fmt === 'json') setContent(JSON.stringify(JSON.parse(text), null, 2))
          else setContent(text)
        } catch { setContent(text) }
      })
      .catch(err => { if (!cancelled) setError(err.message) })
      .finally(() => { if (!cancelled) setLoading(false) })

    return () => { cancelled = true }
  }, [rawUrl, fmt])

  const lines = content.split('\n')

  return (
    <div className="page fade-in">
      <div className="page-header">
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '0.5rem' }}>
          <Link to={`/scan/${source}/${itemId}`} className="btn btn-ghost btn-sm">← Results</Link>
          <span className="badge badge-info">{fmt.toUpperCase()} Report</span>
          <span className="badge badge-ok" style={{ fontFamily: 'var(--mono)' }}>
            {source.toUpperCase()} #{itemId}
          </span>
        </div>
        <h1 className="page-title">{fmt.toUpperCase()} Report Viewer</h1>
      </div>

      <div className="card" style={{ marginBottom: '0.75rem' }}>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <a href={rawUrl} target="_blank" rel="noreferrer" className="btn btn-ghost btn-sm">
            Open Raw ↗
          </a>
          <a href={downloadUrl} download className="btn btn-ghost btn-sm">
            ⬇ Download {fmt.toUpperCase()}
          </a>
        </div>
      </div>

      {loading && (
        <div style={{ color: 'var(--muted)', fontFamily: 'var(--mono)', padding: '1rem 0' }}>
          Loading report…
        </div>
      )}

      {error && <div className="alert alert-error">{error}</div>}

      {!loading && !error && (
        <div className="report-code-wrap card" style={{ padding: '0' }}>
          <div style={{ overflow: 'auto', maxHeight: '75vh', padding: '0.75rem 1rem' }}>
            <ol className="report-lines">
              {lines.map((line, i) => (
                <li key={i}>
                  <code>{line}</code>
                </li>
              ))}
            </ol>
          </div>
        </div>
      )}
    </div>
  )
}