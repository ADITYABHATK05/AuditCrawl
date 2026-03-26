import React, { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'

export default function ReportView() {
  const { source, id, itemId } = useParams()
  const actualId = id || itemId
  const [pdfState, setPdfState] = useState('checking')

  // Only PDF reports are supported now.
  const pdfUrl =
    source === 'backend'
      ? `http://127.0.0.1:8000/output/run_${actualId}.pdf`
      : `http://127.0.0.1:5000/output/${actualId}/report.pdf`

  useEffect(() => {
    let mounted = true
    setPdfState('checking')

    fetch(pdfUrl, { method: 'HEAD' })
      .then((res) => {
        if (!mounted) return
        setPdfState(res.ok ? 'ready' : 'missing')
      })
      .catch(() => {
        if (!mounted) return
        setPdfState('missing')
      })

    return () => { mounted = false }
  }, [pdfUrl])

  return (
    <div className="page fade-in">
      <div className="page-header">
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '0.5rem' }}>
          <Link to={`/scan/${source}/${actualId}`} className="btn btn-ghost btn-sm">← Results</Link>
          <span className="badge badge-info">PDF Report</span>
          <span className="badge badge-ok" style={{ fontFamily: 'var(--mono)' }}>
            {source.toUpperCase()} #{actualId}
          </span>
        </div>
        <h1 className="page-title">PDF Report Viewer</h1>
      </div>

      <div className="card" style={{ marginBottom: '0.75rem' }}>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <a href={pdfUrl} target="_blank" rel="noreferrer" className="btn btn-ghost btn-sm" style={{ pointerEvents: pdfState === 'ready' ? 'auto' : 'none', opacity: pdfState === 'ready' ? 1 : 0.45 }}>
            Open PDF ↗
          </a>
          <a href={pdfUrl} download className="btn btn-ghost btn-sm" style={{ pointerEvents: pdfState === 'ready' ? 'auto' : 'none', opacity: pdfState === 'ready' ? 1 : 0.45 }}>
            ⬇ Download PDF
          </a>
          {pdfState !== 'ready' && (
            <span className="badge badge-error">
              {pdfState === 'checking' ? 'Checking report...' : 'PDF unavailable'}
            </span>
          )}
        </div>
      </div>

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        {pdfState === 'ready' ? (
          <iframe
            title="PDF Report"
            src={pdfUrl}
            style={{ width: '100%', height: '75vh', border: '0' }}
          />
        ) : (
          <div className="empty" style={{ padding: '2rem 1rem' }}>
            <div className="empty-icon">📄</div>
            <div className="empty-text">
              {pdfState === 'checking' ? 'Checking report availability...' : 'Report PDF not found for this run.'}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}