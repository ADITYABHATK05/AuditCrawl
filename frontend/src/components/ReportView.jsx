import React, { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'

export default function ReportView() {
  const { source, id, itemId } = useParams()
  const actualId = id || itemId

  // Only PDF reports are supported now.
  const pdfUrl =
    source === 'backend'
      ? `http://127.0.0.1:8000/output/run_${actualId}.pdf`
      : `http://127.0.0.1:5000/output/${actualId}/report.pdf`

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
          <a href={pdfUrl} target="_blank" rel="noreferrer" className="btn btn-ghost btn-sm">
            Open PDF ↗
          </a>
          <a href={pdfUrl} download className="btn btn-ghost btn-sm">
            ⬇ Download PDF
          </a>
        </div>
      </div>

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <iframe
          title="PDF Report"
          src={pdfUrl}
          style={{ width: '100%', height: '75vh', border: '0' }}
        />
      </div>
    </div>
  )
}