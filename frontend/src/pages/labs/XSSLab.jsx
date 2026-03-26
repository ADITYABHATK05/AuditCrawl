import React, { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import LabLayout from '../../components/LabLayout'

export default function XSSLab() {
  const [searchParams, setSearchParams] = useSearchParams()
  const initial = searchParams.get('q') || ''
  const [q, setQ] = useState(initial)
  const [submitted, setSubmitted] = useState(initial)

  function handleSubmit(e) {
    e.preventDefault()
    setSubmitted(q)
    setSearchParams({ q })
  }

  return (
    <LabLayout
      title="Reflected XSS Demonstration"
      subtitle="Input is intentionally reflected in HTML context for educational scanner testing."
      risk="medium"
    >
      <div className="card">
        <form className="scan-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="q">Search Query</label>
            <input
              id="q"
              type="text"
              value={q}
              onChange={e => setQ(e.target.value)}
              placeholder="Try hello or a test payload"
            />
          </div>
          <div className="scan-action-row">
            <button type="submit" className="btn btn-primary">Search</button>
          </div>
        </form>
      </div>

      <div className="card">
        <div className="card-header">
          <div className="card-title">Rendered Output</div>
          <span className="badge badge-medium">Intentionally Unsafe</span>
        </div>
        {/* ⚠ Intentionally vulnerable: dangerouslySetInnerHTML mirrors Flask's |safe filter */}
        <div
          className="rendered-output"
          dangerouslySetInnerHTML={{ __html: `You searched: ${submitted}` }}
        />
      </div>

      <LabNotes notes={[
        'The Flask backend at /xss?q= reflects the query parameter without escaping.',
        'In React this is mirrored via dangerouslySetInnerHTML to preserve the lab behaviour.',
        'The AuditCrawl scanner detects this by injecting a unique marker and checking if it appears in a sensitive rendering context.',
        'Fix: use context-aware output encoding (e.g. Jinja2 autoescaping, React default interpolation) and a strict Content-Security-Policy.',
      ]} />
    </LabLayout>
  )
}

function LabNotes({ notes }) {
  return (
    <div className="card" style={{ marginTop: '1rem' }}>
      <div className="card-header">
        <div className="card-title">Scanner Notes</div>
      </div>
      <ul style={{ paddingLeft: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
        {notes.map((n, i) => (
          <li key={i} style={{ color: 'var(--muted2)', fontSize: '0.85rem', lineHeight: 1.5 }}>{n}</li>
        ))}
      </ul>
    </div>
  )
}