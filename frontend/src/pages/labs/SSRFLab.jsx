import React, { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import LabLayout from '../../components/LabLayout'

export default function SSRFLab() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [target,  setTarget]  = useState(searchParams.get('url') || '')
  const [preview, setPreview] = useState('')
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState('')

  async function handleSubmit(e) {
    e.preventDefault()
    setLoading(true)
    setError('')
    setSearchParams(target ? { url: target } : {})
    try {
      const resp = await fetch(
        `http://127.0.0.1:5000/ssrf?url=${encodeURIComponent(target)}`,
        { credentials: 'include' }
      )
      const html = await resp.text()
      const doc  = new DOMParser().parseFromString(html, 'text/html')
      const pre  = doc.querySelector('pre')
      setPreview(pre?.textContent || 'No preview output.')
    } catch {
      setError('Could not reach Flask backend at port 5000')
    } finally {
      setLoading(false)
    }
  }

  return (
    <LabLayout
      title="SSRF Input Handling Demo"
      subtitle="URL inputs are accepted for educational SSRF surface detection."
      risk="medium"
    >
      <div className="card">
        <form className="scan-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="ssrf-url">Target URL</label>
            <input
              id="ssrf-url"
              type="text"
              value={target}
              onChange={e => setTarget(e.target.value)}
              placeholder="http://example.com"
            />
          </div>
          <div className="scan-action-row">
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? 'Simulating…' : 'Simulate Fetch'}
            </button>
          </div>
        </form>
      </div>

      {error && <div className="alert alert-error" style={{ marginTop: '0.75rem' }}>{error}</div>}

      <div className="card" style={{ marginTop: '1rem' }}>
        <div className="card-header">
          <div className="card-title">Simulation Output</div>
          <span className="badge badge-medium">No Real Outbound Request</span>
        </div>
        <pre>{preview || 'No URL submitted yet.'}</pre>
      </div>

      <div className="card" style={{ marginTop: '0.75rem' }}>
        <div className="card-header"><div className="card-title">Fix</div></div>
        <pre>{`# Enforce an outbound URL allow-list
from urllib.parse import urlparse

ALLOWED_HOSTS = {'api.example.com'}
parsed = urlparse(user_url)
if parsed.scheme != 'https' or parsed.hostname not in ALLOWED_HOSTS:
    raise ValueError('Blocked outbound URL')

resp = httpx.get(user_url, timeout=5)`}</pre>
      </div>
    </LabLayout>
  )
}