import React, { useState, useEffect, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import LabLayout from '../../components/LabLayout'

export default function SQLiLab() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [userId,  setUserId]  = useState(searchParams.get('id') || '1')
  const [result,  setResult]  = useState(null)
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState('')

  const runQuery = useCallback(async (id) => {
    setLoading(true)
    setError('')
    try {
      const resp = await fetch(`http://127.0.0.1:5000/sqli?id=${encodeURIComponent(id)}`, {
        credentials: 'include',
      })
      const html = await resp.text()
      const doc  = new DOMParser().parseFromString(html, 'text/html')

      const query   = doc.querySelector('pre')?.textContent || ''
      const isError = !!doc.querySelector('.status.error')
      const resultEl = doc.querySelectorAll('pre')[1]
      const rows    = resultEl?.textContent || ''

      setResult({ query, rows, isError })
    } catch {
      setError('Could not reach Flask backend at port 5000')
    } finally {
      setLoading(false)
    }
  }, [])

  // Run on mount with current param
  useEffect(() => {
    runQuery(searchParams.get('id') || '1')
  }, []) // eslint-disable-line

  function handleSubmit(e) {
    e.preventDefault()
    setSearchParams({ id: userId })
    runQuery(userId)
  }

  return (
    <LabLayout
      title="SQL Injection Demonstration"
      subtitle="Query is intentionally built with string formatting for scanner symptom detection."
      risk="high"
    >
      <div className="card">
        <form className="scan-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="userid">User ID</label>
            <input
              id="userid"
              type="text"
              value={userId}
              onChange={e => setUserId(e.target.value)}
              placeholder="Try 1, or ' OR '1'='1"
            />
          </div>
          <div className="scan-action-row">
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? 'Running…' : 'Lookup User'}
            </button>
          </div>
        </form>
      </div>

      {error && <div className="alert alert-error" style={{ marginTop: '0.75rem' }}>{error}</div>}

      {result && (
        <>
          <div className="card" style={{ marginTop: '1rem' }}>
            <div className="card-header">
              <div className="card-title">Executed Query</div>
              <span className="badge badge-high">Unsafe · String Format</span>
            </div>
            <pre>{result.query}</pre>
          </div>

          <div className="card" style={{ marginTop: '0.75rem' }}>
            <div className="card-header">
              <div className="card-title">Result</div>
              {result.isError && <span className="badge badge-high">SQL Error</span>}
            </div>
            {result.isError ? (
              <div className="alert alert-error">{result.rows}</div>
            ) : (
              <pre>{result.rows}</pre>
            )}
          </div>
        </>
      )}

      <div className="card" style={{ marginTop: '0.75rem' }}>
        <div className="card-header"><div className="card-title">Fix</div></div>
        <pre>{`# Parameterized query — safe
from sqlalchemy import text
stmt = text('SELECT username FROM users WHERE id = :id')
rows = session.execute(stmt, {'id': user_id}).fetchall()`}</pre>
      </div>
    </LabLayout>
  )
}