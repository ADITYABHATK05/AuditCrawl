import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import LabLayout from '../../components/LabLayout'

export default function LoginLab() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error,    setError]    = useState('')
  const [loading,  setLoading]  = useState(false)
  const navigate = useNavigate()

  async function handleSubmit(e) {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const form = new URLSearchParams({ username, password })
      const resp = await fetch('http://127.0.0.1:5000/login', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: form.toString(),
        redirect: 'manual',   // Flask redirects to /admin on success
      })
      // 302 redirect = success
      if (resp.type === 'opaqueredirect' || resp.status === 302 || resp.status === 0) {
        navigate('/lab/admin')
      } else {
        const html = await resp.text()
        const doc  = new DOMParser().parseFromString(html, 'text/html')
        const errEl = doc.querySelector('.status.error')
        setError(errEl?.textContent || 'Invalid credentials. Use testuser / testpass')
      }
    } catch {
      setError('Could not reach Flask backend at port 5000')
    } finally {
      setLoading(false)
    }
  }

  return (
    <LabLayout
      title="Authentication Lab"
      subtitle="Use test credentials to inspect session behaviour."
      risk="medium"
    >
      <div className="card" style={{ maxWidth: 420 }}>
        <form className="scan-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              placeholder="testuser"
              autoComplete="off"
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="testpass"
              required
            />
          </div>
          <div className="scan-action-row">
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? 'Signing in…' : 'Sign In'}
            </button>
          </div>
        </form>

        {error && (
          <div className="alert alert-error" style={{ marginTop: '0.75rem' }}>
            {error}
          </div>
        )}

        <p style={{ marginTop: '0.75rem', color: 'var(--muted)', fontSize: '0.82rem', fontFamily: 'var(--mono)' }}>
          Demo credentials: <strong style={{ color: 'var(--neon2)' }}>testuser</strong> / <strong style={{ color: 'var(--neon2)' }}>testpass</strong>
        </p>
      </div>
    </LabLayout>
  )
}