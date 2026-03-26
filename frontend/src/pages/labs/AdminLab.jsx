import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import LabLayout from '../../components/LabLayout'

export default function AdminLab() {
  const [currentUser, setCurrentUser] = useState(null)
  const [checked,     setChecked]     = useState(false)

  // Try to read current user from Flask session by hitting /admin
  useEffect(() => {
    fetch('http://127.0.0.1:5000/admin', { credentials: 'include' })
      .then(r => r.text())
      .then(html => {
        const doc  = new DOMParser().parseFromString(html, 'text/html')
        // Flask template outputs "Current session user: <username>"
        const text = doc.querySelector('.panel p')?.textContent || ''
        const match = text.match(/session user:\s*(.+)/i)
        setCurrentUser(match ? match[1].trim() : 'anonymous')
        setChecked(true)
      })
      .catch(() => { setCurrentUser('unknown'); setChecked(true) })
  }, [])

  return (
    <LabLayout
      title="System Config (Admin Area)"
      subtitle="Intentionally accessible with weak controls for scanner auth checks."
      risk="high"
    >
      <div className="card">
        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'center', marginBottom: '1rem' }}>
          <div>
            <div className="stat-label">Current Session User</div>
            <div style={{ fontSize: '1.1rem', fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--neon)', marginTop: '0.25rem' }}>
              {checked ? currentUser : '…'}
            </div>
          </div>
          <div className="badge badge-high">No Real Auth Check</div>
        </div>

        <p style={{ color: 'var(--muted2)', fontSize: '0.85rem', lineHeight: 1.6, marginBottom: '1rem' }}>
          In a real application this page must enforce server-side authorization and role validation.
          AuditCrawl's auth scanner detects this by accessing the URL unauthenticated and
          checking that it returns 200 without a login redirect.
        </p>

        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
          <Link to="/lab/logout" className="btn btn-danger btn-sm">Simulate Logout</Link>
          <Link to="/lab/login"  className="btn btn-ghost btn-sm">Login Lab →</Link>
        </div>
      </div>

      <div className="card" style={{ marginTop: '1rem' }}>
        <div className="card-header"><div className="card-title">Fix</div></div>
        <pre>{`# Flask — enforce server-side auth on every sensitive route
from functools import wraps
from flask import session, redirect, url_for, abort

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/admin')
@login_required
def admin():
    return render_template('admin.html')`}</pre>
      </div>
    </LabLayout>
  )
}