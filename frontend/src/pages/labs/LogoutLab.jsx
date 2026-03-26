import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import LabLayout from '../../components/LabLayout'

export default function LogoutLab() {
  const [done, setDone] = useState(false)

  async function handleLogout() {
    // Hit Flask /logout — intentionally does NOT clear the session
    await fetch('http://127.0.0.1:5000/logout', { credentials: 'include' }).catch(() => {})
    setDone(true)
  }

  return (
    <LabLayout
      title="Logout Simulation"
      subtitle="Intentionally weak logout — session cookie is not cleared."
      risk="medium"
    >
      <div className="card" style={{ maxWidth: 480 }}>
        {done ? (
          <>
            <div className="alert alert-warning" style={{ marginBottom: '1rem' }}>
              Logged out message shown. However, Flask session cookie was <strong>not</strong> invalidated on the server.
              The /admin route may still be accessible.
            </div>
            <div style={{ display: 'flex', gap: '0.75rem' }}>
              <Link to="/lab/admin" className="btn btn-ghost">Try /admin →</Link>
              <Link to="/lab/login" className="btn btn-primary">Login Again</Link>
            </div>
          </>
        ) : (
          <>
            <p style={{ color: 'var(--muted2)', fontSize: '0.88rem', marginBottom: '1rem', lineHeight: 1.5 }}>
              Clicking logout will call Flask <code style={{ color: 'var(--neon)' }}>/logout</code>.
              The session cookie will NOT be cleared — demonstrating incomplete session invalidation.
            </p>
            <button className="btn btn-danger" onClick={handleLogout}>
              Simulate Logout
            </button>
          </>
        )}
      </div>

      <div className="card" style={{ marginTop: '1rem' }}>
        <div className="card-header"><div className="card-title">Fix</div></div>
        <pre>{`# Flask — properly invalidate session on logout
from flask import session

@app.route('/logout')
def logout():
    session.clear()              # destroy server-side session
    resp = redirect(url_for('login'))
    resp.delete_cookie('session') # clear client cookie
    return resp`}</pre>
      </div>
    </LabLayout>
  )
}