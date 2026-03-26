import React, { useState, useEffect, useCallback } from 'react'
import LabLayout from '../../components/LabLayout'

export default function GuestbookLab() {
  const [comment, setComment] = useState('')
  const [entries, setEntries] = useState([])
  const [loading, setLoading] = useState(true)
  const [posting, setPosting] = useState(false)
  const [error,   setError]   = useState('')

  // Fetch entries by hitting Flask /guestbook and parsing the HTML response.
  // Because Flask /guestbook returns HTML (not JSON), we fetch it and extract notes.
  const loadEntries = useCallback(async () => {
    setLoading(true)
    try {
      const resp = await fetch('http://127.0.0.1:5000/guestbook', { credentials: 'include' })
      const html = await resp.text()
      // Parse the <ul class="entries"> from the returned HTML
      const doc    = new DOMParser().parseFromString(html, 'text/html')
      const items  = doc.querySelectorAll('.entries li')
      const parsed = Array.from(items).map(li => ({
        id:      li.querySelector('.entry-id')?.textContent?.replace('#', '') || '?',
        // preserve raw HTML so stored XSS renders (intentional lab behaviour)
        content: li.querySelector('.entry-content')?.innerHTML || li.innerHTML,
      }))
      setEntries(parsed)
    } catch {
      setError('Could not reach Flask backend at port 5000')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadEntries() }, [loadEntries])

  async function handleSubmit(e) {
    e.preventDefault()
    setPosting(true)
    try {
      const form = new URLSearchParams({ comment })
      await fetch('http://127.0.0.1:5000/guestbook', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: form.toString(),
      })
      setComment('')
      await loadEntries()
    } catch {
      setError('POST failed — is Flask running on port 5000?')
    } finally {
      setPosting(false)
    }
  }

  return (
    <LabLayout
      title="Stored XSS Guestbook"
      subtitle="Comments are intentionally re-rendered unsafely to simulate persistence vulnerabilities."
      risk="high"
    >
      <div className="card">
        <form className="scan-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="comment">Leave a Comment</label>
            <textarea
              id="comment"
              value={comment}
              onChange={e => setComment(e.target.value)}
              rows={4}
              placeholder="Post a harmless test comment"
              style={{
                background: 'var(--bg2)',
                border: '1px solid var(--border2)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text)',
                fontFamily: 'var(--mono)',
                fontSize: '0.88rem',
                padding: '0.65rem 0.9rem',
                width: '100%',
                resize: 'vertical',
                outline: 'none',
              }}
            />
          </div>
          <div className="scan-action-row">
            <button type="submit" className="btn btn-primary" disabled={posting || !comment.trim()}>
              {posting ? 'Submitting…' : 'Submit Comment'}
            </button>
          </div>
        </form>
      </div>

      {error && <div className="alert alert-error" style={{ marginTop: '0.75rem' }}>{error}</div>}

      <div className="card" style={{ marginTop: '1rem' }}>
        <div className="card-header">
          <div className="card-title">Latest Entries</div>
          <span className="badge badge-high">Unsafe Render</span>
        </div>

        {loading ? (
          <div style={{ color: 'var(--muted)', fontFamily: 'var(--mono)', fontSize: '0.85rem' }}>
            Loading entries…
          </div>
        ) : entries.length === 0 ? (
          <div style={{ color: 'var(--muted)', fontSize: '0.85rem' }}>No entries yet.</div>
        ) : (
          <ul className="entries">
            {entries.map((entry, i) => (
              <li key={i} style={{ borderTop: i > 0 ? '1px solid var(--border)' : 'none', padding: '0.6rem 0' }}>
                <span className="entry-id" style={{ color: 'var(--muted)', fontFamily: 'var(--mono)', marginRight: '0.5rem' }}>
                  #{entry.id}
                </span>
                {/* Intentionally unsafe: mirrors Flask |safe for stored XSS lab */}
                <span dangerouslySetInnerHTML={{ __html: entry.content }} />
              </li>
            ))}
          </ul>
        )}
      </div>
    </LabLayout>
  )
}