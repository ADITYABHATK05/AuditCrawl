import React, { useState, useEffect, useRef, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { flaskStartScan, flaskGetJobStatus, flaskStopScan, getAllScans } from '../api'
import ScanArchiveTable from './ScanArchiveTable'
import BatchScanForm from './BatchScanForm'
import BatchScanHistory from './BatchScanHistory'

const LEVELS = [
  { value: '1', name: 'Level 1 — Shallow', desc: '20 pages · depth 1 · ~30s' },
  { value: '2', name: 'Level 2 — Medium',  desc: '80 pages · depth 3 · ~2min' },
  { value: '3', name: 'Level 3 — Deep',    desc: '200 pages · depth 5 · ~5min' },
]

const PROFILE_BY_LEVEL = {
  '1': { maxPages: 20, maxDepth: 1 },
  '2': { maxPages: 80, maxDepth: 3 },
  '3': { maxPages: 200, maxDepth: 5 },
}

function normalizeTargetUrl(value) {
  if (!value) return ''
  return String(value).trim().replace(/\/+$/, '').toLowerCase()
}

function buildCoverageInsight(latestByLevel, currentLevel) {
  const l1 = latestByLevel['1']
  const l2 = latestByLevel['2']
  const l3 = latestByLevel['3']

  if (l1 != null && l2 != null && l3 != null) {
    if (l1 < l2 && l2 === l3) {
      return 'Depth is working: deeper crawling found more issues by level 2, then plateaued. Level 3 did not add new unique findings for this target.'
    }
    if (l1 === l2 && l2 === l3) {
      return 'All levels currently return the same finding set. This usually means vulnerable endpoints are reachable early, not that scanning is broken.'
    }
    if (l1 <= l2 && l2 <= l3 && (l1 < l3 || l2 < l3)) {
      return 'Depth is expanding coverage: higher levels are uncovering additional findings on this target.'
    }
  }

  if (currentLevel === '3') {
    return 'Level 3 explores the widest crawl budget. If counts match level 2, the target likely has no additional unique vulnerable paths beyond medium depth.'
  }

  return 'Finding counts can repeat across levels when deeper pages do not introduce new unique vulnerabilities.'
}

export default function Scanner() {
  const [targetUrl,     setTargetUrl]     = useState('http://127.0.0.1:5000')
  const [scanLevel,     setScanLevel]     = useState('2')
  const [hasPermission, setHasPermission] = useState(false)
  const [job,           setJob]           = useState(null)   // { job_id, status, progress, message }
  const [error,         setError]         = useState('')
  const [loading,       setLoading]       = useState(false)
  const [resultRunId,   setResultRunId]   = useState(null)
  const [sameTargetRuns, setSameTargetRuns] = useState([])
  const [comparisonError, setComparisonError] = useState('')
  const pollRef = useRef(null)

  const stopPoll = useCallback(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null }
  }, [])

  useEffect(() => () => stopPoll(), [stopPoll])

  const startPoll = useCallback((jobId) => {
    stopPoll()
    pollRef.current = setInterval(async () => {
      try {
        const data = await flaskGetJobStatus(jobId)
        setJob(data)
        
        if (data.status === 'completed') {
          stopPoll()
          setLoading(false)
          // FastAPI returns run_id at the top level of the response
          if (data.run_id) {
            setResultRunId(data.run_id)
          }
        }
        
        if (data.status === 'failed' || data.status === 'cancelled') {
          stopPoll()
          setLoading(false)
          if (data.status === 'failed') setError(data.error || 'Scan failed')
        }
      } catch (err) {
        stopPoll()
        setLoading(false)
        setError('Lost connection to backend')
      }
    }, 1000)
  }, [stopPoll])

  async function handleSubmit(e) {
    e.preventDefault()
    if (!hasPermission) return
    setError('')
    setJob(null)
    setResultRunId(null)
    setLoading(true)
    try {
      const data = await flaskStartScan({
        target_url: targetUrl,
        scan_level: scanLevel,
        has_permission: true,
      })
      if (data.error) { setError(data.error); setLoading(false); return }
      setJob({ job_id: data.job_id, status: data.status, progress: data.progress, message: data.message })
      startPoll(data.job_id)
    } catch (err) {
      setLoading(false)
      setError(err?.response?.data?.error || err.message || 'Failed to start scan')
    }
  }

  async function handleStop() {
    if (!job?.job_id) return
    stopPoll()
    try {
      const data = await flaskStopScan(job.job_id)
      setJob(data)
    } catch {}
    setLoading(false)
  }

  const pct    = job?.progress ?? 0
  const isDone = job?.status === 'completed'
  const isFail = job?.status === 'failed'
  const isRunning = job?.status === 'running' || job?.status === 'queued'
  const currentResult = job?.result || null
  const currentLevel = currentResult?.scan_level || scanLevel
  const currentProfile = PROFILE_BY_LEVEL[currentLevel] || PROFILE_BY_LEVEL['2']

  useEffect(() => {
    let cancelled = false

    async function loadSameTargetRuns() {
      if (!isDone || !currentResult?.target_url) return
      try {
        setComparisonError('')
        const rows = await getAllScans()
        if (cancelled) return
        const normalizedTarget = normalizeTargetUrl(currentResult.target_url)
        const sameTarget = rows.filter((row) => normalizeTargetUrl(row.target_url) === normalizedTarget)
        setSameTargetRuns(sameTarget.slice(0, 12))
      } catch (_err) {
        if (!cancelled) {
          setComparisonError('Could not load same-target comparison history.')
          setSameTargetRuns([])
        }
      }
    }

    loadSameTargetRuns()
    return () => {
      cancelled = true
    }
  }, [isDone, currentResult?.target_url, resultRunId])

  const latestByLevel = sameTargetRuns.reduce((acc, run) => {
    if (!acc[run.scan_level]) {
      acc[run.scan_level] = run.findings_count
    }
    return acc
  }, {})

  const coverageInsight = buildCoverageInsight(latestByLevel, currentLevel)

  return (
    <div className="page fade-in">
      <div className="page-header">
        <h1 className="page-title">Initiate Scan</h1>
        <p className="page-sub">Non-destructive heuristic checks · authorized targets only</p>
      </div>

      <div className="alert alert-info" style={{ marginBottom: '1.25rem' }}>
        <InfoIcon />
        <span>
          Checks performed: <strong>Reflected XSS</strong>, <strong>SQL Injection</strong>,
          <strong> SSRF surface</strong>, <strong>Security misconfigurations</strong>,
          missing security headers. Scan is non-destructive — no real exploits are triggered.
        </span>
      </div>

      <div className="card">
        <form className="scan-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="target-url">Target URL</label>
            <input
              id="target-url"
              type="url"
              value={targetUrl}
              onChange={e => setTargetUrl(e.target.value)}
              placeholder="http://127.0.0.1:5000"
              required
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label>Scan Level</label>
            <div className="level-group">
              {LEVELS.map(lvl => (
                <label key={lvl.value} className="level-pill">
                  <input
                    type="radio"
                    name="scan_level"
                    value={lvl.value}
                    checked={scanLevel === lvl.value}
                    onChange={() => setScanLevel(lvl.value)}
                    disabled={loading}
                  />
                  <span className="level-pill-inner">
                    <span className="level-pill-name">{lvl.name}</span>
                    <span className="level-pill-desc">{lvl.desc}</span>
                  </span>
                </label>
              ))}
            </div>
          </div>

          <label className="permission-check">
            <input
              type="checkbox"
              checked={hasPermission}
              onChange={e => setHasPermission(e.target.checked)}
              disabled={loading}
            />
            <span>
              I confirm this target is owned by me or I have <strong>explicit written authorization</strong> to test it.
              Scans are non-destructive and for educational use only.
            </span>
          </label>

          <div className="scan-action-row">
            <button
              type="submit"
              className="btn btn-primary btn-lg"
              disabled={!hasPermission || loading}
            >
              {loading ? <><SpinIcon /> Scanning…</> : <><PlayIcon /> Start Safe Scan</>}
            </button>

            {isRunning && (
              <button type="button" className="btn btn-danger" onClick={handleStop}>
                Stop Scan
              </button>
            )}

            {!hasPermission && !loading && (
              <span className="hint-text">← confirm authorization above first</span>
            )}
          </div>
        </form>

        {error && (
          <div className="alert alert-error" style={{ marginTop: '1rem' }}>
            <ErrIcon /> {error}
          </div>
        )}
      </div>

      {job && (
        <div className="job-card fade-in">
          <div className="job-header">
            <div className="job-status-indicator">
              <span className={`pulse-dot ${isDone ? 'done' : isFail ? 'error' : ''}`} />
              <span style={{ color: isDone ? 'var(--neon)' : isFail ? 'var(--red)' : 'var(--muted2)' }}>
                {{ queued: 'Queued', running: 'Scanning', completed: 'Complete',
                   failed: 'Failed', cancelled: 'Cancelled' }[job.status] ?? job.status}
              </span>
              {job.job_id && (
                <span style={{ color: 'var(--muted)', fontSize: '0.72rem', fontFamily: 'var(--mono)', marginLeft: '0.5rem' }}>
                  {job.job_id.slice(0, 12)}…
                </span>
              )}
            </div>

            {isDone && resultRunId && (
              <Link to={`/scan/backend/${resultRunId}`} className="btn btn-primary btn-sm">
                View Results →
              </Link>
            )}
          </div>

          <div className="progress-meta">
            <span className="progress-message">{job.message || 'Initializing…'}</span>
            <span className="progress-pct">{pct}%</span>
          </div>
          <div className="progress-track">
            <div
              className="progress-fill"
              style={{ width: `${pct}%`, background: isFail ? 'var(--red)' : undefined }}
            />
          </div>
        </div>
      )}

      {isDone && currentResult && (
        <div className="card coverage-card fade-in">
          <div className="card-header" style={{ marginBottom: '0.75rem' }}>
            <div className="card-title"><RadarIcon /> Scan Coverage Insight</div>
          </div>

          <div className="coverage-grid">
            <div className="coverage-metric">
              <span className="coverage-label">Scan Level</span>
              <strong>{currentLevel}</strong>
            </div>
            <div className="coverage-metric">
              <span className="coverage-label">Configured Depth</span>
              <strong>{currentProfile.maxDepth}</strong>
            </div>
            <div className="coverage-metric">
              <span className="coverage-label">Configured Max Pages</span>
              <strong>{currentProfile.maxPages}</strong>
            </div>
            <div className="coverage-metric">
              <span className="coverage-label">Endpoints Discovered</span>
              <strong>{currentResult.endpoints_count ?? 0}</strong>
            </div>
            <div className="coverage-metric">
              <span className="coverage-label">Findings</span>
              <strong>{currentResult.findings_count ?? 0}</strong>
            </div>
          </div>

          <div className="coverage-level-row">
            {['1', '2', '3'].map((lvl) => (
              <div key={lvl} className="coverage-level-pill">
                <span>Level {lvl}</span>
                <strong>{latestByLevel[lvl] ?? '—'} findings</strong>
              </div>
            ))}
          </div>

          <p className="coverage-note">{coverageInsight}</p>

          {comparisonError && (
            <div className="alert alert-error" style={{ marginTop: '0.8rem' }}>
              <ErrIcon /> {comparisonError}
            </div>
          )}
        </div>
      )}

      {/* Note: Ensure ScanArchiveTable exists and is imported correctly */}
      <div className="card recent-archive-card" style={{ marginTop: '1.5rem' }}>
        <div className="card-header">
          <div className="card-title"><ArchiveIcon /> Recent Scan Archive</div>
          <Link to="/archive" className="btn btn-ghost btn-sm">Full Archive →</Link>
        </div>
        <ScanArchiveTable limit={8} />
      </div>

      {/* Batch Scanning */}
      <BatchScanForm />
      <BatchScanHistory />
    </div>
  )
}

/* ── Icons ─────────────────────────────────────────────────────────── */
const PlayIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
    <polygon points="5 3 19 12 5 21 5 3"/>
  </svg>
)
const SpinIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
    style={{ animation: 'spin 1s linear infinite' }}>
    <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
  </svg>
)
const InfoIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
    strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0 }}>
    <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/>
    <line x1="12" y1="16" x2="12.01" y2="16"/>
  </svg>
)
const ErrIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
    strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0 }}>
    <circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/>
    <line x1="9" y1="9" x2="15" y2="15"/>
  </svg>
)
const ArchiveIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
    strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/>
    <line x1="10" y1="12" x2="14" y2="12"/>
  </svg>
)
const RadarIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
    strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="9"/>
    <circle cx="12" cy="12" r="5"/>
    <line x1="12" y1="12" x2="19" y2="9"/>
    <circle cx="19" cy="9" r="1" fill="currentColor"/>
  </svg>
)