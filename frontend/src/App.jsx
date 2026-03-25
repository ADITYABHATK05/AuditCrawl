import React from 'react'
import ScanForm from './components/ScanForm'
import FindingsView from './components/FindingsView'
import JobProgress from './components/JobProgress'
import { enqueueScan, getJobStatus } from './api'

export default function App() {
  const [loading, setLoading] = React.useState(false)
  const [error, setError] = React.useState('')
  const [result, setResult] = React.useState(null)
  const [job, setJob] = React.useState(null)

  const onSubmit = async (payload) => {
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const queued = await enqueueScan(payload)
      setJob(queued)
    } catch (err) {
      setError(err?.response?.data?.detail || err.message)
      setLoading(false)
    }
  }

  React.useEffect(() => {
    if (!job?.job_id) return
    if (job.status === 'completed' || job.status === 'failed') return

    const id = setInterval(async () => {
      try {
        const latest = await getJobStatus(job.job_id)
        setJob(latest)
        if (latest.status === 'completed') {
          setResult(latest.result)
          setLoading(false)
        } else if (latest.status === 'failed') {
          setError(latest.error || 'Scan failed')
          setLoading(false)
        }
      } catch (err) {
        setError(err?.response?.data?.detail || err.message)
        setLoading(false)
      }
    }, 1500)

    return () => clearInterval(id)
  }, [job?.job_id, job?.status])

  React.useEffect(() => {
    if (job && (job.status === 'completed' || job.status === 'failed')) {
      setLoading(false)
    }
  }, [job])

  const showJobProgress = job && job.status !== 'completed'

  return (
    <main className="container">
      <h1>AuditCrawl</h1>
      <p className="sub">Authorized defensive scanning only. Non-destructive checks.</p>
      <ScanForm onSubmit={onSubmit} loading={loading} />
      {error && <div className="error">{error}</div>}
      {showJobProgress && <JobProgress job={job} />}
      <FindingsView result={result} />
    </main>
  )
}
