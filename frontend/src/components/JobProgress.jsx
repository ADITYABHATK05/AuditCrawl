import React from 'react'

export default function JobProgress({ job }) {
  if (!job) return null

  return (
    <div className="card">
      <h2>Live Progress</h2>
      <p><strong>Job ID:</strong> {job.job_id}</p>
      <p><strong>Status:</strong> {job.status}</p>
      <p><strong>Message:</strong> {job.message}</p>
      <div className="progress-track">
        <div className="progress-fill" style={{ width: `${job.progress || 0}%` }} />
      </div>
      <p>{job.progress || 0}%</p>
    </div>
  )
}
