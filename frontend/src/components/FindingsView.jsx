import React from 'react'

export default function FindingsView({ result }) {
  if (!result) return null

  return (
    <div className="card">
      <h2>Scan Results</h2>
      <p><strong>Run ID:</strong> {result.run_id}</p>
      <p><strong>Target:</strong> {result.target_url}</p>
      <p><strong>Findings:</strong> {result.findings_count}</p>
      <div className="downloads">
        <a href={`http://127.0.0.1:8000/output/run_${result.run_id}.pdf`} target="_blank" rel="noreferrer">PDF Report</a>
      </div>

      {result.findings.map((f, idx) => (
        <div key={idx} className="finding">
          <h3>{f.vulnerability_type} <span>{f.severity}</span></h3>
          <p><strong>Endpoint:</strong> {f.endpoint}</p>
          <p><strong>Evidence:</strong> {f.evidence}</p>
          <p><strong>Vulnerable snippet:</strong></p>
          <pre>{f.vulnerable_snippet}</pre>
          <p><strong>Fix snippet:</strong></p>
          <pre>{f.fix_snippet}</pre>
        </div>
      ))}
    </div>
  )
}
