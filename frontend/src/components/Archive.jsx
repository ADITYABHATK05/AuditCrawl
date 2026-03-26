import React from 'react'
import { Link } from 'react-router-dom'
import ScanArchiveTable from '../components/ScanArchiveTable'

export default function Archive() {
  return (
    <div className="page fade-in">
      <div className="page-header">
        <h1 className="page-title">Scan Archive</h1>
        <p className="page-sub">All completed scan runs with their findings</p>
      </div>

      <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.25rem' }}>
        <Link to="/scanner" className="btn btn-primary btn-sm">＋ New Scan</Link>
      </div>

      <div className="card">
        <ScanArchiveTable limit={50} />
      </div>
    </div>
  )
}