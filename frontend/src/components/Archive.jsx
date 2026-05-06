import React from 'react'
import { Link } from 'react-router-dom'
import ScanArchiveTable from '../components/ScanArchiveTable'

export default function Archive() {
  return (
    <div className="page fade-in">
      <div className="glass-card mb-6 p-6">
        <h1 className="section-title-clean">Scan Archive</h1>
        <p className="section-sub-clean">All completed scan runs with severity trends and quick comparison.</p>
      </div>

      <div className="mb-6 flex gap-3">
        <Link to="/scanner" className="btn-primary-clean">＋ New Scan</Link>
      </div>

      <div className="glass-card p-5 md:p-6">
        <ScanArchiveTable limit={50} />
      </div>
    </div>
  )
}