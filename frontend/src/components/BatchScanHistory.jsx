import React, { useState, useEffect } from 'react'
import { listBatchScans, getBatchProgress, getBatchResults, cancelBatchScan } from '../api'

export default function BatchScanHistory() {
  const [batches, setBatches] = useState([])
  const [selectedBatch, setSelectedBatch] = useState(null)
  const [batchDetails, setBatchDetails] = useState(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    loadBatches()
    const interval = setInterval(loadBatches, 5000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    if (selectedBatch) {
      loadBatchDetails(selectedBatch)
      const interval = setInterval(() => loadBatchDetails(selectedBatch), 2000)
      return () => clearInterval(interval)
    }
  }, [selectedBatch])

  const loadBatches = async () => {
    try {
      const data = await listBatchScans(20)
      setBatches(data)
    } catch (err) {
      console.error('Failed to load batches:', err)
    }
  }

  const loadBatchDetails = async (batchId) => {
    try {
      const details = await getBatchProgress(batchId)
      setBatchDetails(details)
    } catch (err) {
      console.error('Failed to load batch details:', err)
    }
  }

  const handleCancel = async (batchId) => {
    if (window.confirm('Are you sure you want to cancel this batch?')) {
      try {
        await cancelBatchScan(batchId)
        await loadBatches()
        if (selectedBatch === batchId) {
          setSelectedBatch(null)
          setBatchDetails(null)
        }
      } catch (err) {
        alert(`Failed to cancel batch: ${err.message}`)
      }
    }
  }

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return 'var(--accent)'
      case 'running': return 'var(--info)'
      case 'queued': return 'var(--muted)'
      case 'failed': return 'var(--danger)'
      case 'cancelled': return 'var(--muted)'
      default: return 'var(--muted)'
    }
  }

  return (
    <div style={{ marginTop: '20px', padding: '15px', backgroundColor: 'var(--surface)', border: '1px solid var(--border)', borderRadius: '6px' }}>
      <h2 style={{ color: 'var(--text)', marginBottom: '15px', fontSize: '18px' }}>Batch Scan History</h2>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '20px' }}>
        {/* Batch List */}
        <div style={{ borderRight: '1px solid var(--border)', paddingRight: '15px' }}>
          <h3 style={{ fontSize: '14px', marginBottom: '15px', color: 'var(--text)' }}>Recent Batches</h3>
          
          {batches.length === 0 ? (
            <p style={{ color: 'var(--muted)', fontSize: '12px' }}>No batches yet</p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '400px', overflowY: 'auto' }}>
              {batches.map((batch) => (
                <div
                  key={batch.batch_id}
                  onClick={() => setSelectedBatch(batch.batch_id)}
                  style={{
                    padding: '10px',
                    backgroundColor: selectedBatch === batch.batch_id ? 'rgba(0,229,160,0.1)' : 'var(--bg)',
                    borderLeft: `3px solid ${getStatusColor(batch.status)}`,
                    borderTop: `1px solid ${selectedBatch === batch.batch_id ? 'var(--accent)' : 'var(--border)'}`,
                    borderRight: `1px solid ${selectedBatch === batch.batch_id ? 'var(--accent)' : 'var(--border)'}`,
                    borderBottom: `1px solid ${selectedBatch === batch.batch_id ? 'var(--accent)' : 'var(--border)'}`,
                    borderRadius: '4px',
                    cursor: 'pointer',
                    transition: 'all 0.2s'
                  }}
                >
                  <div style={{ fontWeight: 'bold', fontSize: '12px', marginBottom: '4px', color: 'var(--text)' }}>
                    {batch.target_count} targets
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--muted)' }}>
                    {batch.status}
                  </div>
                  {batch.progress && (
                    <div style={{ fontSize: '11px', marginTop: '4px', color: 'var(--text)' }}>
                      Progress: {batch.progress.progress_percent}%
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Batch Details */}
        <div>
          {selectedBatch && batchDetails ? (
            <>
              <h3 style={{ fontSize: '14px', marginBottom: '15px', color: 'var(--text)' }}>Batch Details</h3>
              
              <div style={{ marginBottom: '15px' }}>
                <div style={{ fontSize: '11px', color: 'var(--muted)', marginBottom: '10px' }}>
                  ID: {batchDetails.batch_id.slice(0, 8)}...
                </div>
                
                <div style={{ marginBottom: '12px' }}>
                  <div style={{ fontSize: '12px', fontWeight: 'bold', marginBottom: '5px', color: 'var(--text)' }}>
                    Status: <span style={{ color: getStatusColor(batchDetails.status) }}>
                      {batchDetails.status.toUpperCase()}
                    </span>
                  </div>
                </div>

                <div style={{ marginBottom: '12px' }}>
                  <div style={{ fontSize: '11px', marginBottom: '5px', color: 'var(--text)' }}>Progress</div>
                  <div style={{
                    width: '100%',
                    height: '6px',
                    backgroundColor: 'var(--border)',
                    borderRadius: '3px',
                    overflow: 'hidden'
                  }}>
                    <div style={{
                      width: `${batchDetails.progress.progress_percent}%`,
                      height: '100%',
                      backgroundColor: 'var(--accent)',
                      transition: 'width 0.3s'
                    }} />
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--muted)', marginTop: '4px' }}>
                    {batchDetails.progress.completed}/{batchDetails.progress.total_targets} completed
                  </div>
                </div>

                <div style={{
                  padding: '10px',
                  backgroundColor: 'var(--bg)',
                  border: '1px solid var(--border)',
                  borderRadius: '4px',
                  fontSize: '11px',
                  marginBottom: '12px',
                  color: 'var(--text)'
                }}>
                  <div>Scanning: {batchDetails.progress.scanning}</div>
                  <div>Failed: {batchDetails.progress.failed}</div>
                  <div>Pending: {batchDetails.progress.pending}</div>
                </div>

                {batchDetails.summary && (
                  <div style={{
                    padding: '10px',
                    backgroundColor: 'var(--bg)',
                    border: '1px solid var(--border)',
                    borderRadius: '4px',
                    fontSize: '11px',
                    color: 'var(--text)'
                  }}>
                    <div style={{ fontWeight: 'bold', marginBottom: '5px' }}>Findings</div>
                    <div>Total: {batchDetails.summary.total_findings}</div>
                    <div>Critical: {batchDetails.summary.critical}</div>
                    <div>High: {batchDetails.summary.high}</div>
                    <div>Medium: {batchDetails.summary.medium}</div>
                    <div>Low: {batchDetails.summary.low}</div>
                  </div>
                )}

                {batchDetails.status !== 'completed' && batchDetails.status !== 'cancelled' && (
                  <button
                    onClick={() => handleCancel(selectedBatch)}
                    className="btn btn-danger"
                    style={{ marginTop: '15px', width: '100%' }}
                  >
                    Cancel Batch
                  </button>
                )}
              </div>
            </>
          ) : (
            <p style={{ color: 'var(--muted)', fontSize: '12px' }}>Select a batch to view details</p>
          )}
        </div>
      </div>
    </div>
  )
}
