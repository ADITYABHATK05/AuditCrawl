import React, { useState } from 'react'
import { createBatchScan, startBatchScan } from '../api'

export default function BatchScanForm({ onBatchCreated }) {
  const [targets, setTargets] = useState([{ url: '', tags: '' }])
  const [maxWorkers, setMaxWorkers] = useState(3)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const addTarget = () => {
    setTargets([...targets, { url: '', tags: '' }])
  }

  const removeTarget = (index) => {
    setTargets(targets.filter((_, i) => i !== index))
  }

  const updateTarget = (index, field, value) => {
    const newTargets = [...targets]
    newTargets[index][field] = value
    setTargets(newTargets)
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    
    const validTargets = targets.filter(t => t.url.trim())
    if (validTargets.length === 0) {
      setError('Please add at least one target URL')
      return
    }

    try {
      setLoading(true)
      
      // Create batch
      const batchData = {
        targets: validTargets.map(t => ({
          url: t.url,
          tags: t.tags.split(',').map(tag => tag.trim()).filter(tag => tag)
        })),
        max_workers: maxWorkers
      }
      
      const batch = await createBatchScan(batchData.targets, batchData.max_workers)
      
      // Auto-start the batch
      await startBatchScan(batch.batch_id)
      
      // Reset form
      setTargets([{ url: '', tags: '' }])
      
      if (onBatchCreated) {
        onBatchCreated(batch)
      }
    } catch (err) {
      setError(`Failed to create batch: ${err.message}`)
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} style={{ marginTop: '20px', padding: '15px', backgroundColor: 'var(--surface)', border: '1px solid var(--border)', borderRadius: '6px' }}>
      <h2 style={{ color: 'var(--text)', marginBottom: '15px', fontSize: '18px' }}>Batch Scan Multiple Targets</h2>
      
      <label style={{ color: 'var(--text)', display: 'block', marginBottom: '8px' }}>Parallel Workers</label>
      <input 
        type="number" 
        min="1" 
        max="10" 
        value={maxWorkers} 
        onChange={(e) => setMaxWorkers(parseInt(e.target.value))}
        style={{ 
          width: '100%', 
          padding: '8px', 
          backgroundColor: 'var(--bg)',
          color: 'var(--text)',
          border: '1px solid var(--border)',
          borderRadius: '4px',
          marginBottom: '8px'
        }}
      />
      <small style={{ display: 'block', marginBottom: '15px', color: 'var(--muted)' }}>
        Number of targets to scan simultaneously (1-10)
      </small>

      <label style={{ color: 'var(--text)', display: 'block', marginBottom: '8px' }}>Targets to Scan</label>
      
      <div style={{ maxHeight: '300px', overflowY: 'auto', marginBottom: '12px' }}>
        {targets.map((target, index) => (
          <div key={index} style={{ marginBottom: '10px', padding: '10px', backgroundColor: 'var(--bg)', border: '1px solid var(--border)', borderRadius: '4px' }}>
            <div style={{ display: 'flex', gap: '10px', marginBottom: '8px' }}>
              <input
                placeholder="https://target.com"
                value={target.url}
                onChange={(e) => updateTarget(index, 'url', e.target.value)}
                required
                style={{ 
                  flex: 1,
                  padding: '8px',
                  backgroundColor: 'rgba(14,19,24,0.8)',
                  color: 'var(--text)',
                  border: '1px solid var(--border)',
                  borderRadius: '4px'
                }}
              />
              {targets.length > 1 && (
                <button
                  type="button"
                  onClick={() => removeTarget(index)}
                  className="btn btn-danger"
                >
                  Remove
                </button>
              )}
            </div>
            <input
              placeholder="Tags (comma-separated, e.g. prod, api, frontend)"
              value={target.tags}
              onChange={(e) => updateTarget(index, 'tags', e.target.value)}
              style={{ 
                width: '100%',
                padding: '8px',
                backgroundColor: 'rgba(14,19,24,0.8)',
                color: 'var(--text)',
                border: '1px solid var(--border)',
                borderRadius: '4px'
              }}
            />
          </div>
        ))}
      </div>

      <button
        type="button"
        onClick={addTarget}
        className="btn"
        style={{
          marginBottom: '15px',
          background: 'rgba(0,229,160,0.2)',
          color: 'var(--accent)',
          borderColor: 'var(--accent)'
        }}
      >
        + Add Target
      </button>

      {error && (
        <div style={{
          padding: '10px',
          backgroundColor: 'rgba(255,51,85,0.15)',
          color: 'var(--danger)',
          borderRadius: '4px',
          marginBottom: '15px',
          border: '1px solid rgba(255,51,85,0.3)',
          fontSize: '12px'
        }}>
          {error}
        </div>
      )}

      <button 
        className="btn btn-primary" 
        disabled={loading}
        style={{ width: '100%' }}
      >
        {loading ? 'Creating Batch...' : `Start Batch Scan (${targets.filter(t => t.url).length} targets)`}
      </button>
    </form>
  )
}
