import React, { useState } from 'react'
import { exportScanToBurp, exportScanToZap, exportScanToSarif } from '../api'

export default function ExportButtons({ runId }) {
  const [exporting, setExporting] = useState(null)
  const [message, setMessage] = useState('')

  const handleExport = async (format, exportFn) => {
    try {
      setExporting(format)
      setMessage('')
      const data = await exportFn(runId)
      
      // Create download link
      const json = JSON.stringify(data.data || data, null, 2)
      const blob = new Blob([json], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `scan_${runId}_${format}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      
      setMessage(`Exported to ${format.toUpperCase()} format`)
      setTimeout(() => setMessage(''), 3000)
    } catch (error) {
      setMessage(`Error exporting to ${format}: ${error.message}`)
    } finally {
      setExporting(null)
    }
  }

  return (
    <div style={{ marginTop: '20px', padding: '15px', backgroundColor: 'var(--surface)', border: '1px solid var(--border)', borderRadius: '6px' }}>
      <div style={{ marginBottom: '12px', fontWeight: 'bold', fontSize: '14px', color: 'var(--text)' }}>Export Results</div>
      
      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '12px' }}>
        <button
          onClick={() => handleExport('burp', exportScanToBurp)}
          disabled={exporting !== null}
          className="btn"
          style={{
            background: exporting === 'burp' ? 'var(--accent2)' : 'rgba(255,77,109,0.2)',
            color: exporting === 'burp' ? '#000' : 'var(--accent2)',
            borderColor: 'var(--accent2)',
          }}
        >
          {exporting === 'burp' ? 'Exporting...' : 'Burp Suite'}
        </button>

        <button
          onClick={() => handleExport('zap', exportScanToZap)}
          disabled={exporting !== null}
          className="btn"
          style={{
            background: exporting === 'zap' ? 'var(--info)' : 'rgba(64,170,255,0.2)',
            color: exporting === 'zap' ? '#000' : 'var(--info)',
            borderColor: 'var(--info)',
          }}
        >
          {exporting === 'zap' ? 'Exporting...' : 'OWASP ZAP'}
        </button>

        <button
          onClick={() => handleExport('sarif', exportScanToSarif)}
          disabled={exporting !== null}
          className="btn"
          style={{
            background: exporting === 'sarif' ? 'var(--accent3)' : 'rgba(255,160,64,0.2)',
            color: exporting === 'sarif' ? '#000' : 'var(--accent3)',
            borderColor: 'var(--accent3)',
          }}
        >
          {exporting === 'sarif' ? 'Exporting...' : 'SARIF 2.1.0'}
        </button>
      </div>

      {message && (
        <div style={{
          padding: '10px',
          backgroundColor: message.includes('Error') ? 'rgba(255,51,85,0.15)' : 'rgba(0,229,160,0.15)',
          color: message.includes('Error') ? 'var(--danger)' : 'var(--accent)',
          borderRadius: '4px',
          fontSize: '12px',
          border: `1px solid ${message.includes('Error') ? 'rgba(255,51,85,0.3)' : 'rgba(0,229,160,0.3)'}`
        }}>
          {message}
        </div>
      )}
    </div>
  )
}
