import React from 'react'

export default function ScanForm({ onSubmit, loading }) {
  const [targetUrl, setTargetUrl] = React.useState('http://127.0.0.1:5000')
  const [scanLevel, setScanLevel] = React.useState('2')
  const [useSelenium, setUseSelenium] = React.useState(false)

  const submit = (e) => {
    e.preventDefault()
    onSubmit({ target_url: targetUrl, scan_level: scanLevel, use_selenium: useSelenium })
  }

  return (
    <form onSubmit={submit} className="card form">
      <h2>Start New Scan</h2>
      <label>Target URL</label>
      <input value={targetUrl} onChange={(e) => setTargetUrl(e.target.value)} required />

      <label>Scan Level</label>
      <div className="levels">
        {['1', '2', '3'].map((lvl) => (
          <button
            type="button"
            key={lvl}
            className={scanLevel === lvl ? 'level active' : 'level'}
            onClick={() => setScanLevel(lvl)}
          >
            {lvl === '1' ? 'Level 1 - Shallow' : lvl === '2' ? 'Level 2 - Medium' : 'Level 3 - Deep'}
          </button>
        ))}
      </div>

      <label className="check">
        <input type="checkbox" checked={useSelenium} onChange={(e) => setUseSelenium(e.target.checked)} />
        Use Selenium (dynamic page checks)
      </label>

      <button className="primary" disabled={loading}>{loading ? 'Scanning...' : 'Start Safe Scan'}</button>
    </form>
  )
}
