import React from 'react'

export default function ScanForm({ onSubmit, loading }) {
  const [targetUrl, setTargetUrl] = React.useState('http://127.0.0.1:5000')
  const [scanLevel, setScanLevel] = React.useState('2')
  const [useSelenium, setUseSelenium] = React.useState(false)
  const [useAuth, setUseAuth] = React.useState(false)
  const [loginUrl, setLoginUrl] = React.useState('')
  const [username, setUsername] = React.useState('')
  const [password, setPassword] = React.useState('')
  const [authMethod, setAuthMethod] = React.useState('form')

  const submit = (e) => {
    e.preventDefault()
    const payload = {
      target_url: targetUrl,
      scan_level: scanLevel,
      use_selenium: useSelenium
    }
    
    if (useAuth) {
      payload.login_url = loginUrl
      payload.username = username
      payload.password = password
      payload.auth_method = authMethod
    }
    
    onSubmit(payload)
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

      <label className="check">
        <input type="checkbox" checked={useAuth} onChange={(e) => setUseAuth(e.target.checked)} />
        Authenticate before scanning
      </label>

      {useAuth && (
        <div className="auth-section" style={{ marginTop: '15px', padding: '15px', backgroundColor: '#f5f5f5', borderRadius: '5px' }}>
          <label>Authentication Method</label>
          <select value={authMethod} onChange={(e) => setAuthMethod(e.target.value)}>
            <option value="form">Form Login (POST)</option>
            <option value="basic">HTTP Basic Auth</option>
            <option value="bearer">Bearer Token</option>
            <option value="custom">Custom Headers</option>
          </select>

          <label style={{ marginTop: '10px' }}>Login URL</label>
          <input 
            value={loginUrl} 
            onChange={(e) => setLoginUrl(e.target.value)} 
            placeholder="https://target.com/login"
            required={useAuth}
          />

          {authMethod !== 'bearer' && (
            <>
              <label style={{ marginTop: '10px' }}>Username</label>
              <input 
                value={username} 
                onChange={(e) => setUsername(e.target.value)} 
                required={useAuth && authMethod !== 'bearer'}
              />

              <label style={{ marginTop: '10px' }}>Password</label>
              <input 
                type="password"
                value={password} 
                onChange={(e) => setPassword(e.target.value)} 
                required={useAuth && authMethod !== 'bearer'}
              />
            </>
          )}
        </div>
      )}

      <button className="primary" disabled={loading} style={{ marginTop: '15px' }}>
        {loading ? 'Scanning...' : 'Start Safe Scan'}
      </button>
    </form>
  )
}
