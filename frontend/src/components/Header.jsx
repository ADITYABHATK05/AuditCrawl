import { useNavigate, useLocation } from 'react-router-dom'

export default function Header({ scanCount }) {
  const navigate = useNavigate()
  const location = useLocation()
  
  const isScanner = location.pathname === '/' || location.pathname === '/scanner'
  const isArchive = location.pathname === '/archive'

  return (
    <header className="header">
      <button className="header-logo" onClick={() => navigate('/scanner')} title="Go to scanner">
        <span className="logo-icon" aria-hidden="true">
          <span className="logo-ring" />
          <span className="logo-core" />
        </span>
        <span className="logo-text-wrap">
          <span className="logo-text">AuditCrawl</span>
          <span className="logo-sub">Web Security Scanner</span>
        </span>
      </button>
      <nav className="nav">
        <button
          className={`nav-btn ${isScanner ? "active" : ""}`}
          onClick={() => navigate('/scanner')}
        >
          New Scan
        </button>
        <button
          className={`nav-btn ${isArchive ? "active" : ""}`}
          onClick={() => navigate('/archive')}
        >
          History {scanCount > 0 && `(${scanCount})`}
        </button>
      </nav>
    </header>
  );
}