import { useNavigate, useLocation } from 'react-router-dom'

export default function Header({ scanCount }) {
  const navigate = useNavigate()
  const location = useLocation()
  
  const isScanner = location.pathname === '/' || location.pathname === '/scanner'
  const isArchive = location.pathname === '/archive'

  return (
    <header className="header">
      <div className="header-logo">
        <div className="logo-icon">⚡</div>
        AuditCrawl
        <span className="logo-sub">v1.0</span>
      </div>
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