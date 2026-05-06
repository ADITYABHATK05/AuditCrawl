import { useNavigate, useLocation } from 'react-router-dom'

export default function Header({ scanCount }) {
  const navigate = useNavigate()
  const location = useLocation()
  
  const isScanner = location.pathname === '/' || location.pathname === '/scanner'
  const isArchive = location.pathname === '/archive'

  return (
    <header className="glass-nav sticky top-0 z-50">
      <div className="mx-auto flex h-16 w-full max-w-6xl items-center justify-between px-4 md:px-6">
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
      <nav className="flex items-center gap-2">
        <button
          className={`${isScanner ? "btn-primary-clean" : "btn-ghost-clean"}`}
          onClick={() => navigate('/scanner')}
        >
          New Scan
        </button>
        <button
          className={`${isArchive ? "btn-primary-clean" : "btn-ghost-clean"}`}
          onClick={() => navigate('/archive')}
        >
          History {scanCount > 0 && `(${scanCount})`}
        </button>
      </nav>
      </div>
    </header>
  );
}