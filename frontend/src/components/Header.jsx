export default function Header({ view, setView, scanCount }) {
  return (
    <header className="header">
      <div className="header-logo">
        <div className="logo-icon">⚡</div>
        AuditCrawl
        <span className="logo-sub">v1.0</span>
      </div>
      <nav className="nav">
        <button
          className={`nav-btn ${view === "scan" ? "active" : ""}`}
          onClick={() => setView("scan")}
        >
          New Scan
        </button>
        <button
          className={`nav-btn ${view === "history" ? "active" : ""}`}
          onClick={() => setView("history")}
        >
          History {scanCount > 0 && `(${scanCount})`}
        </button>
      </nav>
    </header>
  );
}