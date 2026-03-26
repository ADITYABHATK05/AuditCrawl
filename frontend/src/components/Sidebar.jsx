import React, { useState } from 'react'
import { NavLink } from 'react-router-dom'

/* ── SVG icons ────────────────────────────────────────────────── */
const Ic = ({ d, d2, extra }) => (
  <svg className="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"
    strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d={d} />{d2 && <path d={d2} />}{extra}
  </svg>
)

const icons = {
  home:      <Ic d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" d2="M9 22V12h6v10" />,
  scan:      <Ic d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2"
               extra={<><line x1="7" y1="12" x2="17" y2="12"/><line x1="12" y1="7" x2="12" y2="17"/></>} />,
  archive:   <Ic d="M21 8v13H3V8M1 3h22v5H1zM10 12h4" />,
  xss:       <Ic d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />,
  sqli:      <Ic d="M20 7H4a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2z"
               extra={<><circle cx="12" cy="12" r="1"/><circle cx="7" cy="12" r="1"/><circle cx="17" cy="12" r="1"/></>} />,
  ssrf:      <Ic d="M12 2a10 10 0 1 0 0 20A10 10 0 0 0 12 2z" d2="M12 8v4l3 3" />,
  lock:      <Ic d="M19 11H5a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2z"
               extra={<path d="M7 11V7a5 5 0 0 1 10 0v4"/>} />,
  admin:     <Ic d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" d2="m9 12 2 2 4-4" />,
  book:      <Ic d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" d2="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z" />,
}

const navGroups = [
  {
    label: 'Scanner',
    items: [
      { to: '/',        label: 'Command Center', icon: icons.home,    end: true },
      { to: '/scanner', label: 'Initiate Scan',  icon: icons.scan },
      { to: '/archive', label: 'Scan Archive',   icon: icons.archive },
    ],
  },
  {
    label: 'Exploit Labs',
    items: [
      { to: '/lab/xss',       label: 'Reflected XSS',   icon: icons.xss },
      { to: '/lab/guestbook', label: 'Stored XSS',       icon: icons.book },
      { to: '/lab/sqli',      label: 'SQL Injection',    icon: icons.sqli },
      { to: '/lab/ssrf',      label: 'SSRF',             icon: icons.ssrf },
      { to: '/lab/login',     label: 'Auth / Session',   icon: icons.lock },
      { to: '/lab/admin',     label: 'System Config',    icon: icons.admin },
    ],
  },
]

const LogoIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
    strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    <path d="m9 12 2 2 4-4"/>
  </svg>
)

export default function Sidebar() {
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <>
      {/* Mobile toggle */}
      <button className="mobile-menu-btn" onClick={() => setMobileOpen(o => !o)}
        aria-label="Toggle menu">
        <span /><span /><span />
      </button>

      <aside className={`sidebar${mobileOpen ? ' sidebar-open' : ''}`}
        onClick={() => setMobileOpen(false)}>
        <div className="sidebar-brand">
          <div className="brand-logo">
            <div className="brand-icon"><LogoIcon /></div>
            <span className="brand-name">AuditCrawl</span>
          </div>
          <div className="brand-tag">educational security scanner</div>
        </div>

        <nav className="sidebar-nav">
          {navGroups.map(group => (
            <div key={group.label}>
              <div className="nav-section-label">{group.label}</div>
              {group.items.map(item => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
                >
                  {item.icon}
                  {item.label}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        <div className="sidebar-footer">
          Authorized educational testing only<br />
          Non-destructive · Low-impact
        </div>
      </aside>
    </>
  )
}