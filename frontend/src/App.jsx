import React from 'react'
import { Routes, Route } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import Dashboard    from './pages/Dashboard'
import Scanner      from './pages/Scanner'
import ScanResult   from './pages/ScanResult'
import Archive      from './pages/Archive'
import ReportView   from './pages/ReportView'
import XSSLab       from './pages/labs/XSSLab'
import GuestbookLab from './pages/labs/GuestbookLab'
import SQLiLab      from './pages/labs/SQLiLab'
import SSRFLab      from './pages/labs/SSRFLab'
import LoginLab     from './pages/labs/LoginLab'
import LogoutLab    from './pages/labs/LogoutLab'
import AdminLab     from './pages/labs/AdminLab'

export default function App() {
  return (
    <div className="app-shell">
      <Sidebar />
      <main className="main-content">
        <Routes>
          {/* Main app */}
          <Route path="/"                           element={<Dashboard />} />
          <Route path="/scanner"                    element={<Scanner />} />
          <Route path="/scan/:source/:itemId"       element={<ScanResult />} />
          <Route path="/report/:source/:itemId/:fmt" element={<ReportView />} />
          <Route path="/archive"                    element={<Archive />} />

          {/* Exploit labs */}
          <Route path="/lab/xss"        element={<XSSLab />} />
          <Route path="/lab/guestbook"  element={<GuestbookLab />} />
          <Route path="/lab/sqli"       element={<SQLiLab />} />
          <Route path="/lab/ssrf"       element={<SSRFLab />} />
          <Route path="/lab/login"      element={<LoginLab />} />
          <Route path="/lab/logout"     element={<LogoutLab />} />
          <Route path="/lab/admin"      element={<AdminLab />} />
        </Routes>
      </main>
    </div>
  )
}