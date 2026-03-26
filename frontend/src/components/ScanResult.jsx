import { useState } from "react";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

function severityClass(sev) {
  const s = (sev || "info").toLowerCase();
  return `sev sev-${s}`;
}

function StatusBadge({ status }) {
  return (
    <span className={`badge badge-${status}`}>
      {(status === "running" || status === "queued") && <span className="pulse" />}
      {status}
    </span>
  );
}

function FindingCard({ finding }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`finding-card ${open ? "expanded" : ""}`} onClick={() => setOpen((v) => !v)}>
      <div className="finding-header">
        <span className={severityClass(finding.severity)}>{finding.severity || "info"}</span>
        <span className="finding-type">{finding.type}</span>
        <span style={{ color: "var(--muted)", fontSize: "0.75rem" }}>{open ? "▲" : "▼"}</span>
      </div>
      <div className="finding-url">{finding.url}</div>
      {open && (
        <div className="finding-body">
          {finding.param && (
            <div>
              <div className="field-label">Parameter</div>
              <div className="code-block">{finding.param}</div>
            </div>
          )}
          {finding.evidence && (
            <div>
              <div className="field-label">Evidence</div>
              <div className="code-block">{finding.evidence}</div>
            </div>
          )}
          {finding.description && (
            <div>
              <div className="field-label">Description</div>
              <div style={{ fontSize: "0.82rem", color: "var(--text)" }}>{finding.description}</div>
            </div>
          )}
          {finding.poc && (
            <div>
              <div className="field-label">PoC (educational)</div>
              <div className="code-block">{finding.poc}</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function ScanResults({ scan, onBack }) {
  const [filter, setFilter] = useState("all");

  if (!scan) {
    return (
      <div className="empty">
        <div className="empty-icon">🔍</div>
        <div className="empty-text">No scan selected. Start a new scan.</div>
        <br />
        <button className="btn btn-ghost" onClick={onBack}>← Back</button>
      </div>
    );
  }

  const findings = scan.findings || [];
  const filtered = filter === "all" ? findings : findings.filter((f) => (f.severity || "info").toLowerCase() === filter);

  const bySev = SEV_ORDER.reduce((acc, s) => {
    acc[s] = findings.filter((f) => (f.severity || "info").toLowerCase() === s).length;
    return acc;
  }, {});

  const isRunning = scan.status === "running" || scan.status === "queued";

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: "1rem", marginBottom: "0.35rem", flexWrap: "wrap" }}>
        <div className="section-title" style={{ margin: 0 }}>Scan Results</div>
        <StatusBadge status={scan.status} />
      </div>
      <div className="section-sub">{scan.base_url} · {scan.target_domain}</div>

      {isRunning && (
        <div className="progress-track">
          <div className="progress-bar" />
        </div>
      )}

      {/* Stats */}
      <div className="stats-bar">
        <div className="stat-box">
          <div className={`stat-val ${findings.length > 0 ? "red" : "green"}`}>{findings.length}</div>
          <div className="stat-key">Findings</div>
        </div>
        <div className="stat-box">
          <div className="stat-val">{scan.endpoints_count || 0}</div>
          <div className="stat-key">Endpoints</div>
        </div>
        {SEV_ORDER.slice(0, 3).map((s) => (
          <div className="stat-box" key={s}>
            <div className={`stat-val ${s === "critical" || s === "high" ? "red" : s === "medium" ? "orange" : ""}`}>
              {bySev[s] || 0}
            </div>
            <div className="stat-key">{s}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="filter-tabs">
        {["all", ...SEV_ORDER].map((s) => (
          <button
            key={s}
            className={`filter-tab ${filter === s ? "active" : ""}`}
            onClick={() => setFilter(s)}
          >
            {s} {s !== "all" && `(${bySev[s] || 0})`}
          </button>
        ))}
      </div>

      {/* Findings */}
      {filtered.length === 0 ? (
        <div className="empty">
          <div className="empty-icon">{isRunning ? "⟳" : "✓"}</div>
          <div className="empty-text">
            {isRunning ? "Scan in progress…" : filter === "all" ? "No findings detected." : `No ${filter} findings.`}
          </div>
        </div>
      ) : (
        filtered.map((f) => <FindingCard key={f.id} finding={f} />)
      )}

      {scan.report_html_path && (
        <div style={{ marginTop: "1.5rem", fontSize: "0.8rem", color: "var(--muted)" }}>
          📄 Full report saved to: <span style={{ color: "var(--accent)" }}>{scan.report_html_path}</span>
        </div>
      )}

      <div style={{ marginTop: "1.5rem" }}>
        <button className="btn btn-ghost" onClick={onBack}>← New Scan</button>
      </div>
    </div>
  );
}