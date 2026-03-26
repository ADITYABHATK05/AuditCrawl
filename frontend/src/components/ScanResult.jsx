import { useState, useEffect } from "react";
import { Link } from "react-router-dom";

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
  const [filterSev, setFilterSev] = useState("all");
  const [filterType, setFilterType] = useState("all");
  const [viewMode, setViewMode] = useState("grouped"); // "list" or "grouped"

  // Reset filters when scan changes
  useEffect(() => {
    setFilterSev("all");
    setFilterType("all");
    setViewMode("grouped");
  }, [scan?.run_id]);

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
  
  // Get unique vulnerability types
  const vulnTypes = [...new Set(findings.map(f => f.type || "unknown"))];
  
  // Group findings by type and severity
  const groupedByType = vulnTypes.reduce((acc, type) => {
    acc[type] = findings.filter(f => (f.type || "unknown") === type);
    return acc;
  }, {});

  // Get unique findings (deduplicate by type)
  const uniqueFindings = vulnTypes.map(type => {
    const instances = groupedByType[type];
    const severities = instances.map(f => f.severity || "info").sort();
    return {
      type,
      count: instances.length,
      severity: severities[0], // Most severe
      instances
    };
  }).sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));

  // Calculate stats by severity
  const bySev = SEV_ORDER.reduce((acc, s) => {
    acc[s] = findings.filter((f) => (f.severity || "info").toLowerCase() === s).length;
    return acc;
  }, {});

  // Filter findings
  const filtered = findings.filter(f => {
    const sevMatch = filterSev === "all" || (f.severity || "info").toLowerCase() === filterSev;
    const typeMatch = filterType === "all" || (f.type || "unknown") === filterType;
    return sevMatch && typeMatch;
  });

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

      {/* Report Download Links */}
      {scan.run_id && !isRunning && (
        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
          <a 
            href={`http://127.0.0.1:8000/output/run_${scan.run_id}.pdf`}
            className="btn btn-ghost btn-sm"
            title="Open PDF report"
          >
            📄 PDF Report
          </a>
        </div>
      )}

      {/* Stats */}
      <div className="stats-bar">
        <div className="stat-box">
          <div className={`stat-val ${findings.length > 0 ? "red" : "green"}`}>{findings.length}</div>
          <div className="stat-key">Total Findings</div>
        </div>
        <div className="stat-box">
          <div className="stat-val">{vulnTypes.length}</div>
          <div className="stat-key">Unique Vulnerabilities</div>
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

      {/* View Mode Toggle */}
      <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1.25rem" }}>
        <button
          className={`filter-tab ${viewMode === "grouped" ? "active" : ""}`}
          onClick={() => setViewMode("grouped")}
        >
          Grouped by Type
        </button>
        <button
          className={`filter-tab ${viewMode === "list" ? "active" : ""}`}
          onClick={() => setViewMode("list")}
        >
          All Instances
        </button>
      </div>

      {/* Severity Filters */}
      <div className="filter-tabs">
        {["all", ...SEV_ORDER].map((s) => (
          <button
            key={s}
            className={`filter-tab ${filterSev === s ? "active" : ""}`}
            onClick={() => setFilterSev(s)}
          >
            {s} {s !== "all" && `(${bySev[s] || 0})`}
          </button>
        ))}
      </div>

      {/* Type Filters */}
      <div className="filter-tabs">
        <button
          className={`filter-tab ${filterType === "all" ? "active" : ""}`}
          onClick={() => setFilterType("all")}
        >
          All Types ({vulnTypes.length})
        </button>
        {vulnTypes.map((type) => (
          <button
            key={type}
            className={`filter-tab ${filterType === type ? "active" : ""}`}
            onClick={() => setFilterType(type)}
          >
            {type} ({groupedByType[type].length})
          </button>
        ))}
      </div>

      {/* Findings Display */}
      {filtered.length === 0 ? (
        <div className="empty">
          <div className="empty-icon">{isRunning ? "⟳" : "✓"}</div>
          <div className="empty-text">
            {isRunning ? "Scan in progress…" : filterSev === "all" && filterType === "all" ? "No findings detected." : `No findings matching filters.`}
          </div>
        </div>
      ) : viewMode === "grouped" ? (
        // Grouped view - by Severity, then by Type
        <div>
          {SEV_ORDER.map(sev => {
            // Get all findings for this severity level
            const sevFindings = findings.filter(f => (f.severity || "info").toLowerCase() === sev);
            if (sevFindings.length === 0) return null;
            
            // Apply filters
            const filtered = sevFindings.filter(f => {
              const typeMatch = filterType === "all" || (f.type || "unknown") === filterType;
              return typeMatch;
            });
            if (filtered.length === 0) return null;
            
            // Get unique types for this severity
            const typesForSev = [...new Set(filtered.map(f => f.type || "unknown"))];
            
            return (
              <div key={sev} style={{ marginBottom: "2rem" }}>
                <div style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "0.75rem",
                  marginBottom: "1.25rem",
                  paddingBottom: "1rem",
                  borderBottom: "2px solid var(--border)"
                }}>
                  <span className={severityClass(sev)} style={{ fontSize: "0.85rem" }}>
                    {sev.toUpperCase()}
                  </span>
                  <span style={{ color: "var(--muted)", fontSize: "0.85rem" }}>
                    {filtered.length} finding{filtered.length !== 1 ? "s" : ""}
                  </span>
                </div>
                
                {/* Group by type within severity */}
                {typesForSev.map(type => {
                  const typeInstances = filtered.filter(f => (f.type || "unknown") === type);
                  
                  // Group by description to deduplicate
                  const byDescription = {};
                  typeInstances.forEach(finding => {
                    const desc = finding.description || "No description";
                    if (!byDescription[desc]) {
                      byDescription[desc] = {
                        description: desc,
                        evidence: finding.evidence,
                        param: finding.param,
                        poc: finding.poc,
                        urls: []
                      };
                    }
                    byDescription[desc].urls.push({
                      url: finding.url,
                      severity: finding.severity,
                      type: finding.type
                    });
                  });
                  
                  return (
                    <div key={`${sev}-${type}`} style={{ marginBottom: "1.5rem", marginLeft: "0.5rem" }}>
                      <div style={{
                        fontFamily: "var(--display)",
                        fontWeight: 600,
                        fontSize: "1rem",
                        color: "var(--text)",
                        marginBottom: "1rem",
                        paddingBottom: "0.5rem",
                        borderBottom: "1px solid rgba(74, 96, 112, 0.3)"
                      }}>
                        {type}
                      </div>
                      
                      {/* Show each unique finding once with all affected URLs */}
                      {Object.entries(byDescription).map(([descKey, finding]) => (
                        <div 
                          key={`${sev}-${type}-${descKey}`}
                          style={{
                            background: "var(--bg)",
                            border: "1px solid var(--border)",
                            borderRadius: "8px",
                            padding: "1rem",
                            marginBottom: "0.75rem"
                          }}
                        >
                          <div style={{
                            fontFamily: "var(--display)",
                            fontWeight: 600,
                            fontSize: "0.95rem",
                            color: "var(--text)",
                            marginBottom: "0.75rem"
                          }}>
                            {finding.description}
                          </div>
                          
                          <div style={{ marginBottom: "0.5rem" }}>
                            <span style={{ fontSize: "0.75rem", color: "var(--muted)", textTransform: "uppercase" }}>
                              Affected Endpoints ({finding.urls.length})
                            </span>
                          </div>
                          
                          <div style={{ 
                            display: "flex",
                            flexDirection: "column",
                            marginBottom: "0.75rem"
                          }}>
                            {finding.urls.map((item, idx) => (
                              <div 
                                key={idx}
                                style={{ 
                                  fontSize: "0.8rem", 
                                  color: "var(--muted)",
                                  fontFamily: "var(--mono)",
                                  wordBreak: "break-all"
                                }}
                              >
                                {item.url}
                              </div>
                            ))}
                          </div>
                          
                          {finding.evidence && (
                            <>
                              <div style={{
                                fontSize: "0.75rem",
                                color: "var(--muted)",
                                textTransform: "uppercase",
                                marginBottom: "0.3rem"
                              }}>
                                Evidence
                              </div>
                              <div style={{
                                background: "#050709",
                                border: "1px solid var(--border)",
                                borderRadius: "5px",
                                padding: "0.6rem 0.85rem",
                                fontFamily: "var(--mono)",
                                fontSize: "0.8rem",
                                color: "var(--accent)",
                                overflow: "auto",
                                marginBottom: "0.75rem",
                                wordBreak: "break-all"
                              }}>
                                {finding.evidence}
                              </div>
                            </>
                          )}
                          
                          {finding.poc && (
                            <>
                              <div style={{
                                fontSize: "0.75rem",
                                color: "var(--muted)",
                                textTransform: "uppercase",
                                marginBottom: "0.3rem"
                              }}>
                                PoC (Educational)
                              </div>
                              <div style={{
                                background: "#050709",
                                border: "1px solid var(--border)",
                                borderRadius: "5px",
                                padding: "0.6rem 0.85rem",
                                fontFamily: "var(--mono)",
                                fontSize: "0.8rem",
                                color: "var(--accent)",
                                overflow: "auto",
                                wordBreak: "break-all"
                              }}>
                                {finding.poc}
                              </div>
                            </>
                          )}
                        </div>
                      ))}
                    </div>
                  );
                })}
              </div>
            );
          })}
        </div>
      ) : (
        // List view
        filtered.map((f, idx) => <FindingCard key={idx} finding={f} />)
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