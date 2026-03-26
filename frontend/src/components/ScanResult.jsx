import { useState, useEffect } from "react";
import { Link } from "react-router-dom";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const SEV_WEIGHT = { critical: 4, high: 3, medium: 2, low: 1, info: 0.5 };
const EFFORT_OPTIONS = [
  { key: "S", value: 1, label: "Small" },
  { key: "M", value: 2, label: "Medium" },
  { key: "L", value: 3, label: "Large" },
];
const PREFS_KEY = "auditcrawl.scanResultsPrefs";

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

function SeverityDonut({ counts }) {
  const levels = [
    { key: "critical", label: "Critical", color: "#ff3355" },
    { key: "high", label: "High", color: "#ffa040" },
    { key: "medium", label: "Medium", color: "#ffb020" },
    { key: "low", label: "Low", color: "#40aaff" },
  ];

  const total = levels.reduce((sum, level) => sum + (counts[level.key] || 0), 0);
  const safeTotal = total > 0 ? total : 1;

  let cursor = 0;
  const gradientStops = levels.map((level) => {
    const value = counts[level.key] || 0;
    const start = cursor;
    const end = cursor + (value / safeTotal) * 360;
    cursor = end;
    return `${level.color} ${start}deg ${end}deg`;
  });

  const critical = counts.critical || 0;
  const high = counts.high || 0;
  const medium = counts.medium || 0;
  const low = counts.low || 0;

  // Severity-priority health classification: any critical finding is always high risk.
  const healthLabel =
    critical > 0
      ? "High Risk"
      : high > 0
        ? "Elevated Risk"
        : medium > 0
          ? "Moderate Risk"
          : low > 0
            ? "Low Risk"
            : "No Findings";

  return (
    <div className="severity-donut-card">
      <div className="severity-donut-header">
        <div className="severity-donut-title">Vulnerability Severity</div>
        <div className="severity-donut-subtitle">Instant site health overview</div>
      </div>

      <div className="severity-donut-layout">
        <div
          className="severity-donut"
          style={{ background: `conic-gradient(${gradientStops.join(", ")})` }}
          aria-label="Vulnerability severity distribution"
          role="img"
        >
          <div className="severity-donut-center">
            <div className="severity-donut-total">{total}</div>
            <div className="severity-donut-total-label">Findings</div>
          </div>
        </div>

        <div className="severity-donut-meta">
          {levels.map((level) => (
            <div className="severity-row" key={level.key}>
              <span className="severity-dot" style={{ backgroundColor: level.color }} />
              <span className="severity-label">{level.label}</span>
              <span className="severity-count">{counts[level.key] || 0}</span>
            </div>
          ))}
          <div className="severity-health">
            <span>Health</span>
            <span>{healthLabel}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function FindingCard({ finding, fixValue, effortKey, onEffortChange, isTopRoi }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`finding-card ${open ? "expanded" : ""}`} onClick={() => setOpen((v) => !v)}>
      <div className="finding-header">
        <span className={severityClass(finding.severity)}>{finding.severity || "info"}</span>
        <span className="finding-type">{finding.type}</span>
        {isTopRoi && <span className="roi-badge">Best ROI</span>}
        <span style={{ color: "var(--muted)", fontSize: "0.75rem" }}>{open ? "▲" : "▼"}</span>
      </div>
      <div className="finding-url">{finding.url}</div>
      <div className="finding-roi-row" onClick={(e) => e.stopPropagation()}>
        <span className="finding-roi-score">Fix Value: {fixValue.toFixed(1)}</span>
        <label className="finding-roi-label">
          Effort
          <select
            value={effortKey}
            onChange={(e) => onEffortChange(finding.type || "unknown", e.target.value)}
            className="finding-roi-select"
          >
            {EFFORT_OPTIONS.map((opt) => (
              <option key={opt.key} value={opt.key}>{opt.key}</option>
            ))}
          </select>
        </label>
      </div>
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
  const [sortMode, setSortMode] = useState("severity");
  const [effortByType, setEffortByType] = useState({});

  // Restore persisted preferences when scan changes
  useEffect(() => {
    try {
      const raw = localStorage.getItem(PREFS_KEY);
      const prefs = raw ? JSON.parse(raw) : {};
      setFilterSev(prefs.filterSev || "all");
      setFilterType(prefs.filterType || "all");
      setViewMode(prefs.viewMode || "grouped");
      setSortMode(prefs.sortMode || "severity");
      setEffortByType(prefs.effortByType || {});
    } catch {
      setFilterSev("all");
      setFilterType("all");
      setViewMode("grouped");
      setSortMode("severity");
      setEffortByType({});
    }
  }, [scan?.run_id]);

  useEffect(() => {
    const prefs = { filterSev, filterType, viewMode, sortMode, effortByType };
    localStorage.setItem(PREFS_KEY, JSON.stringify(prefs));
  }, [filterSev, filterType, viewMode, sortMode, effortByType]);

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
    const severities = instances.map((f) => (f.severity || "info").toLowerCase());
    const mostSevere = severities.sort((a, b) => SEV_ORDER.indexOf(a) - SEV_ORDER.indexOf(b))[0] || "info";
    const effortKey = effortByType[type] || "M";
    const effortWeight = EFFORT_OPTIONS.find((opt) => opt.key === effortKey)?.value || 2;
    const fixValue = ((SEV_WEIGHT[mostSevere] || 1) * instances.length * 10) / effortWeight;
    return {
      type,
      count: instances.length,
      severity: mostSevere,
      instances,
      effortKey,
      fixValue,
    };
  }).sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));

  const sortedUniqueFindings =
    sortMode === "fixValue"
      ? [...uniqueFindings].sort((a, b) => b.fixValue - a.fixValue)
      : uniqueFindings;

  const topRoiTypes = new Set(sortedUniqueFindings.slice(0, 3).map((f) => f.type));

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

  const filteredForList =
    sortMode === "fixValue"
      ? [...filtered].sort((a, b) => {
          const aType = a.type || "unknown";
          const bType = b.type || "unknown";
          const aScore = sortedUniqueFindings.find((x) => x.type === aType)?.fixValue || 0;
          const bScore = sortedUniqueFindings.find((x) => x.type === bType)?.fixValue || 0;
          return bScore - aScore;
        })
      : filtered;

  const isRunning = scan.status === "running" || scan.status === "queued";
  const exportCsv = () => {
    const rows = [
      ["type", "severity", "url", "fix_value", "effort", "evidence"],
      ...findings.map((f) => {
        const type = f.type || "unknown";
        const score = sortedUniqueFindings.find((x) => x.type === type);
        return [
          type,
          (f.severity || "info").toLowerCase(),
          f.url || "",
          (score?.fixValue || 0).toFixed(1),
          score?.effortKey || "M",
          (f.evidence || "").replace(/\s+/g, " ").trim(),
        ];
      }),
    ];
    const csv = rows
      .map((cols) => cols.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(","))
      .join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `triage_run_${scan.run_id || "scan"}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

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
          <button className="btn btn-ghost btn-sm" onClick={exportCsv} title="Export triage CSV">
            ⬇ Triage CSV
          </button>
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

      <SeverityDonut counts={bySev} />

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

      <div className="filter-tabs">
        <button
          className={`filter-tab ${sortMode === "severity" ? "active" : ""}`}
          onClick={() => setSortMode("severity")}
        >
          Sort by Severity
        </button>
        <button
          className={`filter-tab ${sortMode === "fixValue" ? "active" : ""}`}
          onClick={() => setSortMode("fixValue")}
        >
          Sort by Fix Value
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
                {(sortMode === "fixValue"
                  ? [...typesForSev].sort((a, b) => {
                      const aScore = sortedUniqueFindings.find((x) => x.type === a)?.fixValue || 0;
                      const bScore = sortedUniqueFindings.find((x) => x.type === b)?.fixValue || 0;
                      return bScore - aScore;
                    })
                  : typesForSev
                ).map(type => {
                  const typeInstances = filtered.filter(f => (f.type || "unknown") === type);
                  const typeScore = sortedUniqueFindings.find((x) => x.type === type);
                  
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
                        <div className="type-roi-row">
                          <span className="finding-roi-score">Fix Value: {typeScore?.fixValue?.toFixed(1) || "0.0"}</span>
                          {topRoiTypes.has(type) && <span className="roi-badge">Best ROI</span>}
                          <label className="finding-roi-label">
                            Effort
                            <select
                              value={typeScore?.effortKey || "M"}
                              onChange={(e) =>
                                setEffortByType((prev) => ({ ...prev, [type]: e.target.value }))
                              }
                              className="finding-roi-select"
                            >
                              {EFFORT_OPTIONS.map((opt) => (
                                <option key={opt.key} value={opt.key}>{opt.key}</option>
                              ))}
                            </select>
                          </label>
                        </div>
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
        filteredForList.map((f, idx) => {
          const type = f.type || "unknown";
          const score = sortedUniqueFindings.find((x) => x.type === type);
          return (
            <FindingCard
              key={idx}
              finding={f}
              fixValue={score?.fixValue || 0}
              effortKey={score?.effortKey || "M"}
              isTopRoi={topRoiTypes.has(type)}
              onEffortChange={(typeName, effortKey) =>
                setEffortByType((prev) => ({ ...prev, [typeName || "unknown"]: effortKey }))
              }
            />
          );
        })
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