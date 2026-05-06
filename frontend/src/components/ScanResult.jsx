import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import ExportButtons from "./ExportButtons";
import SeverityMap from "./SeverityMap";
import ScanPulse from "./ScanPulse";
import TopologyMap from "./TopologyMap";
import { staggerContainer, fadeSlideUp, cardHover } from "../utils/motionVariants";

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
  const isRunning = status === "running" || status === "queued";
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
      <span className={`badge badge-${status}`}>
        {status}
      </span>
      <ScanPulse isActive={isRunning} />
    </div>
  );
}

function SeverityDonut({ counts }) {
  const levels = [
    { key: "critical", label: "Critical", color: "#ff3355" },
    { key: "high", label: "High", color: "#ff8c00" },
    { key: "medium", label: "Medium", color: "#ffd700" },
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
    <motion.div
      className={`finding-card ${open ? "expanded" : ""}`}
      onClick={() => setOpen((v) => !v)}
      variants={cardHover}
      whileHover="whileHover"
      whileTap="whileTap"
    >
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
    </motion.div>
  );
}

export default function ScanResults({ scan, onBack }) {
  const [filterSev, setFilterSev] = useState("all");
  const [filterType, setFilterType] = useState("all");
  const [viewMode, setViewMode] = useState("grouped"); // "list" or "grouped"
  const [sortMode, setSortMode] = useState("severity");
  const [effortByType, setEffortByType] = useState({});
  const [activeTab, setActiveTab] = useState("findings");

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
          <motion.div 
            className="progress-bar" 
            initial={{ width: 0 }}
            animate={{ width: "100%" }}
            transition={{ duration: 1.5, ease: "easeInOut", repeat: Infinity }}
          />
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

      {/* Export to Security Tools */}
      {scan.run_id && !isRunning && (
        <ExportButtons runId={scan.run_id} />
      )}

      {/* Main Tabs */}
      <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1rem", borderBottom: "1px solid var(--line)" }}>
        <button
          className={`filter-tab ${activeTab === "findings" ? "active" : ""}`}
          onClick={() => setActiveTab("findings")}
        >
          Findings ({findings.length})
        </button>
        <button
          className={`filter-tab ${activeTab === "leaked_assets" ? "active" : ""}`}
          onClick={() => setActiveTab("leaked_assets")}
        >
          Leaked Assets ({scan.leaked_assets?.length || 0})
        </button>
      </div>

      {activeTab === "findings" ? (
        <div>
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
              Severity Map
            </button>
            <button
              className={`filter-tab ${viewMode === "topology" ? "active" : ""}`}
              onClick={() => setViewMode("topology")}
            >
              Topology Map
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
      ) : viewMode === "topology" ? (
        <motion.div variants={staggerContainer} initial="hidden" animate="visible" style={{ marginTop: '1.5rem' }}>
          <motion.div variants={fadeSlideUp}>
            <TopologyMap scan={scan} findings={filtered} />
          </motion.div>
        </motion.div>
      ) : viewMode === "grouped" ? (
        // Grouped view - by Severity, then by Type
        <SeverityMap 
          findings={findings}
          filterType={filterType}
          sortMode={sortMode}
          sortedUniqueFindings={sortedUniqueFindings}
          topRoiTypes={topRoiTypes}
          setEffortByType={setEffortByType}
        />
      ) : (
        // List view
        <motion.div variants={staggerContainer} initial="hidden" animate="visible">
        {filteredForList.map((f, idx) => {
          const type = f.type || "unknown";
          const score = sortedUniqueFindings.find((x) => x.type === type);
          return (
            <motion.div key={idx} variants={fadeSlideUp}>
              <FindingCard
                finding={f}
                fixValue={score?.fixValue || 0}
                effortKey={score?.effortKey || "M"}
                isTopRoi={topRoiTypes.has(type)}
                onEffortChange={(typeName, effortKey) =>
                  setEffortByType((prev) => ({ ...prev, [typeName || "unknown"]: effortKey }))
                }
              />
            </motion.div>
          );
        })}
        </motion.div>
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
      ) : (
        // Leaked Assets Tab
        <div>
          {scan.leaked_assets && scan.leaked_assets.length > 0 ? (
            <div className="stats-bar" style={{ marginBottom: "1rem" }}>
              <div className="stat-box">
                <div className="stat-val">{scan.leaked_assets.length}</div>
                <div className="stat-key">Total Leaked Assets</div>
              </div>
              {["High", "Medium", "Low"].map(sev => {
                const count = scan.leaked_assets.filter(asset => asset.severity === sev).length;
                return (
                  <div className="stat-box" key={sev}>
                    <div className={`stat-val ${sev === "High" ? "red" : sev === "Medium" ? "orange" : ""}`}>
                      {count}
                    </div>
                    <div className="stat-key">{sev} Risk</div>
                  </div>
                );
              })}
            </div>
          ) : null}

          {scan.leaked_assets && scan.leaked_assets.length > 0 ? (
            <motion.div variants={staggerContainer} initial="hidden" animate="visible">
            {(() => {
              const assets = scan.leaked_assets || [];
              const grouped = assets.reduce((acc, a) => {
                const type = a.asset_type || 'Unknown';
                const value = String(a.value || '');
                const key = `${type}::${value}`;
                if (!acc[key]) {
                  acc[key] = {
                    asset_type: type,
                    value,
                    severity: a.severity || 'Low',
                    endpoints: [],
                  };
                }
                if (a.endpoint) acc[key].endpoints.push(a.endpoint);
                return acc;
              }, {});

              const groups = Object.values(grouped)
                .map((g) => ({
                  ...g,
                  endpoints: Array.from(new Set(g.endpoints)),
                }))
                .sort((a, b) => {
                  const weight = (s) => {
                    const v = String(s || 'info').toLowerCase();
                    if (v === 'critical') return 5;
                    if (v === 'high') return 4;
                    if (v === 'medium') return 3;
                    if (v === 'low') return 2;
                    return 1;
                  };
                  const w = weight(b.severity) - weight(a.severity);
                  if (w !== 0) return w;
                  return String(a.asset_type).localeCompare(String(b.asset_type));
                });

              return groups.map((g, idx) => (
                <motion.div key={idx} className="finding-card" variants={fadeSlideUp} whileHover={{ scale: 1.01, y: -1 }}>
                  <div className="finding-header">
                    <span className={severityClass(g.severity)}>{g.severity}</span>
                    <span className="finding-type">{g.asset_type}</span>
                    <span style={{ color: 'var(--muted)', fontSize: '0.8rem', marginLeft: 'auto' }}>
                      {g.endpoints.length} file{g.endpoints.length === 1 ? '' : 's'}
                    </span>
                  </div>
                  <div className="finding-body">
                    <div>
                      <div className="field-label">Leaked Value</div>
                      <div className="code-block" style={{
                        fontFamily: "monospace",
                        wordBreak: "break-all",
                        maxWidth: "100%"
                      }}>
                        {g.value.length > 300 ? `${g.value.slice(0, 300)}…` : g.value}
                      </div>
                    </div>
                    {g.endpoints.length > 0 && (
                      <div style={{ marginTop: '0.8rem' }}>
                        <div className="field-label">Locations</div>
                        <div className="code-block" style={{ whiteSpace: 'pre-wrap' }}>
                          {g.endpoints.slice(0, 10).join('\n')}
                          {g.endpoints.length > 10 ? `\n… +${g.endpoints.length - 10} more` : ''}
                        </div>
                      </div>
                    )}
                  </div>
                </motion.div>
              ));
            })()}
            </motion.div>
          ) : (
            <div className="empty">
              <div className="empty-icon">🔍</div>
              <div className="empty-text">No leaked assets detected.</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}