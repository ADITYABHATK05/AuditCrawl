function formatDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

function StatusBadge({ status }) {
  return <span className={`badge badge-${status}`}>{status}</span>;
}

export default function ScanHistory({ scans, onView, onDelete }) {
  if (scans.length === 0) {
    return (
      <div>
        <div className="section-title">Scan History</div>
        <div className="section-sub">Previous scans will appear here</div>
        <div className="empty">
          <div className="empty-icon">📋</div>
          <div className="empty-text">No scans yet. Start your first scan.</div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="section-title">Scan History</div>
      <div className="section-sub">{scans.length} scan{scans.length !== 1 ? "s" : ""} recorded</div>

      {scans.map((scan) => (
        <div className="history-row" key={scan.id}>
          <div>
            <div className="history-url">{scan.base_url}</div>
            <div className="history-meta">{formatDate(scan.started_at)}</div>
          </div>
          <StatusBadge status={scan.status} />
          <div style={{ fontSize: "0.82rem", color: "var(--muted)" }}>
            {(scan.findings || []).length} findings
          </div>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button className="btn btn-ghost" style={{ padding: "0.4rem 0.85rem", fontSize: "0.75rem" }} onClick={() => onView(scan)}>
              View
            </button>
            <button className="btn btn-danger" style={{ padding: "0.4rem 0.85rem", fontSize: "0.75rem" }} onClick={() => onDelete(scan.id)}>
              ✕
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}