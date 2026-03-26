"""
AuditCrawl API — Flask backend that bridges the React frontend to the scanner core.
Run: python backend/api.py
"""
from __future__ import annotations
import json
import os
import sys
import threading
import uuid
from pathlib import Path
from datetime import datetime

from flask import Flask, jsonify, request
from flask_cors import CORS

# Add project root to path so auditcrawl package is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from auditcrawl.config import ScanConfig
from auditcrawl.orchestrator import Scanner

app = Flask(__name__)
CORS(app)  # Allow React dev server requests

# In-memory scan store: scan_id -> {status, config, result, log_lines, started_at, ended_at}
_scans: dict[str, dict] = {}
_lock = threading.Lock()


def _run_scan(scan_id: str, config: ScanConfig) -> None:
    """Runs in a background thread; updates _scans[scan_id] as it progresses."""
    with _lock:
        _scans[scan_id]["status"] = "running"

    try:
        scanner = Scanner(config)
        result = scanner.run()

        findings_list = []
        for f in result.findings:
            findings_list.append({
                "id": str(uuid.uuid4()),
                "type": getattr(f, "vuln_type", "Unknown"),
                "severity": getattr(f, "severity", "medium"),
                "url": getattr(f, "url", ""),
                "param": getattr(f, "param", ""),
                "evidence": getattr(f, "evidence", ""),
                "description": getattr(f, "description", ""),
                "poc": getattr(f, "poc", ""),
            })

        with _lock:
            _scans[scan_id].update({
                "status": "completed",
                "findings": findings_list,
                "endpoints_count": len(result.endpoints),
                "findings_json_path": str(result.findings_json_path) if result.findings_json_path else None,
                "report_html_path": str(result.report_html_path) if result.report_html_path else None,
                "ended_at": datetime.utcnow().isoformat(),
            })
    except Exception as exc:
        with _lock:
            _scans[scan_id].update({
                "status": "error",
                "error": str(exc),
                "ended_at": datetime.utcnow().isoformat(),
            })


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "1.0.0"})


@app.route("/api/scans", methods=["POST"])
def start_scan():
    """
    POST /api/scans
    Body (JSON):
    {
      "base_url": "http://localhost:5000",
      "target_domain": "localhost",
      "max_depth": 3,
      "max_pages": 100,
      "lab_mode": false,
      "modules": ["xss", "sqli", "ssrf", "auth", "rce"]   // empty = all
    }
    """
    body = request.get_json(force=True)

    base_url = body.get("base_url", "").strip()
    target_domain = body.get("target_domain", "").strip()
    if not base_url or not target_domain:
        return jsonify({"error": "base_url and target_domain are required"}), 400

    modules = body.get("modules", [])
    any_module = bool(modules)

    config = ScanConfig(
        base_url=base_url,
        target_domain=target_domain,
        allowed_subdomains=body.get("allowed_subdomains", False),
        max_depth=int(body.get("max_depth", 3)),
        max_pages=int(body.get("max_pages", 100)),
        output_dir=body.get("output_dir", "output"),
        ignore_paths=body.get("ignore_paths", []),
        safe_mode=not body.get("lab_mode", False),
        lab_mode=body.get("lab_mode", False),
        enable_xss=("xss" in modules) if any_module else True,
        enable_sqli=("sqli" in modules) if any_module else True,
        enable_ssrf=("ssrf" in modules) if any_module else True,
        enable_auth=("auth" in modules) if any_module else True,
        enable_rce=("rce" in modules) if any_module else True,
        enable_time_based_sqli=False,
        auth_login_url=body.get("auth_login_url"),
        auth_logout_url=body.get("auth_logout_url"),
    )

    scan_id = str(uuid.uuid4())
    with _lock:
        _scans[scan_id] = {
            "id": scan_id,
            "status": "queued",
            "base_url": base_url,
            "target_domain": target_domain,
            "started_at": datetime.utcnow().isoformat(),
            "ended_at": None,
            "findings": [],
            "endpoints_count": 0,
            "error": None,
        }

    thread = threading.Thread(target=_run_scan, args=(scan_id, config), daemon=True)
    thread.start()

    return jsonify({"scan_id": scan_id, "status": "queued"}), 202


@app.route("/api/scans", methods=["GET"])
def list_scans():
    with _lock:
        scans = list(_scans.values())
    return jsonify(scans)


@app.route("/api/scans/<scan_id>", methods=["GET"])
def get_scan(scan_id: str):
    with _lock:
        scan = _scans.get(scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan)


@app.route("/api/scans/<scan_id>", methods=["DELETE"])
def delete_scan(scan_id: str):
    with _lock:
        if scan_id not in _scans:
            return jsonify({"error": "Scan not found"}), 404
        del _scans[scan_id]
    return jsonify({"deleted": scan_id})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(debug=True, port=port)