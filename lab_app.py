from __future__ import annotations

import asyncio
import json
import re
import sqlite3
import sys
import time
from xml.dom import minidom
from datetime import datetime
from pathlib import Path
from typing import List
from urllib.parse import urlparse

import requests
from flask import Flask, abort, g, jsonify, redirect, render_template, request, send_from_directory, session, url_for

from auditcrawl.config import ScanConfig
from auditcrawl.orchestrator import Scanner

app = Flask(__name__)
app.secret_key = "dev-secret-for-lab-only"
DB_PATH = Path("lab.db")
OUTPUT_ROOT = Path("output").resolve()
BACKEND_OUTPUT_ROOT = Path("backend/output").resolve()


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, content TEXT)")
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)")
    cur.execute("DELETE FROM users")
    cur.execute("DELETE FROM notes")
    cur.execute("INSERT INTO users(username, password) VALUES ('testuser', 'testpass')")
    conn.commit()
    conn.close()


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
    return g.db


@app.teardown_appcontext
def close_db(exc) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.context_processor
def inject_user() -> dict:
    return {"current_user": session.get("user")}


def _safe_report_href(path_value: str) -> str:
    path_obj = Path(path_value)
    rel = path_obj.as_posix()
    if not rel.startswith("output/"):
        rel = f"output/{path_obj.name}"
    return f"/{rel}"


def _read_findings_summary(findings_json_path: str) -> dict:
    path_obj = Path(findings_json_path)
    if not path_obj.exists():
        return {"total_findings": 0, "high": 0, "medium": 0, "low": 0}
    try:
        payload = json.loads(path_obj.read_text(encoding="utf-8"))
    except Exception:
        return {"total_findings": 0, "high": 0, "medium": 0, "low": 0}
    return payload.get("summary", {"total_findings": 0, "high": 0, "medium": 0, "low": 0})


def _collect_scan_archive(limit: int = 10) -> List[dict]:
    archive: List[dict] = []

    output_root = Path("output")
    if output_root.exists():
        candidates = [p for p in output_root.iterdir() if p.is_dir() and p.name.startswith("webscan_")]
        candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)

        for scan_dir in candidates:
            findings_path = scan_dir / "findings.json"
            summary = {"total_findings": 0, "high": 0, "medium": 0, "low": 0}
            if findings_path.exists():
                summary = _read_findings_summary(str(findings_path))

            meta = {}
            meta_path = scan_dir / "scan_meta.json"
            if meta_path.exists():
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                except Exception:
                    meta = {}

            started = meta.get("started_at", datetime.fromtimestamp(scan_dir.stat().st_mtime).strftime("%m/%d/%Y, %I:%M:%S %p"))
            target = meta.get("target_url", "unknown")
            archive.append(
                {
                    "scan_id": scan_dir.name,
                    "target_url": target,
                    "status": "COMPLETED",
                    "vulnerabilities": summary.get("total_findings", 0),
                    "critical": summary.get("high", 0),
                    "high": summary.get("high", 0),
                    "started": started,
                    "report_href": url_for("scan_result", source="legacy", item_id=scan_dir.name),
                    "source": "legacy",
                    "sort_ts": scan_dir.stat().st_mtime,
                }
            )

    backend_root = Path("backend/output")
    if backend_root.exists():
        run_files = sorted(backend_root.glob("run_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        for run_file in run_files:
            try:
                payload = json.loads(run_file.read_text(encoding="utf-8"))
            except Exception:
                continue

            findings = payload.get("findings", [])
            high_count = sum(1 for f in findings if str(f.get("severity", "")).lower() in {"high", "critical"})
            critical_count = sum(1 for f in findings if str(f.get("severity", "")).lower() == "critical")
            run_id = payload.get("run_id")
            target = payload.get("target_url", "unknown")
            started = datetime.fromtimestamp(run_file.stat().st_mtime).strftime("%m/%d/%Y, %I:%M:%S %p")

            archive.append(
                {
                    "scan_id": f"run_{run_id}",
                    "target_url": target,
                    "status": "COMPLETED",
                    "vulnerabilities": len(findings),
                    "critical": critical_count,
                    "high": high_count,
                    "started": started,
                    "report_href": url_for("scan_result", source="backend", item_id=str(run_id)),
                    "source": "backend",
                    "sort_ts": run_file.stat().st_mtime,
                }
            )

    archive.sort(key=lambda item: item.get("sort_ts", 0), reverse=True)
    paged = archive[:limit]
    for idx, item in enumerate(paged, start=1):
        item["sequence"] = idx
    return paged


def _summarize_severity(findings: list[dict]) -> dict:
    summary = {"total_findings": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        sev = str(finding.get("severity", "")).lower()
        if sev == "critical":
            summary["critical"] += 1
        elif sev == "high":
            summary["high"] += 1
        elif sev == "medium":
            summary["medium"] += 1
        elif sev == "low":
            summary["low"] += 1
    return summary


def _count_vulnerability_types(findings: list[dict]) -> list[dict]:
    counts: dict[str, int] = {}
    for finding in findings:
        vuln_type = str(finding.get("vulnerability_type", "Unknown")).strip() or "Unknown"
        counts[vuln_type] = counts.get(vuln_type, 0) + 1
    items = [{"type": k, "count": v} for k, v in counts.items()]
    items.sort(key=lambda x: (-x["count"], x["type"].lower()))
    return items


def _next_backend_run_id() -> int:
    backend_root = Path("backend/output")
    backend_root.mkdir(parents=True, exist_ok=True)
    max_id = 0
    for path in backend_root.glob("run_*.json"):
        try:
            run_id = int(path.stem.split("_")[1])
        except Exception:
            continue
        max_id = max(max_id, run_id)
    return max_id + 1


def _run_backend_scan_api(target_url: str, scan_level: str, timeout_seconds: int = 420) -> dict:
    base_url = "http://127.0.0.1:8000"
    enqueue_resp = requests.post(
        f"{base_url}/api/scan",
        json={"target_url": target_url, "scan_level": scan_level, "use_selenium": False},
        timeout=20,
    )
    enqueue_resp.raise_for_status()
    job_id = enqueue_resp.json().get("job_id")
    if not job_id:
        raise RuntimeError("Backend enqueue did not return a job id.")

    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        status_resp = requests.get(f"{base_url}/api/jobs/{job_id}", timeout=20)
        status_resp.raise_for_status()
        status_payload = status_resp.json()
        status = status_payload.get("status")
        if status == "completed":
            result = status_payload.get("result")
            if not result:
                raise RuntimeError("Backend returned completed job without result payload.")
            return result
        if status == "failed":
            raise RuntimeError(status_payload.get("error") or "Backend scan failed.")
        time.sleep(1.0)

    raise TimeoutError("Timed out waiting for backend scan job completion.")


def _run_backend_scan_local(target_url: str, scan_level: str) -> dict:
    backend_dir = Path("backend").resolve()
    if str(backend_dir) not in sys.path:
        sys.path.insert(0, str(backend_dir))

    from app.services.exporter import export_findings
    from app.services.scanner import WebScanner

    async def _run() -> list[dict]:
        scanner = WebScanner()
        return await scanner.scan(target_url=target_url, scan_level=scan_level, use_selenium=False)

    findings = asyncio.run(_run())
    run_id = _next_backend_run_id()
    payload = {
        "run_id": run_id,
        "target_url": target_url,
        "scan_level": scan_level,
        "findings": findings,
    }
    json_path, xml_path = export_findings(run_id, payload, "backend/output")
    return {
        "run_id": run_id,
        "target_url": target_url,
        "scan_level": scan_level,
        "findings_count": len(findings),
        "findings": findings,
        "json_path": json_path,
        "xml_path": xml_path,
    }


def _dashboard_stats(scan_archive: List[dict]) -> dict:
    return {
        "total_scans": len(scan_archive),
        "total_vulnerabilities": sum(item["vulnerabilities"] for item in scan_archive),
        "critical_issues": sum(item["critical"] for item in scan_archive),
        "high_severity": sum(item["high"] for item in scan_archive),
    }


def _precise_remediation(finding: dict) -> str:
    vuln = str(finding.get("vulnerability_type", "")).lower()
    evidence = str(finding.get("evidence", ""))
    endpoint = str(finding.get("endpoint", ""))

    key_match = re.search(r"'([^']+)'", evidence)
    key_hint = key_match.group(1) if key_match else None

    if "xss" in vuln:
        return (
            f"At endpoint {endpoint}, HTML-encode untrusted input before rendering. "
            + (f"Validate and sanitize field '{key_hint}' on input and output. " if key_hint else "")
            + "Apply a strict Content-Security-Policy and avoid inserting raw user content into DOM sinks."
        )
    if "sql" in vuln:
        return (
            f"At endpoint {endpoint}, replace string-built SQL with parameterized queries/prepared statements. "
            + (f"Treat field '{key_hint}' as untrusted and enforce strict allow-list validation. " if key_hint else "")
            + "Return generic errors to users and log stack traces server-side only."
        )
    if "ssrf" in vuln:
        return (
            f"At endpoint {endpoint}, do not fetch user-supplied URLs directly. "
            "Use an allow-list of approved hosts/schemes, block internal IP ranges, and enforce outbound egress restrictions."
        )
    if "misconfiguration" in vuln:
        return (
            f"At endpoint {endpoint}, apply missing security headers exactly as reported in evidence. "
            "Recommended baseline: CSP, X-Frame-Options, X-Content-Type-Options, and HSTS for HTTPS."
        )
    return "Apply secure-by-default controls for this issue type, validate all untrusted input, and enforce least privilege on the affected endpoint."


def _exact_fix_snippet(finding: dict) -> str:
    vuln = str(finding.get("vulnerability_type", "")).lower()
    evidence = str(finding.get("evidence", ""))
    endpoint = str(finding.get("endpoint", ""))

    quoted_match = re.search(r"'([^']+)'", evidence)
    field_name = quoted_match.group(1) if quoted_match else "input_value"

    if "xss" in vuln:
        return (
            "# Exact fix: escape untrusted input before rendering\n"
            "from markupsafe import escape\n"
            "\n"
            f"unsafe_value = request.values.get('{field_name}', '')\n"
            "safe_value = escape(unsafe_value)\n"
            "return render_template('result.html', query=safe_value)\n"
            "\n"
            "# Also add a strict CSP header\n"
            "response.headers['Content-Security-Policy'] = \"default-src 'self'\"\n"
        )

    if "sql" in vuln:
        return (
            "# Exact fix: parameterized SQL query\n"
            "from sqlalchemy import text\n"
            "\n"
            f"value = request.values.get('{field_name}', '')\n"
            "stmt = text('SELECT * FROM users WHERE username = :value')\n"
            "rows = session.execute(stmt, {'value': value}).fetchall()\n"
            "\n"
            "# Do not return DB errors to clients\n"
            "return {'status': 'ok'}\n"
        )

    if "ssrf" in vuln:
        return (
            "# Exact fix: enforce outbound URL allow-list\n"
            "from urllib.parse import urlparse\n"
            "\n"
            "ALLOWED_HOSTS = {'api.example.com'}\n"
            f"candidate = request.values.get('{field_name}', '')\n"
            "parsed = urlparse(candidate)\n"
            "if parsed.scheme != 'https' or parsed.hostname not in ALLOWED_HOSTS:\n"
            "    raise ValueError('Blocked outbound URL')\n"
            "\n"
            "# Safe request only after validation\n"
            "resp = httpx.get(candidate, timeout=5)\n"
        )

    if "misconfiguration" in vuln:
        header_match = re.search(r"Missing ([A-Za-z\-]+) header", evidence, flags=re.IGNORECASE)
        missing_header = (header_match.group(1) if header_match else "").lower()

        if missing_header == "content-security-policy":
            return "response.headers['Content-Security-Policy'] = \"default-src 'self'\"\n"
        if missing_header == "x-frame-options":
            return "response.headers['X-Frame-Options'] = 'DENY'\n"
        if missing_header == "x-content-type-options":
            return "response.headers['X-Content-Type-Options'] = 'nosniff'\n"
        if "hsts" in evidence.lower() or "strict-transport-security" in evidence.lower():
            return "response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'\n"

        return (
            "# Exact fix: apply baseline secure headers\n"
            "response.headers['Content-Security-Policy'] = \"default-src 'self'\"\n"
            "response.headers['X-Frame-Options'] = 'DENY'\n"
            "response.headers['X-Content-Type-Options'] = 'nosniff'\n"
            "response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'\n"
        )

    return (
        "# Exact fix template\n"
        f"# Endpoint: {endpoint}\n"
        "validate_input(request.values)\n"
        "enforce_output_encoding()\n"
    )


def _resolve_report_file(source: str, item_id: str, fmt: str) -> Path | None:
    if fmt not in {"json", "xml"}:
        return None
    if source == "backend":
        return Path("backend/output") / f"run_{item_id}.{fmt}"
    if source == "legacy":
        if fmt == "json":
            return Path("output") / item_id / "findings.json"
        return Path("output") / item_id / "report.xml"
    return None


def _format_report_text(fmt: str, raw_text: str) -> str:
    if fmt == "json":
        try:
            parsed = json.loads(raw_text)
            return json.dumps(parsed, indent=2, ensure_ascii=False)
        except Exception:
            return raw_text
    if fmt == "xml":
        try:
            pretty = minidom.parseString(raw_text.encode("utf-8")).toprettyxml(indent="  ")
            return "\n".join(line for line in pretty.splitlines() if line.strip())
        except Exception:
            return raw_text
    return raw_text


@app.route("/output/<path:subpath>")
def output_files(subpath: str):
    requested = (OUTPUT_ROOT / subpath).resolve()
    if not str(requested).startswith(str(OUTPUT_ROOT)):
        abort(404)
    if not requested.exists() or requested.is_dir():
        abort(404)
    as_attachment = request.args.get("download") == "1"
    return send_from_directory(str(OUTPUT_ROOT), subpath, as_attachment=as_attachment)


@app.route("/backend-output/<path:subpath>")
def backend_output_files(subpath: str):
    requested = (BACKEND_OUTPUT_ROOT / subpath).resolve()
    if not str(requested).startswith(str(BACKEND_OUTPUT_ROOT)):
        abort(404)
    if not requested.exists() or requested.is_dir():
        abort(404)
    as_attachment = request.args.get("download") == "1"
    return send_from_directory(str(BACKEND_OUTPUT_ROOT), subpath, as_attachment=as_attachment)


@app.route("/scan-result/<source>/<item_id>")
def scan_result(source: str, item_id: str):
    findings: list[dict] = []
    target_url = "unknown"
    scan_label = "unknown"

    if source == "backend":
        run_file = Path("backend/output") / f"run_{item_id}.json"
        xml_file = Path("backend/output") / f"run_{item_id}.xml"
        if not run_file.exists():
            abort(404)
        try:
            payload = json.loads(run_file.read_text(encoding="utf-8"))
        except Exception:
            abort(404)
        findings = payload.get("findings", [])
        target_url = payload.get("target_url", "unknown")
        scan_label = f"Backend Run #{payload.get('run_id', item_id)}"
        report_links = {
            "json_open": url_for("report_view", source=source, item_id=item_id, fmt="json"),
            "json_download": url_for("backend_output_files", subpath=f"run_{item_id}.json") + "?download=1",
            "xml_open": url_for("report_view", source=source, item_id=item_id, fmt="xml") if xml_file.exists() else None,
            "xml_download": (url_for("backend_output_files", subpath=f"run_{item_id}.xml") + "?download=1") if xml_file.exists() else None,
        }
    elif source == "legacy":
        scan_dir = Path("output") / item_id
        findings_file = scan_dir / "findings.json"
        legacy_xml = scan_dir / "report.xml"
        if not findings_file.exists():
            abort(404)
        try:
            payload = json.loads(findings_file.read_text(encoding="utf-8"))
        except Exception:
            abort(404)
        findings = payload.get("findings", [])
        target_url = payload.get("target_url", "unknown")
        scan_label = item_id
        rel_json = f"{item_id}/findings.json"
        report_links = {
            "json_open": url_for("report_view", source=source, item_id=item_id, fmt="json"),
            "json_download": url_for("output_files", subpath=rel_json) + "?download=1",
            "xml_open": url_for("report_view", source=source, item_id=item_id, fmt="xml") if legacy_xml.exists() else None,
            "xml_download": (url_for("output_files", subpath=f"{item_id}/report.xml") + "?download=1") if legacy_xml.exists() else None,
        }
    else:
        abort(404)

    enriched_findings = []
    for finding in findings:
        row = dict(finding)
        row["remediation_precise"] = _precise_remediation(finding)
        row["exact_fix_snippet"] = _exact_fix_snippet(finding)
        enriched_findings.append(row)

    total_findings = len(enriched_findings)
    try:
        page = int(request.args.get("page", "1"))
    except ValueError:
        page = 1
    try:
        page_size = int(request.args.get("page_size", "25"))
    except ValueError:
        page_size = 25

    page = max(1, page)
    page_size = max(10, min(page_size, 100))
    total_pages = max(1, (total_findings + page_size - 1) // page_size)
    if page > total_pages:
        page = total_pages

    start_idx = (page - 1) * page_size
    end_idx = min(start_idx + page_size, total_findings)
    paged_findings = enriched_findings[start_idx:end_idx]

    summary = _summarize_severity(findings)
    vulnerability_types = _count_vulnerability_types(findings)
    return render_template(
        "lab/scan_result.html",
        source=source,
        result_item_id=item_id,
        scan_label=scan_label,
        target_url=target_url,
        summary=summary,
        findings=paged_findings,
        findings_total=total_findings,
        pagination={
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "start": (start_idx + 1) if total_findings > 0 else 0,
            "end": end_idx,
            "has_prev": page > 1,
            "has_next": page < total_pages,
            "prev_page": page - 1,
            "next_page": page + 1,
        },
        vulnerability_types=vulnerability_types,
        report_links=report_links,
    )


@app.route("/report-view/<source>/<item_id>/<fmt>")
def report_view(source: str, item_id: str, fmt: str):
    report_path = _resolve_report_file(source, item_id, fmt)
    if not report_path or not report_path.exists() or report_path.is_dir():
        abort(404)

    try:
        raw_text = report_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        abort(404)

    formatted = _format_report_text(fmt, raw_text)
    lines = formatted.splitlines() or [formatted]

    if source == "backend":
        raw_open = url_for("backend_output_files", subpath=f"run_{item_id}.{fmt}")
        download = raw_open + "?download=1"
        run_label = f"Backend Run #{item_id}"
    else:
        if fmt == "json":
            rel = f"{item_id}/findings.json"
        else:
            rel = f"{item_id}/report.xml"
        raw_open = url_for("output_files", subpath=rel)
        download = raw_open + "?download=1"
        run_label = item_id

    return render_template(
        "lab/report_view.html",
        source=source,
        run_label=run_label,
        report_type=fmt.upper(),
        lines=lines,
        raw_open=raw_open,
        download=download,
    )


@app.route("/")
def index():
    scan_archive = _collect_scan_archive(limit=12)
    stats = _dashboard_stats(scan_archive)
    return render_template(
        "lab/index.html",
        scan_archive=scan_archive,
        stats=stats,
        now=datetime.now().strftime("%I:%M:%S %p"),
    )


@app.route("/xss")
def xss():
    q = request.args.get("q", "")
    # Intentionally vulnerable reflected output for lab demonstration only.
    return render_template("lab/xss.html", q=q)


@app.route("/guestbook", methods=["GET", "POST"])
def guestbook():
    db = get_db()
    if request.method == "POST":
        comment = request.form.get("comment", "")
        db.execute("INSERT INTO notes(content) VALUES (?)", (comment,))
        db.commit()
        return redirect(url_for("guestbook"))

    notes = db.execute("SELECT id, content FROM notes ORDER BY id DESC LIMIT 40").fetchall()
    return render_template("lab/guestbook.html", notes=notes)


@app.route("/sqli")
def sqli():
    user_id = request.args.get("id", "1")
    db = get_db()
    cur = db.cursor()
    # Intentionally unsafe query construction for educational testing.
    query = f"SELECT username FROM users WHERE id = {user_id}"
    try:
        rows = cur.execute(query).fetchall()
        out = rows
        is_error = False
    except Exception as exc:
        out = str(exc)
        is_error = True
    return render_template("lab/sqli.html", query=query, result=out, is_error=is_error)


@app.route("/ssrf")
def ssrf():
    target = request.args.get("url", "")
    # Intentionally simulates URL fetch behavior without making real outbound requests.
    preview = f"Would fetch URL: {target}" if target else "No URL submitted yet."
    return render_template("lab/ssrf.html", target=target, preview=preview)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == "testuser" and password == "testpass":
            session["user"] = username
            return redirect(url_for("admin"))
        error = "Invalid test credentials. Use testuser / testpass"
    return render_template("lab/login.html", error=error)


@app.route("/logout")
def logout():
    # Intentionally weak logout for demo: does not clear session.
    return render_template("lab/logout.html")


@app.route("/admin")
def admin():
    # Intentionally weak auth check for demo purposes.
    return render_template("lab/admin.html")


@app.route("/scanner", methods=["GET", "POST"])
def scanner_ui():
    scan_profiles = {"1": {"label": "Level 1"}, "2": {"label": "Level 2"}, "3": {"label": "Level 3"}}
    error = ""
    scan_result = None
    defaults = {
        "target_url": "http://127.0.0.1:5000",
        "scan_level": "2",
        "allow_subdomains": False,
        "has_permission": False,
    }

    scan_archive = _collect_scan_archive(limit=8)
    stats = _dashboard_stats(scan_archive)
    return render_template(
        "lab/scanner.html",
        error=error,
        scan_result=scan_result,
        defaults=defaults,
        scan_archive=scan_archive,
        stats=stats,
        now=datetime.now().strftime("%I:%M:%S %p"),
    )


@app.post("/scanner/start")
def scanner_start():
    payload = request.get_json(silent=True) or {}
    target_url = str(payload.get("target_url", "")).strip()
    scan_level = str(payload.get("scan_level", "2")).strip()
    has_permission = bool(payload.get("has_permission", False))

    if not has_permission:
        return jsonify({"error": "Confirm authorization before scanning any target."}), 400

    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return jsonify({"error": "Enter a valid URL starting with http:// or https://"}), 400
    if scan_level not in {"1", "2", "3"}:
        return jsonify({"error": "Select a valid scan level."}), 400

    try:
        resp = requests.post(
            "http://127.0.0.1:8000/api/scan",
            json={"target_url": target_url, "scan_level": scan_level, "use_selenium": False},
            timeout=20,
        )
        if resp.status_code >= 400:
            return jsonify({"error": "Backend scanner is not available."}), 502
        data = resp.json()
        return jsonify({
            "job_id": data.get("job_id"),
            "status": data.get("status", "queued"),
            "progress": data.get("progress", 0),
            "message": data.get("message", "Queued"),
        })
    except Exception as exc:
        return jsonify({"error": f"Unable to start backend scan: {exc}"}), 502


@app.get("/scanner/status/<job_id>")
def scanner_status(job_id: str):
    try:
        resp = requests.get(f"http://127.0.0.1:8000/api/jobs/{job_id}", timeout=20)
        return jsonify(resp.json()), resp.status_code
    except Exception as exc:
        return jsonify({"error": f"Unable to fetch scan status: {exc}"}), 502


@app.post("/scanner/stop/<job_id>")
def scanner_stop(job_id: str):
    try:
        resp = requests.post(f"http://127.0.0.1:8000/api/jobs/{job_id}/cancel", timeout=20)
        return jsonify(resp.json()), resp.status_code
    except Exception as exc:
        return jsonify({"error": f"Unable to stop scan: {exc}"}), 502


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
