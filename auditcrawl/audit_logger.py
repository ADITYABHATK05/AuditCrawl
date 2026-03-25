from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


class AuditLogger:
    def __init__(self, output_dir: str, use_sqlite: bool = False) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.use_sqlite = use_sqlite
        self.log_path = self.output_dir / "scan.log"
        self.db_path = self.output_dir / "scan_logs.db"
        if self.use_sqlite:
            self._init_db()

    def _init_db(self) -> None:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                module TEXT,
                url TEXT,
                method TEXT,
                payload TEXT,
                response_status INTEGER,
                response_hash TEXT,
                confirmed INTEGER,
                notes TEXT
            )
            """
        )
        conn.commit()
        conn.close()

    def log_event(
        self,
        module: str,
        url: str,
        method: str,
        payload: str,
        response_status: int,
        response_hash: str,
        confirmed: bool,
        notes: Optional[str] = None,
    ) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "module": module,
            "url": url,
            "method": method,
            "payload": payload,
            "response_status": response_status,
            "response_hash": response_hash,
            "confirmed": confirmed,
            "notes": notes or "",
        }
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        if self.use_sqlite:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO scan_logs
                (timestamp, module, url, method, payload, response_status, response_hash, confirmed, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry["timestamp"],
                    entry["module"],
                    entry["url"],
                    entry["method"],
                    entry["payload"],
                    entry["response_status"],
                    entry["response_hash"],
                    1 if entry["confirmed"] else 0,
                    entry["notes"],
                ),
            )
            conn.commit()
            conn.close()

    def summary(self) -> Dict[str, Any]:
        total = 0
        confirmed = 0
        module_counts: Dict[str, int] = {}
        if not self.log_path.exists():
            return {"total_events": 0, "confirmed_events": 0, "by_module": {}}

        with self.log_path.open("r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                total += 1
                event = json.loads(line)
                if event.get("confirmed"):
                    confirmed += 1
                module = event.get("module", "unknown")
                module_counts[module] = module_counts.get(module, 0) + 1

        return {"total_events": total, "confirmed_events": confirmed, "by_module": module_counts}
