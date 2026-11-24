"""SQLite event store with correlation-based deduplication."""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class EventStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._initialise()

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def _session(self):
        """Commit/rollback and always close connections (important on Windows)."""
        connection = self._connection()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialise(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._session() as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    correlation_key TEXT NOT NULL UNIQUE,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT, dest_ip TEXT, src_port INTEGER, dest_port INTEGER,
                    protocol TEXT, attack_type TEXT NOT NULL, detection_engine TEXT NOT NULL,
                    severity TEXT NOT NULL, confidence REAL, detection_mode TEXT NOT NULL,
                    signature TEXT, rule_id TEXT, response_action TEXT NOT NULL,
                    response_status TEXT NOT NULL, raw_event TEXT NOT NULL
                )
                """
            )
            db.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp DESC)")

    def record(self, event: dict[str, Any]) -> tuple[bool, int | None]:
        payload = dict(event)
        payload["raw_event"] = json.dumps(payload.get("raw_event", {}), default=str, sort_keys=True)
        fields = (
            "correlation_key", "timestamp", "src_ip", "dest_ip", "src_port", "dest_port", "protocol",
            "attack_type", "detection_engine", "severity", "confidence", "detection_mode", "signature",
            "rule_id", "response_action", "response_status", "raw_event",
        )
        with self._lock, self._session() as db:
            try:
                cursor = db.execute(
                    f"INSERT INTO security_events ({', '.join(fields)}) VALUES ({', '.join('?' for _ in fields)})",
                    tuple(payload.get(field) for field in fields),
                )
                return True, cursor.lastrowid
            except sqlite3.IntegrityError:
                return False, None

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with self._session() as db:
            rows = db.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def update_response(self, event_id: int, response: dict[str, Any]) -> None:
        """Complete a previously recorded response decision after it runs."""
        with self._lock, self._session() as db:
            row = db.execute("SELECT raw_event FROM security_events WHERE id = ?", (event_id,)).fetchone()
            raw_event = json.loads(row[0]) if row else {}
            raw_event["response"] = response
            db.execute(
                "UPDATE security_events SET response_action = ?, response_status = ?, raw_event = ? WHERE id = ?",
                (
                    response.get("action", "LOG"),
                    response.get("status", "UNKNOWN"),
                    json.dumps(raw_event, default=str, sort_keys=True),
                    event_id,
                ),
            )

    def get_event(self, event_id: int) -> dict[str, Any] | None:
        with self._session() as db:
            row = db.execute("SELECT * FROM security_events WHERE id = ?", (event_id,)).fetchone()
        return dict(row) if row else None

    def metrics(self) -> dict[str, Any]:
        with self._session() as db:
            total = db.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
            alerts = db.execute("SELECT COUNT(*) FROM security_events WHERE attack_type != 'Normal'").fetchone()[0]
            critical = db.execute("SELECT COUNT(*) FROM security_events WHERE severity = 'Critical'").fetchone()[0]
            blocks = db.execute(
                "SELECT COUNT(*) FROM security_events WHERE response_action IN ('BLOCK', 'TEMPORARY_BLOCK')"
            ).fetchone()[0]
            today_prefix = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            resolved_today = db.execute(
                "SELECT COUNT(*) FROM security_events WHERE timestamp LIKE ? AND response_status IN ('APPLIED', 'ACTIVE')",
                (f"{today_prefix}%",),
            ).fetchone()[0]
            # Active threats = unresolved detections in the last 24h (rolling window)
            active_threats = db.execute(
                "SELECT COUNT(*) FROM security_events WHERE attack_type != 'Normal' AND timestamp >= datetime('now', '-24 hours')"
            ).fetchone()[0]
        return {
            "observed_events": total,
            "alerts": alerts,
            "active_threats": active_threats,
            "critical_alerts": critical,
            "resolved_today": resolved_today,
            "block_decisions": blocks,
        }

    def attack_distribution(self) -> dict[str, int]:
        with self._session() as db:
            rows = db.execute(
                "SELECT attack_type, COUNT(*) as cnt FROM security_events WHERE attack_type != 'Normal' GROUP BY attack_type ORDER BY cnt DESC"
            ).fetchall()
        return {r["attack_type"]: r["cnt"] for r in rows}

    def traffic_series(self, range_key: str = "24h") -> dict[str, Any]:
        with self._session() as db:
            if range_key == "1h":
                # 12 buckets of 5 minutes each within the last hour
                labels = [f"{i*5}m" for i in range(12)]
                rows = db.execute(
                    """
                    SELECT CAST((strftime('%s', 'now') - strftime('%s', timestamp)) / 300 AS INTEGER) as bucket_idx,
                           COUNT(*) as cnt
                    FROM security_events
                    WHERE timestamp >= datetime('now', '-1 hour')
                    GROUP BY bucket_idx
                    """
                ).fetchall()
                # bucket_idx 0 = most recent 5m, 11 = oldest 5m; reverse so label 0 is oldest
                counts_map = {11 - int(r["bucket_idx"]): r["cnt"] for r in rows if 0 <= int(r["bucket_idx"]) < 12}
                values = [counts_map.get(i, 0) for i in range(12)]
            elif range_key == "6h":
                # 12 buckets of 30 minutes each within the last 6 hours
                labels = [f"{i*0.5:.1f}h" for i in range(12)]
                rows = db.execute(
                    """
                    SELECT CAST((strftime('%s', 'now') - strftime('%s', timestamp)) / 1800 AS INTEGER) as bucket_idx,
                           COUNT(*) as cnt
                    FROM security_events
                    WHERE timestamp >= datetime('now', '-6 hours')
                    GROUP BY bucket_idx
                    """
                ).fetchall()
                counts_map = {11 - int(r["bucket_idx"]): r["cnt"] for r in rows if 0 <= int(r["bucket_idx"]) < 12}
                values = [counts_map.get(i, 0) for i in range(12)]
            else:  # 24h
                labels = [f"{i:02d}:00" for i in range(24)]
                rows = db.execute(
                    'SELECT substr(timestamp, 12, 2) || ":00" as hr, COUNT(*) as cnt FROM security_events GROUP BY hr'
                ).fetchall()
                counts_map = {r["hr"]: r["cnt"] for r in rows}
                values = [counts_map.get(lbl, 0) for lbl in labels]
        return {"labels": labels, "values": values}

    def attack_trend(self) -> dict[str, Any]:
        with self._session() as db:
            today_cnt = db.execute(
                "SELECT COUNT(*) FROM security_events WHERE attack_type != 'Normal'"
            ).fetchone()[0]
            prev_cnt = db.execute(
                "SELECT COUNT(*) FROM security_events WHERE attack_type != 'Normal' AND timestamp < datetime('now', '-24 hours')"
            ).fetchone()[0]
        trend_pct = round((today_cnt - prev_cnt) / max(prev_cnt, 1) * 100, 1)
        return {"today_alerts": today_cnt, "trend_pct": trend_pct}

    def top_attackers(self, limit: int = 10) -> list[dict[str, Any]]:
        with self._session() as db:
            rows = db.execute(
                """
                SELECT src_ip, COUNT(*) as count, MAX(timestamp) as last_seen, attack_type
                FROM security_events
                WHERE attack_type != 'Normal'
                GROUP BY src_ip
                ORDER BY count DESC
                LIMIT ?
                """,
                (max(1, min(int(limit), 50)),),
            ).fetchall()
        return [dict(r) for r in rows]

    def heatmap_data(self) -> list[dict[str, Any]]:
        with self._session() as db:
            rows = db.execute(
                """
                SELECT strftime('%w', timestamp) as dow, strftime('%H', timestamp) as hr, COUNT(*) as cnt
                FROM security_events
                WHERE attack_type != 'Normal'
                GROUP BY dow, hr
                """
            ).fetchall()
        return [{"day": int(r["dow"]), "hour": int(r["hr"]), "count": r["cnt"]} for r in rows]

    def protocol_distribution(self) -> dict[str, int]:
        with self._session() as db:
            rows = db.execute(
                "SELECT protocol, COUNT(*) as count FROM security_events GROUP BY protocol ORDER BY count DESC"
            ).fetchall()
        return {r["protocol"]: r["count"] for r in rows}

    def health(self) -> dict[str, Any]:
        try:
            with self._session() as db:
                db.execute("SELECT 1").fetchone()
            return {"status": "HEALTHY", "path": str(self.path)}
        except sqlite3.Error as exc:
            return {"status": "ERROR", "path": str(self.path), "error": str(exc)}
