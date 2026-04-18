import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class Database:
    def __init__(self, db_path: Optional[str] = None):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.db_path = db_path or os.path.join(base_dir, "data", "agent.db")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._lock = threading.RLock()
        self.init_db()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS instances (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    label TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL DEFAULT 22,
                    username TEXT NOT NULL,
                    auth_type TEXT NOT NULL CHECK(auth_type IN ('key','password')),
                    key_path TEXT,
                    password TEXT,
                    tags TEXT DEFAULT '[]',
                    added_at TEXT NOT NULL,
                    last_seen TEXT,
                    last_status TEXT DEFAULT 'unknown'
                );

                CREATE TABLE IF NOT EXISTS jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    instance_id INTEGER,
                    type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL,
                    plan_json TEXT,
                    specs_json TEXT,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    duration_sec INTEGER,
                    result TEXT,
                    FOREIGN KEY(instance_id) REFERENCES instances(id) ON DELETE SET NULL
                );

                CREATE TABLE IF NOT EXISTS job_steps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id INTEGER NOT NULL,
                    phase TEXT,
                    step_id TEXT,
                    title TEXT,
                    commands TEXT,
                    output TEXT,
                    success INTEGER NOT NULL DEFAULT 0,
                    ran_at TEXT NOT NULL,
                    FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS schedules (
                    instance_id INTEGER PRIMARY KEY,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    mode TEXT NOT NULL CHECK(mode IN ('interval','cron')),
                    interval_hours INTEGER,
                    cron_expr TEXT,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(instance_id) REFERENCES instances(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS study_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    instance_id INTEGER NOT NULL,
                    report_json TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(instance_id) REFERENCES instances(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _row_to_dict(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        if row is None:
            return None
        data = dict(row)
        for key in ("tags", "plan_json", "specs_json", "commands", "report_json", "raw_json"):
            if key in data and isinstance(data[key], str):
                try:
                    data[key] = json.loads(data[key])
                except json.JSONDecodeError:
                    pass
        if "success" in data:
            data["success"] = bool(data["success"])
        return data

    # ── Instances ────────────────────────────────────────────────────────────

    def add_instance(self, payload: Dict[str, Any]) -> int:
        now = self._now()
        tags = payload.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO instances
                    (label, host, port, username, auth_type, key_path, password, tags, added_at, last_status)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    payload["label"],
                    payload["host"],
                    int(payload.get("port", 22)),
                    payload["username"],
                    payload.get("auth_type", "key"),
                    payload.get("key_path"),
                    payload.get("password"),
                    json.dumps(tags),
                    now,
                    "unknown",
                ),
            )
            return int(cur.lastrowid)

    def list_instances(self) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM instances ORDER BY id DESC").fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_instance(self, instance_id: int) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM instances WHERE id=?", (instance_id,)).fetchone()
        return self._row_to_dict(row)

    def delete_instance(self, instance_id: int) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM instances WHERE id=?", (instance_id,))

    def update_instance_status(self, instance_id: int, status: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE instances SET last_status=?, last_seen=? WHERE id=?",
                (status, self._now(), instance_id),
            )

    # ── Jobs ─────────────────────────────────────────────────────────────────

    def create_job(
        self,
        instance_id: Optional[int],
        job_type: str,
        title: str,
        status: str = "pending",
        plan_json: Optional[Dict[str, Any]] = None,
        specs_json: Optional[Dict[str, Any]] = None,
    ) -> int:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO jobs (instance_id, type, title, status, plan_json, specs_json, started_at)
                VALUES (?,?,?,?,?,?,?)
                """,
                (
                    instance_id,
                    job_type,
                    title,
                    status,
                    json.dumps(plan_json) if plan_json is not None else None,
                    json.dumps(specs_json) if specs_json is not None else None,
                    self._now(),
                ),
            )
            return int(cur.lastrowid)

    def update_job(self, job_id: int, **updates: Any) -> None:
        if not updates:
            return
        if "plan_json" in updates and not isinstance(updates["plan_json"], str):
            updates["plan_json"] = json.dumps(updates["plan_json"])
        if "specs_json" in updates and not isinstance(updates["specs_json"], str):
            updates["specs_json"] = json.dumps(updates["specs_json"])
        if "finished_at" not in updates and updates.get("status") in {"completed", "failed", "cancelled"}:
            updates["finished_at"] = self._now()
        fields = ", ".join(f"{k}=?" for k in updates)
        params = list(updates.values()) + [job_id]
        with self._lock, self._connect() as conn:
            conn.execute(f"UPDATE jobs SET {fields} WHERE id=?", params)

    def add_job_step(
        self,
        job_id: int,
        phase: str,
        step_id: str,
        title: str,
        commands: List[str],
        output: str,
        success: bool,
    ) -> int:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO job_steps (job_id, phase, step_id, title, commands, output, success, ran_at)
                VALUES (?,?,?,?,?,?,?,?)
                """,
                (job_id, phase, step_id, title, json.dumps(commands), output, int(success), self._now()),
            )
            return int(cur.lastrowid)

    def list_jobs(
        self,
        instance_id: Optional[int] = None,
        job_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM jobs WHERE 1=1"
        params: List[Any] = []
        if instance_id is not None:
            query += " AND instance_id=?"
            params.append(instance_id)
        if job_type:
            query += " AND type=?"
            params.append(job_type)
        query += " ORDER BY id DESC"
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_job(self, job_id: int) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            job = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            steps = conn.execute(
                "SELECT * FROM job_steps WHERE job_id=? ORDER BY id ASC", (job_id,)
            ).fetchall()
        if job is None:
            return None
        job_data = self._row_to_dict(job)
        job_data["steps"] = [self._row_to_dict(s) for s in steps]
        return job_data

    def delete_job(self, job_id: int) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM jobs WHERE id=?", (job_id,))

    # ── Study reports ─────────────────────────────────────────────────────────

    def save_study_report(
        self,
        instance_id: int,
        report_json: Dict[str, Any],
        raw_json: Dict[str, Any],
    ) -> int:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO study_reports (instance_id, report_json, raw_json, created_at) VALUES (?,?,?,?)",
                (instance_id, json.dumps(report_json), json.dumps(raw_json), self._now()),
            )
            return int(cur.lastrowid)

    def list_studies(self, instance_id: Optional[int] = None) -> List[Dict[str, Any]]:
        query = "SELECT * FROM study_reports"
        params: List[Any] = []
        if instance_id is not None:
            query += " WHERE instance_id=?"
            params.append(instance_id)
        query += " ORDER BY id DESC"
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_study(self, study_id: int) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM study_reports WHERE id=?", (study_id,)).fetchone()
        return self._row_to_dict(row)

    def latest_study_for_instance(self, instance_id: int) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM study_reports WHERE instance_id=? ORDER BY id DESC LIMIT 1",
                (instance_id,),
            ).fetchone()
        return self._row_to_dict(row)

    def delete_study(self, study_id: int) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM study_reports WHERE id=?", (study_id,))

    # ── Schedules ─────────────────────────────────────────────────────────────

    def set_schedule(
        self,
        instance_id: int,
        enabled: bool,
        mode: str,
        interval_hours: Optional[int],
        cron_expr: Optional[str],
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO schedules (instance_id, enabled, mode, interval_hours, cron_expr, updated_at)
                VALUES (?,?,?,?,?,?)
                ON CONFLICT(instance_id) DO UPDATE SET
                    enabled=excluded.enabled,
                    mode=excluded.mode,
                    interval_hours=excluded.interval_hours,
                    cron_expr=excluded.cron_expr,
                    updated_at=excluded.updated_at
                """,
                (instance_id, int(enabled), mode, interval_hours, cron_expr, self._now()),
            )

    def get_schedule(self, instance_id: int) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM schedules WHERE instance_id=?", (instance_id,)).fetchone()
        return self._row_to_dict(row)

    def delete_schedule(self, instance_id: int) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM schedules WHERE instance_id=?", (instance_id,))

    def list_enabled_schedules(self) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM schedules WHERE enabled=1").fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ── Config / check logs ───────────────────────────────────────────────────

    def set_config_json(self, key: str, value: Dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO config (key, value, updated_at) VALUES (?,?,?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                """,
                (key, json.dumps(value), self._now()),
            )

    def get_config_json(
        self,
        key: str,
        default: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
        if row is None:
            return default.copy() if default else {}
        try:
            return json.loads(row["value"])
        except json.JSONDecodeError:
            return default.copy() if default else {}

    def append_check_log(
        self,
        instance_id: int,
        entry: Dict[str, Any],
        max_entries: int = 50,
    ) -> List[Dict[str, Any]]:
        key = f"check_log_{instance_id}"
        data = self.get_config_json(key, default={"entries": []})
        entries = data.get("entries", [])
        entries.append(entry)
        entries = entries[-max_entries:]
        self.set_config_json(key, {"entries": entries})
        return entries

    def get_check_log(self, instance_id: int) -> List[Dict[str, Any]]:
        key = f"check_log_{instance_id}"
        data = self.get_config_json(key, default={"entries": []})
        return data.get("entries", [])
