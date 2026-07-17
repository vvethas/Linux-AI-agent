import json
import logging
import os
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from werkzeug.security import generate_password_hash

log = logging.getLogger(__name__)


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
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init_db(self) -> None:
        with self._lock, self._connect() as conn:
            # Migrate instances table if the auth_type CHECK constraint is too narrow.
            # SQLite does not support ALTER TABLE … MODIFY COLUMN, so we recreate the
            # table when the old definition is detected.
            old_schema = conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='instances'"
            ).fetchone()
            if old_schema and "CHECK(auth_type IN ('key','password'))" in (old_schema[0] or ""):
                conn.executescript(
                    """
                    PRAGMA foreign_keys=OFF;
                    CREATE TABLE IF NOT EXISTS instances_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        label TEXT NOT NULL,
                        host TEXT NOT NULL,
                        port INTEGER NOT NULL DEFAULT 22,
                        username TEXT NOT NULL,
                        auth_type TEXT NOT NULL
                            CHECK(auth_type IN ('key','key_paste','key_upload','password')),
                        key_path TEXT,
                        password TEXT,
                        tags TEXT DEFAULT '[]',
                        added_at TEXT NOT NULL,
                        last_seen TEXT,
                        last_status TEXT DEFAULT 'unknown'
                    );
                    INSERT INTO instances_new SELECT * FROM instances;
                    DROP TABLE instances;
                    ALTER TABLE instances_new RENAME TO instances;
                    PRAGMA foreign_keys=ON;
                    """
                )

            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS instances (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    label TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL DEFAULT 22,
                    username TEXT NOT NULL,
                    auth_type TEXT NOT NULL
                        CHECK(auth_type IN ('key','key_paste','key_upload','password')),
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

                CREATE TABLE IF NOT EXISTS ssh_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    instance_id INTEGER NOT NULL,
                    encrypted_key_blob TEXT NOT NULL,
                    key_fingerprint TEXT NOT NULL,
                    passphrase_encrypted TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(instance_id) REFERENCES instances(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    instance_id INTEGER NOT NULL,
                    severity TEXT NOT NULL CHECK(severity IN ('critical','warning','info')),
                    message TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active','acknowledged','resolved')) DEFAULT 'active',
                    first_seen TEXT NOT NULL,
                    last_notified TEXT,
                    acknowledged_by TEXT,
                    acknowledged_at TEXT,
                    resolved_at TEXT,
                    FOREIGN KEY(instance_id) REFERENCES instances(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS alert_subscriptions (
                    instance_id INTEGER PRIMARY KEY,
                    notify_enabled INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY(instance_id) REFERENCES instances(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS roles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE
                );

                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT,
                    role_id INTEGER REFERENCES roles(id),
                    invite_token TEXT,
                    status TEXT NOT NULL DEFAULT 'invited'
                        CHECK(status IN ('active','invited','disabled')),
                    created_at TEXT NOT NULL,
                    must_change_password INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    role_id INTEGER NOT NULL REFERENCES roles(id)
                );

                CREATE TABLE IF NOT EXISTS group_members (
                    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    PRIMARY KEY(group_id, user_id)
                );

                CREATE TABLE IF NOT EXISTS metric_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    instance_id INTEGER NOT NULL,
                    metric_name TEXT NOT NULL CHECK(metric_name IN ('cpu','mem','disk')),
                    value REAL NOT NULL,
                    recorded_at TEXT NOT NULL,
                    FOREIGN KEY(instance_id) REFERENCES instances(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS monitored_services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    instance_id INTEGER NOT NULL,
                    service_name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(instance_id) REFERENCES instances(id) ON DELETE CASCADE,
                    UNIQUE(instance_id, service_name)
                );

                CREATE TABLE IF NOT EXISTS service_status_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    instance_id INTEGER NOT NULL,
                    service_name TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('running','failed')),
                    recorded_at TEXT NOT NULL,
                    FOREIGN KEY(instance_id) REFERENCES instances(id) ON DELETE CASCADE
                );
                """
            )
            # Seed the three fixed roles
            conn.execute("INSERT OR IGNORE INTO roles (name) VALUES ('Admin')")
            conn.execute("INSERT OR IGNORE INTO roles (name) VALUES ('Operator')")
            conn.execute("INSERT OR IGNORE INTO roles (name) VALUES ('Viewer')")

            # Migration: add must_change_password column if it does not exist yet
            existing_cols = {
                row[1]
                for row in conn.execute("PRAGMA table_info(users)").fetchall()
            }
            if "must_change_password" not in existing_cols:
                conn.execute(
                    "ALTER TABLE users ADD COLUMN "
                    "must_change_password INTEGER NOT NULL DEFAULT 0"
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

    def list_alert_subscriptions(self) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT instance_id, notify_enabled FROM alert_subscriptions ORDER BY instance_id ASC"
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def set_alert_subscription(self, instance_id: int, notify_enabled: bool) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO alert_subscriptions (instance_id, notify_enabled)
                VALUES (?,?)
                ON CONFLICT(instance_id) DO UPDATE SET notify_enabled=excluded.notify_enabled
                """,
                (instance_id, int(bool(notify_enabled))),
            )

    def set_alert_subscriptions_bulk(self, instance_ids: List[int]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM alert_subscriptions")
            for instance_id in instance_ids:
                conn.execute(
                    "INSERT INTO alert_subscriptions (instance_id, notify_enabled) VALUES (?,1)",
                    (instance_id,),
                )

    def update_instance_status(self, instance_id: int, status: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE instances SET last_status=?, last_seen=? WHERE id=?",
                (status, self._now(), instance_id),
            )

    # ── SSH Keys (encrypted at rest) ─────────────────────────────────────────

    def store_ssh_key(
        self,
        instance_id: int,
        encrypted_key_blob: str,
        key_fingerprint: str,
        passphrase_encrypted: Optional[str] = None,
    ) -> int:
        with self._lock, self._connect() as conn:
            # Replace any existing key for this instance.
            conn.execute("DELETE FROM ssh_keys WHERE instance_id=?", (instance_id,))
            cur = conn.execute(
                """
                INSERT INTO ssh_keys
                    (instance_id, encrypted_key_blob, key_fingerprint, passphrase_encrypted, created_at)
                VALUES (?,?,?,?,?)
                """,
                (instance_id, encrypted_key_blob, key_fingerprint, passphrase_encrypted, self._now()),
            )
            return int(cur.lastrowid)

    def get_ssh_key(self, instance_id: int) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM ssh_keys WHERE instance_id=?", (instance_id,)
            ).fetchone()
        return self._row_to_dict(row)

    def delete_ssh_key_for_instance(self, instance_id: int) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM ssh_keys WHERE instance_id=?", (instance_id,))

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

    # ── Alerts ────────────────────────────────────────────────────────────────

    def find_open_alert(
        self,
        instance_id: int,
        severity: str,
        message: str,
    ) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM alerts
                WHERE instance_id=? AND severity=? AND message=? AND status IN ('active','acknowledged')
                ORDER BY id DESC
                LIMIT 1
                """,
                (instance_id, severity, message),
            ).fetchone()
        return self._row_to_dict(row)

    def create_alert(
        self,
        instance_id: int,
        severity: str,
        message: str,
        status: str = "active",
        last_notified: Optional[str] = None,
    ) -> int:
        now = self._now()
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO alerts
                    (instance_id, severity, message, status, first_seen, last_notified)
                VALUES (?,?,?,?,?,?)
                """,
                (instance_id, severity, message, status, now, last_notified),
            )
            return int(cur.lastrowid)

    def touch_alert_notification(self, alert_id: int) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE alerts SET last_notified=? WHERE id=?",
                (self._now(), alert_id),
            )

    def acknowledge_alert(self, alert_id: int, acknowledged_by: str) -> None:
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE alerts
                SET status='acknowledged',
                    acknowledged_by=?,
                    acknowledged_at=?
                WHERE id=? AND status='active'
                """,
                (acknowledged_by, now, alert_id),
            )

    def resolve_alert(self, alert_id: int) -> None:
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE alerts
                SET status='resolved',
                    resolved_at=?
                WHERE id=? AND status IN ('active','acknowledged')
                """,
                (now, alert_id),
            )

    def resolve_alerts_for_condition(self, instance_id: int, severity: str, message: str) -> None:
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE alerts
                SET status='resolved', resolved_at=?
                WHERE instance_id=? AND severity=? AND message=? AND status IN ('active','acknowledged')
                """,
                (now, instance_id, severity, message),
            )

    def get_alert(self, alert_id: int) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        return self._row_to_dict(row)

    def list_unresolved_alerts(self) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT a.*, i.label AS instance_label, i.tags AS instance_tags
                FROM alerts a
                JOIN instances i ON i.id = a.instance_id
                WHERE a.status IN ('active','acknowledged')
                ORDER BY
                    CASE a.severity WHEN 'critical' THEN 1 WHEN 'warning' THEN 2 ELSE 3 END,
                    a.first_seen DESC
                """
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def list_due_critical_alerts(self, renotify_minutes: int) -> List[Dict[str, Any]]:
        renotify_minutes = max(1, int(renotify_minutes or 5))
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT a.*, i.label AS instance_label, i.host AS instance_host
                FROM alerts a
                JOIN instances i ON i.id = a.instance_id
                WHERE a.status='active'
                  AND a.severity='critical'
                  AND (
                    a.last_notified IS NULL
                    OR datetime(a.last_notified) <= datetime('now', '-' || ? || ' minutes')
                  )
                ORDER BY a.first_seen ASC
                """,
                (renotify_minutes,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ── Roles ──────────────────────────────────────────────────────────────────

    def list_roles(self) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM roles ORDER BY id ASC").fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_role(self, role_id: int) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM roles WHERE id=?", (role_id,)).fetchone()
        return self._row_to_dict(row)

    def get_role_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM roles WHERE name=?", (name,)).fetchone()
        return self._row_to_dict(row)

    # ── Users ──────────────────────────────────────────────────────────────────

    def count_users(self) -> int:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
        return int(row[0])

    def seed_default_admin(self) -> None:
        """Seed a default admin account if the users table is empty.

        Called once at application startup.  The account is seeded with
        must_change_password=1 so the operator is forced to choose a new
        password on first login.
        """
        with self._lock, self._connect() as conn:
            count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if count > 0:
                return
            admin_role = conn.execute(
                "SELECT id FROM roles WHERE name='Admin'"
            ).fetchone()
            if not admin_role:
                return
            now = self._now()
            pw_hash = generate_password_hash("admin")
            conn.execute(
                """
                INSERT INTO users
                    (name, email, password_hash, role_id, invite_token,
                     status, created_at, must_change_password)
                VALUES (?,?,?,?,NULL,'active',?,1)
                """,
                ("admin", "admin@localhost", pw_hash, int(admin_role[0]), now),
            )
        log.warning(
            "Default admin account created — "
            "email: admin@localhost, password: admin — "
            "change required on first login"
        )

    def create_user(
        self,
        name: str,
        email: str,
        role_id: Optional[int] = None,
    ) -> tuple:
        """Create a new invited user. Returns (user_id, invite_token)."""
        token = secrets.token_urlsafe(32)
        now = self._now()
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO users (name, email, role_id, invite_token, status, created_at)
                VALUES (?,?,?,?,?,?)
                """,
                (name, email, role_id, token, "invited", now),
            )
            return int(cur.lastrowid), token

    def get_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return self._row_to_dict(row)

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE email=?", (email,)
            ).fetchone()
        return self._row_to_dict(row)

    def get_user_by_invite_token(self, token: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE invite_token=?", (token,)
            ).fetchone()
        return self._row_to_dict(row)

    def list_users(self) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    u.*,
                    r.name AS role_name,
                    (SELECT g.name FROM groups g
                     JOIN group_members gm ON gm.group_id = g.id
                     WHERE gm.user_id = u.id LIMIT 1) AS group_name,
                    (SELECT g.id FROM groups g
                     JOIN group_members gm ON gm.group_id = g.id
                     WHERE gm.user_id = u.id LIMIT 1) AS group_id
                FROM users u
                LEFT JOIN roles r ON r.id = u.role_id
                ORDER BY u.created_at ASC
                """
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def update_user(self, user_id: int, **fields: Any) -> None:
        # Column-to-fragment map with compile-time constants — no external data
        # is ever interpolated into the SQL string, preventing SQL injection.
        _COLUMNS = {
            "name": "name=?",
            "email": "email=?",
            "role_id": "role_id=?",
            "status": "status=?",
            "password_hash": "password_hash=?",
            "invite_token": "invite_token=?",
            "must_change_password": "must_change_password=?",
        }
        parts: List[str] = []
        params: List[Any] = []
        for col, frag in _COLUMNS.items():
            if col in fields:
                parts.append(frag)
                params.append(fields[col])
        if not parts:
            return
        params.append(user_id)
        sql = "UPDATE users SET " + ", ".join(parts) + " WHERE id=?"
        with self._lock, self._connect() as conn:
            conn.execute(sql, params)

    def set_user_password(self, user_id: int, password_hash: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE users SET password_hash=?, status='active', "
                "invite_token=NULL, must_change_password=0 WHERE id=?",
                (password_hash, user_id),
            )

    def regenerate_invite_token(self, user_id: int) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE users SET invite_token=?, status='invited', password_hash=NULL WHERE id=?",
                (token, user_id),
            )
        return token

    def get_user_groups(self, user_id: int) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT g.* FROM groups g
                JOIN group_members gm ON gm.group_id = g.id
                WHERE gm.user_id = ?
                """,
                (user_id,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ── Groups ─────────────────────────────────────────────────────────────────

    def create_group(self, name: str, role_id: int) -> int:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO groups (name, role_id) VALUES (?,?)",
                (name, role_id),
            )
            return int(cur.lastrowid)

    def list_groups(self) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    g.*,
                    r.name AS role_name,
                    COUNT(gm.user_id) AS member_count
                FROM groups g
                LEFT JOIN roles r ON r.id = g.role_id
                LEFT JOIN group_members gm ON gm.group_id = g.id
                GROUP BY g.id
                ORDER BY g.id ASC
                """
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_group(self, group_id: int) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT g.*, r.name AS role_name
                FROM groups g
                LEFT JOIN roles r ON r.id = g.role_id
                WHERE g.id=?
                """,
                (group_id,),
            ).fetchone()
        return self._row_to_dict(row)

    def update_group(self, group_id: int, **fields: Any) -> None:
        _COLUMNS = {
            "name": "name=?",
            "role_id": "role_id=?",
        }
        parts: List[str] = []
        params: List[Any] = []
        for col, frag in _COLUMNS.items():
            if col in fields:
                parts.append(frag)
                params.append(fields[col])
        if not parts:
            return
        params.append(group_id)
        sql = "UPDATE groups SET " + ", ".join(parts) + " WHERE id=?"
        with self._lock, self._connect() as conn:
            conn.execute(sql, params)

    def delete_group(self, group_id: int) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM groups WHERE id=?", (group_id,))

    def get_group_members(self, group_id: int) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT u.id, u.name, u.email, u.status
                FROM users u
                JOIN group_members gm ON gm.user_id = u.id
                WHERE gm.group_id = ?
                ORDER BY u.name ASC
                """,
                (group_id,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def add_group_member(self, group_id: int, user_id: int) -> None:
        """Add a user to a group and clear any direct role assignment."""
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?,?)",
                (group_id, user_id),
            )
            conn.execute("UPDATE users SET role_id=NULL WHERE id=?", (user_id,))

    def remove_group_member(self, group_id: int, user_id: int) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "DELETE FROM group_members WHERE group_id=? AND user_id=?",
                (group_id, user_id),
            )

    # ── Metric history ─────────────────────────────────────────────────────────

    def add_metric_history(
        self, instance_id: int, metric_name: str, value: float
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO metric_history (instance_id, metric_name, value, recorded_at)"
                " VALUES (?,?,?,?)",
                (instance_id, metric_name, value, self._now()),
            )

    def get_metric_history(
        self,
        instance_id: int,
        metric_name: Optional[str] = None,
        hours: int = 24,
    ) -> List[Dict[str, Any]]:
        query = (
            "SELECT * FROM metric_history"
            " WHERE instance_id=?"
            "   AND datetime(recorded_at) >= datetime('now',?)"
        )
        params: List[Any] = [instance_id, f"-{hours} hours"]
        if metric_name:
            query += " AND metric_name=?"
            params.append(metric_name)
        query += " ORDER BY recorded_at ASC"
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_latest_metrics(self, instance_id: int) -> Dict[str, Optional[float]]:
        """Return the most recent value for each of cpu, mem, disk."""
        result: Dict[str, Optional[float]] = {"cpu": None, "mem": None, "disk": None}
        with self._lock, self._connect() as conn:
            for metric in ("cpu", "mem", "disk"):
                row = conn.execute(
                    "SELECT value FROM metric_history"
                    " WHERE instance_id=? AND metric_name=?"
                    " ORDER BY id DESC LIMIT 1",
                    (instance_id, metric),
                ).fetchone()
                if row:
                    result[metric] = row[0]
        return result

    def get_metric_rolling_avg(
        self, instance_id: int, metric_name: str, n: int = 10
    ) -> Optional[float]:
        """Return the rolling average of the last *n* values for a metric."""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT value FROM metric_history"
                " WHERE instance_id=? AND metric_name=?"
                " ORDER BY id DESC LIMIT ?",
                (instance_id, metric_name, n),
            ).fetchall()
        if not rows:
            return None
        return sum(r[0] for r in rows) / len(rows)

    # ── Monitored services ─────────────────────────────────────────────────────

    def add_monitored_service(self, instance_id: int, service_name: str) -> int:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO monitored_services"
                " (instance_id, service_name, created_at) VALUES (?,?,?)",
                (instance_id, service_name.strip(), self._now()),
            )
            if cur.lastrowid:
                return int(cur.lastrowid)
            row = conn.execute(
                "SELECT id FROM monitored_services"
                " WHERE instance_id=? AND service_name=?",
                (instance_id, service_name.strip()),
            ).fetchone()
            return int(row[0]) if row else 0

    def remove_monitored_service(self, service_id: int, instance_id: int) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "DELETE FROM monitored_services WHERE id=? AND instance_id=?",
                (service_id, instance_id),
            )

    def list_monitored_services(self, instance_id: int) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM monitored_services WHERE instance_id=?"
                " ORDER BY service_name ASC",
                (instance_id,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ── Service status history ─────────────────────────────────────────────────

    def add_service_status(
        self, instance_id: int, service_name: str, status: str
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO service_status_history"
                " (instance_id, service_name, status, recorded_at)"
                " VALUES (?,?,?,?)",
                (instance_id, service_name, status, self._now()),
            )

    def get_service_status_history(
        self,
        instance_id: int,
        service_name: Optional[str] = None,
        hours: int = 24,
    ) -> List[Dict[str, Any]]:
        query = (
            "SELECT * FROM service_status_history"
            " WHERE instance_id=?"
            "   AND datetime(recorded_at) >= datetime('now',?)"
        )
        params: List[Any] = [instance_id, f"-{hours} hours"]
        if service_name:
            query += " AND service_name=?"
            params.append(service_name)
        query += " ORDER BY recorded_at ASC"
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_latest_service_statuses(
        self, instance_id: int
    ) -> List[Dict[str, Any]]:
        """Return the most recent status row for each monitored service."""
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT s.id, s.instance_id, s.service_name, s.status, s.recorded_at
                FROM service_status_history s
                INNER JOIN (
                    SELECT service_name, MAX(id) AS max_id
                    FROM service_status_history
                    WHERE instance_id=?
                    GROUP BY service_name
                ) latest ON s.service_name = latest.service_name
                           AND s.id = latest.max_id
                ORDER BY s.service_name ASC
                """,
                (instance_id,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]
