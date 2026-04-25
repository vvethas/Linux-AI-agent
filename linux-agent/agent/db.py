"""
db.py — SQLite schema and helper functions.

Tables:
  instances      — managed Linux hosts
  jobs           — top-level job records
  job_steps      — per-step execution records
  schedules      — per-instance APScheduler config
  study_reports  — Claude analysis JSON
  config         — key/value store (notify_config, check_log, etc.)
"""
import json
import os
import sqlite3
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "agent.db")


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def get_db():
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Schema
# ─────────────────────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS instances (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    label       TEXT NOT NULL,
    host        TEXT NOT NULL,
    port        INTEGER NOT NULL DEFAULT 22,
    username    TEXT NOT NULL,
    auth_type   TEXT NOT NULL DEFAULT 'key',   -- 'key' | 'password'
    key_path    TEXT,
    password    TEXT,
    tags        TEXT NOT NULL DEFAULT '[]',     -- JSON array
    added_at    TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen   TEXT,
    last_status TEXT NOT NULL DEFAULT 'unknown' -- online|offline|auth_error|unknown
);

CREATE TABLE IF NOT EXISTS jobs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id  INTEGER REFERENCES instances(id) ON DELETE CASCADE,
    type         TEXT NOT NULL,   -- troubleshoot|build|explore|study|replicate
    title        TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending', -- pending|running|done|failed
    plan_json    TEXT,
    specs_json   TEXT,
    started_at   TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at  TEXT,
    duration_sec REAL,
    result       TEXT
);

CREATE TABLE IF NOT EXISTS job_steps (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id      INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    phase       TEXT,
    step_id     TEXT,
    title       TEXT,
    commands    TEXT NOT NULL DEFAULT '[]',  -- JSON array
    output      TEXT,
    success     INTEGER NOT NULL DEFAULT 0,  -- 0|1
    ran_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS schedules (
    instance_id    INTEGER PRIMARY KEY REFERENCES instances(id) ON DELETE CASCADE,
    enabled        INTEGER NOT NULL DEFAULT 0,
    mode           TEXT NOT NULL DEFAULT 'interval',  -- 'interval'|'cron'
    interval_hours REAL NOT NULL DEFAULT 6,
    cron_expr      TEXT NOT NULL DEFAULT '0 */6 * * *',
    updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS study_reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id INTEGER REFERENCES instances(id) ON DELETE CASCADE,
    job_id      INTEGER REFERENCES jobs(id) ON DELETE SET NULL,
    report_json TEXT,    -- Claude's structured analysis
    raw_json    TEXT,    -- raw SSH command outputs
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS chat_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
    role        TEXT NOT NULL,   -- 'user' | 'ai' | 'system'
    content     TEXT NOT NULL,   -- HTML or plain text
    pre_text    TEXT,            -- optional <pre> block text
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_db() as conn:
        conn.executescript(SCHEMA)


# ─────────────────────────────────────────────────────────────────────────────
# Instance helpers
# ─────────────────────────────────────────────────────────────────────────────

def add_instance(label, host, port, username, auth_type, key_path, password, tags):
    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO instances (label,host,port,username,auth_type,
               key_path,password,tags) VALUES (?,?,?,?,?,?,?,?)""",
            (label, host, int(port), username, auth_type,
             key_path, password, json.dumps(tags)),
        )
        return cur.lastrowid


def list_instances():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM instances ORDER BY id").fetchall()
        return [dict(r) for r in rows]


def get_instance(instance_id: int):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM instances WHERE id=?", (instance_id,)
        ).fetchone()
        return dict(row) if row else None


def delete_instance(instance_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM instances WHERE id=?", (instance_id,))


def update_instance_status(instance_id: int, status: str):
    with get_db() as conn:
        conn.execute(
            "UPDATE instances SET last_status=?, last_seen=datetime('now') WHERE id=?",
            (status, instance_id),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Job helpers
# ─────────────────────────────────────────────────────────────────────────────

def create_job(instance_id, job_type, title, plan_json=None, specs_json=None):
    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO jobs (instance_id,type,title,status,plan_json,specs_json)
               VALUES (?,?,?,'running',?,?)""",
            (instance_id, job_type, title,
             json.dumps(plan_json) if plan_json else None,
             json.dumps(specs_json) if specs_json else None),
        )
        return cur.lastrowid


def finish_job(job_id, status, result=None):
    with get_db() as conn:
        conn.execute(
            """UPDATE jobs SET status=?, finished_at=datetime('now'),
               duration_sec=(julianday('now')-julianday(started_at))*86400,
               result=? WHERE id=?""",
            (status, result, job_id),
        )


def update_job_plan(job_id, plan_json):
    with get_db() as conn:
        conn.execute(
            "UPDATE jobs SET plan_json=? WHERE id=?",
            (json.dumps(plan_json), job_id),
        )


def list_jobs(instance_id=None, job_type=None, limit=200):
    clauses, params = [], []
    if instance_id:
        clauses.append("j.instance_id=?")
        params.append(instance_id)
    if job_type:
        clauses.append("j.type=?")
        params.append(job_type)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_db() as conn:
        rows = conn.execute(
            f"""SELECT j.*, i.label as instance_label, i.host
                FROM jobs j LEFT JOIN instances i ON j.instance_id=i.id
                {where} ORDER BY j.id DESC LIMIT ?""",
            params + [limit],
        ).fetchall()
        return [dict(r) for r in rows]


def get_job(job_id: int):
    with get_db() as conn:
        row = conn.execute(
            """SELECT j.*, i.label as instance_label, i.host
               FROM jobs j LEFT JOIN instances i ON j.instance_id=i.id
               WHERE j.id=?""",
            (job_id,),
        ).fetchone()
        return dict(row) if row else None


def delete_job(job_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM jobs WHERE id=?", (job_id,))


# ─────────────────────────────────────────────────────────────────────────────
# Job step helpers
# ─────────────────────────────────────────────────────────────────────────────

def add_job_step(job_id, phase, step_id, title, commands, output, success):
    with get_db() as conn:
        conn.execute(
            """INSERT INTO job_steps
               (job_id,phase,step_id,title,commands,output,success)
               VALUES (?,?,?,?,?,?,?)""",
            (job_id, phase, step_id, title,
             json.dumps(commands), output, 1 if success else 0),
        )


def get_job_steps(job_id: int):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM job_steps WHERE job_id=? ORDER BY id",
            (job_id,),
        ).fetchall()
        return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# Schedule helpers
# ─────────────────────────────────────────────────────────────────────────────

def upsert_schedule(instance_id, enabled, mode, interval_hours, cron_expr):
    with get_db() as conn:
        conn.execute(
            """INSERT INTO schedules
               (instance_id,enabled,mode,interval_hours,cron_expr,updated_at)
               VALUES (?,?,?,?,?,datetime('now'))
               ON CONFLICT(instance_id) DO UPDATE SET
               enabled=excluded.enabled, mode=excluded.mode,
               interval_hours=excluded.interval_hours,
               cron_expr=excluded.cron_expr,
               updated_at=excluded.updated_at""",
            (instance_id, 1 if enabled else 0, mode, interval_hours, cron_expr),
        )


def get_schedule(instance_id: int):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM schedules WHERE instance_id=?", (instance_id,)
        ).fetchone()
        return dict(row) if row else None


def delete_schedule(instance_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM schedules WHERE instance_id=?", (instance_id,))


def list_enabled_schedules():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT s.*, i.label, i.host FROM schedules s "
            "JOIN instances i ON s.instance_id=i.id WHERE s.enabled=1"
        ).fetchall()
        return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# Study report helpers
# ─────────────────────────────────────────────────────────────────────────────

def save_study_report(instance_id, job_id, report_json, raw_json):
    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO study_reports (instance_id,job_id,report_json,raw_json)
               VALUES (?,?,?,?)""",
            (instance_id, job_id,
             json.dumps(report_json), json.dumps(raw_json)),
        )
        return cur.lastrowid


def list_study_reports(instance_id=None, limit=100):
    clauses, params = [], []
    if instance_id:
        clauses.append("s.instance_id=?")
        params.append(instance_id)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_db() as conn:
        rows = conn.execute(
            f"""SELECT s.id, s.instance_id, s.job_id, s.created_at,
                       i.label as instance_label, i.host
                FROM study_reports s
                LEFT JOIN instances i ON s.instance_id=i.id
                {where} ORDER BY s.id DESC LIMIT ?""",
            params + [limit],
        ).fetchall()
        return [dict(r) for r in rows]


def get_study_report(study_id: int):
    with get_db() as conn:
        row = conn.execute(
            """SELECT s.*, i.label as instance_label, i.host
               FROM study_reports s
               LEFT JOIN instances i ON s.instance_id=i.id
               WHERE s.id=?""",
            (study_id,),
        ).fetchone()
        return dict(row) if row else None


def delete_study_report(study_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM study_reports WHERE id=?", (study_id,))


def get_latest_study_report(instance_id: int):
    with get_db() as conn:
        row = conn.execute(
            """SELECT * FROM study_reports WHERE instance_id=?
               ORDER BY id DESC LIMIT 1""",
            (instance_id,),
        ).fetchone()
        return dict(row) if row else None


# ─────────────────────────────────────────────────────────────────────────────
# Config helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_config(key: str, default=None):
    with get_db() as conn:
        row = conn.execute(
            "SELECT value FROM config WHERE key=?", (key,)
        ).fetchone()
        return row["value"] if row else default


def set_config(key: str, value):
    if not isinstance(value, str):
        value = json.dumps(value)
    with get_db() as conn:
        conn.execute(
            "INSERT INTO config (key,value) VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


def get_check_log(instance_id: int):
    raw = get_config(f"check_log_{instance_id}", "[]")
    try:
        return json.loads(raw)
    except Exception:
        return []


def append_check_log(instance_id: int, entry: dict, max_entries=50):
    log = get_check_log(instance_id)
    log.insert(0, entry)
    log = log[:max_entries]
    set_config(f"check_log_{instance_id}", json.dumps(log))


# ─────────────────────────────────────────────────────────────────────────────
# Chat history helpers
# ─────────────────────────────────────────────────────────────────────────────

def save_chat_message(instance_id: int, role: str, content: str, pre_text: str = None):
    with get_db() as conn:
        conn.execute(
            """INSERT INTO chat_history (instance_id, role, content, pre_text)
               VALUES (?, ?, ?, ?)""",
            (instance_id, role, content, pre_text),
        )


def get_chat_history(instance_id: int, limit: int = 200):
    with get_db() as conn:
        rows = conn.execute(
            """SELECT id, role, content, pre_text, created_at
               FROM chat_history WHERE instance_id=?
               ORDER BY id ASC LIMIT ?""",
            (instance_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def clear_chat_history(instance_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM chat_history WHERE instance_id=?", (instance_id,))


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard helpers
# ─────────────────────────────────────────────────────────────────────────────

def dashboard_stats():
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM instances").fetchone()[0]
        online = conn.execute(
            "SELECT COUNT(*) FROM instances WHERE last_status='online'"
        ).fetchone()[0]
        offline = conn.execute(
            "SELECT COUNT(*) FROM instances WHERE last_status='offline'"
        ).fetchone()[0]
        recent_jobs = conn.execute(
            """SELECT j.id, j.type, j.title, j.status, j.started_at,
                      i.label as instance_label
               FROM jobs j LEFT JOIN instances i ON j.instance_id=i.id
               ORDER BY j.id DESC LIMIT 10"""
        ).fetchall()
        return {
            "total_instances": total,
            "online": online,
            "offline": offline,
            "recent_jobs": [dict(r) for r in recent_jobs],
        }
