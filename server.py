"""
Linux AI Agent – Flask server
Provides a SQLite-backed knowledge base and three API endpoints.
"""

import hashlib
import json
import logging
import os
import queue
import sqlite3
import subprocess
import threading
import time
from datetime import datetime, timezone

from flask import Flask, Response, g, jsonify, request, stream_with_context
from openai import OpenAI

app = Flask(__name__)

DB_PATH = os.environ.get("DB_PATH", "knowledge_base.db")

# ── Database helpers ───────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    """Return the per-request database connection, opening it if needed."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create database tables on first run (idempotent); migrate existing DBs."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS knowledge (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                instance    TEXT    NOT NULL,
                issue       TEXT    NOT NULL,
                diagnosis   TEXT    NOT NULL,
                confirmed   INTEGER NOT NULL DEFAULT 0,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                fingerprint TEXT,
                fix_steps   TEXT,
                seen_count  INTEGER NOT NULL DEFAULT 1,
                last_seen   TIMESTAMP
            )
            """
        )
        # Safe migration: add new columns if this is an older DB that lacks them.
        existing = {
            row[1]
            for row in conn.execute("PRAGMA table_info(knowledge)").fetchall()
        }
        migrations = {
            "fingerprint": "ALTER TABLE knowledge ADD COLUMN fingerprint TEXT",
            "fix_steps":   "ALTER TABLE knowledge ADD COLUMN fix_steps TEXT",
            "seen_count":  "ALTER TABLE knowledge ADD COLUMN seen_count INTEGER NOT NULL DEFAULT 1",
            "last_seen":   "ALTER TABLE knowledge ADD COLUMN last_seen TIMESTAMP",
        }
        for col, sql in migrations.items():
            if col not in existing:
                conn.execute(sql)
        conn.commit()


# ── AI helpers ─────────────────────────────────────────────────────────────────

def _fingerprint(instance: str, issue: str) -> str:
    """Return a 16-char hex sha256 fingerprint of (instance + issue)."""
    raw = (instance + issue).encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def _call_openai(instance: str, issue: str) -> dict:
    """
    Call gpt-4o and return {"diagnosis": str, "fix_steps": list[str]}.
    Raises RuntimeError if OPENAI_API_KEY is missing or the API fails.
    """
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY environment variable is not set.")

    client = OpenAI(api_key=api_key)

    system_prompt = (
        "You are an expert Linux systems administrator and SRE. "
        "When given a hostname and a problem description, respond ONLY with a "
        "valid JSON object (no markdown fences) with exactly two keys:\n"
        '  "diagnosis": a concise string explaining the root cause,\n'
        '  "fix_steps": an array of short, actionable string steps to resolve the issue.\n'
        "Do not include any other text."
    )
    user_prompt = (
        f"Hostname: {instance}\n"
        f"Problem: {issue}"
    )

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
        temperature=0.2,
        response_format={"type": "json_object"},
    )

    content = response.choices[0].message.content
    parsed = json.loads(content)

    diagnosis = str(parsed.get("diagnosis", "")).strip()
    fix_steps = parsed.get("fix_steps", [])
    if not isinstance(fix_steps, list):
        fix_steps = [str(fix_steps)]

    return {"diagnosis": diagnosis, "fix_steps": fix_steps}


# ── SSE broadcast ──────────────────────────────────────────────────────────────

_subscribers: set = set()
_subscribers_lock = threading.Lock()


def _broadcast(event_type: str, data: dict) -> None:
    """Push an SSE message to all connected /api/events clients."""
    msg = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    with _subscribers_lock:
        dead: set = set()
        for q in _subscribers:
            try:
                q.put_nowait(msg)
            except queue.Full:
                dead.add(q)
        _subscribers -= dead


def _sse_stream():
    """Generator that yields SSE-formatted strings for one connected client."""
    q: queue.Queue = queue.Queue(maxsize=50)
    with _subscribers_lock:
        _subscribers.add(q)
    try:
        yield 'data: {"type":"connected"}\n\n'
        while True:
            try:
                yield q.get(timeout=25)
            except queue.Empty:
                yield ": keepalive\n\n"
    finally:
        with _subscribers_lock:
            _subscribers.discard(q)


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.post("/api/diagnose")
def diagnose():
    """
    Diagnose an issue on a Linux instance.

    Expected JSON body:
        { "instance": "<hostname>", "issue": "<description>" }

    Checks the SQLite cache first (by sha256 fingerprint of instance+issue,
    truncated to 16 chars).  On a cache hit the seen_count and last_seen are
    updated and the cached result is returned immediately.  On a miss the
    OpenAI gpt-4o model is called, the result is stored, and returned.

    Response:
        {
            "source":    "cache" | "new",
            "diagnosis": "...",
            "fix_steps": ["step 1", "step 2"],
            "seen_count": 3,
            "last_seen": "2026-06-16T19:00:00"
        }
    """
    body = request.get_json(silent=True) or {}
    instance = (body.get("instance") or "").strip()
    issue = (body.get("issue") or "").strip()

    if not instance or not issue:
        return jsonify({"error": "Both 'instance' and 'issue' are required."}), 400

    fp = _fingerprint(instance, issue)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

    db = get_db()

    # ── Cache hit ──────────────────────────────────────────────────────────────
    row = db.execute(
        "SELECT * FROM knowledge WHERE fingerprint = ? LIMIT 1", (fp,)
    ).fetchone()

    if row is not None:
        new_count = (row["seen_count"] or 1) + 1
        db.execute(
            "UPDATE knowledge SET seen_count = ?, last_seen = ? WHERE id = ?",
            (new_count, now, row["id"]),
        )
        db.commit()

        fix_steps = []
        if row["fix_steps"]:
            try:
                fix_steps = json.loads(row["fix_steps"])
            except (json.JSONDecodeError, TypeError):
                fix_steps = []

        return jsonify(
            {
                "source":    "cache",
                "diagnosis": row["diagnosis"],
                "fix_steps": fix_steps,
                "seen_count": new_count,
                "last_seen":  now,
            }
        )

    # ── Cache miss: call OpenAI ────────────────────────────────────────────────
    try:
        ai_result = _call_openai(instance, issue)
    except RuntimeError as exc:
        logging.warning("Diagnose configuration error: %s", exc)
        return jsonify({"error": "AI service is not configured. Check OPENAI_API_KEY."}), 503
    except Exception as exc:  # noqa: BLE001
        logging.exception("OpenAI request failed for instance=%s", instance)
        return jsonify({"error": "AI service request failed. Please try again later."}), 502

    diagnosis  = ai_result["diagnosis"]
    fix_steps  = ai_result["fix_steps"]

    db.execute(
        """
        INSERT INTO knowledge
            (instance, issue, diagnosis, fingerprint, fix_steps, seen_count, last_seen)
        VALUES (?, ?, ?, ?, ?, 1, ?)
        """,
        (instance, issue, diagnosis, fp, json.dumps(fix_steps), now),
    )
    db.commit()

    return jsonify(
        {
            "source":    "new",
            "diagnosis": diagnosis,
            "fix_steps": fix_steps,
            "seen_count": 1,
            "last_seen":  now,
        }
    ), 201


@app.post("/api/diagnose/confirm")
def diagnose_confirm():
    """
    Mark a pending diagnosis as confirmed (accepted into the knowledge base).

    Expected JSON body:
        { "id": <int> }

    Optionally the caller may override the diagnosis text:
        { "id": <int>, "diagnosis": "<revised text>" }
    """
    body = request.get_json(silent=True) or {}
    row_id = body.get("id")

    if row_id is None:
        return jsonify({"error": "'id' is required."}), 400

    try:
        row_id = int(row_id)
    except (TypeError, ValueError):
        return jsonify({"error": "'id' must be an integer."}), 400

    db = get_db()
    row = db.execute("SELECT * FROM knowledge WHERE id = ?", (row_id,)).fetchone()

    if row is None:
        return jsonify({"error": f"No diagnosis found with id {row_id}."}), 404

    if row["confirmed"]:
        return jsonify({"error": f"Diagnosis {row_id} is already confirmed."}), 409

    # Allow optional override of the diagnosis text at confirmation time.
    revised_diagnosis = (body.get("diagnosis") or "").strip() or row["diagnosis"]

    db.execute(
        "UPDATE knowledge SET confirmed = 1, diagnosis = ? WHERE id = ?",
        (revised_diagnosis, row_id),
    )
    db.commit()

    return jsonify(
        {
            "id": row_id,
            "instance": row["instance"],
            "issue": row["issue"],
            "diagnosis": revised_diagnosis,
            "confirmed": True,
        }
    )


@app.get("/api/knowledge")
def knowledge():
    """
    Return all confirmed knowledge-base entries.

    Optional query parameters:
        instance=<hostname>   – filter by instance name
    """
    instance_filter = request.args.get("instance", "").strip()

    db = get_db()
    if instance_filter:
        rows = db.execute(
            "SELECT * FROM knowledge WHERE confirmed = 1 AND instance = ? ORDER BY created_at DESC",
            (instance_filter,),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM knowledge WHERE confirmed = 1 ORDER BY created_at DESC"
        ).fetchall()

    return jsonify(
        [
            {
                "id": r["id"],
                "instance": r["instance"],
                "issue": r["issue"],
                "diagnosis": r["diagnosis"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]
    )


@app.get("/api/events")
def events():
    """
    Server-Sent Events stream for real-time auto-diagnosis notifications.

    Clients receive an initial ``connected`` keepalive and then
    ``auto_diagnosis`` events whenever the background poller detects a
    failed systemd service and obtains an AI diagnosis.

    Event format::

        event: auto_diagnosis
        data: {"instance": "...", "issue": "...", "diagnosis": "...",
               "fix_steps": [...], "source": "new"|"cache", "timestamp": "..."}
    """
    return Response(
        stream_with_context(_sse_stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── Background service poller ──────────────────────────────────────────────────

def _get_failed_services() -> list:
    """Return names of failed systemd units; returns [] if systemctl is absent."""
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--state=failed", "--no-legend", "--plain"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        services = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if parts:
                services.append(parts[0])
        return services
    except Exception:  # noqa: BLE001
        return []


def _poll_failed_services() -> None:
    """
    Background daemon thread: every 60 s check for failed systemd services,
    auto-diagnose new ones via OpenAI, and broadcast ``auto_diagnosis`` SSE
    events to all connected clients.
    """
    instance = os.environ.get("AGENT_INSTANCE", "localhost")
    while True:
        time.sleep(60)
        failed = _get_failed_services()
        for service in failed:
            issue = f"systemd service '{service}' is in a failed state"
            fp = _fingerprint(instance, issue)
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

            # Use a direct connection – this runs outside a Flask request context.
            with sqlite3.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT * FROM knowledge WHERE fingerprint = ? LIMIT 1", (fp,)
                ).fetchone()

            if row is not None:
                # Already diagnosed – broadcast the cached result.
                fix_steps = []
                if row["fix_steps"]:
                    try:
                        fix_steps = json.loads(row["fix_steps"])
                    except (json.JSONDecodeError, TypeError):
                        fix_steps = []
                _broadcast(
                    "auto_diagnosis",
                    {
                        "instance": instance,
                        "issue": issue,
                        "diagnosis": row["diagnosis"],
                        "fix_steps": fix_steps,
                        "source": "cache",
                        "timestamp": now,
                    },
                )
            else:
                try:
                    ai_result = _call_openai(instance, issue)
                except Exception:  # noqa: BLE001
                    logging.exception(
                        "Auto-diagnosis failed for service=%s", service
                    )
                    continue

                diagnosis = ai_result["diagnosis"]
                fix_steps = ai_result["fix_steps"]

                with sqlite3.connect(DB_PATH) as conn:
                    conn.execute(
                        """
                        INSERT INTO knowledge
                            (instance, issue, diagnosis, fingerprint,
                             fix_steps, seen_count, last_seen)
                        VALUES (?, ?, ?, ?, ?, 1, ?)
                        """,
                        (
                            instance,
                            issue,
                            diagnosis,
                            fp,
                            json.dumps(fix_steps),
                            now,
                        ),
                    )
                    conn.commit()

                _broadcast(
                    "auto_diagnosis",
                    {
                        "instance": instance,
                        "issue": issue,
                        "diagnosis": diagnosis,
                        "fix_steps": fix_steps,
                        "source": "new",
                        "timestamp": now,
                    },
                )


# ── Startup ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    # Start the background poller only in the process that actually serves
    # requests.  When debug/reloader is active, werkzeug sets WERKZEUG_RUN_MAIN
    # to "true" in the child; the parent (file-watcher) must not start the
    # thread so it isn't duplicated after a reload.
    if not debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        poller = threading.Thread(
            target=_poll_failed_services,
            daemon=True,
            name="service-poller",
        )
        poller.start()
    app.run(debug=debug, host="0.0.0.0", port=5000)
