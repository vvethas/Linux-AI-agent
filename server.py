"""
Linux AI Agent – Flask server
Provides a SQLite-backed knowledge base and three API endpoints.
"""

import sqlite3
import os
from flask import Flask, g, jsonify, request

app = Flask(__name__)

DB_PATH = os.environ.get("DB_PATH", "knowledge_base.db")

# ── Database helpers ───────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    """Return the per-request database connection, opening it if needed."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create database tables on first run (idempotent)."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS knowledge (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                instance    TEXT    NOT NULL,
                issue       TEXT    NOT NULL,
                diagnosis   TEXT    NOT NULL,
                confirmed   INTEGER NOT NULL DEFAULT 0,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.post("/api/diagnose")
def diagnose():
    """
    Stub diagnosis endpoint.

    Expected JSON body:
        { "instance": "<hostname>", "issue": "<description>" }

    Returns a placeholder diagnosis and persists it as an unconfirmed row so
    the caller can later confirm it via POST /api/diagnose/confirm.
    """
    body = request.get_json(silent=True) or {}
    instance = (body.get("instance") or "").strip()
    issue = (body.get("issue") or "").strip()

    if not instance or not issue:
        return jsonify({"error": "Both 'instance' and 'issue' are required."}), 400

    # Placeholder diagnosis – real AI logic will replace this later.
    diagnosis = (
        f"[STUB] Preliminary analysis for '{issue}' on {instance}: "
        "no anomalies detected by automated scan. Manual review recommended."
    )

    db = get_db()
    cursor = db.execute(
        "INSERT INTO knowledge (instance, issue, diagnosis) VALUES (?, ?, ?)",
        (instance, issue, diagnosis),
    )
    db.commit()
    row_id = cursor.lastrowid

    return jsonify(
        {
            "id": row_id,
            "instance": instance,
            "issue": issue,
            "diagnosis": diagnosis,
            "confirmed": False,
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


# ── Startup ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug, host="0.0.0.0", port=5000)
