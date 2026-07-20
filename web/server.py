import sys
import os
import logging

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Ensure the project root is on the path when running web/server.py directly
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import hashlib
import json
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from flask import Flask, Response, jsonify, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from openai import OpenAI as _OpenAIClient
    _openai = _OpenAIClient(api_key=os.getenv("OPENAI_API_KEY", ""))
except Exception:
    _openai = None

from agent.core import ClaudeClient
from agent.crypto_utils import (
    encrypt_value,
    decrypt_value,
    ssh_key_fingerprint,
    validate_master_key,
)
from agent.db import Database
from agent.notify import Notifier
from agent.replicate import Replicator
from agent.report import generate_study_html
from agent.scheduler import HealthScheduler
from agent.ssh import SSHManager
from agent.study import StudyRunner
from web.auth import init_auth, require_permission

# Hard-fail on startup if the master encryption key is absent.
validate_master_key()

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

KB_DB = DATA_DIR / "knowledge_base.db"


def _kb_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(KB_DB))
    conn.row_factory = sqlite3.Row
    return conn


def _kb_setup() -> None:
    with _kb_conn() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS knowledge_base (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT UNIQUE NOT NULL,
            instance_id TEXT NOT NULL,
            instance_host TEXT,
            problem TEXT NOT NULL,
            diagnosis TEXT NOT NULL,
            fix_steps TEXT NOT NULL,
            seen_count INTEGER DEFAULT 1,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            fix_confirmed INTEGER DEFAULT 0
        )""")
        conn.commit()


_kb_setup()

app = Flask(__name__, template_folder=str(BASE_DIR / "web" / "templates"))

db = Database(str(DATA_DIR / "agent.db"))
ssh = SSHManager()
claude = ClaudeClient()
study_runner = StudyRunner(db, ssh, claude)
notifier = Notifier(db)
replicator = Replicator(db, ssh, claude)
scheduler = HealthScheduler(db, ssh, study_runner, notifier)

# Initialise session-based auth (sets secret_key, registers before_request)
init_auth(app, db)

# Seed the default admin account if no users exist yet
db.seed_default_admin()

# In-memory job sessions: {job_id: {plan, history, instance_id, type, started}}
sessions: Dict[int, Dict[str, Any]] = {}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _err(message: str, status: int = 400):
    # Avoid exposing raw exception details to callers
    return jsonify({"error": message}), status


def _safe_err(exc: Exception, status: int = 500):
    """Return a sanitized error — never leak raw stack-trace text to clients."""
    return jsonify({"error": "An internal error occurred. Check server logs."}), status


def _enrich_instance(instance: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Attach the ``_ssh_key`` record (from *ssh_keys* table) for paste/upload instances."""
    if instance is None:
        return None
    if instance.get("auth_type") in ("key_paste", "key_upload"):
        instance["_ssh_key"] = db.get_ssh_key(instance["id"])
    return instance


def _safe_instance_for_api(instance: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Return a copy of *instance* safe to send to the browser (no raw credentials)."""
    if instance is None:
        return None
    out = {k: v for k, v in instance.items() if k not in ("password", "_ssh_key")}
    if instance.get("auth_type") in ("key_paste", "key_upload"):
        key_rec = db.get_ssh_key(instance["id"])
        out["key_fingerprint"] = key_rec["key_fingerprint"] if key_rec else None
        out.pop("key_path", None)
    return out


def _get_instance(instance_id: int) -> Optional[Dict[str, Any]]:
    return _enrich_instance(db.get_instance(instance_id))


def _safe_dumps(value: Any) -> str:
    try:
        return json.dumps(value, default=str)
    except Exception:
        return str(value)


# ── UI ────────────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/invite/<token>")
def invite_page(token: str):
    user = db.get_user_by_invite_token(token)
    if not user:
        return render_template("index.html")
    # Render the same SPA; JS detects ?invite=<token> and shows the set-password form
    return render_template("index.html")


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.route("/api/auth/me", methods=["GET"])
def auth_me():
    from flask import g as _g
    role = _g.get("user_role")
    if role is None:
        return jsonify({"authenticated": False}), 401
    user = _g.get("current_user")
    return jsonify({
        "authenticated": True,
        "user": {
            "id": user["id"] if user else None,
            "name": user["name"] if user else "admin",
            "email": user["email"] if user else "",
        },
        "role": role,
        "must_change_password": bool(_g.get("must_change_password")),
    })


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    payload = request.get_json(force=True) or {}
    email = str(payload.get("email", "")).strip().lower()
    password = str(payload.get("password", ""))
    if not email or not password:
        return _err("email and password are required")
    user = db.get_user_by_email(email)
    if not user or user.get("status") != "active":
        return _err("Invalid credentials", 401)
    if not user.get("password_hash"):
        return _err("Invalid credentials", 401)
    if not check_password_hash(user["password_hash"], password):
        return _err("Invalid credentials", 401)
    session.clear()
    session["user_id"] = user["id"]
    role_name = ""
    if user.get("role_id"):
        role = db.get_role(user["role_id"])
        role_name = role["name"] if role else ""
    else:
        groups = db.get_user_groups(user["id"])
        for grp in groups:
            r = db.get_role(grp["role_id"])
            if r:
                role_name = r["name"]
                break
    must_change = bool(user.get("must_change_password"))
    return jsonify({"ok": True, "role": role_name, "name": user["name"],
                    "must_change_password": must_change})


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/auth/set_password", methods=["POST"])
def auth_set_password():
    """Accept an invite: validate token, set password, activate account."""
    payload = request.get_json(force=True) or {}
    token = str(payload.get("token", ""))
    password = str(payload.get("password", ""))
    if not token or not password:
        return _err("token and password are required")
    if len(password) < 8:
        return _err("password must be at least 8 characters")
    user = db.get_user_by_invite_token(token)
    if not user:
        return _err("Invalid or expired invite token", 404)
    db.set_user_password(user["id"], generate_password_hash(password))
    session.clear()
    session["user_id"] = user["id"]
    return jsonify({"ok": True, "name": user["name"]})


@app.route("/api/auth/change_password", methods=["POST"])
def auth_change_password():
    """Forced password change for accounts with must_change_password=1.

    Requires an active session.  Sets the new password and clears the
    must_change_password flag so normal access is restored.
    """
    from flask import g as _g
    user = _g.get("current_user")
    if not user:
        return _err("Authentication required", 401)
    payload = request.get_json(force=True) or {}
    password = str(payload.get("password", ""))
    if not password:
        return _err("password is required")
    if len(password) < 8:
        return _err("password must be at least 8 characters")
    db.set_user_password(user["id"], generate_password_hash(password))
    return jsonify({"ok": True})


@app.route("/api/auth/change_my_password", methods=["POST"])
def auth_change_my_password():
    """Self-service password change: any logged-in user can change their own
    password by providing their current password and a new one."""
    from flask import g as _g
    user = _g.get("current_user")
    if not user:
        return _err("Authentication required", 401)
    payload = request.get_json(force=True) or {}
    current_password = str(payload.get("current_password", ""))
    new_password = str(payload.get("new_password", ""))
    if not current_password or not new_password:
        return _err("current_password and new_password are required")
    if len(new_password) < 8:
        return _err("new password must be at least 8 characters")
    if not user.get("password_hash"):
        return _err("account has no password set — use invite link", 400)
    if not check_password_hash(user["password_hash"], current_password):
        return _err("current password is incorrect", 403)
    db.set_user_password(user["id"], generate_password_hash(new_password))
    log.info("Self-service password change: user '%s' (id=%s)", user["name"], user["id"])
    return jsonify({"ok": True})


# ── User management (Admin only) ──────────────────────────────────────────────

@app.route("/api/roles", methods=["GET"])
@require_permission("view")
def list_roles():
    return jsonify({"roles": db.list_roles()})


@app.route("/api/users", methods=["GET"])
@require_permission("manage_users")
def list_users():
    users = db.list_users()
    # Strip password_hash from response
    for u in users:
        u.pop("password_hash", None)
        u.pop("invite_token", None)
    return jsonify({"users": users})


@app.route("/api/users", methods=["POST"])
@require_permission("manage_users")
def create_user():
    payload = request.get_json(force=True) or {}
    name = str(payload.get("name", "")).strip()
    email = str(payload.get("email", "")).strip().lower()
    assign_type = str(payload.get("assign_type", ""))  # "role" | "group"
    role_id = payload.get("role_id")
    group_id = payload.get("group_id")

    if not name or not email:
        return _err("name and email are required")
    if assign_type not in ("role", "group"):
        return _err("assign_type must be 'role' or 'group'")
    if assign_type == "role" and not role_id:
        return _err("role_id required when assign_type is 'role'")
    if assign_type == "group" and not group_id:
        return _err("group_id required when assign_type is 'group'")

    # Check email uniqueness
    if db.get_user_by_email(email):
        return _err("a user with that email already exists")

    direct_role_id = int(role_id) if assign_type == "role" else None
    try:
        user_id, token = db.create_user(name, email, role_id=direct_role_id)
    except Exception as exc:
        log.exception("create_user error")
        return _safe_err(exc)

    if assign_type == "group":
        db.add_group_member(int(group_id), user_id)

    invite_url = f"/invite/{token}"
    return jsonify({"user_id": user_id, "invite_url": invite_url}), 201


@app.route("/api/users/<int:user_id>", methods=["PUT"])
@require_permission("manage_users")
def edit_user(user_id: int):
    payload = request.get_json(force=True) or {}
    user = db.get_user(user_id)
    if not user:
        return _err("user not found", 404)

    assign_type = str(payload.get("assign_type", ""))
    role_id = payload.get("role_id")
    group_id = payload.get("group_id")
    name = str(payload.get("name", user["name"])).strip()
    email = str(payload.get("email", user["email"])).strip().lower()

    if assign_type not in ("role", "group", ""):
        return _err("assign_type must be 'role' or 'group'")

    # Remove from all current groups first
    for grp in db.get_user_groups(user_id):
        db.remove_group_member(grp["id"], user_id)

    direct_role = None
    if assign_type == "role":
        if not role_id:
            return _err("role_id required when assign_type is 'role'")
        direct_role = int(role_id)
    elif assign_type == "group":
        if not group_id:
            return _err("group_id required when assign_type is 'group'")
        db.add_group_member(int(group_id), user_id)

    db.update_user(user_id, name=name, email=email, role_id=direct_role)
    updated = db.get_user(user_id)
    if updated:
        updated.pop("password_hash", None)
        updated.pop("invite_token", None)
    return jsonify({"user": updated})


@app.route("/api/users/<int:user_id>/disable", methods=["POST"])
@require_permission("manage_users")
def disable_user(user_id: int):
    user = db.get_user(user_id)
    if not user:
        return _err("user not found", 404)
    db.update_user(user_id, status="disabled")
    return jsonify({"ok": True})


@app.route("/api/users/<int:user_id>/resend_invite", methods=["POST"])
@require_permission("manage_users")
def resend_invite(user_id: int):
    user = db.get_user(user_id)
    if not user:
        return _err("user not found", 404)
    token = db.regenerate_invite_token(user_id)
    invite_url = f"/invite/{token}"
    return jsonify({"invite_url": invite_url})


@app.route("/api/users/<int:user_id>/reset_password", methods=["POST"])
@require_permission("manage_users")
def reset_user_password(user_id: int):
    """Admin-triggered password reset: generate a random temporary password,
    set must_change_password=true so user is forced to choose their own."""
    from flask import g as _g
    user = db.get_user(user_id)
    if not user:
        return _err("user not found", 404)
    # Generate a secure random temporary password
    temp_password = secrets.token_urlsafe(12)
    db.update_user(
        user_id,
        password_hash=generate_password_hash(temp_password),
        must_change_password=1,
        status="active",
    )
    admin = _g.get("current_user")
    admin_name = admin["name"] if admin else "unknown"
    log.info(
        "Password reset: admin '%s' (id=%s) reset password for user '%s' (id=%s)",
        admin_name, admin.get("id") if admin else "?", user["name"], user_id,
    )
    return jsonify({"ok": True, "temporary_password": temp_password})


# ── Group management (Admin only) ─────────────────────────────────────────────

@app.route("/api/groups", methods=["GET"])
@require_permission("manage_users")
def list_groups():
    return jsonify({"groups": db.list_groups()})


@app.route("/api/groups", methods=["POST"])
@require_permission("manage_users")
def create_group():
    payload = request.get_json(force=True) or {}
    name = str(payload.get("name", "")).strip()
    role_id = payload.get("role_id")
    if not name or not role_id:
        return _err("name and role_id are required")
    try:
        group_id = db.create_group(name, int(role_id))
    except Exception as exc:
        log.exception("create_group error")
        return _safe_err(exc)
    return jsonify({"group": db.get_group(group_id)}), 201


@app.route("/api/groups/<int:group_id>", methods=["PUT"])
@require_permission("manage_users")
def edit_group(group_id: int):
    group = db.get_group(group_id)
    if not group:
        return _err("group not found", 404)
    payload = request.get_json(force=True) or {}
    fields: Dict[str, Any] = {}
    if "name" in payload:
        fields["name"] = str(payload["name"]).strip()
    if "role_id" in payload:
        fields["role_id"] = int(payload["role_id"])
    db.update_group(group_id, **fields)
    return jsonify({"group": db.get_group(group_id)})


@app.route("/api/groups/<int:group_id>", methods=["DELETE"])
@require_permission("manage_users")
def delete_group(group_id: int):
    db.delete_group(group_id)
    return jsonify({"ok": True})


@app.route("/api/groups/<int:group_id>/members", methods=["GET"])
@require_permission("manage_users")
def group_members(group_id: int):
    return jsonify({"members": db.get_group_members(group_id)})


@app.route("/api/groups/<int:group_id>/members", methods=["POST"])
@require_permission("manage_users")
def add_group_member(group_id: int):
    payload = request.get_json(force=True) or {}
    user_id = payload.get("user_id")
    if not user_id:
        return _err("user_id is required")
    if not db.get_group(group_id):
        return _err("group not found", 404)
    if not db.get_user(int(user_id)):
        return _err("user not found", 404)
    db.add_group_member(group_id, int(user_id))
    return jsonify({"ok": True})


@app.route("/api/groups/<int:group_id>/members/<int:user_id>", methods=["DELETE"])
@require_permission("manage_users")
def remove_group_member(group_id: int, user_id: int):
    db.remove_group_member(group_id, user_id)
    return jsonify({"ok": True})


# ── Instances ─────────────────────────────────────────────────────────────────

@app.route("/api/instances", methods=["POST"])
@require_permission("manage_instances")
def add_instance():
    payload = request.get_json(force=True) or {}
    for field in ("label", "host", "username", "auth_type"):
        if not payload.get(field):
            return _err(f"missing required field: {field}")

    auth_type = payload["auth_type"]
    if auth_type not in ("key", "key_paste", "key_upload", "password"):
        return _err("invalid auth_type")

    # ── Validate & fingerprint the key before persisting anything ─────────────
    key_pem: Optional[str] = None
    passphrase: Optional[str] = payload.get("passphrase") or None
    fingerprint: Optional[str] = None

    if auth_type in ("key_paste", "key_upload"):
        key_pem = (payload.get("key_content") or "").strip()
        if not key_pem:
            return _err("key_content is required for auth_type key_paste / key_upload")
        try:
            fingerprint = ssh_key_fingerprint(key_pem, passphrase)
        except ValueError as exc:
            return _err(f"Invalid private key: {exc}")

    # ── Build a temporary instance dict to test the connection first ──────────
    test_instance: Dict[str, Any] = {
        "host": payload["host"],
        "port": int(payload.get("port", 22)),
        "username": payload["username"],
        "auth_type": auth_type,
        "key_path": payload.get("key_path"),
        "password": payload.get("password"),
    }
    if key_pem:
        test_instance["_ssh_key"] = {
            "encrypted_key_blob": encrypt_value(key_pem),
            "passphrase_encrypted": encrypt_value(passphrase) if passphrase else None,
        }

    ok, reason = ssh.test_connection(test_instance)
    if not ok:
        # Log the full reason server-side; never send raw exception text to callers.
        log.warning("SSH test failed for %s: %s", payload.get("host"), reason)
        return jsonify({
            "ssh_test": {"ok": False},
            "error": "SSH connection test failed — check host, port, and credentials (see server logs for details)",
        }), 422

    # ── Persist only after a successful test ──────────────────────────────────
    db_payload = {
        "label": payload["label"],
        "host": payload["host"],
        "port": int(payload.get("port", 22)),
        "username": payload["username"],
        "auth_type": auth_type,
        "tags": payload.get("tags", []),
    }
    if auth_type == "key":
        db_payload["key_path"] = payload.get("key_path")
    elif auth_type == "password":
        db_payload["password"] = payload.get("password")
    # key_paste / key_upload: key_path and password intentionally omitted

    iid = db.add_instance(db_payload)

    if key_pem and fingerprint:
        db.store_ssh_key(
            iid,
            encrypted_key_blob=encrypt_value(key_pem),
            key_fingerprint=fingerprint,
            passphrase_encrypted=encrypt_value(passphrase) if passphrase else None,
        )

    db.update_instance_status(iid, "online")
    return jsonify({
        "instance": _safe_instance_for_api(db.get_instance(iid)),
        "ssh_test": {"ok": True, "reason": "ok"},
    })


@app.route("/api/instances", methods=["GET"])
@require_permission("view")
def list_instances():
    raw = db.list_instances()
    return jsonify({"instances": [_safe_instance_for_api(i) for i in raw]})


@app.route("/api/instances/<int:instance_id>", methods=["DELETE"])
@require_permission("manage_instances")
def delete_instance(instance_id: int):
    db.delete_instance(instance_id)
    scheduler.remove_schedule(instance_id)
    return jsonify({"ok": True})


@app.route("/api/instances/<int:instance_id>/test", methods=["POST"])
@require_permission("run_diagnostics")
def test_instance(instance_id: int):
    instance = _get_instance(instance_id)
    if not instance:
        return _err("instance not found", 404)
    ok, reason = ssh.test_connection(instance)
    db.update_instance_status(instance_id, "online" if ok else "auth_error")
    if ok:
        notifier.resolve_instance_reachable(instance_id)
    else:
        notifier.notify_instance_down(instance, reason)
    return jsonify({"ok": ok, "reason": reason})


@app.route("/api/instances/<int:instance_id>/diagnostics", methods=["GET"])
@require_permission("run_diagnostics")
def instance_diagnostics(instance_id: int):
    instance = _get_instance(instance_id)
    if not instance:
        return _err("instance not found", 404)
    try:
        return jsonify({"diagnostics": ssh.collect_diagnostics(instance)})
    except Exception as exc:
        log.exception("Internal error"); return _safe_err(exc, 500)


@app.route("/api/instances/<int:instance_id>/study", methods=["POST"])
@require_permission("run_diagnostics")
def run_study(instance_id: int):
    instance = _get_instance(instance_id)
    if not instance:
        return _err("instance not found", 404)
    try:
        result = study_runner.run(instance)
        job_id = db.create_job(
            instance_id,
            "study",
            f"Study {instance['label']}",
            status="completed",
            plan_json=result["report"],
        )
        db.update_job(job_id, status="completed", result="study complete")
        notifier.notify_study_complete(instance, result["report"])
        return jsonify(result)
    except Exception as exc:
        log.exception("Internal error"); return _safe_err(exc, 500)


# ── Schedule ──────────────────────────────────────────────────────────────────

@app.route("/api/instances/<int:instance_id>/schedule", methods=["GET"])
@require_permission("view")
def get_schedule(instance_id: int):
    return jsonify({"schedule": db.get_schedule(instance_id)})


@app.route("/api/instances/<int:instance_id>/schedule", methods=["POST"])
@require_permission("manage_instances")
def set_schedule(instance_id: int):
    payload = request.get_json(force=True) or {}
    mode = str(payload.get("mode", "interval"))
    interval_hours = payload.get("interval_hours")
    cron_expr = payload.get("cron_expr")
    enabled = bool(payload.get("enabled", True))
    db.set_schedule(instance_id, enabled, mode, interval_hours, cron_expr)
    scheduler.apply_schedule(instance_id)
    return jsonify({"schedule": db.get_schedule(instance_id)})


@app.route("/api/instances/<int:instance_id>/schedule", methods=["DELETE"])
@require_permission("manage_instances")
def del_schedule(instance_id: int):
    db.delete_schedule(instance_id)
    scheduler.remove_schedule(instance_id)
    return jsonify({"ok": True})


@app.route("/api/instances/<int:instance_id>/trigger", methods=["POST"])
@require_permission("run_diagnostics")
def trigger_check(instance_id: int):
    instance = _get_instance(instance_id)
    if not instance:
        return _err("instance not found", 404)
    scheduler.trigger_manual(instance_id)
    return jsonify({"ok": True, "message": "triggered in background"})


@app.route("/api/instances/<int:instance_id>/check_log", methods=["GET"])
@require_permission("view")
def check_log(instance_id: int):
    return jsonify({"entries": db.get_check_log(instance_id)})


# ── Dashboard ─────────────────────────────────────────────────────────────────

def _disk_forecast(history: list) -> Optional[str]:
    """Linear regression to estimate days until disk reaches 90%.

    *history* is a list of dicts with keys ``value`` (float) and
    ``recorded_at`` (ISO-8601 string), ordered oldest-first.
    Returns a human-readable string like ``"~3d to 90%"`` or ``None``
    if there is not enough data or the trend is flat/declining.
    """
    if len(history) < 2:
        return None
    n = len(history)
    try:
        # Use the position index as x; value as y
        sx = sum(range(n))
        sy = sum(p["value"] for p in history)
        sxx = sum(i * i for i in range(n))
        sxy = sum(i * history[i]["value"] for i in range(n))
        denom = n * sxx - sx * sx
        if denom == 0:
            return None
        slope = (n * sxy - sx * sy) / denom
        if slope <= 0:
            return None  # flat or declining
        intercept = (sy - slope * sx) / n
        # How many steps until we hit 90?
        current = intercept + slope * (n - 1)
        if current >= 90:
            return None
        steps_to_90 = (90 - intercept) / slope
        remaining_steps = steps_to_90 - (n - 1)
        if remaining_steps <= 0:
            return None
        # Estimate the step interval from timestamps
        try:
            from datetime import datetime as _dt
            t0 = _dt.fromisoformat(history[0]["recorded_at"].replace("Z", "+00:00"))
            t1 = _dt.fromisoformat(history[-1]["recorded_at"].replace("Z", "+00:00"))
            elapsed_hours = (t1 - t0).total_seconds() / 3600
            step_hours = elapsed_hours / (n - 1) if n > 1 else 6
        except Exception:
            step_hours = 6
        remaining_hours = remaining_steps * step_hours
        days = remaining_hours / 24
        if days > 365:
            return None
        if days < 1:
            return "<1d to 90%"
        return f"~{int(days)}d to 90%"
    except Exception:
        return None


@app.route("/api/dashboard", methods=["GET"])
@require_permission("view")
def dashboard():
    instances = db.list_instances()
    studies = db.list_studies()

    latest_by_instance: Dict[int, Dict[str, Any]] = {}
    for s in studies:
        iid = s["instance_id"]
        if iid not in latest_by_instance:
            latest_by_instance[iid] = s

    scores = []
    tiles = []
    for inst in instances:
        study = latest_by_instance.get(inst["id"], {})
        report = study.get("report_json", {}) if study else {}
        score = int((report.get("summary") or {}).get("health_score", 0) or 0)
        if score:
            scores.append(score)

        iid = inst["id"]

        # Sparklines: last 24h of data for cpu, mem, disk
        sparklines: Dict[str, Any] = {}
        for metric in ("cpu", "mem", "disk"):
            pts = db.get_metric_history(iid, metric, hours=24)
            sparklines[metric] = [
                {"value": p["value"], "ts": p["recorded_at"]} for p in pts
            ]

        # Disk forecast using regression over stored disk history
        disk_forecast = _disk_forecast(
            [{"value": p["value"], "recorded_at": p["ts"]} for p in sparklines["disk"]]
        )

        # Service chips: latest status per monitored service
        service_chips = [
            {"name": s["service_name"], "status": s["status"]}
            for s in db.get_latest_service_statuses(iid)
        ]

        # Cached AI insight (generated during poll, only if notable)
        insight_cfg = db.get_config_json(f"insight_{iid}", default={})
        ai_insight = insight_cfg.get("text") or None

        tiles.append({
            "instance": inst,
            "health_score": score,
            "role": (report.get("summary") or {}).get("role", "unknown"),
            "last_check": inst.get("last_seen"),
            "schedule": db.get_schedule(iid),
            "sparklines": sparklines,
            "disk_forecast": disk_forecast,
            "service_chips": service_chips,
            "ai_insight": ai_insight,
        })

    online = sum(1 for i in instances if i.get("last_status") == "online")
    avg_health = round(sum(scores) / len(scores), 1) if scores else 0
    activity = db.list_jobs()[:10]
    active_alerts = db.list_unresolved_alerts()

    return jsonify({
        "stats": {
            "total_instances": len(instances),
            "online_count": online,
            "offline_count": len(instances) - online,
            "avg_health_score": avg_health,
        },
        "tiles": tiles,
        "activity": activity,
        "active_alerts": active_alerts,
    })


# ── Monitoring (lightweight cached metrics for sidebar/polling) ───────────────

@app.route("/api/monitoring", methods=["GET"])
@require_permission("view")
def monitoring():
    """Return the most recent metric snapshot for every instance (DB-only, no SSH)."""
    instances = db.list_instances()
    result = []
    for inst in instances:
        iid = inst["id"]
        m = db.get_latest_metrics(iid)
        latest_svcs = db.get_latest_service_statuses(iid)
        result.append({
            "id": iid,
            "reachable": inst.get("last_status") == "online",
            "cpu_pct": m.get("cpu"),
            "mem_pct": m.get("mem"),
            "disk_pct": m.get("disk"),
            "services": [
                {"name": s["service_name"], "status": s["status"]}
                for s in latest_svcs
            ],
        })
    return jsonify({"instances": result})


# ── Metric history ────────────────────────────────────────────────────────────

@app.route("/api/instances/<int:instance_id>/metrics_history", methods=["GET"])
@require_permission("view")
def instance_metrics_history(instance_id: int):
    if not db.get_instance(instance_id):
        return _err("instance not found", 404)
    hours = int(request.args.get("hours", 24))
    metric = request.args.get("metric") or None
    rows = db.get_metric_history(instance_id, metric_name=metric, hours=hours)
    return jsonify({"history": rows})


# ── Monitored services CRUD ───────────────────────────────────────────────────

@app.route("/api/instances/<int:instance_id>/monitored_services", methods=["GET"])
@require_permission("view")
def list_monitored_services(instance_id: int):
    if not db.get_instance(instance_id):
        return _err("instance not found", 404)
    return jsonify({"services": db.list_monitored_services(instance_id)})


@app.route("/api/instances/<int:instance_id>/monitored_services", methods=["POST"])
@require_permission("manage_instances")
def add_monitored_service(instance_id: int):
    if not db.get_instance(instance_id):
        return _err("instance not found", 404)
    payload = request.get_json(force=True) or {}
    service_name = str(payload.get("service_name", "")).strip()
    if not service_name:
        return _err("service_name is required")
    sid = db.add_monitored_service(instance_id, service_name)
    return jsonify({"service": {"id": sid, "instance_id": instance_id, "service_name": service_name}}), 201


@app.route("/api/instances/<int:instance_id>/monitored_services/<int:service_id>", methods=["DELETE"])
@require_permission("manage_instances")
def remove_monitored_service(instance_id: int, service_id: int):
    if not db.get_instance(instance_id):
        return _err("instance not found", 404)
    db.remove_monitored_service(service_id, instance_id)
    return jsonify({"ok": True})


# ── Service status drill-down ─────────────────────────────────────────────────

@app.route("/api/instances/<int:instance_id>/service_history", methods=["GET"])
@require_permission("view")
def service_history(instance_id: int):
    if not db.get_instance(instance_id):
        return _err("instance not found", 404)
    service_name = request.args.get("service") or None
    period = request.args.get("period", "24h")
    period_map = {"1h": 1, "24h": 24, "7d": 168, "30d": 720}
    hours = period_map.get(period, 24)

    rows = db.get_service_status_history(instance_id, service_name=service_name, hours=hours)
    if not rows:
        return jsonify({
            "rows": [],
            "uptime_pct": None,
            "restart_count": 0,
            "longest_outage_sec": 0,
            "transitions": [],
        })

    # Compute summary stats
    total = len(rows)
    running_count = sum(1 for r in rows if r["status"] == "running")
    uptime_pct = round(running_count / total * 100, 1) if total else None

    # Restart count = number of failed→running transitions
    restart_count = 0
    transitions = []
    prev_status = None
    prev_ts = None
    outage_start = None
    outages = []
    for r in rows:
        st = r["status"]
        ts = r["recorded_at"]
        if prev_status is not None and st != prev_status:
            transitions.append({"from": prev_status, "to": st, "at": ts})
            if st == "running" and prev_status == "failed":
                restart_count += 1
                if outage_start is not None:
                    try:
                        from datetime import datetime as _dt
                        t0 = _dt.fromisoformat(outage_start.replace("Z", "+00:00"))
                        t1 = _dt.fromisoformat(ts.replace("Z", "+00:00"))
                        outages.append(int((t1 - t0).total_seconds()))
                    except Exception:
                        pass
                    outage_start = None
            elif st == "failed" and prev_status == "running":
                outage_start = ts
        prev_status = st
        prev_ts = ts

    # If still in failed state at end
    if prev_status == "failed" and outage_start is not None:
        import datetime as _dt_mod
        try:
            t0 = _dt_mod.datetime.fromisoformat(outage_start.replace("Z", "+00:00"))
            t1 = _dt_mod.datetime.now(_dt_mod.timezone.utc)
            outages.append(int((t1 - t0).total_seconds()))
        except Exception:
            pass

    longest_outage_sec = max(outages) if outages else 0

    return jsonify({
        "rows": rows,
        "uptime_pct": uptime_pct,
        "restart_count": restart_count,
        "longest_outage_sec": longest_outage_sec,
        "transitions": transitions,
    })




# ── Metric context for chat ───────────────────────────────────────────────────

@app.route("/api/instances/<int:instance_id>/metrics_context", methods=["GET"])
@require_permission("view")
def metrics_context(instance_id: int):
    """Return a compact text summary of recent metric+service history for chat injection."""
    if not db.get_instance(instance_id):
        return _err("instance not found", 404)
    lines = []
    for metric in ("cpu", "mem", "disk"):
        pts = db.get_metric_history(instance_id, metric, hours=24)
        if pts:
            vals = [f"{p['value']:.0f}" for p in pts[-8:]]
            lines.append(f"{metric.upper()} last 24h (%): {', '.join(vals)}")
    svc_rows = db.get_latest_service_statuses(instance_id)
    if svc_rows:
        svc_summary = ", ".join(f"{s['service_name']}={s['status']}" for s in svc_rows)
        lines.append(f"Monitored services: {svc_summary}")
    return jsonify({"context": "\n".join(lines)})


@app.route("/api/classify", methods=["POST"])
@require_permission("run_diagnostics")
def classify():
    payload = request.get_json(force=True) or {}
    text = str(payload.get("text", ""))
    if not text:
        return _err("missing text")
    try:
        intent = claude.classify_intent(text)
    except Exception as exc:
        log.exception("Internal error"); return _safe_err(exc, 500)
    return jsonify({"intent": intent})


# ── Troubleshoot ──────────────────────────────────────────────────────────────

@app.route("/api/diagnose/plan", methods=["POST"])
@require_permission("run_diagnostics")
def diagnose_plan():
    payload = request.get_json(force=True) or {}
    instance_id = payload.get("instance_id")
    if not instance_id:
        return _err("missing instance_id")
    instance = _get_instance(int(instance_id))
    if not instance:
        return _err("instance not found", 404)

    issue = str(payload.get("issue", ""))
    try:
        diagnostics = ssh.collect_diagnostics(instance)
        plan = claude.troubleshoot_plan(issue, diagnostics)
    except Exception as exc:
        log.exception("Internal error"); return _safe_err(exc, 500)

    title = f"Troubleshoot: {issue[:80]}" if issue else "Troubleshoot"
    job_id = db.create_job(
        int(instance_id), "troubleshoot", title, status="planned", plan_json=plan
    )
    sessions[job_id] = {
        "plan": plan,
        "history": [
            {"role": "user", "content": _safe_dumps({"issue": issue, "diagnostics": diagnostics})}
        ],
        "instance_id": int(instance_id),
        "type": "troubleshoot",
        "started": time.time(),
    }
    return jsonify({"job_id": job_id, "plan": plan, "diagnostics": diagnostics})


# ── AI diagnostic (OpenAI knowledge-base) ────────────────────────────────────

@app.route("/api/diagnose", methods=["POST"])
@require_permission("run_diagnostics")
def ai_diagnose():
    payload = request.get_json(force=True) or {}
    instance_id = str(payload.get("instance_id", ""))
    problem = str(payload.get("problem", ""))
    context = str(payload.get("context", ""))
    if not instance_id or not problem:
        return _err("missing instance_id or problem")

    fingerprint = hashlib.sha256((instance_id + problem).encode()).hexdigest()[:16]
    now = datetime.now(timezone.utc).isoformat()

    with _kb_conn() as conn:
        row = conn.execute(
            "SELECT * FROM knowledge_base WHERE fingerprint=?", (fingerprint,)
        ).fetchone()
        if row:
            new_count = row["seen_count"] + 1
            conn.execute(
                "UPDATE knowledge_base SET seen_count=?, last_seen=? WHERE fingerprint=?",
                (new_count, now, fingerprint),
            )
            conn.commit()
            return jsonify({
                "source": "cache",
                "fingerprint": fingerprint,
                "diagnosis": row["diagnosis"],
                "fix_steps": json.loads(row["fix_steps"]),
                "seen_count": new_count,
                "last_seen": now,
            })

    if not _openai:
        return _err("OpenAI not configured", 503)

    try:
        resp = _openai.chat.completions.create(
            model="gpt-4o",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a Linux systems diagnostic expert. "
                        "Respond with JSON containing exactly two keys: "
                        "\"diagnosis\" (a concise string) and "
                        "\"fix_steps\" (an array of action strings)."
                    ),
                },
                {
                    "role": "user",
                    "content": f"Instance: {instance_id}\nProblem: {problem}\nContext: {context}",
                },
            ],
            response_format={"type": "json_object"},
            temperature=0.2,
        )
        result = json.loads(resp.choices[0].message.content)
    except Exception as exc:
        log.exception("OpenAI error")
        return _safe_err(exc, 503)

    diagnosis = str(result.get("diagnosis", ""))
    fix_steps = list(result.get("fix_steps", []))

    instance = _get_instance(int(instance_id)) if instance_id.isdigit() else None
    with _kb_conn() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO knowledge_base
               (fingerprint, instance_id, instance_host, problem, diagnosis,
                fix_steps, seen_count, first_seen, last_seen, fix_confirmed)
               VALUES (?,?,?,?,?,?,1,?,?,0)""",
            (
                fingerprint, instance_id,
                instance["host"] if instance else None,
                problem, diagnosis, json.dumps(fix_steps), now, now,
            ),
        )
        conn.commit()

    return jsonify({
        "source": "new",
        "fingerprint": fingerprint,
        "diagnosis": diagnosis,
        "fix_steps": fix_steps,
        "seen_count": 1,
        "last_seen": now,
    })


@app.route("/api/diagnose/confirm", methods=["POST"])
@require_permission("run_diagnostics")
def ai_diagnose_confirm():
    payload = request.get_json(force=True) or {}
    fingerprint = str(payload.get("fingerprint", ""))
    if not fingerprint:
        return _err("missing fingerprint")
    with _kb_conn() as conn:
        conn.execute(
            "UPDATE knowledge_base SET fix_confirmed=1 WHERE fingerprint=?",
            (fingerprint,),
        )
        conn.commit()
    return jsonify({"ok": True})


@app.route("/api/knowledge", methods=["GET"])
@require_permission("view")
def knowledge_base_list():
    with _kb_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM knowledge_base ORDER BY last_seen DESC"
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/events", methods=["GET"])
@require_permission("view")
def sse_events():
    def generate():
        while True:
            time.sleep(15)
            yield "event: ping\ndata: {}\n\n"
    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )



def execute_step():
    payload = request.get_json(force=True) or {}
    job_id = payload.get("job_id")
    if not job_id:
        return _err("missing job_id")
    job_id = int(job_id)

    job = db.get_job(job_id)
    if not job:
        return _err("job not found", 404)

    instance_id = int(payload.get("instance_id") or job.get("instance_id") or 0)
    if not instance_id:
        return _err("missing instance_id")
    instance = _get_instance(instance_id)
    if not instance:
        return _err("instance not found", 404)

    step = payload.get("step") or {}
    phase = str(payload.get("phase", "main"))

    outputs = []
    success = True
    for cmd in step.get("commands", []):
        result = ssh.execute(instance, str(cmd), timeout=600)
        outputs.append(result)
        if not result["success"]:
            success = False
            break

    summary: Dict[str, Any] = {}
    try:
        summary = claude.summarize_execution(
            step,
            {"outputs": outputs, "success": success},
            history=sessions.get(job_id, {}).get("history"),
        )
    except Exception:
        summary = {"status": "unknown", "summary": "summary unavailable", "next_action": "review output"}

    db.add_job_step(
        job_id,
        phase,
        str(step.get("id", "step")),
        str(step.get("title", "step")),
        list(step.get("commands", [])),
        _safe_dumps({"outputs": outputs, "summary": summary}),
        success,
    )

    is_final = bool(payload.get("final", False))
    new_status = ("completed" if success else "failed") if is_final else ("running" if success else "failed")
    updates: Dict[str, Any] = {"status": new_status}
    if is_final:
        started = sessions.get(job_id, {}).get("started")
        updates["duration_sec"] = int(time.time() - started) if started else None
        updates["result"] = str(summary.get("summary", "done"))
        instance_data = db.get_instance(instance_id) or {}
        notifier.notify_job_complete(instance_data, db.get_job(job_id) or {"id": job_id, "status": new_status, "type": job.get("type")})
    db.update_job(job_id, **updates)

    return jsonify({"success": success, "outputs": outputs, "summary": summary, "job_status": new_status})


@app.route("/api/verify", methods=["POST"])
@require_permission("run_diagnostics")
def verify_fix():
    payload = request.get_json(force=True) or {}
    instance_id = payload.get("instance_id")
    command = payload.get("command")
    if not instance_id or not command:
        return _err("missing instance_id or command")
    instance = _get_instance(int(instance_id))
    if not instance:
        return _err("instance not found", 404)
    result = ssh.execute(instance, str(command), timeout=180)
    return jsonify({"verification": result})


# ── Build ─────────────────────────────────────────────────────────────────────

@app.route("/api/build/plan", methods=["POST"])
@require_permission("manage_instances")
def build_plan():
    payload = request.get_json(force=True) or {}
    instance_id = payload.get("instance_id")
    if not instance_id:
        return _err("missing instance_id")
    instance = _get_instance(int(instance_id))
    if not instance:
        return _err("instance not found", 404)

    request_text = str(payload.get("request", ""))
    try:
        specs = ssh.collect_specs(instance)
        plan = claude.build_plan(request_text, specs)
    except Exception as exc:
        log.exception("Internal error"); return _safe_err(exc, 500)

    title = f"Build: {request_text[:80]}" if request_text else "Build"
    job_id = db.create_job(
        int(instance_id), "build", title, status="planned", plan_json=plan, specs_json=specs
    )
    sessions[job_id] = {
        "plan": plan,
        "history": [
            {"role": "user", "content": _safe_dumps({"request": request_text, "specs": specs})}
        ],
        "instance_id": int(instance_id),
        "type": "build",
        "started": time.time(),
    }
    return jsonify({"job_id": job_id, "specs": specs, "plan": plan})


@app.route("/api/build/execute_step", methods=["POST"])
@require_permission("manage_instances")
def build_execute_step():
    return execute_step()


@app.route("/api/build/post_install", methods=["POST"])
@require_permission("manage_instances")
def build_post_install():
    payload = request.get_json(force=True) or {}
    instance_id = payload.get("instance_id")
    if not instance_id:
        return _err("missing instance_id")
    instance = _get_instance(int(instance_id))
    if not instance:
        return _err("instance not found", 404)
    commands = list(payload.get("commands", []))
    results = [ssh.execute(instance, str(cmd), timeout=240) for cmd in commands]
    return jsonify({"results": results})


# ── Jobs ──────────────────────────────────────────────────────────────────────

@app.route("/api/jobs", methods=["GET"])
@require_permission("view")
def list_jobs():
    instance_id = request.args.get("instance_id")
    job_type = request.args.get("type")
    data = db.list_jobs(
        instance_id=int(instance_id) if instance_id else None,
        job_type=job_type,
    )
    return jsonify({"jobs": data})


@app.route("/api/jobs/<int:job_id>", methods=["GET"])
@require_permission("view")
def job_detail(job_id: int):
    job = db.get_job(job_id)
    if not job:
        return _err("job not found", 404)
    return jsonify(job)


@app.route("/api/jobs/<int:job_id>", methods=["DELETE"])
@require_permission("manage_instances")
def delete_job(job_id: int):
    db.delete_job(job_id)
    sessions.pop(job_id, None)
    return jsonify({"ok": True})


# ── Studies ───────────────────────────────────────────────────────────────────

@app.route("/api/studies", methods=["GET"])
@require_permission("view")
def list_studies():
    instance_id = request.args.get("instance_id")
    data = db.list_studies(instance_id=int(instance_id) if instance_id else None)
    return jsonify({"studies": data})


@app.route("/api/studies/<int:study_id>", methods=["GET"])
@require_permission("view")
def study_detail(study_id: int):
    study = db.get_study(study_id)
    if not study:
        return _err("study not found", 404)
    return jsonify(study)


@app.route("/api/studies/<int:study_id>/html", methods=["GET"])
@require_permission("view")
def study_html(study_id: int):
    study = db.get_study(study_id)
    if not study:
        return _err("study not found", 404)
    instance = db.get_instance(study["instance_id"])
    label = instance["label"] if instance else f"Instance {study['instance_id']}"
    html = generate_study_html(
        label,
        study.get("report_json") or {},
        study.get("created_at", ""),
    )
    return app.response_class(html, mimetype="text/html")


@app.route("/api/studies/<int:study_id>", methods=["DELETE"])
@require_permission("manage_instances")
def delete_study(study_id: int):
    db.delete_study(study_id)
    return jsonify({"ok": True})


# ── Replication ───────────────────────────────────────────────────────────────

@app.route("/api/replicate/plan", methods=["POST"])
@require_permission("manage_instances")
def replicate_plan():
    payload = request.get_json(force=True) or {}
    source_instance_id = payload.get("source_instance_id")
    target_instance_id = payload.get("target_instance_id")
    if not source_instance_id or not target_instance_id:
        return _err("missing source_instance_id or target_instance_id")

    source_study: Optional[Dict[str, Any]] = None
    if payload.get("study_id"):
        source_study = db.get_study(int(payload["study_id"]))
    if not source_study:
        source_study = db.latest_study_for_instance(int(source_instance_id))
    if not source_study:
        return _err("source study report not found — run a study on source instance first", 404)

    target_instance = _get_instance(int(target_instance_id))
    if not target_instance:
        return _err("target instance not found", 404)

    try:
        target_specs = ssh.collect_specs(target_instance)
        plan = replicator.generate_plan(
            source_study.get("report_json", {}), target_instance, target_specs
        )
    except Exception as exc:
        log.exception("Internal error"); return _safe_err(exc, 500)

    title = f"Replicate {source_instance_id} → {target_instance_id}"
    job_id = db.create_job(
        int(target_instance_id),
        "replicate",
        title,
        status="planned",
        plan_json=plan,
        specs_json=target_specs,
    )
    sessions[job_id] = {
        "plan": plan,
        "history": [],
        "instance_id": int(target_instance_id),
        "type": "replicate",
        "started": time.time(),
    }
    return jsonify({"job_id": job_id, "plan": plan, "target_specs": target_specs})


@app.route("/api/replicate/<int:job_id>/step", methods=["POST"])
@require_permission("manage_instances")
def replicate_step(job_id: int):
    payload = request.get_json(force=True) or {}
    job = db.get_job(job_id)
    if not job:
        return _err("replication job not found", 404)

    instance = _get_instance(int(job["instance_id"]))
    if not instance:
        return _err("instance not found", 404)

    step = payload.get("step", {})
    result = replicator.execute_step(instance, step)

    db.add_job_step(
        job_id,
        str(payload.get("phase", "replication")),
        str(step.get("id", "step")),
        str(step.get("title", "replication step")),
        list(step.get("commands", [])),
        _safe_dumps(result),
        result["success"],
    )

    if bool(payload.get("final", False)):
        new_status = "completed" if result["success"] else "failed"
        started = sessions.get(job_id, {}).get("started")
        db.update_job(
            job_id,
            status=new_status,
            duration_sec=int(time.time() - started) if started else None,
            result=_safe_dumps(result),
        )
        notifier.notify_job_complete(
            instance,
            db.get_job(job_id) or {"id": job_id, "status": new_status, "type": "replicate"},
        )

    return jsonify(result)


@app.route("/api/replicate/<int:job_id>/verify", methods=["POST"])
@require_permission("manage_instances")
def replicate_verify(job_id: int):
    payload = request.get_json(force=True) or {}
    job = db.get_job(job_id)
    if not job:
        return _err("replication job not found", 404)
    instance = _get_instance(int(job["instance_id"]))
    if not instance:
        return _err("instance not found", 404)
    commands = list(payload.get("commands", []))
    return jsonify(replicator.post_verify(instance, commands))


@app.route("/api/replicate/<int:job_id>/playbook", methods=["GET"])
@require_permission("view")
def replicate_playbook(job_id: int):
    job = db.get_job(job_id)
    if not job:
        return _err("replication job not found", 404)
    plan = job.get("plan_json") or {}
    playbook = str(plan.get("ansible_playbook", ""))

    if request.args.get("save") == "1":
        instance = _get_instance(int(job["instance_id"]))
        if not instance:
            return _err("instance not found", 404)
        try:
            path = replicator.save_playbook(instance, playbook)
            return jsonify({"playbook": playbook, "saved_path": path})
        except Exception as exc:
            log.exception("Internal error"); return _safe_err(exc, 500)

    return jsonify({"playbook": playbook})


# ── Notifications ─────────────────────────────────────────────────────────────

@app.route("/api/notifications/config", methods=["GET"])
@require_permission("view")
def get_notify_config():
    return jsonify({"config": notifier.get_config()})


@app.route("/api/notifications/config", methods=["POST"])
@require_permission("notification_settings")
def set_notify_config():
    payload = request.get_json(force=True) or {}
    return jsonify({"config": notifier.save_config(payload)})


@app.route("/api/notifications/subscriptions", methods=["GET"])
@require_permission("view")
def get_notify_subscriptions():
    return jsonify({
        "subscriptions": notifier.get_subscriptions(),
        "instances": [_safe_instance_for_api(i) for i in db.list_instances()],
    })


@app.route("/api/notifications/subscriptions", methods=["POST"])
@require_permission("notification_settings")
def set_notify_subscriptions():
    payload = request.get_json(force=True) or {}
    instance_ids = [int(i) for i in payload.get("instance_ids", [])]
    return jsonify({"subscriptions": notifier.save_subscriptions(instance_ids)})


@app.route("/api/notifications/test", methods=["POST"])
@require_permission("notification_settings")
def test_notify():
    return jsonify(notifier.test())


@app.route("/api/alerts/active", methods=["GET"])
@require_permission("view")
def active_alerts():
    return jsonify({"alerts": db.list_unresolved_alerts()})


@app.route("/api/alerts/<int:alert_id>/acknowledge", methods=["POST"])
@require_permission("acknowledge_alerts")
def acknowledge_alert(alert_id: int):
    payload = request.get_json(force=True) or {}
    acknowledged_by = str(payload.get("acknowledged_by") or "ui-user")
    db.acknowledge_alert(alert_id, acknowledged_by)
    return jsonify({"alert": db.get_alert(alert_id)})


# ── Scheduler ─────────────────────────────────────────────────────────────────

@app.route("/api/scheduler/jobs", methods=["GET"])
@require_permission("view")
def scheduler_jobs():
    return jsonify({"jobs": scheduler.list_jobs()})


# ── Start scheduler on import ─────────────────────────────────────────────────

def _boot_scheduler() -> None:
    try:
        scheduler.start()
    except Exception:
        pass


_boot_scheduler()

if __name__ == "__main__":
    host = os.getenv("AGENT_HOST", "0.0.0.0")
    port = int(os.getenv("AGENT_PORT", "7070"))
    app.run(host=host, port=port, debug=False, use_reloader=False)
