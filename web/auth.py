"""
Auth middleware for Linux AI Agent.

Permission matrix
-----------------
Admin    – manage_users, manage_instances, manage_ssh_keys,
           acknowledge_alerts, notification_settings, run_diagnostics, view
Operator – acknowledge_alerts, run_diagnostics, view
Viewer   – view

When the users table is empty (legacy / first-run mode) every request is
treated as Admin so the existing single-user workflow is unchanged.
"""
import secrets
from functools import wraps
from typing import Optional

from flask import Flask, g, jsonify, session

# Fixed permission sets per role
PERMISSION_MATRIX: dict = {
    "Admin": {
        "manage_users",
        "manage_instances",
        "manage_ssh_keys",
        "acknowledge_alerts",
        "notification_settings",
        "run_diagnostics",
        "view",
    },
    "Operator": {"acknowledge_alerts", "run_diagnostics", "view"},
    "Viewer": {"view"},
}


def _resolve_role(db, user: Optional[dict]) -> Optional[str]:
    """Return the effective role name for *user*, or None if unauthenticated."""
    if user is None:
        # Legacy mode: no users configured → treat as Admin
        if db.count_users() == 0:
            return "Admin"
        return None

    if user.get("status") != "active":
        return None

    # Direct role assignment takes precedence
    if user.get("role_id"):
        role = db.get_role(user["role_id"])
        return role["name"] if role else None

    # Role via group membership
    groups = db.get_user_groups(user["id"])
    for grp in groups:
        if grp.get("role_id"):
            role = db.get_role(grp["role_id"])
            if role:
                return role["name"]

    return None


def init_auth(app: Flask, db_instance) -> None:
    """
    Attach auth to *app*:
    - Loads (or generates) a persistent secret key from the config table.
    - Registers a before_request hook that populates g.current_user and
      g.user_role for every request.
    """
    # Persistent secret key – stored in the config table so no env var is needed
    cfg = db_instance.get_config_json("app_secret_key", default={})
    secret = cfg.get("key")
    if not secret:
        secret = secrets.token_hex(32)
        db_instance.set_config_json("app_secret_key", {"key": secret})
    app.secret_key = secret

    @app.before_request
    def _load_user() -> None:
        user_id = session.get("user_id")
        if user_id:
            g.current_user = db_instance.get_user(int(user_id))
        else:
            g.current_user = None
        g.user_role = _resolve_role(db_instance, g.current_user)


def require_permission(permission: str):
    """
    Route decorator: returns 401 if not authenticated, 403 if the current
    user's effective role does not include *permission*.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            role = g.get("user_role")
            if role is None:
                return jsonify({"error": "Authentication required"}), 401
            if permission not in PERMISSION_MATRIX.get(role, set()):
                return jsonify({"error": "Forbidden"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator
