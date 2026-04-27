"""
server.py — Flask REST API server for the Linux AI Infrastructure Agent.
Listens on 0.0.0.0:7070.
"""
import json
import logging
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone

from flask import Flask, jsonify, request, send_from_directory

# Ensure the parent linux-agent directory is on sys.path so `agent.*` imports work.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent import db, core, ssh as _ssh, study as _study, report as _report
from agent import notify as _notify, scheduler as _scheduler, replicate as _replicate

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
log = logging.getLogger(__name__)

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")

app = Flask(__name__, template_folder=TEMPLATES_DIR)

# ── in-memory job state ───────────────────────────────────────────────────────
# {job_id: {plan, history (Claude messages), instance_id, type}}
sessions: dict = {}
sessions_lock = threading.Lock()

# ── per-instance conversational state ────────────────────────────────────────
# {instance_id: [openai message dicts]}  — LLM context for the chat conversation
instance_conversations: dict = {}
instance_conversations_lock = threading.Lock()

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _ok(data=None, **kwargs):
    payload = {"ok": True}
    if data is not None:
        payload["data"] = data
    payload.update(kwargs)
    return jsonify(payload)


def _err(message: str, code: int = 400):
    # Sanitize: truncate to 300 chars and strip potential stack-trace lines
    safe = str(message).split("\n")[0][:300]
    return jsonify({"ok": False, "error": safe}), code


def _require_instance(instance_id):
    inst = db.get_instance(int(instance_id))
    if not inst:
        return None, _err("Instance not found", 404)
    return inst, None


# ─────────────────────────────────────────────────────────────────────────────
# Static / UI
# ─────────────────────────────────────────────────────────────────────────────

@app.errorhandler(500)
def internal_error(exc):
    log.exception("Unhandled server error")
    return jsonify({"ok": False, "error": "Internal server error"}), 500


@app.route("/")
def index():
    return send_from_directory(TEMPLATES_DIR, "index.html")


# ─────────────────────────────────────────────────────────────────────────────
# Instances
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/instances", methods=["GET"])
def list_instances():
    return _ok(db.list_instances())


@app.route("/api/instances", methods=["POST"])
def add_instance():
    body = request.json or {}
    required = ("label", "host", "username")
    for f in required:
        if not body.get(f):
            return _err(f"Missing field: {f}")

    iid = db.add_instance(
        label=body["label"],
        host=body["host"],
        port=int(body.get("port", 22)),
        username=body["username"],
        auth_type=body.get("auth_type", "key"),
        key_path=body.get("key_path"),
        password=body.get("password"),
        tags=body.get("tags", []),
    )
    return _ok({"id": iid}), 201


@app.route("/api/instances/<int:iid>", methods=["DELETE"])
def delete_instance(iid):
    inst, err = _require_instance(iid)
    if err:
        return err
    db.delete_instance(iid)
    return _ok()


@app.route("/api/instances/<int:iid>/test", methods=["POST"])
def test_instance(iid):
    inst, err = _require_instance(iid)
    if err:
        return err
    result = _ssh.test_connection(inst)
    status = "online" if result["ok"] else (
        "auth_error" if "auth_error" in result.get("error", "") else "offline"
    )
    db.update_instance_status(iid, status)
    return _ok(result)


@app.route("/api/instances/<int:iid>/diagnostics", methods=["GET"])
def get_diagnostics(iid):
    inst, err = _require_instance(iid)
    if err:
        return err
    diag = _ssh.collect_diagnostics(inst)
    return _ok(diag)


@app.route("/api/instances/<int:iid>/study", methods=["POST"])
def run_study(iid):
    inst, err = _require_instance(iid)
    if err:
        return err

    def _do():
        job_id = db.create_job(iid, "study", f"Study — {inst['label']}")
        try:
            rep, raw = _study.run_study(inst)
            sid = db.save_study_report(iid, job_id, rep, raw)
            db.finish_job(job_id, "done", result=f"study_id={sid}")
            db.update_instance_status(iid, "online")
            _notify.notify_study_complete(inst, rep)
        except Exception as exc:
            db.finish_job(job_id, "failed", result=str(exc))
            log.error("Study failed: %s", exc)

    t = threading.Thread(target=_do, daemon=True)
    t.start()
    return _ok({"message": "Study started in background"})


# ─────────────────────────────────────────────────────────────────────────────
# Schedule
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/instances/<int:iid>/schedule", methods=["GET"])
def get_schedule(iid):
    inst, err = _require_instance(iid)
    if err:
        return err
    sched = db.get_schedule(iid)
    return _ok(sched or {})


@app.route("/api/instances/<int:iid>/schedule", methods=["POST"])
def set_schedule(iid):
    inst, err = _require_instance(iid)
    if err:
        return err
    body = request.json or {}
    enabled = bool(body.get("enabled", True))
    mode = body.get("mode", "interval")
    interval_hours = float(body.get("interval_hours", 6))
    cron_expr = body.get("cron_expr", "0 */6 * * *")
    db.upsert_schedule(iid, enabled, mode, interval_hours, cron_expr)
    if enabled:
        _scheduler.add_schedule(iid, mode, interval_hours, cron_expr)
    else:
        _scheduler.remove_schedule(iid)
    return _ok()


@app.route("/api/instances/<int:iid>/schedule", methods=["DELETE"])
def delete_schedule(iid):
    inst, err = _require_instance(iid)
    if err:
        return err
    db.delete_schedule(iid)
    _scheduler.remove_schedule(iid)
    return _ok()


@app.route("/api/instances/<int:iid>/trigger", methods=["POST"])
def trigger_check(iid):
    inst, err = _require_instance(iid)
    if err:
        return err
    _scheduler.trigger_now(iid)
    return _ok({"message": "Health check triggered"})


@app.route("/api/instances/<int:iid>/check_log", methods=["GET"])
def check_log(iid):
    inst, err = _require_instance(iid)
    if err:
        return err
    log_data = db.get_check_log(iid)
    return _ok(log_data)


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/dashboard", methods=["GET"])
def dashboard():
    stats = db.dashboard_stats()
    instances = db.list_instances()
    # Attach latest health score to each instance
    for inst in instances:
        row = db.get_latest_study_report(inst["id"])
        if row and row.get("report_json"):
            try:
                rep = json.loads(row["report_json"])
                inst["health_score"] = (rep.get("summary") or {}).get("health_score")
                inst["role"] = (rep.get("summary") or {}).get("role")
            except Exception:
                inst["health_score"] = None
                inst["role"] = None
        else:
            inst["health_score"] = None
            inst["role"] = None
    stats["instances"] = instances
    return _ok(stats)


# ─────────────────────────────────────────────────────────────────────────────
# Intent classification
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/classify", methods=["POST"])
def classify():
    body = request.json or {}
    message = body.get("message", "")
    if not message:
        return _err("message required")
    intent = core.classify_intent(message)
    return _ok({"intent": intent})


# ─────────────────────────────────────────────────────────────────────────────
# Troubleshoot
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/diagnose", methods=["POST"])
def diagnose():
    body = request.json or {}
    iid = body.get("instance_id")
    message = body.get("message", "")
    if not iid or not message:
        return _err("instance_id and message required")

    inst, err = _require_instance(iid)
    if err:
        return err

    try:
        diag = _ssh.collect_diagnostics(inst)
    except Exception as exc:
        return _err(f"SSH error: {exc}")

    history: list = []
    plan = core.generate_fix_plan(diag, message, history)

    job_id = db.create_job(iid, "troubleshoot", message[:120], plan_json=plan)
    with sessions_lock:
        sessions[job_id] = {
            "plan": plan,
            "history": history,
            "instance_id": iid,
            "type": "troubleshoot",
        }
    return _ok({"job_id": job_id, "plan": plan, "diagnostics": diag})


@app.route("/api/execute_step", methods=["POST"])
def execute_step():
    body = request.json or {}
    job_id = body.get("job_id")
    step_id = body.get("step_id")
    if not job_id or not step_id:
        return _err("job_id and step_id required")

    with sessions_lock:
        session = sessions.get(int(job_id))
    if not session:
        return _err("Session not found — job may have expired")

    plan = session["plan"]
    steps = plan.get("steps", [])
    step = next((s for s in steps if str(s.get("id")) == str(step_id)), None)
    if not step:
        return _err("Step not found")

    inst = db.get_instance(session["instance_id"])
    if not inst:
        return _err("Instance not found")

    cmds = step.get("commands", [])
    results = _ssh.run_commands(inst, cmds, timeout=300)
    combined = "\n".join(
        f"$ {r['command']}\n{r['stdout']}{r['stderr']}"
        for r in results
    )
    success = all(r["success"] for r in results)

    summary = core.summarize_step_output(step, combined, session["history"])
    db.add_job_step(int(job_id), None, step_id, step.get("title", ""), cmds, combined, success)

    return _ok({
        "output": combined,
        "success": success,
        "summary": summary,
    })


@app.route("/api/verify", methods=["POST"])
def verify():
    body = request.json or {}
    job_id = body.get("job_id")
    if not job_id:
        return _err("job_id required")

    with sessions_lock:
        session = sessions.get(int(job_id))
    if not session:
        return _err("Session not found")

    plan = session["plan"]
    verification_cmd = plan.get("verification", "")
    if not verification_cmd:
        return _ok({"output": "", "summary": "No verification command defined."})

    inst = db.get_instance(session["instance_id"])
    if not inst:
        return _err("Instance not found")

    stdout, stderr, code = _ssh.run_command(inst, verification_cmd, timeout=60)
    output = stdout + stderr
    summary = core.run_verification_summary(verification_cmd, output, session["history"])
    db.finish_job(int(job_id), "done", result=summary)

    return _ok({"output": output, "summary": summary, "success": code == 0})


# ─────────────────────────────────────────────────────────────────────────────
# Build
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/build/plan", methods=["POST"])
def build_plan():
    body = request.json or {}
    iid = body.get("instance_id")
    message = body.get("message", "")
    if not iid or not message:
        return _err("instance_id and message required")

    inst, err = _require_instance(iid)
    if err:
        return err

    try:
        specs = _ssh.collect_specs(inst)
    except Exception as exc:
        return _err(f"SSH error: {exc}")

    history: list = []
    plan = core.generate_build_plan(specs, message, history)

    job_id = db.create_job(iid, "build", message[:120], plan_json=plan, specs_json=specs)
    with sessions_lock:
        sessions[job_id] = {
            "plan": plan,
            "history": history,
            "instance_id": iid,
            "type": "build",
        }
    return _ok({"job_id": job_id, "plan": plan, "specs": specs})


@app.route("/api/build/execute_step", methods=["POST"])
def build_execute_step():
    body = request.json or {}
    job_id = body.get("job_id")
    phase_id = body.get("phase_id")
    step_id = body.get("step_id")
    if not all([job_id, phase_id, step_id]):
        return _err("job_id, phase_id, and step_id required")

    with sessions_lock:
        session = sessions.get(int(job_id))
    if not session:
        return _err("Session not found")

    plan = session["plan"]
    phase = next((p for p in plan.get("phases", []) if str(p["id"]) == str(phase_id)), None)
    if not phase:
        return _err("Phase not found")
    step = next((s for s in phase.get("steps", []) if str(s["id"]) == str(step_id)), None)
    if not step:
        return _err("Step not found")

    inst = db.get_instance(session["instance_id"])
    if not inst:
        return _err("Instance not found")

    cmds = step.get("commands", [])
    results = _ssh.run_commands(inst, cmds, timeout=600)
    combined = "\n".join(
        f"$ {r['command']}\n{r['stdout']}{r['stderr']}"
        for r in results
    )
    success = all(r["success"] for r in results)
    summary = core.summarize_build_step(step, combined, session["history"])

    db.add_job_step(int(job_id), phase.get("name", phase_id), step_id,
                    step.get("title", ""), cmds, combined, success)

    return _ok({
        "output": combined,
        "success": success,
        "summary": summary,
    })


@app.route("/api/build/post_install", methods=["POST"])
def build_post_install():
    body = request.json or {}
    job_id = body.get("job_id")
    if not job_id:
        return _err("job_id required")

    with sessions_lock:
        session = sessions.get(int(job_id))
    if not session:
        return _err("Session not found")

    inst = db.get_instance(session["instance_id"])
    if not inst:
        return _err("Instance not found")

    post = session["plan"].get("post_install", {})
    cred_cmds = post.get("credential_commands", [])
    verify_cmds = post.get("verification_commands", [])
    all_cmds = cred_cmds + verify_cmds
    results = _ssh.run_commands(inst, all_cmds, timeout=120)
    combined_outputs = [
        {"command": r["command"], "output": r["stdout"] + r["stderr"]}
        for r in results
    ]
    summary = core.collect_post_install(post, combined_outputs, session["history"])
    db.finish_job(int(job_id), "done", result=summary)

    return _ok({"outputs": combined_outputs, "summary": summary})


# ─────────────────────────────────────────────────────────────────────────────
# Jobs
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/jobs", methods=["GET"])
def list_jobs():
    iid = request.args.get("instance_id")
    jtype = request.args.get("type")
    jobs = db.list_jobs(
        instance_id=int(iid) if iid else None,
        job_type=jtype,
    )
    return _ok(jobs)


@app.route("/api/jobs/<int:jid>", methods=["GET"])
def get_job(jid):
    job = db.get_job(jid)
    if not job:
        return _err("Job not found", 404)
    steps = db.get_job_steps(jid)
    job["steps"] = steps
    return _ok(job)


@app.route("/api/jobs/<int:jid>", methods=["DELETE"])
def delete_job(jid):
    db.delete_job(jid)
    return _ok()


# ─────────────────────────────────────────────────────────────────────────────
# Studies
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/studies", methods=["GET"])
def list_studies():
    iid = request.args.get("instance_id")
    rows = db.list_study_reports(instance_id=int(iid) if iid else None)
    return _ok(rows)


@app.route("/api/studies/<int:sid>", methods=["GET"])
def get_study(sid):
    row = db.get_study_report(sid)
    if not row:
        return _err("Study not found", 404)
    if isinstance(row.get("report_json"), str):
        try:
            row["report_json"] = json.loads(row["report_json"])
        except Exception:
            pass
    return _ok(row)


@app.route("/api/studies/<int:sid>/html", methods=["GET"])
def get_study_html(sid):
    row = db.get_study_report(sid)
    if not row:
        return _err("Study not found", 404)
    html = _report.generate_html(row)
    from flask import Response
    return Response(html, mimetype="text/html")


@app.route("/api/studies/<int:sid>", methods=["DELETE"])
def delete_study(sid):
    db.delete_study_report(sid)
    return _ok()


# ─────────────────────────────────────────────────────────────────────────────
# Replication
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/replicate/plan", methods=["POST"])
def replicate_plan():
    body = request.json or {}
    source_id = body.get("source_instance_id")
    target_id = body.get("target_instance_id")
    if not source_id or not target_id:
        return _err("source_instance_id and target_instance_id required")

    source_inst, err = _require_instance(source_id)
    if err:
        return err
    target_inst, err = _require_instance(target_id)
    if err:
        return err

    source_study_row = db.get_latest_study_report(source_id)
    if not source_study_row:
        return _err("No study report found for source instance. Run a study first.")

    source_report = json.loads(source_study_row["report_json"])

    try:
        target_specs = _ssh.collect_specs(target_inst)
    except Exception as exc:
        return _err(f"Cannot SSH into target: {exc}")

    history: list = []
    plan = _replicate.generate_replication_plan(
        source_report, target_specs, source_inst, target_inst, history
    )

    job_id = db.create_job(
        target_id, "replicate",
        f"Replicate {source_inst['label']} → {target_inst['label']}",
        plan_json=plan,
    )
    with sessions_lock:
        sessions[job_id] = {
            "plan": plan,
            "history": history,
            "instance_id": target_id,
            "source_instance_id": source_id,
            "type": "replicate",
        }
    return _ok({"job_id": job_id, "plan": plan})


@app.route("/api/replicate/<int:job_id>/step", methods=["POST"])
def replicate_step(job_id):
    body = request.json or {}
    phase_id = body.get("phase_id")
    step_id = body.get("step_id")

    with sessions_lock:
        session = sessions.get(job_id)
    if not session:
        return _err("Session not found")

    plan = session["plan"]
    phase = next((p for p in plan.get("phases", []) if str(p["id"]) == str(phase_id)), None)
    if not phase:
        return _err("Phase not found")
    step = next((s for s in phase.get("steps", []) if str(s["id"]) == str(step_id)), None)
    if not step:
        return _err("Step not found")

    inst = db.get_instance(session["instance_id"])
    if not inst:
        return _err("Instance not found")

    result = _replicate.execute_replication_step(inst, step)
    db.add_job_step(job_id, phase.get("name", phase_id), step_id,
                    step.get("title", ""), step.get("commands", []),
                    result["output"], result["success"])
    return _ok(result)


@app.route("/api/replicate/<int:job_id>/verify", methods=["POST"])
def replicate_verify(job_id):
    with sessions_lock:
        session = sessions.get(job_id)
    if not session:
        return _err("Session not found")

    inst = db.get_instance(session["instance_id"])
    if not inst:
        return _err("Instance not found")

    post_verify = session["plan"].get("post_verify", {})
    result = _replicate.run_post_verify(inst, post_verify)
    db.finish_job(job_id, "done" if result["success"] else "failed",
                  result=result["output"][:500])
    return _ok(result)


@app.route("/api/replicate/<int:job_id>/playbook", methods=["GET"])
def get_playbook(job_id):
    with sessions_lock:
        session = sessions.get(job_id)
    if not session:
        # Fallback: load from DB
        job = db.get_job(job_id)
        if not job or not job.get("plan_json"):
            return _err("Plan not found", 404)
        plan = json.loads(job["plan_json"])
    else:
        plan = session["plan"]

    playbook = plan.get("ansible_playbook", "")
    return _ok({"playbook": playbook})


@app.route("/api/replicate/<int:job_id>/playbook", methods=["POST"])
def save_playbook(job_id):
    body = request.json or {}
    with sessions_lock:
        session = sessions.get(job_id)
    if not session:
        return _err("Session not found")

    inst = db.get_instance(session["instance_id"])
    if not inst:
        return _err("Instance not found")

    playbook = body.get("playbook") or session["plan"].get("ansible_playbook", "")
    try:
        path = _replicate.save_playbook_to_target(inst, playbook)
        return _ok({"path": path})
    except Exception as exc:
        return _err(str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Notifications
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/notifications/config", methods=["GET"])
def get_notify_config():
    raw = db.get_config("notify_config", "{}")
    try:
        cfg = json.loads(raw)
    except Exception:
        cfg = {}
    return _ok(cfg)


@app.route("/api/notifications/config", methods=["POST"])
def set_notify_config():
    body = request.json or {}
    db.set_config("notify_config", body)
    return _ok()


@app.route("/api/notifications/test", methods=["POST"])
def test_notify():
    body = request.json or {}
    results = _notify.send_test_notification(body)
    return _ok(results)


# ─────────────────────────────────────────────────────────────────────────────
# PEM key upload
# ─────────────────────────────────────────────────────────────────────────────

KEYS_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "keys")


@app.route("/api/upload_key", methods=["POST"])
def upload_key():
    if "file" not in request.files:
        return _err("No file provided")
    f = request.files["file"]
    filename = f.filename or ""
    if not filename.lower().endswith(".pem"):
        return _err("Only .pem files are accepted")

    # Validate that the file looks like a PEM private key
    content = f.read()
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return _err("File is not valid UTF-8 text")
    if "PRIVATE KEY" not in text:
        return _err("File does not appear to be a PEM private key")

    try:
        os.makedirs(KEYS_DIR, mode=0o700, exist_ok=True)
    except OSError as exc:
        log.exception("Failed to create keys directory")
        return _err(f"Cannot create keys directory: {exc.strerror}")
    # Use a timestamp-prefixed name to avoid collisions while keeping the original stem
    safe_stem = re.sub(r"[^a-zA-Z0-9_\-]", "_", filename[:-4])[:64] or "key"
    dest_name = f"{int(time.time())}_{safe_stem}.pem"
    dest_path = os.path.realpath(os.path.join(KEYS_DIR, dest_name))
    # Confirm the resolved path is still inside KEYS_DIR
    if not dest_path.startswith(os.path.realpath(KEYS_DIR) + os.sep):
        return _err("Invalid filename")

    try:
        with open(dest_path, "wb") as fh:
            fh.write(content)
        os.chmod(dest_path, 0o600)
    except OSError as exc:
        log.exception("Failed to save uploaded key")
        return _err(f"Could not save key file: {exc.strerror}")

    return _ok({"path": dest_path, "filename": dest_name})


# ─────────────────────────────────────────────────────────────────────────────
# Explore / chat mode
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/explore", methods=["POST"])
def explore():
    body = request.json or {}
    iid = body.get("instance_id")
    message = body.get("message", "")
    if not iid or not message:
        return _err("instance_id and message required")

    inst, err = _require_instance(iid)
    if err:
        return err

    try:
        diag = _ssh.collect_diagnostics(inst)
    except Exception as exc:
        return _err(f"SSH error: {exc}")

    history: list = []
    response = core.generate_explore_response(diag, message, history)

    job_id = db.create_job(iid, "explore", message[:120], plan_json=response)
    with sessions_lock:
        sessions[job_id] = {
            "plan": response,
            "history": history,
            "instance_id": iid,
            "type": "explore",
        }
    return _ok({"job_id": job_id, "response": response})


@app.route("/api/explore_cmd", methods=["POST"])
def explore_cmd():
    body = request.json or {}
    job_id = body.get("job_id")
    title = body.get("title", "")
    cmd = body.get("cmd", "")
    if not job_id or not cmd:
        return _err("job_id and cmd required")

    with sessions_lock:
        session = sessions.get(int(job_id))
    if not session:
        return _err("Session not found — job may have expired")

    inst = db.get_instance(session["instance_id"])
    if not inst:
        return _err("Instance not found")

    results = _ssh.run_commands(inst, [cmd], timeout=60)
    combined = "\n".join(
        f"$ {r['command']}\n{r['stdout']}{r['stderr']}"
        for r in results
    )
    success = all(r["success"] for r in results)
    summary = core.run_explore_command(title, cmd, combined, session["history"])

    return _ok({"output": combined, "success": success, "summary": summary})


# ─────────────────────────────────────────────────────────────────────────────
# Conversational chat
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/chat/message", methods=["POST"])
def chat_message():
    """
    Conversational turn endpoint. Maintains per-instance LLM history so the AI
    can ask clarifying questions and propose actions with confirmation.
    Accepts application/json or multipart/form-data (when an attachment is included).
    Returns {type: 'reply'|'action_proposal', reply, action?}.
    """
    content_type = request.content_type or ""
    if content_type.startswith("multipart/form-data"):
        iid = request.form.get("instance_id")
        message = request.form.get("message", "")
        attach_name = request.form.get("attach_name", "")
        attach_mime = request.form.get("attach_mime", "")
        attach_data = request.form.get("attach_data", "")  # base64 string
        attachment = {"name": attach_name, "mime": attach_mime, "data": attach_data} if attach_data else None
    else:
        body = request.json or {}
        iid = body.get("instance_id")
        message = body.get("message", "")
        attachment = None

    if not iid or not message:
        return _err("instance_id and message required")

    inst, err = _require_instance(iid)
    if err:
        return err

    with instance_conversations_lock:
        history = instance_conversations.setdefault(int(iid), [])

    try:
        result = core.chat_reply(message, inst["label"], history, attachment=attachment)
    except Exception as exc:
        return _err(f"AI error: {exc}")

    return _ok(result)


@app.route("/api/chat/reset/<int:instance_id>", methods=["POST"])
def chat_reset_conversation(instance_id):
    """Reset the in-memory LLM conversation context for an instance."""
    with instance_conversations_lock:
        instance_conversations.pop(instance_id, None)
    return _ok()


# ─────────────────────────────────────────────────────────────────────────────
# Configure
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/configure/plan", methods=["POST"])
def configure_plan():
    body = request.json or {}
    iid = body.get("instance_id")
    message = body.get("message", "")
    if not iid or not message:
        return _err("instance_id and message required")

    inst, err = _require_instance(iid)
    if err:
        return err

    try:
        diag = _ssh.collect_diagnostics(inst)
    except Exception as exc:
        return _err(f"SSH error: {exc}")

    history: list = []
    plan = core.generate_configure_plan(diag, message, history)

    job_id = db.create_job(iid, "configure", message[:120], plan_json=plan)
    with sessions_lock:
        sessions[job_id] = {
            "plan": plan,
            "history": history,
            "instance_id": iid,
            "type": "configure",
        }
    return _ok({"job_id": job_id, "plan": plan})


@app.route("/api/configure/execute_step", methods=["POST"])
def configure_execute_step():
    body = request.json or {}
    job_id = body.get("job_id")
    step_id = body.get("step_id")
    if not job_id or not step_id:
        return _err("job_id and step_id required")

    with sessions_lock:
        session = sessions.get(int(job_id))
    if not session:
        return _err("Session not found — job may have expired")

    plan = session["plan"]
    steps = plan.get("steps", [])
    step = next((s for s in steps if str(s.get("id")) == str(step_id)), None)
    if not step:
        return _err("Step not found")

    inst = db.get_instance(session["instance_id"])
    if not inst:
        return _err("Instance not found")

    cmds = step.get("commands", [])
    results = _ssh.run_commands(inst, cmds, timeout=300)
    combined = "\n".join(
        f"$ {r['command']}\n{r['stdout']}{r['stderr']}"
        for r in results
    )
    success = all(r["success"] for r in results)
    summary = core.summarize_configure_step(step, combined, session["history"])
    db.add_job_step(int(job_id), None, step_id, step.get("title", ""), cmds, combined, success)

    return _ok({"output": combined, "success": success, "summary": summary})


@app.route("/api/configure/verify", methods=["POST"])
def configure_verify():
    body = request.json or {}
    job_id = body.get("job_id")
    if not job_id:
        return _err("job_id required")

    with sessions_lock:
        session = sessions.get(int(job_id))
    if not session:
        return _err("Session not found")

    plan = session["plan"]
    verification_cmd = plan.get("verification", "")
    if not verification_cmd:
        return _ok({"output": "", "summary": "No verification command defined."})

    inst = db.get_instance(session["instance_id"])
    if not inst:
        return _err("Instance not found")

    stdout, stderr, code = _ssh.run_command(inst, verification_cmd, timeout=60)
    output = stdout + stderr
    summary = core.run_verification_summary(verification_cmd, output, session["history"])
    db.finish_job(int(job_id), "done", result=summary)

    return _ok({"output": output, "summary": summary, "success": code == 0})


# ─────────────────────────────────────────────────────────────────────────────
# Chat history
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/chat_history/<int:instance_id>", methods=["GET"])
def get_chat_history(instance_id):
    inst, err = _require_instance(instance_id)
    if err:
        return err
    limit = int(request.args.get("limit", 200))
    messages = db.get_chat_history(instance_id, limit=limit)
    return _ok(messages)


@app.route("/api/chat_history/<int:instance_id>", methods=["POST"])
def save_chat_message(instance_id):
    inst, err = _require_instance(instance_id)
    if err:
        return err
    body = request.json or {}
    role = body.get("role", "")
    content = body.get("content", "")
    pre_text = body.get("pre_text") or None
    if role not in ("user", "ai", "system"):
        return _err("role must be user, ai, or system")
    if not content:
        return _err("content required")
    db.save_chat_message(instance_id, role, content, pre_text)
    return _ok()


@app.route("/api/chat_history/<int:instance_id>", methods=["DELETE"])
def clear_chat_history(instance_id):
    inst, err = _require_instance(instance_id)
    if err:
        return err
    db.clear_chat_history(instance_id)
    return _ok()


@app.route("/api/scheduler/jobs", methods=["GET"])
def scheduler_jobs():
    return _ok(_scheduler.list_jobs())


# ─────────────────────────────────────────────────────────────────────────────
# Monitoring
# ─────────────────────────────────────────────────────────────────────────────

_MONITORING_DEFAULTS: dict = {
    "cpu_warn": 75.0,
    "cpu_crit": 90.0,
    "mem_warn": 70.0,
    "mem_crit": 85.0,
    "disk_warn": 75.0,
    "disk_crit": 90.0,
}


def _load_thresholds() -> dict:
    raw = db.get_config("monitoring_thresholds", None)
    if raw:
        try:
            saved = json.loads(raw)
            merged = dict(_MONITORING_DEFAULTS)
            for k, v in saved.items():
                try:
                    merged[k] = float(v)
                except (TypeError, ValueError):
                    pass
            return merged
        except Exception:
            pass
    return dict(_MONITORING_DEFAULTS)


def _compute_health(metrics: dict, thresholds: dict) -> tuple:
    """Return (status_str, alerts_list) for one instance."""
    cpu = metrics.get("cpu_pct", 0.0)
    mem = metrics.get("mem_pct", 0.0)
    disk = metrics.get("disk_pct", 0.0)
    alerts: list = []
    now_iso = datetime.now(timezone.utc).isoformat()

    def _check(label, value, warn, crit):
        if value >= crit:
            alerts.append({
                "severity": "critical",
                "metric": label,
                "value": value,
                "threshold": crit,
                "at": now_iso,
            })
        elif value >= warn:
            alerts.append({
                "severity": "warning",
                "metric": label,
                "value": value,
                "threshold": warn,
                "at": now_iso,
            })

    _check("CPU", cpu, thresholds["cpu_warn"], thresholds["cpu_crit"])
    _check("Memory", mem, thresholds["mem_warn"], thresholds["mem_crit"])
    _check("Disk", disk, thresholds["disk_warn"], thresholds["disk_crit"])

    failed = metrics.get("failed_svc_count", 0)
    if failed > 0:
        alerts.append({
            "severity": "warning",
            "metric": "Failed Services",
            "value": failed,
            "threshold": 0,
            "at": now_iso,
        })

    if any(a["severity"] == "critical" for a in alerts):
        status = "critical"
    elif alerts:
        status = "warning"
    else:
        status = "healthy"

    return status, alerts


@app.route("/api/monitoring/thresholds", methods=["GET"])
def get_monitoring_thresholds():
    return _ok(_load_thresholds())


@app.route("/api/monitoring/thresholds", methods=["POST"])
def set_monitoring_thresholds():
    body = request.json or {}
    t: dict = {}
    for key in ("cpu_warn", "cpu_crit", "mem_warn", "mem_crit", "disk_warn", "disk_crit"):
        try:
            t[key] = float(body.get(key, _MONITORING_DEFAULTS[key]))
        except (TypeError, ValueError):
            t[key] = _MONITORING_DEFAULTS[key]
    db.set_config("monitoring_thresholds", json.dumps(t))
    return _ok(t)


@app.route("/api/monitoring", methods=["GET"])
def get_monitoring():
    instances = db.list_instances()
    thresholds = _load_thresholds()
    poll_results: dict = {}
    poll_errors: dict = {}

    def _poll(inst):
        try:
            metrics = _ssh.collect_monitoring(inst)
            poll_results[inst["id"]] = metrics
        except Exception as exc:
            poll_errors[inst["id"]] = str(exc).split("\n")[0][:200]

    threads = [
        threading.Thread(target=_poll, args=(inst,), daemon=True)
        for inst in instances
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=35)

    inst_data: list = []
    all_alerts: list = []
    cpu_vals: list = []
    mem_vals: list = []
    online_count = 0
    offline_count = 0

    for inst in instances:
        iid = inst["id"]
        if iid in poll_errors:
            inst_data.append({
                "id": iid,
                "label": inst["label"],
                "host": inst["host"],
                "status": "unreachable",
                "error": poll_errors[iid],
                "metrics": None,
                "alerts": [],
            })
            offline_count += 1
        else:
            metrics = poll_results.get(iid, {})
            status, inst_alerts = _compute_health(metrics, thresholds)
            for a in inst_alerts:
                a["instance_id"] = iid
                a["instance_label"] = inst["label"]
            all_alerts.extend(inst_alerts)
            if metrics.get("cpu_pct") is not None:
                cpu_vals.append(metrics["cpu_pct"])
            if metrics.get("mem_pct") is not None:
                mem_vals.append(metrics["mem_pct"])
            online_count += 1
            inst_data.append({
                "id": iid,
                "label": inst["label"],
                "host": inst["host"],
                "status": status,
                "metrics": metrics,
                "alerts": inst_alerts,
            })

    summary = {
        "total": len(instances),
        "online": online_count,
        "offline": offline_count,
        "alert_count": len(all_alerts),
        "avg_cpu": round(sum(cpu_vals) / len(cpu_vals), 1) if cpu_vals else None,
        "avg_mem": round(sum(mem_vals) / len(mem_vals), 1) if mem_vals else None,
    }

    return _ok({
        "instances": inst_data,
        "alerts": all_alerts,
        "summary": summary,
        "thresholds": thresholds,
    })


# ─────────────────────────────────────────────────────────────────────────────
# Bootstrap
# ─────────────────────────────────────────────────────────────────────────────

def _bootstrap():
    db.init_db()
    _scheduler.start()
    log.info("Database initialized")


if __name__ == "__main__":
    _bootstrap()
    app.run(host="0.0.0.0", port=7070, debug=False, use_reloader=False)
