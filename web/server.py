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
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from flask import Flask, Response, jsonify, render_template, request

try:
    from openai import OpenAI as _OpenAIClient
    _openai = _OpenAIClient(api_key=os.getenv("OPENAI_API_KEY", ""))
except Exception:
    _openai = None

from agent.core import ClaudeClient
from agent.db import Database
from agent.notify import Notifier
from agent.replicate import Replicator
from agent.report import generate_study_html
from agent.scheduler import HealthScheduler
from agent.ssh import SSHManager
from agent.study import StudyRunner

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

# In-memory job sessions: {job_id: {plan, history, instance_id, type, started}}
sessions: Dict[int, Dict[str, Any]] = {}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _err(message: str, status: int = 400):
    # Avoid exposing raw exception details to callers
    return jsonify({"error": message}), status


def _safe_err(exc: Exception, status: int = 500):
    """Return a sanitized error — never leak raw stack-trace text to clients."""
    return jsonify({"error": "An internal error occurred. Check server logs."}), status


def _get_instance(instance_id: int) -> Optional[Dict[str, Any]]:
    return db.get_instance(instance_id)


def _safe_dumps(value: Any) -> str:
    try:
        return json.dumps(value, default=str)
    except Exception:
        return str(value)


# ── UI ────────────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    return render_template("index.html")


# ── Instances ─────────────────────────────────────────────────────────────────

@app.route("/api/instances", methods=["POST"])
def add_instance():
    payload = request.get_json(force=True) or {}
    for field in ("label", "host", "username", "auth_type"):
        if not payload.get(field):
            return _err(f"missing required field: {field}")
    iid = db.add_instance(payload)
    instance = db.get_instance(iid)
    ok, reason = ssh.test_connection(instance)
    db.update_instance_status(iid, "online" if ok else "auth_error")
    return jsonify({"instance": db.get_instance(iid), "ssh_test": {"ok": ok, "reason": reason}})


@app.route("/api/instances", methods=["GET"])
def list_instances():
    return jsonify({"instances": db.list_instances()})


@app.route("/api/instances/<int:instance_id>", methods=["DELETE"])
def delete_instance(instance_id: int):
    db.delete_instance(instance_id)
    scheduler.remove_schedule(instance_id)
    return jsonify({"ok": True})


@app.route("/api/instances/<int:instance_id>/test", methods=["POST"])
def test_instance(instance_id: int):
    instance = _get_instance(instance_id)
    if not instance:
        return _err("instance not found", 404)
    ok, reason = ssh.test_connection(instance)
    db.update_instance_status(instance_id, "online" if ok else "auth_error")
    return jsonify({"ok": ok, "reason": reason})


@app.route("/api/instances/<int:instance_id>/diagnostics", methods=["GET"])
def instance_diagnostics(instance_id: int):
    instance = _get_instance(instance_id)
    if not instance:
        return _err("instance not found", 404)
    try:
        return jsonify({"diagnostics": ssh.collect_diagnostics(instance)})
    except Exception as exc:
        log.exception("Internal error"); return _safe_err(exc, 500)


@app.route("/api/instances/<int:instance_id>/study", methods=["POST"])
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
def get_schedule(instance_id: int):
    return jsonify({"schedule": db.get_schedule(instance_id)})


@app.route("/api/instances/<int:instance_id>/schedule", methods=["POST"])
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
def del_schedule(instance_id: int):
    db.delete_schedule(instance_id)
    scheduler.remove_schedule(instance_id)
    return jsonify({"ok": True})


@app.route("/api/instances/<int:instance_id>/trigger", methods=["POST"])
def trigger_check(instance_id: int):
    instance = _get_instance(instance_id)
    if not instance:
        return _err("instance not found", 404)
    scheduler.trigger_manual(instance_id)
    return jsonify({"ok": True, "message": "triggered in background"})


@app.route("/api/instances/<int:instance_id>/check_log", methods=["GET"])
def check_log(instance_id: int):
    return jsonify({"entries": db.get_check_log(instance_id)})


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route("/api/dashboard", methods=["GET"])
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
        tiles.append({
            "instance": inst,
            "health_score": score,
            "role": (report.get("summary") or {}).get("role", "unknown"),
            "last_check": inst.get("last_seen"),
            "schedule": db.get_schedule(inst["id"]),
        })

    online = sum(1 for i in instances if i.get("last_status") == "online")
    avg_health = round(sum(scores) / len(scores), 1) if scores else 0
    activity = db.list_jobs()[:10]

    return jsonify({
        "stats": {
            "total_instances": len(instances),
            "online_count": online,
            "offline_count": len(instances) - online,
            "avg_health_score": avg_health,
        },
        "tiles": tiles,
        "activity": activity,
    })


# ── Chat / classify ───────────────────────────────────────────────────────────

@app.route("/api/classify", methods=["POST"])
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
def knowledge_base_list():
    with _kb_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM knowledge_base ORDER BY last_seen DESC"
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/events", methods=["GET"])
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
def build_execute_step():
    return execute_step()


@app.route("/api/build/post_install", methods=["POST"])
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
def list_jobs():
    instance_id = request.args.get("instance_id")
    job_type = request.args.get("type")
    data = db.list_jobs(
        instance_id=int(instance_id) if instance_id else None,
        job_type=job_type,
    )
    return jsonify({"jobs": data})


@app.route("/api/jobs/<int:job_id>", methods=["GET"])
def job_detail(job_id: int):
    job = db.get_job(job_id)
    if not job:
        return _err("job not found", 404)
    return jsonify(job)


@app.route("/api/jobs/<int:job_id>", methods=["DELETE"])
def delete_job(job_id: int):
    db.delete_job(job_id)
    sessions.pop(job_id, None)
    return jsonify({"ok": True})


# ── Studies ───────────────────────────────────────────────────────────────────

@app.route("/api/studies", methods=["GET"])
def list_studies():
    instance_id = request.args.get("instance_id")
    data = db.list_studies(instance_id=int(instance_id) if instance_id else None)
    return jsonify({"studies": data})


@app.route("/api/studies/<int:study_id>", methods=["GET"])
def study_detail(study_id: int):
    study = db.get_study(study_id)
    if not study:
        return _err("study not found", 404)
    return jsonify(study)


@app.route("/api/studies/<int:study_id>/html", methods=["GET"])
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
def delete_study(study_id: int):
    db.delete_study(study_id)
    return jsonify({"ok": True})


# ── Replication ───────────────────────────────────────────────────────────────

@app.route("/api/replicate/plan", methods=["POST"])
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
def get_notify_config():
    return jsonify({"config": notifier.get_config()})


@app.route("/api/notifications/config", methods=["POST"])
def set_notify_config():
    payload = request.get_json(force=True) or {}
    return jsonify({"config": notifier.save_config(payload)})


@app.route("/api/notifications/test", methods=["POST"])
def test_notify():
    return jsonify(notifier.test())


# ── Scheduler ─────────────────────────────────────────────────────────────────

@app.route("/api/scheduler/jobs", methods=["GET"])
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
