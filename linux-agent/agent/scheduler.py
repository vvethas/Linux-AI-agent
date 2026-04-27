"""
scheduler.py — APScheduler background health check cron.

Starts on server import via scheduler.start().
Reloads all enabled schedules from DB on startup.
"""
import logging
import threading
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from . import db, notify, ssh, study

log = logging.getLogger(__name__)

_scheduler = BackgroundScheduler(timezone="UTC")
_lock = threading.Lock()


# ─────────────────────────────────────────────────────────────────────────────
# Health check task
# ─────────────────────────────────────────────────────────────────────────────

def _run_check(instance_id: int):
    instance = db.get_instance(instance_id)
    if not instance:
        return

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "status": "unknown",
        "health_score": None,
        "error": None,
    }

    conn_result = ssh.test_connection(instance)
    if not conn_result.get("ok"):
        entry["status"] = "offline"
        entry["error"] = conn_result.get("error", "unreachable")
        db.update_instance_status(instance_id, "offline")
        db.append_check_log(instance_id, entry)
        notify.notify_instance_down(instance)
        return

    db.update_instance_status(instance_id, "online")

    # Run full study
    try:
        report, raw = study.run_study(instance)
        score = (report.get("summary") or {}).get("health_score", 0)
        entry["status"] = "online"
        entry["health_score"] = score

        job_id = db.create_job(instance_id, "study", "Scheduled Health Check")
        study_id = db.save_study_report(instance_id, job_id, report, raw)
        db.finish_job(job_id, "done", result=f"study_id={study_id}")

        notify.notify_study_complete(instance, report)
    except Exception as exc:
        log.error("Study failed for instance %s: %s", instance_id, exc)
        entry["status"] = "online"
        entry["error"] = str(exc)

    db.append_check_log(instance_id, entry)


# ─────────────────────────────────────────────────────────────────────────────
# Scheduler management
# ─────────────────────────────────────────────────────────────────────────────

def _job_id(instance_id: int) -> str:
    return f"health_check_{instance_id}"


def add_schedule(instance_id: int, mode: str, interval_hours: float, cron_expr: str):
    """Add or replace the APScheduler job for the given instance."""
    jid = _job_id(instance_id)
    with _lock:
        if _scheduler.get_job(jid):
            _scheduler.remove_job(jid)

        if mode == "cron":
            parts = cron_expr.strip().split()
            if len(parts) == 5:
                trigger = CronTrigger(
                    minute=parts[0],
                    hour=parts[1],
                    day=parts[2],
                    month=parts[3],
                    day_of_week=parts[4],
                    timezone="UTC",
                )
            else:
                log.warning("Invalid cron expression %s, falling back to interval", cron_expr)
                trigger = IntervalTrigger(hours=max(0.5, interval_hours))
        else:
            trigger = IntervalTrigger(hours=max(0.5, interval_hours))

        _scheduler.add_job(
            _run_check,
            trigger=trigger,
            id=jid,
            kwargs={"instance_id": instance_id},
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        log.info("Scheduled health check for instance %s (%s)", instance_id, mode)


def remove_schedule(instance_id: int):
    jid = _job_id(instance_id)
    with _lock:
        if _scheduler.get_job(jid):
            _scheduler.remove_job(jid)
            log.info("Removed schedule for instance %s", instance_id)


def trigger_now(instance_id: int):
    """Run a health check immediately in a background thread."""
    t = threading.Thread(target=_run_check, args=(instance_id,), daemon=True)
    t.start()


def list_jobs() -> list:
    jobs = _scheduler.get_jobs()
    return [
        {
            "id": j.id,
            "next_run": j.next_run_time.isoformat() if j.next_run_time else None,
            "trigger": str(j.trigger),
        }
        for j in jobs
    ]


def start():
    """Start scheduler and reload all enabled schedules from DB."""
    _scheduler.start()
    _reload_from_db()
    log.info("Scheduler started with %d jobs", len(_scheduler.get_jobs()))


def _reload_from_db():
    schedules = db.list_enabled_schedules()
    for s in schedules:
        try:
            add_schedule(
                s["instance_id"],
                s["mode"],
                s["interval_hours"],
                s["cron_expr"],
            )
        except Exception as exc:
            log.error("Failed to reload schedule for instance %s: %s", s["instance_id"], exc)
