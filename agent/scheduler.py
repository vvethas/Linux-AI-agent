from datetime import datetime, timezone
from threading import Thread
from typing import Any, Dict, List, Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from .db import Database
from .notify import Notifier
from .ssh import SSHManager
from .study import StudyRunner


class HealthScheduler:
    def __init__(
        self,
        db: Database,
        ssh: SSHManager,
        study_runner: StudyRunner,
        notifier: Notifier,
    ):
        self.db = db
        self.ssh = ssh
        self.study_runner = study_runner
        self.notifier = notifier
        self.scheduler = BackgroundScheduler(timezone="UTC")
        self._started = False

    @staticmethod
    def _job_id(instance_id: int) -> str:
        return f"health_check_{instance_id}"

    def start(self) -> None:
        if not self._started:
            self.scheduler.start()
            self._started = True
        self.reload_from_db()

    def shutdown(self) -> None:
        if self._started:
            self.scheduler.shutdown(wait=False)
            self._started = False

    def reload_from_db(self) -> None:
        for schedule in self.db.list_enabled_schedules():
            self.apply_schedule(schedule["instance_id"])

    def apply_schedule(self, instance_id: int) -> None:
        schedule = self.db.get_schedule(instance_id)
        if not schedule or not schedule.get("enabled"):
            self.remove_schedule(instance_id)
            return

        job_id = self._job_id(instance_id)
        existing = self.scheduler.get_job(job_id)
        if existing:
            self.scheduler.remove_job(job_id)

        if schedule["mode"] == "interval":
            hours = max(1, int(schedule.get("interval_hours") or 1))
            self.scheduler.add_job(
                self.run_check,
                "interval",
                hours=hours,
                args=[instance_id],
                id=job_id,
                replace_existing=True,
            )
        else:
            raw_expr = schedule.get("cron_expr") or "0 */6 * * *"
            parts = raw_expr.split()
            if len(parts) != 5:
                parts = ["0", "*/6", "*", "*", "*"]
            trigger = CronTrigger(
                minute=parts[0],
                hour=parts[1],
                day=parts[2],
                month=parts[3],
                day_of_week=parts[4],
                timezone="UTC",
            )
            self.scheduler.add_job(
                self.run_check,
                trigger=trigger,
                args=[instance_id],
                id=job_id,
                replace_existing=True,
            )

    def remove_schedule(self, instance_id: int) -> None:
        job_id = self._job_id(instance_id)
        if self.scheduler.get_job(job_id):
            self.scheduler.remove_job(job_id)

    def list_jobs(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": job.id,
                "next_run": (
                    job.next_run_time.isoformat() if job.next_run_time else None
                ),
                "trigger": str(job.trigger),
            }
            for job in self.scheduler.get_jobs()
        ]

    def trigger_manual(self, instance_id: int) -> None:
        thread = Thread(target=self.run_check, args=(instance_id,), daemon=True)
        thread.start()

    def run_check(self, instance_id: int) -> Dict[str, Any]:
        instance = self.db.get_instance(instance_id)
        if not instance:
            return {"ok": False, "error": "instance not found"}

        now = datetime.now(timezone.utc).isoformat()
        ok, reason = self.ssh.test_connection(instance)

        if not ok:
            self.db.update_instance_status(instance_id, "offline")
            entry: Dict[str, Any] = {"time": now, "status": "offline", "error": reason}
            self.db.append_check_log(instance_id, entry)
            self.notifier.notify_instance_down(instance, reason)
            return {"ok": False, "error": reason}

        self.db.update_instance_status(instance_id, "online")

        try:
            result = self.study_runner.run(instance, note="scheduled health check")
        except Exception as exc:
            entry = {"time": now, "status": "study_error", "error": str(exc)}
            self.db.append_check_log(instance_id, entry)
            return {"ok": False, "error": str(exc)}

        report = result["report"]
        self.notifier.notify_study_complete(instance, report)

        entry = {
            "time": now,
            "status": "online",
            "health_score": report.get("summary", {}).get("health_score"),
            "study_id": result["study_id"],
        }
        self.db.append_check_log(instance_id, entry)
        return {"ok": True, "study_id": result["study_id"]}
