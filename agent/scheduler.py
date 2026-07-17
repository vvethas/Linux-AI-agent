from datetime import datetime, timezone
from threading import Thread
from typing import Any, Dict, List, Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from .db import Database
from .notify import Notifier
from .ssh import SSHManager
from .study import StudyRunner

# Drift thresholds
_DRIFT_WARN_PCT = 20.0   # warn if metric is >20 percentage points above rolling avg
_DRIFT_CRIT_SVC = True   # critical alert whenever a monitored service goes failed


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

    @staticmethod
    def _critical_renotify_job_id() -> str:
        return "critical_alert_renotify"

    def start(self) -> None:
        if not self._started:
            self.scheduler.start()
            self._started = True
            self.scheduler.add_job(
                self.notifier.process_critical_renotifications,
                "interval",
                minutes=1,
                id=self._critical_renotify_job_id(),
                replace_existing=True,
            )
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

    # ── Drift / correlation helpers ───────────────────────────────────────────

    def _check_metric_drift(self, instance_id: int, metric: str, current: float) -> None:
        avg = self.db.get_metric_rolling_avg(instance_id, metric, n=10)
        if avg is None:
            return
        diff = current - avg
        alert_msg = f"{metric.upper()} usage at {current:.0f}% — {diff:+.0f}pp vs rolling avg ({avg:.0f}%)"
        if diff >= _DRIFT_WARN_PCT:
            existing = self.db.find_open_alert(instance_id, "warning", alert_msg)
            if not existing:
                self.db.create_alert(instance_id, "warning", alert_msg)
        else:
            self.db.resolve_alerts_for_condition(instance_id, "warning", alert_msg)

    def _check_service_drift(self, instance_id: int, service_name: str, status: str) -> None:
        alert_msg = f"Monitored service '{service_name}' is failed"
        if status == "failed":
            existing = self.db.find_open_alert(instance_id, "critical", alert_msg)
            if not existing:
                self.db.create_alert(instance_id, "critical", alert_msg)
        else:
            self.db.resolve_alerts_for_condition(instance_id, "critical", alert_msg)

    def _generate_and_cache_insight(
        self,
        instance_id: int,
        metrics: Dict[str, Optional[float]],
        service_statuses: List[Dict[str, Any]],
    ) -> None:
        """Generate an AI correlation insight and cache it in the config table."""
        # Only run if something is notable
        failed_svcs = [s["service_name"] for s in service_statuses if s.get("status") == "failed"]
        high_metrics = {k: v for k, v in metrics.items() if v is not None and v >= 80}
        if not failed_svcs and not high_metrics:
            return

        # Build a short context summary
        metric_lines = ", ".join(f"{k}={v:.0f}%" for k, v in high_metrics.items())
        svc_lines = ", ".join(failed_svcs)
        context_parts = []
        if metric_lines:
            context_parts.append(f"High metrics: {metric_lines}")
        if svc_lines:
            context_parts.append(f"Failed services: {svc_lines}")

        # Fetch recent metric history for context
        history_lines: List[str] = []
        for metric in ("cpu", "mem", "disk"):
            pts = self.db.get_metric_history(instance_id, metric, hours=4)
            if pts:
                vals = [f"{p['value']:.0f}" for p in pts[-6:]]
                history_lines.append(f"{metric}: [{', '.join(vals)}]")

        full_context = "; ".join(context_parts)
        if history_lines:
            full_context += " | Recent trend: " + "; ".join(history_lines)

        try:
            from .core import ClaudeClient
            client = ClaudeClient()
            if not client.api_key:
                return
            prompt = (
                f"Briefly (1 sentence, ≤20 words) note any notable correlation "
                f"or drift for this Linux instance: {full_context}. "
                f"Be specific about what metric or service and why it matters."
            )
            result = client.call_json(
                system_prompt=(
                    "You are a Linux monitoring assistant. "
                    "Respond with JSON: {{\"insight\": \"<one sentence>\"}}"
                ),
                user_message=prompt,
            )
            insight = result.get("insight", "")
            if insight:
                self.db.set_config_json(
                    f"insight_{instance_id}",
                    {
                        "text": insight,
                        "generated_at": datetime.now(timezone.utc).isoformat(),
                    },
                )
        except Exception:
            pass

    # ── Main poll cycle ───────────────────────────────────────────────────────

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
        self.notifier.resolve_instance_reachable(instance_id)

        # ── Collect and persist quick metrics ────────────────────────────────
        try:
            metrics = self.ssh.collect_quick_metrics(instance)
            for metric, value in metrics.items():
                if value is not None:
                    self.db.add_metric_history(instance_id, metric, value)
                    self._check_metric_drift(instance_id, metric, value)
        except Exception:
            metrics: Dict[str, Optional[float]] = {}

        # ── Poll monitored services ───────────────────────────────────────────
        service_statuses: List[Dict[str, Any]] = []
        try:
            monitored = self.db.list_monitored_services(instance_id)
            for svc in monitored:
                svc_name = svc["service_name"]
                try:
                    res = self.ssh.execute(
                        instance,
                        f"systemctl is-active {svc_name} 2>/dev/null || echo failed",
                        timeout=10,
                        get_pty=False,
                    )
                    raw = res.get("stdout", "").strip().lower()
                    status = "running" if raw == "active" else "failed"
                except Exception:
                    status = "failed"
                self.db.add_service_status(instance_id, svc_name, status)
                self._check_service_drift(instance_id, svc_name, status)
                service_statuses.append({"service_name": svc_name, "status": status})
        except Exception:
            pass

        # ── AI correlation insight ────────────────────────────────────────────
        try:
            self._generate_and_cache_insight(instance_id, metrics, service_statuses)
        except Exception:
            pass

        # ── Study ─────────────────────────────────────────────────────────────
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
