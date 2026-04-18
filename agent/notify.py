import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, Optional

import requests

from .db import Database


DEFAULT_NOTIFY_CONFIG: Dict[str, Any] = {
    "slack_webhook": "",
    "enabled": False,
    "alert_score_below": 70,
    "alert_on_failed_services": True,
    "notify_all_studies": False,
    "notify_jobs": True,
    "notify_unreachable": True,
    "smtp_host": "",
    "smtp_port": 587,
    "smtp_user": "",
    "smtp_pass": "",
    "email_from": "",
    "email_to": "",
    "smtp_tls": True,
}


class Notifier:
    def __init__(self, db: Database):
        self.db = db

    def get_config(self) -> Dict[str, Any]:
        cfg = self.db.get_config_json("notify_config", default=DEFAULT_NOTIFY_CONFIG)
        merged = DEFAULT_NOTIFY_CONFIG.copy()
        merged.update(cfg)
        return merged

    def save_config(self, cfg: Dict[str, Any]) -> Dict[str, Any]:
        merged = self.get_config()
        merged.update(cfg)
        self.db.set_config_json("notify_config", merged)
        return merged

    # ── Transport helpers ─────────────────────────────────────────────────────

    def _send_slack(self, title: str, body: str, severity: str = "info") -> Optional[str]:
        cfg = self.get_config()
        webhook = cfg.get("slack_webhook", "")
        if not webhook:
            return "slack_webhook not configured"
        color_map = {
            "ok": "#4caf50",
            "warn": "#e5b840",
            "error": "#e05252",
            "info": "#5b9bd5",
        }
        color = color_map.get(severity, "#5b9bd5")
        payload = {
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": f"*{title}*\n{body}"},
                        }
                    ],
                }
            ]
        }
        try:
            requests.post(webhook, json=payload, timeout=15).raise_for_status()
            return None
        except Exception as exc:
            return str(exc)

    def _send_email(
        self, subject: str, text_body: str, html_body: str
    ) -> Optional[str]:
        cfg = self.get_config()
        required_keys = ["smtp_host", "smtp_port", "email_from", "email_to"]
        if any(not cfg.get(k) for k in required_keys):
            return "SMTP config incomplete"

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = str(cfg["email_from"])
        msg["To"] = str(cfg["email_to"])
        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        try:
            port = int(cfg.get("smtp_port", 587))
            use_tls = bool(cfg.get("smtp_tls", True))
            if use_tls:
                server = smtplib.SMTP(str(cfg["smtp_host"]), port, timeout=20)
                server.starttls()
            else:
                server = smtplib.SMTP_SSL(str(cfg["smtp_host"]), port, timeout=20)
            if cfg.get("smtp_user"):
                server.login(str(cfg["smtp_user"]), str(cfg.get("smtp_pass", "")))
            server.sendmail(
                str(cfg["email_from"]), [str(cfg["email_to"])], msg.as_string()
            )
            server.quit()
            return None
        except Exception as exc:
            return str(exc)

    def _dispatch(
        self, title: str, body: str, severity: str = "info"
    ) -> Dict[str, Any]:
        cfg = self.get_config()
        if not cfg.get("enabled"):
            return {"sent": False, "reason": "notifications disabled"}

        slack_err = self._send_slack(title, body, severity)
        html_body = f"<h3>{title}</h3><pre>{body}</pre>"
        email_err = self._send_email(title, body, html_body)

        return {
            "sent": not (slack_err and email_err),
            "slack_error": slack_err,
            "email_error": email_err,
        }

    # ── Alert events ───────────────────────────────────────────────────────────

    def notify_study_complete(
        self, instance: Dict[str, Any], report: Dict[str, Any]
    ) -> Dict[str, Any]:
        summary = report.get("summary", {})
        health = int(summary.get("health_score", 0) or 0)
        failed = int(report.get("services", {}).get("total_failed", 0) or 0)
        cfg = self.get_config()

        should_alert = bool(cfg.get("notify_all_studies", False))
        should_alert = should_alert or health < int(cfg.get("alert_score_below", 70))
        should_alert = should_alert or (
            bool(cfg.get("alert_on_failed_services", True)) and failed > 0
        )
        if not should_alert:
            return {"sent": False, "reason": "threshold not met"}

        severity = "error" if (health < 50 or failed > 3) else "warn"
        body = (
            f"Instance: {instance.get('label','?')}\n"
            f"Health: {health}/100\n"
            f"Failed services: {failed}\n"
            f"Headline: {summary.get('headline','')}"
        )
        return self._dispatch("Study complete alert", body, severity)

    def notify_job_complete(
        self, instance: Dict[str, Any], job: Dict[str, Any]
    ) -> Dict[str, Any]:
        cfg = self.get_config()
        if not cfg.get("notify_jobs", True):
            return {"sent": False, "reason": "job alerts disabled"}
        severity = "ok" if job.get("status") == "completed" else "error"
        body = (
            f"Instance: {instance.get('label','N/A')}\n"
            f"Job #{job.get('id')} ({job.get('type','?')})\n"
            f"Status: {job.get('status','?')}\n"
            f"Title: {job.get('title','')}"
        )
        return self._dispatch("Job completed", body, severity)

    def notify_instance_down(
        self, instance: Dict[str, Any], error: str
    ) -> Dict[str, Any]:
        cfg = self.get_config()
        if not cfg.get("notify_unreachable", True):
            return {"sent": False, "reason": "unreachable alerts disabled"}
        body = (
            f"Instance: {instance.get('label','?')} ({instance.get('host','?')})\n"
            f"Status: unreachable\n"
            f"Error: {error}"
        )
        return self._dispatch("Instance unreachable", body, "error")

    def test(self) -> Dict[str, Any]:
        return self._dispatch(
            "Linux AI Agent — test notification",
            "This is a test alert from the Linux AI Agent.",
            "info",
        )
