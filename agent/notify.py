from typing import Any, Dict, List, Optional

import requests

from .db import Database


DEFAULT_NOTIFY_CONFIG: Dict[str, Any] = {
    "slack_webhook": "",
    "enabled": False,
    "notify_all_instances": True,
    "critical_slack": True,
    "critical_email": True,
    "warning_slack": True,
    "warning_email": True,
    "info_slack": True,
    "info_email": True,
    "critical_renotify_minutes": 5,
    "warning_health_score_below": 70,
    "smtp_host": "",
    "smtp_port": 587,
    "smtp_user": "",
    "smtp_pass": "",
    "email_from": "",
    "email_to": "",
    "smtp_tls": True,
}

ALERT_MSG_INSTANCE_UNREACHABLE = "Instance unreachable"
ALERT_MSG_FAILED_SERVICES = "Failed services detected"
ALERT_MSG_HEALTH_BELOW_THRESHOLD = "Health score below warning threshold"


class Notifier:
    def __init__(self, db: Database):
        self.db = db

    def _migrate_legacy_config(self, cfg: Dict[str, Any]) -> Dict[str, Any]:
        migrated = dict(cfg)
        if "notify_all_instances" not in migrated:
            migrated["notify_all_instances"] = bool(migrated.get("notify_all_studies", True))
        if "warning_health_score_below" not in migrated:
            migrated["warning_health_score_below"] = int(migrated.get("alert_score_below", 70) or 70)
        return migrated

    def get_config(self) -> Dict[str, Any]:
        cfg = self.db.get_config_json("notify_config", default=DEFAULT_NOTIFY_CONFIG)
        cfg = self._migrate_legacy_config(cfg)
        merged = DEFAULT_NOTIFY_CONFIG.copy()
        merged.update(cfg)
        return merged

    def save_config(self, cfg: Dict[str, Any]) -> Dict[str, Any]:
        merged = self.get_config()
        merged.update(cfg)
        merged = self._migrate_legacy_config(merged)
        self.db.set_config_json("notify_config", merged)
        return merged

    def get_subscriptions(self) -> List[Dict[str, Any]]:
        return self.db.list_alert_subscriptions()

    def save_subscriptions(self, instance_ids: List[int]) -> List[Dict[str, Any]]:
        self.db.set_alert_subscriptions_bulk([int(i) for i in instance_ids])
        return self.get_subscriptions()

    def _send_slack(self, title: str, body: str, severity: str = "info") -> Optional[str]:
        cfg = self.get_config()
        webhook = cfg.get("slack_webhook", "")
        if not webhook:
            return "slack_webhook not configured"
        color_map = {
            "critical": "#e05252",
            "warning": "#e5b840",
            "info": "#5b9bd5",
        }
        payload = {
            "attachments": [
                {
                    "color": color_map.get(severity, "#5b9bd5"),
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

    def _send_email(self, subject: str, body: str) -> Optional[str]:
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        import smtplib
        import ssl

        cfg = self.get_config()
        required_keys = ["smtp_host", "smtp_port", "email_from", "email_to"]
        if any(not cfg.get(k) for k in required_keys):
            return "SMTP config incomplete"

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = str(cfg["email_from"])
        msg["To"] = str(cfg["email_to"])
        msg.attach(MIMEText(body, "plain"))
        msg.attach(MIMEText(f"<h3>{subject}</h3><pre>{body}</pre>", "html"))

        try:
            port = int(cfg.get("smtp_port", 587))
            use_tls = bool(cfg.get("smtp_tls", True))
            if use_tls:
                context = ssl.create_default_context()
                server = smtplib.SMTP(str(cfg["smtp_host"]), port, timeout=20)
                server.starttls(context=context)
            else:
                server = smtplib.SMTP_SSL(str(cfg["smtp_host"]), port, timeout=20)
            if cfg.get("smtp_user"):
                server.login(str(cfg["smtp_user"]), str(cfg.get("smtp_pass", "")))
            server.sendmail(str(cfg["email_from"]), [str(cfg["email_to"])], msg.as_string())
            server.quit()
            return None
        except Exception as exc:
            return str(exc)

    def _instance_notifications_enabled(self, instance_id: int, cfg: Dict[str, Any]) -> bool:
        if instance_id <= 0:
            return True
        if bool(cfg.get("notify_all_instances", True)):
            return True
        sub_map = {
            int(s["instance_id"]): bool(s["notify_enabled"])
            for s in self.db.list_alert_subscriptions()
        }
        return bool(sub_map.get(int(instance_id), False))

    def _dispatch(self, instance_id: int, title: str, body: str, severity: str) -> Dict[str, Any]:
        cfg = self.get_config()
        if not cfg.get("enabled"):
            return {"sent": False, "reason": "notifications disabled"}
        if not self._instance_notifications_enabled(int(instance_id), cfg):
            return {"sent": False, "reason": "instance not subscribed"}

        send_slack = bool(cfg.get(f"{severity}_slack", False))
        send_email = bool(cfg.get(f"{severity}_email", False))
        if not send_slack and not send_email:
            return {"sent": False, "reason": "routing disabled"}

        slack_err = self._send_slack(title, body, severity) if send_slack else None
        email_err = self._send_email(title, body) if send_email else None
        sent = (send_slack and not slack_err) or (send_email and not email_err)
        return {"sent": sent, "slack_error": slack_err, "email_error": email_err}

    def _create_alert_if_missing(self, instance_id: int, severity: str, message: str) -> Dict[str, Any]:
        existing = self.db.find_open_alert(instance_id, severity, message)
        if existing:
            return existing
        alert_id = self.db.create_alert(instance_id, severity, message)
        return self.db.get_alert(alert_id) or {}

    def _send_and_track(
        self,
        alert: Dict[str, Any],
        title: str,
        body: str,
    ) -> Dict[str, Any]:
        result = self._dispatch(int(alert["instance_id"]), title, body, str(alert["severity"]))
        if result.get("sent"):
            self.db.touch_alert_notification(int(alert["id"]))
        return result

    def notify_instance_down(self, instance: Dict[str, Any], error: str) -> Dict[str, Any]:
        alert = self._create_alert_if_missing(int(instance["id"]), "critical", ALERT_MSG_INSTANCE_UNREACHABLE)
        if alert.get("status") != "active" or alert.get("last_notified"):
            return {"sent": False, "reason": "already notified"}
        body = (
            f"Instance: {instance.get('label', '?')} ({instance.get('host', '?')})\n"
            f"Status: unreachable\n"
            f"Error: {error}"
        )
        return self._send_and_track(alert, "Critical alert: Instance unreachable", body)

    def resolve_instance_reachable(self, instance_id: int) -> None:
        self.db.resolve_alerts_for_condition(instance_id, "critical", ALERT_MSG_INSTANCE_UNREACHABLE)

    def notify_study_complete(self, instance: Dict[str, Any], report: Dict[str, Any]) -> Dict[str, Any]:
        summary = report.get("summary", {})
        health = int(summary.get("health_score", 0) or 0)
        failed = int(report.get("services", {}).get("total_failed", 0) or 0)
        cfg = self.get_config()
        threshold = int(cfg.get("warning_health_score_below", 70) or 70)
        responses: List[Dict[str, Any]] = []

        if failed > 0:
            crit_alert = self._create_alert_if_missing(int(instance["id"]), "critical", ALERT_MSG_FAILED_SERVICES)
            if crit_alert.get("status") == "active" and not crit_alert.get("last_notified"):
                body = (
                    f"Instance: {instance.get('label', '?')}\n"
                    f"Failed services: {failed}\n"
                    f"Health: {health}/100\n"
                    f"Headline: {summary.get('headline', '')}"
                )
                responses.append(self._send_and_track(crit_alert, "Critical alert: Failed services", body))
        else:
            self.db.resolve_alerts_for_condition(int(instance["id"]), "critical", ALERT_MSG_FAILED_SERVICES)

        if health < threshold:
            warn_alert = self._create_alert_if_missing(int(instance["id"]), "warning", ALERT_MSG_HEALTH_BELOW_THRESHOLD)
            if warn_alert.get("status") == "active" and not warn_alert.get("last_notified"):
                body = (
                    f"Instance: {instance.get('label', '?')}\n"
                    f"Health: {health}/100\n"
                    f"Threshold: {threshold}\n"
                    f"Headline: {summary.get('headline', '')}"
                )
                responses.append(self._send_and_track(warn_alert, "Warning alert: Health score low", body))
        else:
            self.db.resolve_alerts_for_condition(int(instance["id"]), "warning", ALERT_MSG_HEALTH_BELOW_THRESHOLD)

        return {"sent": any(r.get("sent") for r in responses), "results": responses}

    def notify_job_complete(self, instance: Dict[str, Any], job: Dict[str, Any]) -> Dict[str, Any]:
        message = f"Job completed #{job.get('id')}"
        alert_id = self.db.create_alert(int(instance["id"]), "info", message, status="active")
        alert = self.db.get_alert(alert_id) or {}
        body = (
            f"Instance: {instance.get('label', 'N/A')}\n"
            f"Job #{job.get('id')} ({job.get('type', '?')})\n"
            f"Status: {job.get('status', '?')}\n"
            f"Title: {job.get('title', '')}"
        )
        result = self._send_and_track(alert, "Info alert: Job completed", body)
        self.db.resolve_alert(alert_id)
        return result

    def process_critical_renotifications(self) -> Dict[str, Any]:
        cfg = self.get_config()
        interval = int(cfg.get("critical_renotify_minutes", 5) or 5)
        due = self.db.list_due_critical_alerts(interval)
        sent = 0
        for alert in due:
            if alert.get("message") == ALERT_MSG_INSTANCE_UNREACHABLE:
                body = (
                    f"Instance: {alert.get('instance_label', '?')} ({alert.get('instance_host', '?')})\n"
                    "Status: unreachable"
                )
                result = self._send_and_track(alert, "Critical alert: Instance unreachable", body)
            elif alert.get("message") == ALERT_MSG_FAILED_SERVICES:
                body = f"Instance: {alert.get('instance_label', '?')}\nFailed services remain unresolved"
                result = self._send_and_track(alert, "Critical alert: Failed services", body)
            else:
                result = self._send_and_track(alert, "Critical alert", str(alert.get("message", "")))
            if result.get("sent"):
                sent += 1
        return {"checked": len(due), "sent": sent}

    def test(self) -> Dict[str, Any]:
        return self._dispatch(
            0,
            "Linux AI Agent — test notification",
            "This is a test alert from the Linux AI Agent.",
            "info",
        )
