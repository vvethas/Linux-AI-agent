"""
notify.py — Slack webhook + SMTP email notifications.
"""
import json
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests

from .db import get_config

log = logging.getLogger(__name__)


def _get_cfg() -> dict:
    raw = get_config("notify_config", "{}")
    try:
        return json.loads(raw)
    except Exception:
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# Slack
# ─────────────────────────────────────────────────────────────────────────────

def _severity_color(score: int) -> str:
    if score >= 80:
        return "#4caf50"
    if score >= 60:
        return "#e5b840"
    return "#e05252"


def _slack_post(webhook: str, payload: dict) -> bool:
    try:
        resp = requests.post(webhook, json=payload, timeout=10)
        return resp.status_code == 200
    except Exception as exc:
        log.error("Slack post failed: %s", exc)
        return False


def _build_slack_study_payload(instance_label: str, report: dict) -> dict:
    summary = report.get("summary", {})
    score = summary.get("health_score", 0)
    color = _severity_color(int(score))
    findings = "\n".join(f"• {f}" for f in summary.get("key_findings", [])[:5])
    return {
        "attachments": [{
            "color": color,
            "title": f"Study Report — {instance_label}",
            "fields": [
                {"title": "Health Score", "value": str(score), "short": True},
                {"title": "Role", "value": summary.get("role", "unknown"), "short": True},
                {"title": "Key Findings", "value": findings or "None", "short": False},
            ],
            "footer": "Linux AI Agent",
        }]
    }


def _build_slack_job_payload(instance_label: str, job: dict) -> dict:
    status = job.get("status", "unknown")
    color = "#4caf50" if status == "done" else "#e05252"
    return {
        "attachments": [{
            "color": color,
            "title": f"Job {status.upper()} — {instance_label}",
            "fields": [
                {"title": "Type", "value": job.get("type", "?"), "short": True},
                {"title": "Title", "value": job.get("title", "?"), "short": True},
                {"title": "Duration", "value": f'{job.get("duration_sec", 0):.0f}s', "short": True},
            ],
            "footer": "Linux AI Agent",
        }]
    }


def _build_slack_down_payload(instance_label: str, host: str) -> dict:
    return {
        "attachments": [{
            "color": "#e05252",
            "title": f"⚠ Instance Unreachable — {instance_label}",
            "text": f"Cannot SSH into `{host}`. Please investigate.",
            "footer": "Linux AI Agent",
        }]
    }


# ─────────────────────────────────────────────────────────────────────────────
# Email
# ─────────────────────────────────────────────────────────────────────────────

def _send_email(cfg: dict, subject: str, html_body: str, plain_body: str) -> bool:
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = cfg.get("email_from", "linux-agent@localhost")
        msg["To"] = cfg.get("email_to", "")
        msg.attach(MIMEText(plain_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        host = cfg.get("smtp_host", "")
        port = int(cfg.get("smtp_port", 587))
        use_tls = cfg.get("smtp_tls", True)

        if use_tls:
            server = smtplib.SMTP(host, port, timeout=20)
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(host, port, timeout=20)

        if cfg.get("smtp_user"):
            server.login(cfg["smtp_user"], cfg.get("smtp_pass", ""))
        server.sendmail(msg["From"], [msg["To"]], msg.as_string())
        server.quit()
        return True
    except Exception as exc:
        log.error("Email send failed: %s", exc)
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Public notification functions
# ─────────────────────────────────────────────────────────────────────────────

def notify_study_complete(instance: dict, report: dict):
    """Fire if health_score < threshold OR failed_services > 0."""
    cfg = _get_cfg()
    if not cfg.get("enabled"):
        return

    score = int((report.get("summary") or {}).get("health_score", 100))
    threshold = int(cfg.get("alert_score_below", 70))
    failed = int((report.get("services") or {}).get("total_failed", 0))

    should_fire = (
        cfg.get("notify_all_studies")
        or score < threshold
        or (cfg.get("alert_on_failed_services") and failed > 0)
    )
    if not should_fire:
        return

    label = instance.get("label", instance.get("host", "unknown"))

    if cfg.get("slack_webhook"):
        payload = _build_slack_study_payload(label, report)
        _slack_post(cfg["slack_webhook"], payload)

    if cfg.get("email_to") and cfg.get("smtp_host"):
        subject = f"[Linux Agent] Study Alert — {label} (score {score})"
        plain = f"Health score: {score}\nFailed services: {failed}"
        html = f"<h3>Study Alert</h3><p>Health score: <b>{score}</b></p><p>Failed services: <b>{failed}</b></p>"
        _send_email(cfg, subject, html, plain)


def notify_job_complete(instance: dict, job: dict):
    """Fire for all build/troubleshoot/replicate job completions."""
    cfg = _get_cfg()
    if not cfg.get("enabled") or not cfg.get("notify_jobs"):
        return

    label = instance.get("label", instance.get("host", "unknown"))

    if cfg.get("slack_webhook"):
        payload = _build_slack_job_payload(label, job)
        _slack_post(cfg["slack_webhook"], payload)

    if cfg.get("email_to") and cfg.get("smtp_host"):
        status = job.get("status", "unknown")
        subject = f"[Linux Agent] Job {status.upper()} — {label}"
        plain = f"Job: {job.get('title')}\nType: {job.get('type')}\nStatus: {status}"
        html = f"<h3>Job {status.upper()}</h3><p>{plain}</p>"
        _send_email(cfg, subject, html, plain)


def notify_instance_down(instance: dict):
    """Fire when scheduled check cannot SSH into instance."""
    cfg = _get_cfg()
    if not cfg.get("enabled") or not cfg.get("notify_unreachable"):
        return

    label = instance.get("label", instance.get("host", "unknown"))
    host = instance.get("host", "unknown")

    if cfg.get("slack_webhook"):
        payload = _build_slack_down_payload(label, host)
        _slack_post(cfg["slack_webhook"], payload)

    if cfg.get("email_to") and cfg.get("smtp_host"):
        subject = f"[Linux Agent] Instance DOWN — {label}"
        plain = f"Cannot SSH into {host}. Please investigate."
        html = f"<h3>Instance Unreachable</h3><p>Cannot SSH into <b>{host}</b></p>"
        _send_email(cfg, subject, html, plain)


def send_test_notification(cfg: dict) -> dict:
    """Test Slack and/or email with the provided config."""
    results = {}
    if cfg.get("slack_webhook"):
        ok = _slack_post(cfg["slack_webhook"], {"text": "Linux AI Agent — test notification ✓"})
        results["slack"] = "ok" if ok else "failed"
    if cfg.get("email_to") and cfg.get("smtp_host"):
        ok = _send_email(cfg, "[Linux Agent] Test Notification", "<p>Test OK</p>", "Test OK")
        results["email"] = "ok" if ok else "failed"
    return results
