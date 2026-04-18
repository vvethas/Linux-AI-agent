"""
replicate.py — Instance replication plan + execution.
"""
import json
import logging

from .core import _call_json
from . import ssh as _ssh

log = logging.getLogger(__name__)

REPLICATE_SYSTEM = """You are a Linux infrastructure replication AI.
Given the source instance's study report and target specs, produce a replication plan.
Return ONLY valid JSON (no markdown fences):
{
  "summary": "<string>",
  "source_role": "<string>",
  "warnings": ["<string>"],
  "phases": [
    {
      "id": "<string>",
      "name": "<string>",
      "description": "<string>",
      "estimated_minutes": 0,
      "risky": false,
      "steps": [
        {
          "id": "<string>",
          "title": "<string>",
          "description": "<string>",
          "commands": ["<cmd>"],
          "verify_cmd": "<optional shell command>"
        }
      ]
    }
  ],
  "ansible_playbook": "<full YAML string>",
  "post_verify": {
    "commands": ["<cmd>"],
    "description": "<string>"
  },
  "estimated_total_minutes": 0
}

Rules:
- SKIP: IP addresses, hostnames, SSH keys, SSL certificates, UUIDs.
- REPLICATE: packages, services, non-root users (no passwords), software versions,
  configs, cron jobs, kernel settings, environment deployments (OpenStack/K8s/Docker).
- If OS or RAM differs significantly, include a warning but still produce a best-effort plan.
"""


def generate_replication_plan(
    source_report: dict,
    target_specs: dict,
    source_instance: dict,
    target_instance: dict,
    history: list,
) -> dict:
    content = (
        f"Source instance: {source_instance.get('label')} ({source_instance.get('host')})\n"
        f"Target instance: {target_instance.get('label')} ({target_instance.get('host')})\n\n"
        f"Source study report:\n{json.dumps(source_report, indent=2)}\n\n"
        f"Target quick specs:\n{json.dumps(target_specs, indent=2)}"
    )
    history.append({"role": "user", "content": content})
    result = _call_json(REPLICATE_SYSTEM, history)
    history.append({"role": "assistant", "content": json.dumps(result)})
    return result


def execute_replication_step(instance: dict, step: dict) -> dict:
    """Execute a single replication step on the target instance."""
    commands = step.get("commands", [])
    outputs = _ssh.run_commands(instance, commands, timeout=600)
    combined = "\n".join(
        f"$ {r['command']}\n{r['stdout']}{r['stderr']}"
        for r in outputs
    )
    success = all(r["success"] for r in outputs)

    verify_output = ""
    if step.get("verify_cmd") and success:
        try:
            stdout, stderr, code = _ssh.run_command(instance, step["verify_cmd"], timeout=30)
            verify_output = stdout.strip() or stderr.strip()
        except Exception as exc:
            verify_output = f"verify error: {exc}"

    return {
        "output": combined,
        "verify_output": verify_output,
        "success": success,
    }


def run_post_verify(instance: dict, post_verify: dict) -> dict:
    commands = post_verify.get("commands", [])
    results = _ssh.run_commands(instance, commands, timeout=60)
    combined = "\n".join(
        f"$ {r['command']}\n{r['stdout']}{r['stderr']}"
        for r in results
    )
    return {
        "output": combined,
        "success": all(r["success"] for r in results),
    }


def save_playbook_to_target(instance: dict, playbook_yaml: str) -> str:
    """Write the Ansible playbook to /tmp/replication_playbook.yml on target via SFTP."""
    remote_path = "/tmp/replication_playbook.yml"
    _ssh.sftp_write(instance, remote_path, playbook_yaml)
    return remote_path
