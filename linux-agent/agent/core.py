"""
core.py — Claude API calls for troubleshoot and build modes.

All Claude calls use POST https://api.anthropic.com/v1/messages
and strip ```json fences before parsing.
"""
import json
import logging
import os
import re

import requests

log = logging.getLogger(__name__)

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-sonnet-4-20250514"
MAX_TOKENS = 4000
ANTHROPIC_VERSION = "2023-06-01"


# ─────────────────────────────────────────────────────────────────────────────
# Low-level helpers
# ─────────────────────────────────────────────────────────────────────────────

def _api_key() -> str:
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY environment variable is not set")
    return key


def _strip_fences(text: str) -> str:
    """Remove ```json … ``` or ``` … ``` fences."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


def _call(system: str, messages: list) -> str:
    """Raw Claude API call. Returns the assistant's text content."""
    headers = {
        "x-api-key": _api_key(),
        "anthropic-version": ANTHROPIC_VERSION,
        "content-type": "application/json",
    }
    body = {
        "model": MODEL,
        "max_tokens": MAX_TOKENS,
        "system": system,
        "messages": messages,
    }
    resp = requests.post(ANTHROPIC_API_URL, headers=headers, json=body, timeout=120)
    resp.raise_for_status()
    data = resp.json()
    return data["content"][0]["text"]


def _call_json(system: str, messages: list) -> dict:
    """Claude API call that parses the response as JSON."""
    raw = _call(system, messages)
    clean = _strip_fences(raw)
    return json.loads(clean)


# ─────────────────────────────────────────────────────────────────────────────
# Feature 3 — Intent classification
# ─────────────────────────────────────────────────────────────────────────────

CLASSIFY_SYSTEM = (
    "Classify the user's message as either troubleshoot or build. "
    "Reply with exactly one word: troubleshoot or build."
)


def classify_intent(user_message: str) -> str:
    """Returns 'troubleshoot' or 'build'."""
    result = _call(
        CLASSIFY_SYSTEM,
        [{"role": "user", "content": user_message}],
    )
    result = result.strip().lower()
    if "build" in result:
        return "build"
    return "troubleshoot"


# ─────────────────────────────────────────────────────────────────────────────
# Feature 1 — Troubleshoot
# ─────────────────────────────────────────────────────────────────────────────

TROUBLESHOOT_SYSTEM = """You are a Linux troubleshooting AI. \
Analyze the provided diagnostics and return ONLY valid JSON (no markdown fences):
{
  "diagnosis": "<string>",
  "risk_level": "low|medium|high",
  "steps": [
    {
      "id": "<string>",
      "title": "<string>",
      "description": "<string>",
      "commands": ["<cmd1>", "<cmd2>"],
      "risky": false
    }
  ],
  "verification": "<shell command to verify the fix>"
}"""


def generate_fix_plan(diagnostics: dict, user_issue: str, history: list) -> dict:
    """
    Send diagnostics + issue description to Claude.
    Returns parsed JSON plan.
    history is the conversation messages list (mutated in place for multi-turn).
    """
    content = (
        f"Issue reported by user: {user_issue}\n\n"
        f"Diagnostics collected from the instance:\n{json.dumps(diagnostics, indent=2)}"
    )
    history.append({"role": "user", "content": content})
    result = _call_json(TROUBLESHOOT_SYSTEM, history)
    history.append({"role": "assistant", "content": json.dumps(result)})
    return result


def summarize_step_output(step: dict, output: str, history: list) -> str:
    """
    After executing a step, send the output back to Claude for a brief summary.
    Returns a plain-text summary string.
    """
    content = (
        f"Step '{step.get('title')}' executed.\n"
        f"Commands: {step.get('commands')}\n"
        f"Output:\n{output[:3000]}"
    )
    history.append({"role": "user", "content": content})
    system = (
        "You are a Linux troubleshooting AI. "
        "The user just executed a fix step. "
        "Briefly summarise the output (2-4 sentences) and indicate if it succeeded."
    )
    result = _call(system, history)
    history.append({"role": "assistant", "content": result})
    return result


def run_verification_summary(verification_cmd: str, output: str, history: list) -> str:
    content = (
        f"Verification command: {verification_cmd}\n"
        f"Output:\n{output[:3000]}"
    )
    history.append({"role": "user", "content": content})
    system = (
        "You are a Linux troubleshooting AI. "
        "Briefly state whether the verification confirms the issue is resolved."
    )
    result = _call(system, history)
    history.append({"role": "assistant", "content": result})
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Feature 2 — Build mode
# ─────────────────────────────────────────────────────────────────────────────

BUILD_SYSTEM = """You are a Linux infrastructure automation AI. \
Given system specs and the user's deployment request, return ONLY valid JSON:
{
  "intent": "<string>",
  "method": "<e.g. kolla-ansible|packstack|microstack|proxmox|k3s|kubeadm|docker-swarm>",
  "requirements": {
    "min_ram_gb": 0,
    "min_disk_gb": 0,
    "min_cpus": 0,
    "required_os": ["<os_name>"]
  },
  "requirements_met": true,
  "requirements_issues": [],
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
          "commands": ["<cmd1>"]
        }
      ]
    }
  ],
  "post_install": {
    "endpoints": ["<url or desc>"],
    "credential_commands": ["<cmd>"],
    "verification_commands": ["<cmd>"]
  },
  "estimated_total_minutes": 0
}
Supported methods: OpenStack (kolla-ansible for ≥16GB RAM, microstack for <16GB),
Proxmox VE, K3s, kubeadm, Docker Swarm. Choose the best method for the specs."""


def generate_build_plan(specs: dict, user_request: str, history: list) -> dict:
    content = (
        f"User request: {user_request}\n\n"
        f"System specs:\n{json.dumps(specs, indent=2)}"
    )
    history.append({"role": "user", "content": content})
    result = _call_json(BUILD_SYSTEM, history)
    history.append({"role": "assistant", "content": json.dumps(result)})
    return result


def summarize_build_step(step: dict, output: str, history: list) -> str:
    content = (
        f"Build step '{step.get('title')}' executed.\n"
        f"Commands: {step.get('commands')}\n"
        f"Output:\n{output[:3000]}"
    )
    history.append({"role": "user", "content": content})
    system = (
        "You are a Linux infrastructure automation AI. "
        "Summarise this build step's output (2-4 sentences) and note success or failure."
    )
    result = _call(system, history)
    history.append({"role": "assistant", "content": result})
    return result


def collect_post_install(post_install: dict, outputs: list, history: list) -> str:
    content = (
        f"Post-install commands executed.\n"
        f"Endpoints: {post_install.get('endpoints')}\n"
        f"Outputs:\n{json.dumps(outputs[:10], indent=2)}"
    )
    history.append({"role": "user", "content": content})
    system = (
        "You are a Linux infrastructure automation AI. "
        "Summarise the post-install results, list discovered credentials and endpoints."
    )
    result = _call(system, history)
    history.append({"role": "assistant", "content": result})
    return result
