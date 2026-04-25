"""
core.py — OpenAI API calls for troubleshoot and build modes.

All calls use the openai Python library (chat completions) and
strip ```json fences before parsing.
"""
import json
import logging
import os
import re

from openai import OpenAI

log = logging.getLogger(__name__)

MODEL = "gpt-4o"
MAX_TOKENS = 4000


# ─────────────────────────────────────────────────────────────────────────────
# Low-level helpers
# ─────────────────────────────────────────────────────────────────────────────

def _client() -> OpenAI:
    key = os.environ.get("OPENAI_API_KEY", "")
    if not key:
        raise RuntimeError("OPENAI_API_KEY environment variable is not set")
    return OpenAI(api_key=key)


def _strip_fences(text: str) -> str:
    """Remove ```json … ``` or ``` … ``` fences."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


def _call(system: str, messages: list) -> str:
    """Raw OpenAI chat completion call. Returns the assistant's text content."""
    openai_messages = [{"role": "system", "content": system}] + messages
    response = _client().chat.completions.create(
        model=MODEL,
        max_tokens=MAX_TOKENS,
        messages=openai_messages,
        timeout=120,
    )
    return response.choices[0].message.content


def _call_json(system: str, messages: list) -> dict:
    """OpenAI API call that parses the response as JSON."""
    raw = _call(system, messages)
    clean = _strip_fences(raw)
    return json.loads(clean)


# ─────────────────────────────────────────────────────────────────────────────
# Feature 3 — Intent classification
# ─────────────────────────────────────────────────────────────────────────────

CLASSIFY_SYSTEM = (
    "Classify the user's message into exactly one of these four categories:\n"
    "  troubleshoot — the user is reporting a problem, error, or failure that needs fixing.\n"
    "  build        — the user wants to deploy, install, or set up new infrastructure.\n"
    "  configure    — the user wants to change settings, edit config files, or reconfigure existing services.\n"
    "  explore      — the user wants to inspect, query, or learn about the current state of the "
    "instance (e.g. list services, check what is running, show logs, answer a question about the system).\n"
    "Reply with exactly one word: troubleshoot, build, configure, or explore."
)


def classify_intent(user_message: str) -> str:
    """Returns 'troubleshoot', 'build', 'configure', or 'explore'."""
    result = _call(
        CLASSIFY_SYSTEM,
        [{"role": "user", "content": user_message}],
    )
    result = result.strip().lower()
    if "build" in result:
        return "build"
    if "configure" in result:
        return "configure"
    if "explore" in result:
        return "explore"
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
    Send diagnostics + issue description to OpenAI.
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


# ─────────────────────────────────────────────────────────────────────────────
# Feature 4 — Explore / chat mode
# ─────────────────────────────────────────────────────────────────────────────

EXPLORE_SYSTEM = """You are a Linux systems assistant. \
The user wants to inspect or learn about the current state of a Linux instance. \
You are given basic diagnostics and the user's question. \
Return ONLY valid JSON (no markdown fences):
{
  "answer": "<conversational answer to the user's question>",
  "commands": [
    {"title": "<short label>", "cmd": "<shell command>"}
  ]
}
The "commands" array should contain read-only shell commands that would give the user \
the information they asked for (e.g. list services, show logs, check disk). \
Keep commands safe and non-destructive. \
If no additional commands are needed, return an empty array."""


def generate_explore_response(diagnostics: dict, user_question: str, history: list) -> dict:
    """
    Answer the user's question about the instance state.
    Returns parsed JSON with 'answer' and optional 'commands' to run.
    """
    content = (
        f"User question: {user_question}\n\n"
        f"Basic diagnostics from the instance:\n{json.dumps(diagnostics, indent=2)}"
    )
    history.append({"role": "user", "content": content})
    result = _call_json(EXPLORE_SYSTEM, history)
    history.append({"role": "assistant", "content": json.dumps(result)})
    return result


def run_explore_command(title: str, cmd: str, output: str, history: list) -> str:
    """Summarise the output of an explore command."""
    content = (
        f"Command '{title}' (`{cmd}`) executed.\n"
        f"Output:\n{output[:3000]}"
    )
    history.append({"role": "user", "content": content})
    system = (
        "You are a Linux systems assistant. "
        "Briefly summarise the command output in 2-4 sentences for a human reader."
    )
    result = _call(system, history)
    history.append({"role": "assistant", "content": result})
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Feature 5 — Conversational chat (ask clarifying questions, propose actions)
# ─────────────────────────────────────────────────────────────────────────────

CHAT_SYSTEM = """You are a Linux systems assistant having a conversation with a system administrator.
Help them manage their Linux instance through natural conversation.

You can:
  1. Ask clarifying questions when the request is ambiguous or you need more detail.
  2. Reply conversationally to general questions or small talk.
  3. When you have enough information to take a specific action, propose it and ask for confirmation.

Always reply with ONLY valid JSON (no markdown fences) in one of two forms:

Conversational reply (questions, answers, clarifications):
{
  "type": "reply",
  "reply": "<your message to the user>"
}

Action proposal (when you are ready to act and want user confirmation):
{
  "type": "action_proposal",
  "reply": "<explain what you will do and ask the user to confirm>",
  "action": {
    "intent": "troubleshoot|build|configure|explore",
    "summary": "<one-line description of the action>"
  }
}

Guidelines:
- troubleshoot: the user has a problem/error/failure that needs fixing.
- build: the user wants to deploy or install new infrastructure.
- configure: the user wants to change settings, edit config files, or reconfigure a service.
- explore: the user wants information about the system state (logs, status, disk usage, etc.).
- For destructive actions (troubleshoot, configure, build) ALWAYS use action_proposal so the user can confirm.
- For read-only information requests (explore) you may use action_proposal as well, but it is optional.
- Keep replies concise and professional."""


def chat_reply(user_message: str, instance_label: str, history: list) -> dict:
    """
    Process a conversational turn.
    Returns a dict with 'type' ('reply' | 'action_proposal') and associated fields.
    history is mutated in place for multi-turn context.
    """
    content = f"[Instance: {instance_label}]\nUser: {user_message}"
    history.append({"role": "user", "content": content})
    result = _call_json(CHAT_SYSTEM, history)
    history.append({"role": "assistant", "content": json.dumps(result)})
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Feature 6 — Configure mode
# ─────────────────────────────────────────────────────────────────────────────

CONFIGURE_SYSTEM = """You are a Linux configuration AI.
Given system diagnostics and the user's configuration request, return ONLY valid JSON (no markdown fences):
{
  "intent": "<what is being configured>",
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
  "verification": "<shell command to verify the configuration change>"
}
Always include a backup/rollback step first when modifying important config files."""


def generate_configure_plan(diagnostics: dict, user_request: str, history: list) -> dict:
    """
    Generate a configuration change plan.
    Returns parsed JSON plan.
    """
    content = (
        f"Configuration request: {user_request}\n\n"
        f"System diagnostics:\n{json.dumps(diagnostics, indent=2)}"
    )
    history.append({"role": "user", "content": content})
    result = _call_json(CONFIGURE_SYSTEM, history)
    history.append({"role": "assistant", "content": json.dumps(result)})
    return result


def summarize_configure_step(step: dict, output: str, history: list) -> str:
    """Summarise the output of a configuration step."""
    content = (
        f"Configuration step '{step.get('title')}' executed.\n"
        f"Commands: {step.get('commands')}\n"
        f"Output:\n{output[:3000]}"
    )
    history.append({"role": "user", "content": content})
    system = (
        "You are a Linux configuration AI. "
        "Briefly summarise the configuration step output (2-4 sentences) and indicate if it succeeded."
    )
    result = _call(system, history)
    history.append({"role": "assistant", "content": result})
    return result
