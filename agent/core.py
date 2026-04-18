import json
import os
from typing import Any, Dict, List, Optional

import requests


class ClaudeClient:
    API_URL = "https://api.anthropic.com/v1/messages"
    DEFAULT_MODEL = "claude-sonnet-4-20250514"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")

    @staticmethod
    def _strip_json_fences(text: str) -> str:
        cleaned = text.strip()
        if cleaned.startswith("```"):
            # strip all leading/trailing backtick fences
            lines = cleaned.splitlines()
            # remove first line if it is a fence marker
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            # remove last line if it is a fence marker
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            cleaned = "\n".join(lines).strip()
        return cleaned

    def _extract_text(self, payload: Dict[str, Any]) -> str:
        content = payload.get("content", [])
        parts: List[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(item.get("text", ""))
        return "\n".join(parts).strip()

    def call_json(
        self,
        system_prompt: str,
        user_message: Any,
        history: Optional[List[Dict[str, str]]] = None,
        model: Optional[str] = None,
        max_tokens: int = 4000,
    ) -> Dict[str, Any]:
        if not self.api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")

        messages = list(history or [])
        content = (
            user_message
            if isinstance(user_message, str)
            else json.dumps(user_message, default=str)
        )
        messages.append({"role": "user", "content": content})

        response = requests.post(
            self.API_URL,
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": model or self.DEFAULT_MODEL,
                "max_tokens": max_tokens,
                "system": system_prompt,
                "messages": messages,
            },
            timeout=120,
        )
        response.raise_for_status()
        payload = response.json()
        text = self._extract_text(payload)
        cleaned = self._strip_json_fences(text)
        return json.loads(cleaned)

    # ── High-level helpers ─────────────────────────────────────────────────────

    def classify_intent(self, user_input: str) -> str:
        """Return 'troubleshoot' or 'build'."""
        result = self.call_json(
            system_prompt=(
                'Is this a troubleshoot or build request? '
                'Return ONLY JSON: {"intent":"troubleshoot"} or {"intent":"build"}'
            ),
            user_message={"input": user_input},
            max_tokens=64,
        )
        intent = str(result.get("intent", "troubleshoot")).lower().strip()
        return "build" if intent == "build" else "troubleshoot"

    def troubleshoot_plan(
        self,
        issue: str,
        diagnostics: Dict[str, Any],
        history: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        prompt = (
            "You are a Linux troubleshooting AI. Analyze the diagnostics and return "
            "ONLY JSON (no markdown): "
            '{"diagnosis":"...","risk_level":"low|medium|high",'
            '"steps":[{"id":1,"title":"...","description":"...",'
            '"commands":["..."],"risky":false}],"verification":"..."}'
        )
        return self.call_json(
            prompt, {"issue": issue, "diagnostics": diagnostics}, history=history
        )

    def summarize_execution(
        self,
        step: Dict[str, Any],
        output: Dict[str, Any],
        history: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        prompt = (
            "Return ONLY JSON: "
            '{"status":"ok|warn|error","summary":"...","next_action":"..."}'
            " based on the execution output."
        )
        return self.call_json(
            prompt, {"step": step, "output": output}, history=history, max_tokens=400
        )

    def build_plan(
        self,
        request_text: str,
        specs: Dict[str, Any],
        history: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        prompt = (
            "You are a Linux infrastructure automation AI. Return ONLY JSON: "
            '{"intent":"...","method":"...",'
            '"requirements":{"min_ram_gb":0,"min_disk_gb":0,"min_cpus":0,"required_os":[]},'
            '"requirements_met":true,"requirements_issues":[],'
            '"phases":[{"id":1,"name":"...","description":"...","estimated_minutes":0,'
            '"risky":false,"steps":[{"id":1,"title":"...","description":"...","commands":[]}]}],'
            '"post_install":{"endpoints":[],"credential_commands":[],"verification_commands":[]},'
            '"estimated_total_minutes":0}'
        )
        return self.call_json(
            prompt, {"request": request_text, "specs": specs}, history=history
        )

    def analyze_study(
        self,
        raw_data: Dict[str, Any],
        instance: Dict[str, Any],
    ) -> Dict[str, Any]:
        prompt = (
            "You are a Linux instance analysis AI. Return ONLY JSON with this schema: "
            '{"summary":{"headline":"...","role":"...","health_score":0,"health_label":"...",'
            '"key_findings":[]},'
            '"hardware":{"analysis":"..."},'
            '"os":{"analysis":"..."},'
            '"services":{"total_running":0,"total_failed":0,"critical":[],"failed":[],"analysis":"..."},'
            '"network":{"interfaces":[],"open_ports":[],"firewall":"...","analysis":"..."},'
            '"security":{"score":0,"label":"...","ssh_root_login":"...","password_auth":"...",'
            '"firewall_active":false,"pending_security_updates":0,'
            '"findings":[{"severity":"low|medium|high","issue":"...","recommendation":"..."}],'
            '"analysis":"..."},'
            '"software":{"installed_highlights":[],"runtimes":[],"databases":[],"analysis":"..."},'
            '"environment":{"type":"generic|openstack|proxmox|kubernetes|docker","details":{},"analysis":"..."},'
            '"performance":{"cpu_load_1m":0,"cpu_load_5m":0,"cpu_load_15m":0,'
            '"top_cpu_processes":[],"top_mem_processes":[],"analysis":"..."},'
            '"recommendations":[{"priority":"high|medium|low","category":"...","title":"...",'
            '"detail":"...","command":"..."}]}'
        )
        return self.call_json(prompt, {"instance": instance, "raw_data": raw_data})

    def replication_plan(
        self,
        study_report: Dict[str, Any],
        target_specs: Dict[str, Any],
    ) -> Dict[str, Any]:
        prompt = (
            "Return ONLY JSON: "
            '{"summary":"...","source_role":"...","warnings":[],'
            '"phases":[{"id":1,"name":"...","description":"...","estimated_minutes":0,'
            '"risky":false,"steps":[{"id":1,"title":"...","description":"...",'
            '"commands":[],"verify_cmd":"..."}]}],'
            '"ansible_playbook":"...","post_verify":{"commands":[],"description":"..."},'
            '"estimated_total_minutes":0}. '
            "Skip IP addresses, hostnames, SSH keys, SSL certs, and UUIDs."
        )
        return self.call_json(
            prompt, {"source_study": study_report, "target_specs": target_specs}
        )
