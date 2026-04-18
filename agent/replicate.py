from typing import Any, Dict, List

from .core import ClaudeClient
from .db import Database
from .ssh import SSHManager


class Replicator:
    def __init__(self, db: Database, ssh: SSHManager, claude: ClaudeClient):
        self.db = db
        self.ssh = ssh
        self.claude = claude

    def generate_plan(
        self,
        source_study: Dict[str, Any],
        target_instance: Dict[str, Any],
        target_specs: Dict[str, Any],
    ) -> Dict[str, Any]:
        plan = self.claude.replication_plan(source_study, target_specs)
        warnings: List[str] = list(plan.get("warnings", []))

        # Flag OS mismatch heuristically
        source_os = str(
            source_study.get("os", {}).get("distribution", "") or ""
        ).lower()
        target_os_raw = str(target_specs.get("os", {}).get("stdout", "") or "").lower()
        if source_os and target_os_raw and source_os not in target_os_raw:
            warnings.append(
                f"Possible OS mismatch: source={source_os!r} not found in target OS info"
            )

        plan["warnings"] = warnings
        plan["target_instance_id"] = target_instance["id"]
        return plan

    def execute_step(
        self, instance: Dict[str, Any], step: Dict[str, Any]
    ) -> Dict[str, Any]:
        outputs = []
        success = True
        for command in step.get("commands", []):
            result = self.ssh.execute(instance, command, timeout=600)
            outputs.append(result)
            if not result["success"]:
                success = False
                break

        verify_result = None
        if success and step.get("verify_cmd"):
            verify_result = self.ssh.execute(
                instance, str(step["verify_cmd"]), timeout=120
            )
            success = verify_result["success"]

        return {"success": success, "outputs": outputs, "verify": verify_result}

    def save_playbook(
        self, instance: Dict[str, Any], playbook_yaml: str
    ) -> str:
        return self.ssh.write_temp_file(
            instance, playbook_yaml, prefix="replication_playbook"
        )

    def post_verify(
        self, instance: Dict[str, Any], commands: List[str]
    ) -> Dict[str, Any]:
        results = [
            self.ssh.execute(instance, cmd, timeout=300) for cmd in commands
        ]
        return {
            "success": all(r["success"] for r in results),
            "results": results,
        }
