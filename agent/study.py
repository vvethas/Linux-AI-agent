from typing import Any, Dict, Optional

from .core import ClaudeClient
from .db import Database
from .ssh import SSHManager


class StudyRunner:
    def __init__(self, db: Database, ssh: SSHManager, claude: ClaudeClient):
        self.db = db
        self.ssh = ssh
        self.claude = claude

    def run(self, instance: Dict[str, Any], note: Optional[str] = None) -> Dict[str, Any]:
        raw = self.ssh.collect_deep_study_raw(instance)
        meta = {
            "id": instance["id"],
            "label": instance["label"],
            "host": instance["host"],
            "note": note or "",
        }
        report = self.claude.analyze_study(raw, meta)
        study_id = self.db.save_study_report(instance["id"], report, raw)
        return {"study_id": study_id, "report": report, "raw": raw}
