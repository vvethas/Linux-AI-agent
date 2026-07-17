import io
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import paramiko

from agent.crypto_utils import decrypt_value, load_private_key


class SSHManager:
    def __init__(self):
        self._clients: Dict[str, paramiko.SSHClient] = {}

    @staticmethod
    def _cache_key(instance: Dict[str, Any]) -> str:
        return f"{instance['host']}:{instance.get('port', 22)}:{instance['username']}"

    def _is_client_alive(self, client: paramiko.SSHClient) -> bool:
        transport = client.get_transport()
        if transport is None or not transport.is_active():
            return False
        try:
            transport.send_ignore()
            return True
        except Exception:
            return False

    def _build_client(self, instance: Dict[str, Any], timeout: int = 15) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        # WarningPolicy logs unknown host keys instead of silently accepting them.
        # For production use, configure known_hosts on the control server and use
        # RejectPolicy together with a pre-populated known_hosts file.
        client.set_missing_host_key_policy(paramiko.WarningPolicy())
        connect_kwargs: Dict[str, Any] = {
            "hostname": instance["host"],
            "port": int(instance.get("port", 22)),
            "username": instance["username"],
            "timeout": timeout,
            "banner_timeout": timeout,
            "auth_timeout": timeout,
        }
        auth_type = instance.get("auth_type", "key")
        if auth_type == "password":
            connect_kwargs["password"] = instance.get("password")
            connect_kwargs["look_for_keys"] = False
            connect_kwargs["allow_agent"] = False
        elif auth_type in ("key_paste", "key_upload"):
            # Key is stored encrypted; decrypt in memory — never written to disk.
            key_record = instance.get("_ssh_key")  # injected by server before calling connect
            if not key_record:
                raise ValueError("No encrypted key record found for this instance")
            key_pem = decrypt_value(key_record["encrypted_key_blob"])
            passphrase: Optional[str] = None
            if key_record.get("passphrase_encrypted"):
                passphrase = decrypt_value(key_record["passphrase_encrypted"])
            pkey = load_private_key(key_pem, passphrase)
            connect_kwargs["pkey"] = pkey
            connect_kwargs["look_for_keys"] = False
            connect_kwargs["allow_agent"] = False
        else:
            key_path = instance.get("key_path")
            if key_path:
                connect_kwargs["key_filename"] = key_path
        client.connect(**connect_kwargs)
        return client

    def connect(self, instance: Dict[str, Any], timeout: int = 15) -> paramiko.SSHClient:
        key = self._cache_key(instance)
        client = self._clients.get(key)
        if client and self._is_client_alive(client):
            return client
        if client:
            try:
                client.close()
            except Exception:
                pass
        client = self._build_client(instance, timeout=timeout)
        self._clients[key] = client
        return client

    def close_all(self) -> None:
        for client in self._clients.values():
            try:
                client.close()
            except Exception:
                pass
        self._clients.clear()

    def test_connection(self, instance: Dict[str, Any], timeout: int = 10) -> Tuple[bool, str]:
        try:
            client = self.connect(instance, timeout=timeout)
            _stdin, stdout, stderr = client.exec_command(
                "echo connected", timeout=timeout, get_pty=True
            )
            output = stdout.read().decode("utf-8", errors="replace").strip()
            if output == "connected":
                return True, "ok"
            err = stderr.read().decode("utf-8", errors="replace").strip()
            return False, err or "unexpected output"
        except Exception as exc:
            return False, str(exc)

    def execute(
        self,
        instance: Dict[str, Any],
        command: str,
        timeout: int = 600,
        get_pty: bool = True,
    ) -> Dict[str, Any]:
        started = time.time()
        client = self.connect(instance, timeout=min(timeout, 60))
        _stdin, stdout, stderr = client.exec_command(
            command, timeout=timeout, get_pty=get_pty
        )
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        code = stdout.channel.recv_exit_status()
        return {
            "command": command,
            "stdout": out,
            "stderr": err,
            "exit_status": code,
            "success": code == 0,
            "duration_sec": round(time.time() - started, 2),
            "ran_at": datetime.now(timezone.utc).isoformat(),
        }

    # ── Diagnostic collections ────────────────────────────────────────────────

    def collect_diagnostics(self, instance: Dict[str, Any]) -> Dict[str, Any]:
        checks = {
            "hostname": "hostnamectl 2>/dev/null || hostname",
            "uptime": "uptime",
            "cpu": "lscpu",
            "memory": "free -h",
            "disk": "df -hT",
            "failed_services": "systemctl --failed --no-pager 2>/dev/null || true",
            "journal_errors": "journalctl -p err -n 120 --no-pager 2>/dev/null || true",
            "network": "ip -brief addr 2>/dev/null; echo '---'; ip route 2>/dev/null",
            "internet": "ping -c1 8.8.8.8 >/dev/null 2>&1 && echo ok || echo fail",
            "processes": "ps aux --sort=-%cpu | head -n 15",
            "env": "printenv | sort",
        }
        return self._run_command_map(instance, checks)

    def collect_specs(self, instance: Dict[str, Any]) -> Dict[str, Any]:
        checks = {
            "os": "cat /etc/os-release",
            "kernel": "uname -r",
            "ram_gb": "awk '/MemTotal/ {printf \"%.2f\", $2/1024/1024}' /proc/meminfo",
            "cpus": "nproc",
            "disk_root_gb": "df -BG / | awk 'NR==2 {gsub(/G/,\"\",$2); print $2}'",
            "internet": "curl -Is https://www.google.com >/dev/null 2>&1 && echo yes || echo no",
            "tools": (
                "for c in python3 docker kubectl ansible terraform openstack"
                " pveversion kolla-ansible; do"
                " command -v $c >/dev/null 2>&1 && echo $c:yes || echo $c:no; done"
            ),
        }
        return self._run_command_map(instance, checks)

    def collect_deep_study_raw(self, instance: Dict[str, Any]) -> Dict[str, Any]:
        checks = {
            "hardware_cpu_model": "lscpu | sed -n '1,30p'",
            "hardware_cpu_flags": (
                "lscpu | grep -i '^Flags' 2>/dev/null"
                " || grep -m1 -i '^flags' /proc/cpuinfo"
            ),
            "hardware_memory": "free -h && echo '---' && swapon --show 2>/dev/null || true",
            "hardware_disk_layout": "lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINT,TYPE 2>/dev/null || true",
            "os_release": "cat /etc/os-release",
            "os_kernel": "uname -a",
            "os_uptime": "uptime -p",
            "os_timezone": "timedatectl 2>/dev/null || true",
            "os_updates": (
                "(apt list --upgradable 2>/dev/null | wc -l)"
                " || (yum check-update 2>/dev/null | wc -l)"
                " || true"
            ),
            "services_running": (
                "systemctl list-units --type=service --state=running"
                " --no-pager 2>/dev/null | head -n 200"
            ),
            "services_failed": (
                "systemctl list-units --type=service --state=failed"
                " --no-pager 2>/dev/null"
            ),
            "services_journal_errors": "journalctl -p err -n 200 --no-pager 2>/dev/null",
            "network_interfaces": "ip -brief addr 2>/dev/null",
            "network_routes": "ip route 2>/dev/null",
            "network_dns": "cat /etc/resolv.conf",
            "network_ports": "ss -tulpn 2>/dev/null | head -n 200",
            "network_firewall": (
                "(ufw status verbose 2>/dev/null || true)"
                " && (iptables -S 2>/dev/null || true)"
                " && (nft list ruleset 2>/dev/null || true)"
            ),
            "security_ssh": (
                "grep -E '^(PermitRootLogin|PasswordAuthentication)'"
                " /etc/ssh/sshd_config"
                " /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true"
            ),
            "security_sudoers": (
                "getent group sudo 2>/dev/null || true"
                " && getent group wheel 2>/dev/null || true"
            ),
            "security_users": (
                "getent passwd"
                r" | awk -F: '$3>=1000 {print $1\":\"$3\":\"$7}'"
            ),
            "security_suid": (
                "find / -xdev -perm -4000 -type f 2>/dev/null | head -n 200"
            ),
            "security_selinux_apparmor": (
                "(getenforce 2>/dev/null || true)"
                " && (aa-status 2>/dev/null || true)"
            ),
            "security_failed_logins": (
                "(grep -i 'failed password' /var/log/auth.log 2>/dev/null | tail -n 100)"
                " || (journalctl -u ssh -n 120 --no-pager 2>/dev/null || true)"
            ),
            "software_versions": (
                "for c in python3 node java go docker kubectl kubeadm k3s"
                " nginx psql redis-server ansible terraform; do"
                " $c --version 2>/dev/null | head -n1"
                " || echo \"$c:not_installed\"; done"
            ),
            "performance_load": "cat /proc/loadavg",
            "performance_top_cpu": (
                "ps -eo pid,ppid,cmd,%cpu,%mem --sort=-%cpu | head -n 15"
            ),
            "performance_top_mem": (
                "ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -n 15"
            ),
            "performance_io": "iostat -x 1 1 2>/dev/null || vmstat 1 5",
            "env_openstack": (
                "openstack service list 2>/dev/null || true"
                " && openstack hypervisor list 2>/dev/null || true"
                " && openstack project list 2>/dev/null || true"
            ),
            "env_proxmox": (
                "pveversion 2>/dev/null || true"
                " && pvesh get /nodes 2>/dev/null || true"
                " && qm list 2>/dev/null || true"
                " && pct list 2>/dev/null || true"
            ),
            "env_kubernetes": (
                "kubectl get nodes 2>/dev/null || true"
                " && kubectl get ns 2>/dev/null || true"
                " && kubectl get deploy -A 2>/dev/null || true"
                " && kubectl get pods -A 2>/dev/null || true"
                " && kubectl get pvc -A 2>/dev/null || true"
            ),
            "env_docker": (
                "docker ps -a 2>/dev/null || true"
                " && docker volume ls 2>/dev/null || true"
                " && docker network ls 2>/dev/null || true"
                " && docker compose version 2>/dev/null || true"
            ),
        }
        return self._run_command_map(instance, checks)

    def _run_command_map(
        self,
        instance: Dict[str, Any],
        mapping: Dict[str, str],
    ) -> Dict[str, Any]:
        output: Dict[str, Any] = {}
        for key, cmd in mapping.items():
            try:
                output[key] = self.execute(instance, cmd)
            except Exception as exc:
                output[key] = {
                    "command": cmd,
                    "stdout": "",
                    "stderr": str(exc),
                    "exit_status": 255,
                    "success": False,
                    "duration_sec": 0,
                    "ran_at": datetime.now(timezone.utc).isoformat(),
                }
        return output

    def collect_quick_metrics(self, instance: Dict[str, Any]) -> Dict[str, Optional[float]]:
        """Return numeric CPU%, memory%, and disk-root% for *instance*.

        Uses simple /proc reads and df so the results are numeric and
        already normalised to 0-100.  Any individual metric that fails
        to parse is returned as None.
        """
        commands = {
            "cpu": (
                "awk '/^cpu / {"
                "  idle=$5+$6; total=0;"
                "  for(i=2;i<=NF;i++) total+=$i;"
                "  printf \"%.1f\", (1-idle/total)*100"
                "}' /proc/stat"
            ),
            "mem": (
                "awk '/^MemTotal/{t=$2} /^MemAvailable/{a=$2}"
                " END{printf \"%.1f\", (1-a/t)*100}' /proc/meminfo"
            ),
            "disk": (
                "df / | awk 'NR==2{gsub(/%/,\"\"); printf \"%s\", $5}'"
            ),
        }
        result: Dict[str, Optional[float]] = {"cpu": None, "mem": None, "disk": None}
        for key, cmd in commands.items():
            try:
                out = self.execute(instance, cmd, timeout=10, get_pty=False)
                val = float(out.get("stdout", "").strip())
                result[key] = val
            except Exception:
                pass
        return result

    def write_temp_file(
        self,
        instance: Dict[str, Any],
        content: str,
        prefix: str = "agent",
    ) -> str:
        client = self.connect(instance)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        remote_path = f"/tmp/{prefix}_{ts}.yml"
        data = io.BytesIO(content.encode("utf-8"))
        with client.open_sftp() as sftp:
            sftp.putfo(data, remote_path)
        return remote_path
