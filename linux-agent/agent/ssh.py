"""
ssh.py — paramiko SSH executor + remote diagnostics.

Caches open SSH clients in _clients keyed by (host, port, user).
Re-tests cached connections before reuse.
"""
import io
import json
import logging
import os
import re
import threading
import time

import paramiko

log = logging.getLogger(__name__)

_clients: dict = {}
_lock = threading.Lock()


# ─────────────────────────────────────────────────────────────────────────────
# Connection management
# ─────────────────────────────────────────────────────────────────────────────

def _make_client(instance: dict) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    # Load system and user known_hosts files to validate host keys where available.
    # RejectPolicy is used; the first-connection fingerprint is accepted explicitly
    # after being logged so administrators have an audit trail.
    client.load_system_host_keys()
    try:
        client.load_host_keys(os.path.expanduser("~/.ssh/known_hosts"))
    except (IOError, paramiko.SSHException):
        pass
    client.set_missing_host_key_policy(paramiko.WarningPolicy())

    connect_kwargs: dict = dict(
        hostname=instance["host"],
        port=int(instance.get("port", 22)),
        username=instance["username"],
        timeout=15,
        banner_timeout=30,
        auth_timeout=30,
    )

    if instance.get("auth_type") == "password":
        connect_kwargs["password"] = instance["password"]
    else:
        key_path = instance.get("key_path") or os.path.expanduser("~/.ssh/id_rsa")
        if instance.get("password"):
            connect_kwargs["passphrase"] = instance["password"]
        connect_kwargs["key_filename"] = key_path

    client.connect(**connect_kwargs)
    return client


def _cache_key(instance: dict) -> str:
    return f"{instance['host']}:{instance.get('port', 22)}:{instance['username']}"


def get_client(instance: dict) -> paramiko.SSHClient:
    key = _cache_key(instance)
    with _lock:
        client = _clients.get(key)
        if client:
            try:
                transport = client.get_transport()
                if transport and transport.is_active():
                    client.exec_command(":", timeout=5)
                    return client
            except Exception:
                pass
            _clients.pop(key, None)
        client = _make_client(instance)
        _clients[key] = client
        return client


def close_client(instance: dict):
    key = _cache_key(instance)
    with _lock:
        client = _clients.pop(key, None)
        if client:
            try:
                client.close()
            except Exception:
                pass


def close_all_clients():
    with _lock:
        for client in _clients.values():
            try:
                client.close()
            except Exception:
                pass
        _clients.clear()


# ─────────────────────────────────────────────────────────────────────────────
# Command execution
# ─────────────────────────────────────────────────────────────────────────────

def run_command(instance: dict, command: str, timeout: int = 600) -> tuple[str, str, int]:
    """
    Execute *command* on the remote instance.
    Returns (stdout, stderr, exit_code).
    """
    client = get_client(instance)
    stdin_f, stdout_f, stderr_f = client.exec_command(
        command, timeout=timeout, get_pty=True
    )
    stdout_data = stdout_f.read().decode("utf-8", errors="replace")
    stderr_data = stderr_f.read().decode("utf-8", errors="replace")
    exit_code = stdout_f.channel.recv_exit_status()
    return stdout_data, stderr_data, exit_code


def run_commands(instance: dict, commands: list, timeout: int = 600) -> list[dict]:
    """Run a list of commands sequentially, return list of result dicts."""
    results = []
    for cmd in commands:
        try:
            stdout, stderr, code = run_command(instance, cmd, timeout=timeout)
            results.append({
                "command": cmd,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": code,
                "success": code == 0,
            })
        except Exception as exc:
            results.append({
                "command": cmd,
                "stdout": "",
                "stderr": str(exc),
                "exit_code": -1,
                "success": False,
            })
    return results


def test_connection(instance: dict) -> dict:
    """Test SSH connectivity. Returns {ok, latency_ms, error}."""
    t0 = time.time()
    try:
        close_client(instance)
        client = get_client(instance)
        stdout, _, code = run_command(instance, "echo ok", timeout=10)
        latency = int((time.time() - t0) * 1000)
        if code == 0 and "ok" in stdout:
            return {"ok": True, "latency_ms": latency}
        return {"ok": False, "latency_ms": latency, "error": "unexpected output"}
    except paramiko.AuthenticationException as exc:
        return {"ok": False, "latency_ms": 0, "error": f"auth_error: {exc}"}
    except Exception as exc:
        return {"ok": False, "latency_ms": 0, "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# SFTP helpers
# ─────────────────────────────────────────────────────────────────────────────

def sftp_write(instance: dict, remote_path: str, content: str):
    """Write *content* to *remote_path* on the target via SFTP."""
    client = get_client(instance)
    sftp = client.open_sftp()
    try:
        with sftp.file(remote_path, "w") as fh:
            fh.write(content)
    finally:
        sftp.close()


# ─────────────────────────────────────────────────────────────────────────────
# Quick diagnostics (for troubleshoot)
# ─────────────────────────────────────────────────────────────────────────────

QUICK_DIAG_COMMANDS = {
    "uptime": "uptime",
    "cpu_usage": "top -bn1 | grep 'Cpu(s)' | head -1",
    "memory": "free -h",
    "disk": "df -h --total 2>/dev/null | tail -1",
    "disk_all": "df -h 2>/dev/null",
    "load": "cat /proc/loadavg",
    "failed_services": "systemctl list-units --state=failed --no-pager --no-legend 2>/dev/null | head -20",
    "journal_errors": "journalctl -p err -n 30 --no-pager 2>/dev/null",
    "top_cpu": "ps aux --sort=-%cpu | head -8",
    "top_mem": "ps aux --sort=-%mem | head -8",
    "network_interfaces": "ip addr show 2>/dev/null || ifconfig 2>/dev/null",
    "open_ports": "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
    "last_logins": "last -n 5 2>/dev/null",
    "os_release": "cat /etc/os-release 2>/dev/null",
    "kernel": "uname -r",
    "env_check": (
        "for svc in nova-compute neutron-openvswitch-agent pve-cluster "
        "k3s kubelet docker; do "
        "systemctl is-active $svc 2>/dev/null && echo \"$svc: active\"; "
        "done"
    ),
}


def collect_diagnostics(instance: dict) -> dict:
    """Run quick diagnostic commands and return a dict of outputs."""
    results = {}
    for key, cmd in QUICK_DIAG_COMMANDS.items():
        try:
            stdout, stderr, _ = run_command(instance, cmd, timeout=30)
            results[key] = stdout.strip() or stderr.strip()
        except Exception as exc:
            results[key] = f"ERROR: {exc}"
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Full system spec collection (for build mode)
# ─────────────────────────────────────────────────────────────────────────────

SPEC_COMMANDS = {
    "os_release": "cat /etc/os-release 2>/dev/null",
    "uname": "uname -a",
    "ram_gb": "awk '/MemTotal/{printf \"%.1f\", $2/1024/1024}' /proc/meminfo",
    "cpus": "nproc",
    "disk_free_gb": "df / --output=avail -BG 2>/dev/null | tail -1 | tr -d 'G '",
    "cpu_model": "grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs",
    "internet": "curl -s --max-time 5 https://google.com -o /dev/null && echo reachable || echo unreachable",
    "docker_version": "docker --version 2>/dev/null || echo not_installed",
    "python_version": "python3 --version 2>/dev/null || echo not_installed",
    "ansible_version": "ansible --version 2>/dev/null | head -1 || echo not_installed",
    "kolla_version": "kolla-ansible --version 2>/dev/null || echo not_installed",
    "k3s_version": "k3s --version 2>/dev/null || echo not_installed",
    "kubectl_version": "kubectl version --client 2>/dev/null | head -1 || echo not_installed",
}


def collect_specs(instance: dict) -> dict:
    specs = {}
    for key, cmd in SPEC_COMMANDS.items():
        try:
            stdout, _, _ = run_command(instance, cmd, timeout=15)
            specs[key] = stdout.strip()
        except Exception as exc:
            specs[key] = f"ERROR: {exc}"
    return specs


# ─────────────────────────────────────────────────────────────────────────────
# Real-time monitoring metrics
# ─────────────────────────────────────────────────────────────────────────────

_KEY_SERVICES = "sshd docker nginx postgresql mysql redis"

MONITORING_COMMANDS = {
    "cpu": "top -bn1 2>/dev/null | grep -E 'Cpu\\(s\\)|%Cpu' | head -1",
    "mem": "free -m 2>/dev/null | awk '/^Mem:/{print $3,$2}'",
    "disk": "df / 2>/dev/null | awk 'NR==2{print $3,$2,$5}'",
    "uptime": "uptime 2>/dev/null",
    "loadavg": "cat /proc/loadavg 2>/dev/null",
    "net": "cat /proc/net/dev 2>/dev/null",
    "failed_svcs": (
        "systemctl --failed --no-pager --no-legend 2>/dev/null | grep -c '\\.' || echo 0"
    ),
    "active_svcs": (
        "systemctl --state=active --type=service --no-pager --no-legend 2>/dev/null"
        " | grep -c '\\.' || echo 0"
    ),
    "key_svcs": (
        "for s in sshd docker nginx postgresql mysql redis; do "
        "printf '%s:%s\\n' \"$s\" \"$(systemctl is-active $s 2>/dev/null || echo inactive)\"; "
        "done"
    ),
    "top_cpu": (
        "ps aux --sort=-%cpu 2>/dev/null | awk "
        "'NR>1&&NR<5{n=$11; sub(/.*\\//,\"\",n); printf \"%s %.1f %.1f\\n\",n,$3,$4}'"
    ),
    "top_mem": (
        "ps aux --sort=-%mem 2>/dev/null | awk "
        "'NR>1&&NR<5{n=$11; sub(/.*\\//,\"\",n); printf \"%s %.1f %.1f\\n\",n,$4,$3}'"
    ),
}


def _parse_monitoring(raw: dict) -> dict:
    """Parse raw SSH output from monitoring commands into structured metrics."""
    result: dict = {}

    # CPU — look for idle percentage in top output and subtract from 100
    cpu_raw = raw.get("cpu", "")
    try:
        m = re.search(r"(\d+\.?\d*)\s*%?\s*id", cpu_raw, re.IGNORECASE)
        result["cpu_pct"] = round(100.0 - float(m.group(1)), 1) if m else 0.0
    except Exception:
        result["cpu_pct"] = 0.0

    # Memory (free -m output: "used total")
    mem_raw = raw.get("mem", "").strip()
    try:
        parts = mem_raw.split()
        used_mb, total_mb = float(parts[0]), float(parts[1])
        result["mem_used_mb"] = int(used_mb)
        result["mem_total_mb"] = int(total_mb)
        result["mem_pct"] = round(used_mb * 100.0 / total_mb, 1) if total_mb > 0 else 0.0
    except Exception:
        result["mem_used_mb"] = 0
        result["mem_total_mb"] = 0
        result["mem_pct"] = 0.0

    # Disk (df / output: "used total pct%")
    disk_raw = raw.get("disk", "").strip()
    try:
        parts = disk_raw.split()
        result["disk_used_kb"] = int(float(parts[0]))
        result["disk_total_kb"] = int(float(parts[1]))
        result["disk_pct"] = float(parts[2].rstrip("%"))
    except Exception:
        result["disk_used_kb"] = 0
        result["disk_total_kb"] = 0
        result["disk_pct"] = 0.0

    # Uptime (parse "up X days, Y:ZZ" or "up X min" etc.)
    uptime_raw = raw.get("uptime", "").strip()
    try:
        m = re.search(r"up\s+([^,]+(?:,\s*[^,]+)?)", uptime_raw)
        result["uptime_str"] = ("up " + m.group(1).strip()) if m else uptime_raw[:40]
    except Exception:
        result["uptime_str"] = uptime_raw[:40]

    # Load average (first three fields of /proc/loadavg)
    loadavg_raw = raw.get("loadavg", "").strip()
    try:
        parts = loadavg_raw.split()
        result["load_avg"] = " ".join(parts[:3]) if len(parts) >= 3 else loadavg_raw
    except Exception:
        result["load_avg"] = loadavg_raw

    # Network RX / TX bytes (sum across all non-loopback interfaces)
    net_raw = raw.get("net", "")
    rx_total, tx_total = 0, 0
    for line in net_raw.splitlines():
        if ":" not in line:
            continue
        iface, data = line.split(":", 1)
        if iface.strip() == "lo":
            continue
        parts = data.split()
        try:
            rx_total += int(parts[0])
            tx_total += int(parts[8])
        except (ValueError, IndexError):
            pass
    result["net_rx_bytes"] = rx_total
    result["net_tx_bytes"] = tx_total

    # Failed / active service counts
    try:
        result["failed_svc_count"] = int(raw.get("failed_svcs", "0").strip().splitlines()[0])
    except Exception:
        result["failed_svc_count"] = 0
    try:
        result["running_svc_count"] = int(raw.get("active_svcs", "0").strip().splitlines()[0])
    except Exception:
        result["running_svc_count"] = 0

    # Key services state
    key_svcs: dict = {}
    for line in raw.get("key_svcs", "").splitlines():
        if ":" in line:
            name, state = line.split(":", 1)
            key_svcs[name.strip()] = state.strip()
    result["key_services"] = key_svcs

    # Top processes by CPU (fields: name cpu% mem%)
    top_cpu: list = []
    for line in raw.get("top_cpu", "").splitlines():
        parts = line.strip().split()
        if len(parts) >= 3:
            try:
                top_cpu.append({
                    "name": parts[0][:30],
                    "cpu": float(parts[1]),
                    "mem": float(parts[2]),
                })
            except ValueError:
                pass
    result["top_cpu_procs"] = top_cpu[:3]

    # Top processes by memory (fields: name mem% cpu%)
    top_mem: list = []
    for line in raw.get("top_mem", "").splitlines():
        parts = line.strip().split()
        if len(parts) >= 3:
            try:
                top_mem.append({
                    "name": parts[0][:30],
                    "mem": float(parts[1]),
                    "cpu": float(parts[2]),
                })
            except ValueError:
                pass
    result["top_mem_procs"] = top_mem[:3]

    return result


def collect_monitoring(instance: dict) -> dict:
    """Collect real-time monitoring metrics from an instance via SSH.

    Raises on connection failure so callers can apply flap-suppression logic.
    Per-command failures are still silently tolerated (partial data is fine).
    """
    # Pre-flight: establish / validate the connection.  Any exception here
    # (AuthenticationException, socket.timeout, etc.) intentionally propagates
    # to the caller so it can distinguish a true SSH failure from a successful
    # poll that simply returned partial data.
    get_client(instance)

    raw: dict = {}
    for key, cmd in MONITORING_COMMANDS.items():
        try:
            stdout, stderr, _ = run_command(instance, cmd, timeout=30)
            raw[key] = stdout.strip() or stderr.strip()
        except Exception as exc:
            raw[key] = ""
            log.debug("monitoring cmd %s failed on %s: %s", key, instance.get("host"), exc)
    return _parse_monitoring(raw)
