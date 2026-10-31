#!/usr/bin/env bash
# stage1-port-key.sh —— SSH 加固三步指导体系：第 1 步，切端口 / 切密钥 / 验证 sudo 用户
#
# 本脚本【纯只读】：不修改 SSH/防火墙/systemd 配置，不写状态文件，不安装定时器，
# 不代执行任何命令，也没有任何形式的自动回滚。它按内置的只读步骤方案：
#   0. 救援通道演练确认（--rescue-confirmed，硬门槛）
#   1. 手工全量备份（约定目录 /var/backups/ssh-hardening/）
#   2. 建立/确认 sudo 组非 root 账户与公钥
#   3. 开启新端口（旧端口原样保留）
#   4. 从新端口外部公钥会话验证（硬门槛：必须从新端口会话重跑本脚本才解锁第 5 步）
#   5. 关闭旧端口（需第 4 步已证实 + 救援通道已确认）
# 逐步打印：当前步骤的状态确认、为什么、手工命令、验证命令与预期、手工撤销命令。
# 所有命令由操作员本人（或其监督下的智能体）手工执行；重跑本脚本只读核对进度。
#
# 退出码：0=stage1 目标全部达成；1=阻断性异常（旧版残留、sshd 配置损坏、参数冲突）；
#         2=步骤未全部完成或需要 sudo。
# 设计文档：plans/DESIGN-v2.md。旧版自动执行体系已废弃，见 legacy/README.md。

set -uo pipefail
umask 077

if ! command -v python3 >/dev/null 2>&1; then
  echo "缺少 python3；请先安装：sudo apt-get install python3" >&2
  exit 2
fi

SELF_PATH=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/$(basename -- "${BASH_SOURCE[0]}")
export REINFORCE_SELF="$SELF_PATH"

exec python3 - "$@" <<'REINFORCE_STAGE1_PY'
"""stage1-port-key.sh：切端口/装公钥/验证 sudo 用户的只读分步指导；绝不修改系统。"""
import argparse
import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

SCRIPT = "stage1-port-key.sh"
STAGE2 = "stage2-lockdown.sh"
BACKUP_ROOT = "/var/backups/ssh-hardening"
LEGACY_STATE_ROOT = "/var/lib/reinforce-my-ssh"
LEGACY_MANAGED = (
    "/etc/ssh/sshd_config.d/00-reinforce-my-ssh.conf",
    "/etc/nftables.d/reinforce-my-ssh.nft",
    "/usr/local/sbin/reinforce-my-ssh-firewall",
    "/etc/systemd/system/reinforce-my-ssh-firewall.service",
    "/etc/systemd/system/ssh.socket.d/00-reinforce-my-ssh.conf",
)
SSHD_CONFIG = "/etc/ssh/sshd_config"
SSHD_CONFIG_D = "/etc/ssh/sshd_config.d"
SOCKET_DROPIN_DIR = "/etc/systemd/system/ssh.socket.d"
NEWPORT_DROPIN = SSHD_CONFIG_D + "/10-newport.conf"
NEWPORT_SOCKET_DROPIN = SOCKET_DROPIN_DIR + "/10-newport.conf"
TAILSCALE_IFACE = "/sys/class/net/tailscale0"
CGNAT = ipaddress.ip_network("100.64.0.0/10")
TAILSCALE_V6 = ipaddress.ip_network("fd7a:115c:a1e0::/48")

DONE, TODO, BLOCKED, WARN, UNKNOWN = "done", "todo", "blocked", "warn", "unknown"
STATUS_LABEL = {DONE: "已完成", TODO: "未完成", BLOCKED: "被门槛阻塞", WARN: "需注意", UNKNOWN: "无法证实"}

READ_ONLY_COMMANDS = {
    "ss": None,
    "id": None,
    "getent": None,
    "sshd": {"-t", "-T"},
    "nft": {"list", "-j"},
    "ufw": {"status"},
    "systemctl": {"show", "is-active", "is-enabled", "cat", "status"},
    "journalctl": None,
}


class EvidenceError(Exception):
    pass


def validate_read_only_command(args):
    if not args or args[0] not in READ_ONLY_COMMANDS:
        raise EvidenceError("拒绝非只读命令")
    tool, tail = args[0], tuple(args[1:])
    allowed = READ_ONLY_COMMANDS[tool]
    if allowed is not None and (not tail or tail[0] not in allowed):
        raise EvidenceError("拒绝非只读子命令")
    exact = {
        "ss": {("-tlnpH",)},
        "nft": {("-j", "list", "ruleset"), ("list", "tables"), ("list", "ruleset")},
        "ufw": {("status", "verbose")},
        "journalctl": {("-b", "-u", "ssh", "-u", "sshd", "-u", "ssh@*", "-o", "cat", "--no-pager")},
    }
    if tool in exact and tail not in exact[tool]:
        raise EvidenceError("拒绝未经声明的只读命令参数：" + tool)
    if tool == "sshd":
        rest = list(tail[1:])
        while rest:
            if len(rest) < 2 or rest[0] not in ("-f", "-C"):
                raise EvidenceError("拒绝 sshd 参数")
            del rest[:2]


class System:
    """只执行白名单内的只读命令；一切失败都以证据异常上报，不猜测。"""

    def __init__(self):
        self.calls = []

    def run(self, *args):
        result = self.run_allow_fail(*args)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip().splitlines()
            raise EvidenceError(args[0] + " 退出码 " + str(result.returncode) + "：" + (detail[0][:180] if detail else "无输出"))
        return result.stdout

    def run_allow_fail(self, *args):
        validate_read_only_command(args)
        self.calls.append(list(args))
        try:
            return subprocess.run(list(args), capture_output=True, text=True, timeout=60)
        except OSError as exc:
            raise EvidenceError("无法运行 " + args[0] + "：" + str(exc))
        except subprocess.TimeoutExpired:
            raise EvidenceError("命令超时：" + args[0])

    def read(self, path):
        try:
            return Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise EvidenceError("无法读取 " + path + "：" + exc.strerror)

    def exists(self, path):
        try:
            Path(path).stat()
            return True
        except (FileNotFoundError, NotADirectoryError):
            return False
        except OSError as exc:
            raise EvidenceError("无法检查路径 " + path + "：" + str(exc))

    def is_dir(self, path):
        import stat
        try:
            return stat.S_ISDIR(Path(path).stat().st_mode)
        except (FileNotFoundError, NotADirectoryError):
            return False
        except OSError as exc:
            raise EvidenceError("无法检查目录 " + path + "：" + str(exc))

    def list_dir(self, path):
        try:
            return sorted(p.name for p in Path(path).iterdir())
        except OSError as exc:
            raise EvidenceError("无法列出目录 " + path + "：" + exc.strerror)

    def stat(self, path):
        try:
            return Path(path).stat()
        except OSError as exc:
            raise EvidenceError("无法读取属性 " + path + "：" + exc.strerror)

    def mtime(self, path):
        try:
            return Path(path).stat().st_mtime
        except OSError:
            return None


def entry_dir():
    return str(Path(os.environ.get("REINFORCE_SELF", SCRIPT)).resolve().parent)


def is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


# ---------------------------------------------------------------- 只读探测

def find_connection(system):
    value = os.environ.get("SSH_CONNECTION")
    pid, seen = os.getpid(), set()
    while not value and pid > 1 and pid not in seen:
        seen.add(pid)
        try:
            for item in system.read("/proc/%d/environ" % pid).split("\0"):
                if item.startswith("SSH_CONNECTION="):
                    value = item.split("=", 1)[1]
                    break
            pid = int(re.search(r"^PPid:\s+(\d+)", system.read("/proc/%d/status" % pid), re.M)[1])
        except (EvidenceError, TypeError):
            break
    if not value:
        return None
    parts = value.split()
    if len(parts) != 4:
        raise EvidenceError("SSH_CONNECTION 格式异常：" + value)
    client, client_port, local, local_port = parts
    try:
        ipaddress.ip_address(client)
        ipaddress.ip_address(local)
        if not (1 <= int(client_port) <= 65535 and 1 <= int(local_port) <= 65535):
            raise ValueError("端口越界")
    except ValueError as exc:
        raise EvidenceError("SSH_CONNECTION 含非法地址或端口：" + value + "（" + str(exc) + "）")
    return {"source": client, "source_port": int(client_port), "local": local, "port": int(local_port)}


def session_auth(system, connection, user):
    if not connection or not user:
        return None
    try:
        logs = system.run("journalctl", "-b", "-u", "ssh", "-u", "sshd", "-u", "ssh@*", "-o", "cat", "--no-pager")
    except EvidenceError:
        return None
    pattern = re.compile(r"Accepted (\S+) for (?:invalid user )?(\S+) from (\S+) port (\d+)")
    found = None
    for line in logs.splitlines():
        match = pattern.search(line)
        if (match and match.group(2) == user and match.group(3) == connection["source"]
                and int(match.group(4)) == connection["source_port"]):
            found = match.group(1)
    return found


def endpoint_port(text):
    value = text.rsplit(":", 1)[-1]
    if not value.isdecimal() or not 1 <= int(value) <= 65535:
        raise ValueError("不是有效 TCP 端口：" + text)
    return int(value)


def sshd_listeners(system):
    ports = set()
    for line in system.run("ss", "-tlnpH").splitlines():
        words = line.split()
        if len(words) >= 5 and re.search(r'"sshd(?:-session)?"', line):
            try:
                ports.add(endpoint_port(words[3]))
            except (ValueError, IndexError):
                continue
    return sorted(p for p in ports if 1 <= p <= 65535)


def socket_state(system):
    props = system.run("systemctl", "show", "ssh.socket", "-p", "LoadState", "-p", "ActiveState",
                       "-p", "Accept", "-p", "Listen")
    data = {}
    for line in props.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            data[key] = (data.get(key, "") + "\n" + value).strip() if key == "Listen" else value
    ports = set()
    for line in data.get("Listen", "").splitlines():
        if line.endswith(" (Stream)"):
            try:
                ports.add(endpoint_port(line.rsplit(" (Stream)", 1)[0]))
            except ValueError:
                continue
    return {"load": data.get("LoadState", "unknown"), "active": data.get("ActiveState", "unknown"),
            "accept": data.get("Accept", "unknown"), "listen_ports": sorted(ports)}


def unit_probe(system, unit, sub):
    try:
        result = system.run_allow_fail("systemctl", sub, unit)
    except EvidenceError:
        return "unknown"
    value = (result.stdout or "").strip().splitlines()
    return value[0] if value else "unknown"


def sshd_valid(system):
    try:
        system.run("sshd", "-t", "-f", SSHD_CONFIG)
        return True, None
    except EvidenceError as exc:
        return False, str(exc)


def sshd_config_files(system):
    files = [SSHD_CONFIG]
    try:
        files += [SSHD_CONFIG_D + "/" + name for name in system.list_dir(SSHD_CONFIG_D) if name.endswith(".conf")]
    except EvidenceError:
        pass
    return files


def match_blocks(system):
    found = []
    for path in sshd_config_files(system):
        try:
            for number, line in enumerate(system.read(path).splitlines(), 1):
                if re.match(r"\s*Match\s", line):
                    found.append("%s:%d %s" % (path, number, line.strip()))
        except EvidenceError:
            found.append(path + "（无法读取）")
    return found


def disk_port_directives(system):
    ports = {}
    for path in sshd_config_files(system):
        try:
            for number, line in enumerate(system.read(path).splitlines(), 1):
                m = re.match(r"\s*Port\s+(\d+)\s*(?:#.*)?$", line)
                if m:
                    ports.setdefault(int(m.group(1)), []).append("%s:%d" % (path, number))
        except EvidenceError:
            continue
    try:
        for name in system.list_dir(SOCKET_DROPIN_DIR):
            if not name.endswith(".conf"):
                continue
            path = SOCKET_DROPIN_DIR + "/" + name
            for number, line in enumerate(system.read(path).splitlines(), 1):
                m = re.match(r"\s*ListenStream\s*=\s*(\S+)\s*$", line)
                if m:
                    try:
                        ports.setdefault((int(m.group(1)) if m.group(1).isdigit() else endpoint_port(m.group(1))), []).append("%s:%d" % (path, number))
                    except ValueError:
                        continue
    except EvidenceError:
        pass
    return ports


def account_facts(system, user):
    facts = {"user": user, "authorized_keys_readable": False}
    try:
        facts["uid"] = int(system.run("id", "-u", user).strip())
    except (EvidenceError, ValueError) as exc:
        facts.update(exists=False, detail=str(exc))
        return facts
    facts["exists"] = True
    try:
        facts["groups"] = system.run("id", "-nG", user).split()
        home = system.run("getent", "passwd", user).split(":")[5]
    except (EvidenceError, IndexError):
        home = None
    facts["sudo"] = "sudo" in facts.get("groups", []) and facts["uid"] != 0
    facts["home"] = home
    if home:
        keyfile = home.rstrip("/") + "/.ssh/authorized_keys"
        facts["authorized_keys_path"] = keyfile
        try:
            content = system.read(keyfile)
            facts["authorized_keys_readable"] = True
            facts["authorized_keys_count"] = sum(bool(line.strip()) and not line.lstrip().startswith("#")
                                                  for line in content.splitlines())
            attrs = [("home", home), ("ssh_dir", home.rstrip("/") + "/.ssh"), ("authorized_keys", keyfile)]
            for label, path in attrs:
                st = system.stat(path)
                facts[label + "_mode"] = oct(st.st_mode & 0o777)
                facts[label + "_owner_ok"] = st.st_uid in (0, facts["uid"])
            facts["permissions_safe"] = all(
                facts[label + "_owner_ok"] and not (int(facts[label + "_mode"], 8) & 0o022)
                for label, _ in attrs)
        except EvidenceError as exc:
            facts["permissions_safe"] = False
            facts["detail"] = str(exc)
    return facts


def backup_facts(system, backup_root):
    facts = {"root": backup_root, "latest": None, "has_sshd_config": False, "complete": False}
    if not system.is_dir(backup_root):
        return facts
    names = [name for name in system.list_dir(backup_root)
             if re.fullmatch(r"[0-9]{8}-[0-9]{6}(?:-[0-9]+)?", name)
             and system.is_dir(backup_root.rstrip("/") + "/" + name)]
    if not names:
        return facts
    latest = backup_root.rstrip("/") + "/" + names[-1]
    facts["latest"] = latest
    required = ["sshd_config", "units.txt", "backup-complete", "ssh.socket.active", "nftables.enabled"]
    missing = [name for name in required if not system.exists(latest + "/" + name)]
    for name in ("sshd_config.d", "ssh.socket.d", "nftables.d", "ufw"):
        if not (system.is_dir(latest + "/" + name) or system.exists(latest + "/" + name + ".absent")):
            missing.append(name)
    for name in ("nftables.conf",):
        if not (system.exists(latest + "/" + name) or system.exists(latest + "/" + name + ".absent")):
            missing.append(name)
    for name in ("nft-ruleset.nft", "ufw-status.txt"):
        if not (system.exists(latest + "/" + name) or system.exists(latest + "/" + name + ".unavailable")):
            missing.append(name)
    if system.exists(latest + "/nft-ruleset.nft"):
        if not system.exists(latest + "/nft-ruleset.json"):
            missing.append("nft-ruleset.json")
        if not (system.exists(latest + "/sshguard.nft") or system.exists(latest + "/sshguard.nft.absent")):
            missing.append("sshguard.nft")
    facts["has_sshd_config"] = system.exists(latest + "/sshd_config")
    for item in ("ssh-allowlist.service", "ssh-allowlist.service.d"):
        if not (system.exists(latest + "/" + item) or system.is_dir(latest + "/" + item)
                or system.exists(latest + "/" + item + ".absent")):
            missing.append(item)
    for item in ("ssh-allowlist.active", "ssh-allowlist.enabled"):
        if not system.exists(latest + "/" + item):
            missing.append(item)
    facts["missing"] = missing
    facts["complete"] = not missing
    return facts


def legacy_blocking(system):
    """旧版自动执行体系残留检测；返回 (阻断原因, 信息性痕迹)。"""
    reasons, traces = [], []
    state_path = LEGACY_STATE_ROOT + "/state.conf"
    if system.exists(state_path):
        state = {}
        for line in system.read(state_path).splitlines():
            key, sep, value = line.partition("=")
            if sep:
                state[key.strip()] = value.strip()
        traces.append("旧版受管状态 STAGE=%s TX=%s" % (state.get("STAGE"), state.get("TX")))
        if state.get("STAGE", "").endswith("-pending"):
            reasons.append("旧版事务待确认（STAGE=%s TX=%s）" % (state.get("STAGE"), state.get("TX")))
    try:
        timers = [name for name in system.list_dir("/etc/systemd/system")
                  if name.startswith("reinforce-my-ssh-") and name.endswith(".timer")]
    except EvidenceError:
        timers = []
    for unit in timers:
        states = []
        for sub in ("is-active", "is-enabled"):
            try:
                result = system.run_allow_fail("systemctl", sub, unit)
                states.append((result.stdout or "").strip() or "unknown")
            except EvidenceError:
                states.append("unknown")
        active, enabled = states
        traces.append("旧版恢复定时器 %s（%s / %s）" % (unit, active, enabled))
        if active not in ("inactive", "failed") or enabled not in ("disabled", "masked"):
            reasons.append("旧版恢复定时器运行、已启用或状态未知，先人工核对：" + unit)
    for path in LEGACY_MANAGED:
        if system.exists(path):
            traces.append(path)
    return reasons, traces


def firewall_summary(system):
    summary = {"nft_input": [], "nft_tables": [], "ufw": {"available": False}}
    try:
        js = json.loads(system.run("nft", "-j", "list", "ruleset"))
        for item in js.get("nftables", []):
            if "table" in item:
                summary["nft_tables"].append(item["table"].get("family", "?") + " " + item["table"].get("name", "?"))
            if "chain" in item and item["chain"].get("hook") == "input":
                summary["nft_input"].append({"family": item["chain"].get("family"), "table": item["chain"].get("table"),
                                             "chain": item["chain"].get("name"), "policy": item["chain"].get("policy", "?")})
    except (EvidenceError, ValueError):
        pass
    try:
        text = system.run("ufw", "status", "verbose")
        summary["ufw"] = {"available": True, "active": not re.search(r"Status:\s*inactive", text), "text": text.strip()}
    except EvidenceError:
        pass
    return summary


# ---------------------------------------------------------------- 参数

def tailnet_facts(system):
    """tailscale0 存在且 IFF_UP；TUN 的 operstate 常为 unknown，故以 flags 位为准。"""
    facts = {"interface": TAILSCALE_IFACE, "present": False, "state": None, "flags": None, "up": False}
    if not system.exists(TAILSCALE_IFACE):
        return facts
    facts["present"] = True
    try:
        facts["state"] = system.read(TAILSCALE_IFACE + "/operstate").strip()
    except EvidenceError:
        pass
    try:
        facts["flags"] = int(system.read(TAILSCALE_IFACE + "/flags").strip(), 16)
    except (EvidenceError, ValueError):
        pass
    if facts["flags"] is not None:
        facts["up"] = bool(facts["flags"] & 0x1)
    else:
        facts["up"] = facts["state"] in ("up", "unknown")
    return facts


def is_tailnet_address(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address in CGNAT or address in TAILSCALE_V6


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog=SCRIPT,
        description="只读指导：切端口 / 装公钥 / 验证 sudo 用户；不修改系统、不代执行。",
        epilog="退出码：0=stage1 目标全部达成；1=阻断性异常；2=步骤未完成或需要 sudo。")
    parser.add_argument("--port", type=int, required=True, help="目标新端口（加固后唯一保留的端口）")
    parser.add_argument("--user", required=True, help="目标非 root 管理账户（需在 sudo 组）")
    parser.add_argument("--allow", action="append", default=[], help="传给 stage2 的可信来源 CIDR，可重复；不自动推定信任范围")
    parser.add_argument("--old-port", help="旧端口；默认从当前会话或现有监听推断；无旧端口用 none")
    parser.add_argument("--host", help="客户端连接地址或 SSH 别名，仅用于生成提示命令")
    parser.add_argument("--rescue-confirmed", action="store_true", help="已实际演练 VNC/串口救援登录（硬门槛）")
    parser.add_argument("--tailnet", action="store_true", help="管理通路经 Tailscale tailnet；增加接入与验证步骤")
    parser.add_argument("--backup-dir", default=BACKUP_ROOT, help="备份约定目录（默认 " + BACKUP_ROOT + "）")
    parser.add_argument("--tailnet-session-confirmed", action="store_true", help="已核实当前 SSH 会话确经 tailscale0 到 sshd；地址段不能代替入口证据")
    parser.add_argument("--reboot-confirmed", action="store_true", help="本次冷启动后已验证全部允许来源和拒绝来源的新连接；任何运行态变更后须重新验收")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    options = parser.parse_args(argv)
    if options.tailnet_session_confirmed and not options.tailnet:
        parser.error("--tailnet-session-confirmed 必须与 --tailnet 同用，且只声明本次实际入口")
    if not 1 <= options.port <= 65535:
        parser.error("--port 超出范围")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*\$?", options.user) or options.user == "root":
        parser.error("--user 必须是非 root 的合法账户名")
    if options.old_port not in (None, "none"):
        if not re.fullmatch(r"\d+", options.old_port) or not 1 <= int(options.old_port) <= 65535:
            parser.error("--old-port 必须是端口号或 none")
        if int(options.old_port) == options.port:
            parser.error("旧端口不能等于目标端口")
    try:
        options.allow = sorted({str(ipaddress.ip_network(value, strict=True)) for value in options.allow})
    except ValueError as exc:
        parser.error(str(exc))
    if options.host and not re.fullmatch(r"[A-Za-z0-9_.:\[\]-]+", options.host):
        parser.error("--host 含不支持的字符")
    if (not options.backup_dir.startswith("/") or options.backup_dir.startswith("//")
            or options.backup_dir.rstrip("/") == "" or any(part in (".", "..") for part in options.backup_dir.split("/"))
            or any(ord(c) < 32 or ord(c) == 127 for c in options.backup_dir)):
        parser.error("--backup-dir 必须是非根目录的绝对路径，不含 .、.. 或控制字符")
    options.backup_dir = options.backup_dir.rstrip("/")
    return options


# ---------------------------------------------------------------- 步骤方案

def continuation_command(options, script=SCRIPT, old_port=None):
    args = ["sudo", "bash", entry_dir() + "/" + script, "--port", str(options.port),
            "--user", options.user, "--backup-dir", options.backup_dir]
    if script == SCRIPT and old_port is not None:
        args += ["--old-port", str(old_port)]
    for cidr in options.allow:
        args += ["--allow", cidr]
    if options.host:
        args += ["--host", options.host]
    if options.tailnet:
        args += ["--tailnet"]
    for flag in ("rescue_confirmed", "tailnet_session_confirmed", "reboot_confirmed"):
        if getattr(options, flag):
            args += ["--" + flag.replace("_", "-")]
    return shlex.join(args)


def backup_commands(backup_root):
    # 目录通过位置参数进入 root shell；任何复制/快照失败均停止，不写完成标记。
    body = '''umask 077
DIR="$1/$(date +%Y%m%d-%H%M%S)-$$"
mkdir -p -- "$1"
mkdir -m 700 -- "$DIR"
cp -a -- /etc/ssh/sshd_config "$DIR/sshd_config"
for spec in /etc/ssh/sshd_config.d:sshd_config.d /etc/systemd/system/ssh.socket.d:ssh.socket.d /etc/nftables.conf:nftables.conf /etc/nftables.d:nftables.d /etc/ufw:ufw /etc/systemd/system/ssh-allowlist.service:ssh-allowlist.service /etc/systemd/system/ssh-allowlist.service.d:ssh-allowlist.service.d; do
    src=${spec%:*}; dst=${spec##*:}
    if [ -e "$src" ]; then cp -a -- "$src" "$DIR/$dst"; else : > "$DIR/$dst.absent"; fi
done
if command -v nft >/dev/null 2>&1; then
    nft list ruleset > "$DIR/nft-ruleset.nft"
    nft -j list ruleset > "$DIR/nft-ruleset.json"
    nft list tables > "$DIR/nft-tables.txt"
    if grep -Fxq 'table inet sshguard' "$DIR/nft-tables.txt"; then
        nft list table inet sshguard > "$DIR/sshguard.nft"
    else : > "$DIR/sshguard.nft.absent"; fi
else : > "$DIR/nft-ruleset.nft.unavailable"; fi
if command -v ufw >/dev/null 2>&1; then ufw status verbose > "$DIR/ufw-status.txt"; else : > "$DIR/ufw-status.txt.unavailable"; fi
systemctl show ssh.service ssh.socket > "$DIR/units.txt"
for spec in ssh.socket:is-active:ssh.socket.active nftables.service:is-enabled:nftables.enabled ssh-allowlist.service:is-active:ssh-allowlist.active ssh-allowlist.service:is-enabled:ssh-allowlist.enabled; do
    unit=${spec%%:*}; rest=${spec#*:}; sub=${rest%%:*}; dst=${rest#*:}
    load=$(systemctl show "$unit" -p LoadState --value)
    case "$load" in
        not-found) printf '%s\\n' not-found > "$DIR/$dst"; continue;;
        loaded|masked) :;;
        *) printf '无法确认单元加载状态: %s (%s)\\n' "$unit" "$load" >&2; exit 1;;
    esac
    result=0
    value=$(systemctl "$sub" "$unit") || result=$?
    case "$sub:$result:$value" in
        is-active:0:active|is-active:3:inactive|is-active:3:failed|is-enabled:0:enabled|is-enabled:0:enabled-runtime|is-enabled:0:static|is-enabled:1:disabled|is-enabled:1:masked) :;;
        *) printf '无法确认单元状态: %s (%s, %s)\\n' "$unit" "$result" "$value" >&2; exit 1;;
    esac
    printf '%s\\n' "$value" > "$DIR/$dst"
done
printf '%s\\n' complete > "$DIR/backup-complete"
printf '备份完成: %s\\n' "$DIR"
'''
    return ["sudo sh -eu -c " + shlex.quote(body) + " sh " + shlex.quote(backup_root)]


def ssh_service_program():
    # 仅生成手工命令文本，不在只读指导进程中执行。
    return r'''import json
import shlex
import subprocess

SSH_SERVICE = "ssh.service"
SSH_SOCKET = "ssh.socket"

def ssh_properties(unit, names):
    result = subprocess.run(["systemctl", "show", unit, "--all"] +
                            [arg for name in names for arg in ("-p", name)],
                            check=True, text=True, capture_output=True)
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    if not all(name in values for name in names):
        raise SystemExit("服务状态采集不完整；保留现有会话，从控制台核对，未停止 SSH。")
    return values

def ssh_preflight(socket_active):
    service = ssh_properties(SSH_SERVICE, ("KillMode", "SendSIGHUP"))
    # systemctl show 即使 --all 也可能省略空的 ExecStop 数组；通过 D-Bus 获取明确的空数组。
    unit_path = "/org/freedesktop/systemd1/unit/" + "".join(
        c if c.isascii() and c.isalnum() else "_%02x" % ord(c) for c in SSH_SERVICE)
    hooks = []
    for name in ("ExecStop", "ExecStopPost"):
        result = subprocess.run(["busctl", "--json=short", "get-property", "org.freedesktop.systemd1",
                                 unit_path, "org.freedesktop.systemd1.Service", name],
                                check=True, text=True, capture_output=True)
        value = json.loads(result.stdout)
        if value.get("type") != "a(sasbttttuii)" or not isinstance(value.get("data"), list):
            raise SystemExit("停止钩子的 D-Bus 证据无效，未停止 SSH。")
        hooks.extend(value["data"])
    if (service["KillMode"] != "process" or service["SendSIGHUP"] != "no"
            or hooks):
        raise SystemExit("无法证明现有会话可保留：要求 KillMode=process、SendSIGHUP=no 且无 ExecStop/ExecStopPost；"
                         "未停止 SSH，不自动修改保护参数。请保持救援控制台并人工核对。")
    socket = ssh_properties(SSH_SOCKET, ("LoadState", "ActiveState"))
    if socket["LoadState"] not in ("loaded", "not-found") or socket["ActiveState"] not in ("active", "inactive", "failed"):
        raise SystemExit("socket 状态不明确，未停止 SSH；请从救援控制台核对。")
    if socket_active and socket["LoadState"] != "loaded":
        raise SystemExit("要求 socket 激活但单元不存在，未停止 SSH。")
    return socket["ActiveState"]

def switch_ssh(socket_active):
    start = ["systemctl", "start"] + ([SSH_SOCKET] if socket_active else []) + [SSH_SERVICE]
    try:
        subprocess.run(["sshd", "-t"], check=True)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        current = ssh_preflight(socket_active)
        coordinated = socket_active or current in ("active", "failed")
        if coordinated:
            # 同一 stop 事务禁止 socket 激活并停主进程；保护条件保留已建立会话的子进程。
            subprocess.run(["systemctl", "stop", SSH_SOCKET, SSH_SERVICE], check=True)
            subprocess.run(start, check=True)
        else:
            subprocess.run(["systemctl", "reload-or-restart", SSH_SERVICE], check=True)
        subprocess.run(["systemctl", "is-active", "--quiet", SSH_SERVICE], check=True)
        if socket_active:
            subprocess.run(["systemctl", "is-active", "--quiet", SSH_SOCKET], check=True)
    except (subprocess.CalledProcessError, OSError, ValueError, SystemExit) as error:
        # 失败即停止：这里只生成文本，不再执行查询、start、stop 或回滚命令。
        status = ["sudo", "systemctl", "status", SSH_SERVICE, SSH_SOCKET, "--no-pager"]
        journal = ["sudo", "journalctl", "-u", SSH_SERVICE, "-u", SSH_SOCKET, "-n", "50", "--no-pager"]
        raise SystemExit("SSH 切换未完成，已停止执行：%s\n"
                         "保持现有会话和救援控制台；故障后的服务状态尚未核实。\n"
                         "以下仅供手工执行，本程序没有执行这些建议：\n"
                         "1. 核对当前状态与日志：\n%s\n%s\n"
                         "2. 检查并修正配置：\nsudo sshd -t\n"
                         "3. 确认故障原因已处理、保护条件仍满足后，由操作员决定是否启动：\n%s\n"
                         "随后验证监听和新的公钥会话，未验证前不要继续下一步或重启主机。"
                         % (error, shlex.join(status), shlex.join(journal), shlex.join(["sudo"] + start)))
'''


def socket_switch_commands():
    return ["# 保持已验证的救援控制台；保护检查通过后才协调切换主进程/socket。",
            "sudo python3 - <<'SSH_SWITCH_PY'\n" + ssh_service_program()
            + "\nswitch_ssh(True)\nSSH_SWITCH_PY"]


def recovery_commands(backup_dir):
    # 只生成供操作员执行的恢复程序；指导脚本本身不会执行它。
    program = r'''import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path("/")
backup = Path(sys.argv[1])

def target(path):
    return ROOT / path.lstrip("/")

def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)

def require(condition, message):
    if not condition:
        raise SystemExit(message)

def remove_file(path):
    # 只删除精确列出的文件；目录异常直接失败，绝不递归删除配置树。
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        raise SystemExit("预期文件却发现目录，停止恢复：" + str(path))

def copy_file(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    remove_file(destination)
    run("cp", "-a", "--", str(source), str(destination))

domains = [
    ("sshd_config.d", "/etc/ssh/sshd_config.d", ["10-newport.conf", "20-hardening.conf"]),
    ("ssh.socket.d", "/etc/systemd/system/ssh.socket.d", ["10-newport.conf"]),
    ("nftables.d", "/etc/nftables.d", ["ssh-allowlist.nft"]),
    ("ufw", "/etc/ufw", []),
    ("ssh-allowlist.service.d", "/etc/systemd/system/ssh-allowlist.service.d", []),
]
for name in ("backup-complete", "sshd_config", "units.txt", "ssh.socket.active", "nftables.enabled"):
    require((backup / name).is_file(), "备份不完整，停止恢复：" + name)
require((backup / "backup-complete").read_text().strip() == "complete", "备份未成功完成")
for name, _, _ in domains:
    require((backup / name).is_dir() or (backup / (name + ".absent")).is_file(), "备份缺少目录状态：" + name)
require((backup / "nftables.conf").exists() or (backup / "nftables.conf.absent").is_file(), "备份缺少 nftables.conf 状态")
require((backup / "ssh-allowlist.service").is_file() or (backup / "ssh-allowlist.service.absent").is_file(), "缺少实际加载器备份")
loader_active = (backup / "ssh-allowlist.active").read_text().strip()
loader_enabled = (backup / "ssh-allowlist.enabled").read_text().strip()
require(loader_active in ("active", "inactive", "failed", "not-found"), "加载器活跃状态不明确")
require(loader_enabled in ("enabled", "enabled-runtime", "disabled", "masked", "static", "not-found"), "加载器启用状态不明确")
require(loader_enabled != "masked", "原加载器 masked，须人工核对掩码链接，停止自动还原")
socket_state = (backup / "ssh.socket.active").read_text().strip()
nft_enabled = (backup / "nftables.enabled").read_text().strip()
require(socket_state in ("active", "inactive", "failed", "not-found"), "备份中 ssh.socket 状态不明确")
require(nft_enabled in ("enabled", "enabled-runtime", "disabled", "masked", "static", "not-found"), "备份中 nftables 启用状态不明确")
snapshot = None
if (backup / "nft-ruleset.nft").is_file():
    require(shutil.which("nft"), "缺少 nft，不能恢复防火墙")
    snapshot = json.loads((backup / "nft-ruleset.json").read_text())
    require(isinstance(snapshot.get("nftables"), list), "nft JSON 快照无效")
    require((backup / "sshguard.nft").is_file() or (backup / "sshguard.nft.absent").is_file(), "缺少 sshguard 原始状态")
    had_table = any(x.get("table", {}).get("family") == "inet" and x.get("table", {}).get("name") == "sshguard"
                    for x in snapshot["nftables"])
    require(had_table == (backup / "sshguard.nft").is_file(), "sshguard 快照与规则清单矛盾")
else:
    require((backup / "nft-ruleset.nft.unavailable").is_file(), "缺少 nft 备份状态")
    require(not shutil.which("nft"), "备份时 nft 不可用，现在已安装；先人工核对防火墙，不能猜测原始规则")
ufw_active = False
if (backup / "ufw-status.txt").is_file():
    ufw_active = "Status: active" in (backup / "ufw-status.txt").read_text()
    require(not ufw_active or shutil.which("ufw"), "原 UFW 处于 active，当前缺少 ufw")
else:
    require((backup / "ufw-status.txt.unavailable").is_file(), "缺少 UFW 备份状态")

loader_dropins = target("/etc/systemd/system/ssh-allowlist.service.d")
saved_dropins = backup / "ssh-allowlist.service.d"
if loader_dropins.is_dir():
    saved_names = {p.name for p in saved_dropins.iterdir()} if saved_dropins.is_dir() else set()
    require(all(p.name in saved_names for p in loader_dropins.iterdir()), "实际加载器存在未备份的 drop-in，先人工协调，停止恢复")
# 先校验恢复表的语法，错误快照不得触发文件删除。
if snapshot is not None and (backup / "sshguard.nft").is_file():
    # 该表可能已存在，完整替换事务在执行前统一检查。
    require((backup / "sshguard.nft").stat().st_size > 0, "sshguard 快照为空")

def firewall_transaction():
    current = json.loads(run("nft", "-j", "list", "ruleset", capture_output=True).stdout)
    entries = current.get("nftables", [])
    commands = []
    if any(x.get("table", {}).get("family") == "inet" and x.get("table", {}).get("name") == "sshguard" for x in entries):
        commands.append("delete table inet sshguard")
    if (backup / "sshguard.nft").is_file():
        commands.append((backup / "sshguard.nft").read_text())
    def identity(rule):
        return tuple(rule.get(k) for k in ("family", "table", "chain", "handle"))
    original = {identity(x["rule"]) for x in snapshot["nftables"] if "rule" in x}
    for item in entries:
        rule = item.get("rule", {})
        if (rule.get("comment") != "stage1 new-port bridge" or identity(rule) in original
                or (rule.get("family") == "inet" and rule.get("table") == "sshguard")):
            continue
        require(rule.get("family") in ("ip", "ip6", "inet") and isinstance(rule.get("handle"), int), "过渡规则身份不明确")
        require(all(isinstance(rule.get(key), str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", rule[key])
                    for key in ("table", "chain")), "规则表/链名称需人工核对，停止恢复")
        commands.append("delete rule " + rule["family"] + " " + rule["table"]
                        + " " + rule["chain"] + " handle " + str(rule["handle"]))
    return "\n".join(commands) + "\n"

if snapshot is not None:
    run("nft", "-c", "-f", "-", input=firewall_transaction())

# 写入恢复文件前预检，daemon-reload 后再次检查保护条件。
ssh_preflight(socket_state == "active")
copy_file(backup / "sshd_config", target("/etc/ssh/sshd_config"))
for name, destination, introduced in domains:
    saved = backup / name
    destination = target(destination)
    for filename in introduced:
        remove_file(destination / filename)
    if saved.is_dir():
        destination.mkdir(parents=True, exist_ok=True)
        run("cp", "-a", "--", str(saved) + "/.", str(destination) + "/")
if (backup / "nftables.conf").exists():
    copy_file(backup / "nftables.conf", target("/etc/nftables.conf"))
else:
    remove_file(target("/etc/nftables.conf"))
loader_path = target("/etc/systemd/system/ssh-allowlist.service")
if (backup / "ssh-allowlist.service").is_file():
    copy_file(backup / "ssh-allowlist.service", loader_path)
else:
    remove_file(loader_path)
# 先恢复磁盘与内核快照；加载器 active 状态仅在原配置可检查且不执行未知变更时恢复。
run("systemctl", "daemon-reload")
if loader_enabled in ("enabled", "enabled-runtime"):
    args = ["systemctl", "enable"]
    if loader_enabled == "enabled-runtime":
        args.append("--runtime")
    run(*args, "ssh-allowlist.service")
elif loader_enabled == "disabled":
    run("systemctl", "disable", "ssh-allowlist.service")
elif loader_enabled == "not-found":
    # 本工具仅生成 multi-user.target 链接；不能在删除 unit 后 disable 一个不存在的服务。
    for directory in ("/etc/systemd/system", "/run/systemd/system"):
        remove_file(target(directory + "/multi-user.target.wants/ssh-allowlist.service"))
if ufw_active:
    run("ufw", "reload")
if snapshot is not None:
    transaction = firewall_transaction()
    run("nft", "-c", "-f", "-", input=transaction)
    run("nft", "-f", "-", input=transaction)
# 不 stop nftables：其 ExecStop 可能 flush 全机规则。仅撤销本流程增加的开机启用。
if nft_enabled == "disabled":
    run("systemctl", "disable", "nftables.service")
if loader_active == "active":
    print("原专用加载器为 active：内核快照已还原；请核对原 unit/drop-in 后，另行手工恢复其 active 状态，避免未知 ExecStart 改写快照。")
switch_ssh(socket_state == "active")
if loader_active == "active":
    raise SystemExit("SSH 配置及内核快照已恢复，但原加载器 active 状态待操作员核实后另行恢复；本次不宣称完整恢复。")
print("备份中的配置与 SSH 防火墙域已恢复；保持救援会话，验证旧入口、新公钥会话及完整规则，再考虑重启。")
'''
    program = ssh_service_program() + "\n" + program
    return ["# 完整恢复到 stage1 备份，会同时撤销后续 SSH/防火墙更改；从已验证的救援通道执行，失败停止。",
            "sudo python3 - " + shlex.quote(backup_dir) + " <<'SSH_RECOVERY_PY'\n" + program + "SSH_RECOVERY_PY",
            "sudo ss -ltnp  # 核对旧入口恢复，再从客户端建立新的公钥 SSH 会话",
            "# 有 nft 时核对 sudo nft list ruleset；原有其它规则不应被清空。"]


def build_steps(system, options, ctx):
    """按内置只读方案构造步骤；每步含状态确认/为什么/执行/验证/撤销。"""
    host = options.host or "SERVER"
    port = options.port
    user = options.user
    old_port = ctx["old_port"]
    sock = ctx["socket"]
    socket_activation = sock["load"] == "loaded" and sock["active"] == "active"
    restore_path = ctx["backup"].get("latest") or options.backup_dir + "/REPLACE_WITH_TIMESTAMP"
    steps = []

    def step(sid, title, status, evidence, why, do, verify, undo, blocked_by=None):
        steps.append({"id": sid, "title": title, "status": status, "evidence": evidence,
                      "why": why, "do": do, "verify": verify, "undo": undo, "blocked_by": blocked_by or []})

    rescue = options.rescue_confirmed
    step("0-rescue", "救援通道演练确认",
         DONE if rescue else TODO,
         "已声明 --rescue-confirmed" if rescue else "尚未声明；脚本无法替你验证 VNC/串口",
         "2026-10-27 事故的教训是：救援通道“假定可用”等于没有救援通道。加固期间任何一步出问题，云控制台 VNC/串口是你唯一的退路。",
         ["在云控制台打开本实例的 VNC/串口终端，实际登录一次并确认可以使用（不是只看到按钮）。",
          "演练成功后，后续命令都加 --rescue-confirmed 重跑本脚本。"],
         ["云控制台能打开 VNC/串口并成功登录一次。"],
         ["无需撤销；这是前置事实确认。"])

    backup = ctx["backup"]
    backup_ok = backup.get("complete")
    step("1-backup", "手工全量备份",
         DONE if backup_ok else TODO,
         ("最近备份：%s（含 sshd_config）" % backup.get("latest")) if backup_ok else "未发现 %s 下的完整备份" % options.backup_dir,
         "此后每一步都改动系统；任何撤销都只依赖这份备份。工具不替你回滚，备份是唯一退路。",
         backup_commands(options.backup_dir),
         ["sudo ls -la -- " + shlex.quote(options.backup_dir),
          "# 重跑本脚本：必须同时有配置副本、快照/缺省记录与 backup-complete 标记"],
         ["# 保留备份；备份本身不改变配置，无需删除或撤销"])

    account = ctx["account"]
    if not account.get("exists"):
        account_ok, account_note = False, "账户 %s 不存在" % user
    elif not account.get("sudo"):
        account_ok, account_note = False, "账户 %s 不在 sudo 组" % user
    elif not account.get("authorized_keys_count"):
        account_ok, account_note = False, "账户 %s 未安装公钥" % user
    elif not account.get("permissions_safe"):
        account_ok, account_note = False, "家目录/.ssh/authorized_keys 的属主或写权限不安全，或无法读取"
    else:
        account_ok = True
        account_note = "uid=%s，sudo 组，authorized_keys %d 个公钥" % (account.get("uid"), account["authorized_keys_count"])
        if account.get("authorized_keys_mode") not in ("0o600", "0o400") or account.get("ssh_dir_mode") != "0o700":
            account_note += "；权限安全，但建议收紧至目录 700 / 文件 600"
    home = shlex.quote(account.get("home") or "/home/" + user)
    permission_commands = [
        "# 服务器：只修复这三个路径，属主不含组名，不递归修改整个家目录：",
        "sudo chown -- " + user + " " + home + " " + home + "/.ssh " + home + "/.ssh/authorized_keys",
        "sudo chmod go-w -- " + home,
        "sudo chmod 700 -- " + home + "/.ssh",
        "sudo chmod 600 -- " + home + "/.ssh/authorized_keys",
    ]
    step("2-account", "sudo 组非 root 账户与公钥",
         DONE if account_ok else TODO,
         account_note,
         "加固的终点是“只有非 root 账户 + 公钥”能登录。这一步先把新账户和公钥准备好并在旧端口上验证，之后才谈切端口。",
         ["# 服务器（账户不存在时）：",
          "sudo adduser --gecos '' " + user,
          "sudo usermod -aG sudo " + user,
          "# 客户端（本地机器）安装公钥，出现提示时输入该账户密码：",
          "ssh-copy-id -i ~/.ssh/<你的公钥> -p " + (str(old_port) if isinstance(old_port, int) else "22") + " " + user + "@" + host,
          *permission_commands,
          "# 客户端验证公钥登录与 sudo（sudo 输密码属正常）：",
          "ssh -i ~/.ssh/<你的私钥> -o PreferredAuthentications=publickey -o PasswordAuthentication=no -p " + (str(old_port) if isinstance(old_port, int) else "22") + " " + user + "@" + host + " 'sudo -v && echo SUDO_OK'"],
         ["重跑本脚本：本步骤应为“已完成”；账户权限异常会单独提示并给出 chmod/chown 命令"],
         ["sudo deluser --remove-home " + user + "  # 仅在决定放弃该账户时执行"])

    if options.tailnet:
        tn = ctx["tailnet"]
        if tn.get("up"):
            tn_status, tn_note = DONE, "tailscale0 已 up：节点已加入 tailnet"
        elif tn.get("present"):
            tn_status, tn_note = TODO, "tailscale0 存在但状态为 %s：tailscaled 未就绪" % (tn.get("state") or "不可读")
        else:
            tn_status, tn_note = TODO, "未发现 tailscale0：尚未加入 tailnet"
        step("2b-tailnet", "接入 Tailscale tailnet（管理/救援通路）",
             tn_status, tn_note,
             "tailnet 提供一条独立于 sshd 的管理通路，可在关闭公网端口后继续管理，也是 VNC/串口之外的备份救援路径。"
             "但它不能替代救援演练，也不能作为 sshd 加固的证据：Tailscale SSH 由 tailscaled 终结认证，不经过 sshd。",
             ["# 服务器（Ubuntu/Debian，安装方式以官方当前说明为准）：",
              "sudo apt-get update && sudo apt-get install -y tailscale",
              "sudo tailscale up   # 按提示完成登录；需要验证 sshd 路径时不要加 --ssh",
              "# 管理台 Machines 页对本节点禁用 key expiry（默认 180 天后节点会被登出）",
              "# 客户端（另一台已入 tailnet 的设备）：",
              "ssh -p " + (str(old_port) if isinstance(old_port, int) else "22") + " " + user + "@<本节点 tailnet 地址>   # 地址用 tailscale ip -4 查询；新端口在第 4 步再验证"],
             ["服务器：tailscale status 显示本节点；tailscale ip -4 返回 100.64.0.0/10 内的地址",
              "服务器：tailscale0 已启用（IFF_UP；TUN 的 operstate 可能显示 unknown）",
              "客户端：经 tailnet 用公钥登录成功（此时用当前/旧端口；新端口的公钥证明在第 4 步）"],
             ["sudo tailscale down    # 临时下线，保留登录状态",
              "sudo tailscale logout  # 完全退出 tailnet（之后需要重新授权）"],
             blocked_by=[] if backup_ok else ["1-backup"])

    new_listening = port in ctx["listeners"]
    disk_has_new = port in ctx["disk_ports"]
    if new_listening and disk_has_new:
        new_status, new_note = DONE, "端口 %d 正在监听且已写入磁盘配置（重启后仍生效）" % port
    elif new_listening:
        new_status, new_note = WARN, "端口 %d 正在监听但未见于磁盘配置，重启后会丢失；请按下方命令写入配置" % port
    else:
        new_status, new_note = TODO, "端口 %d 未在监听（当前 sshd 监听：%s）" % (port, ctx["listeners"] or "无")
    old_text = str(old_port) if isinstance(old_port, int) else ""
    nft_review_required = False
    if backup_ok:
        if socket_activation:
            new_commands = [
                "# 本机布局：ssh.socket 激活。新增监听端口（旧端口保留）：",
                "sudo install -d -m 755 " + SOCKET_DROPIN_DIR,
                "sudo tee " + NEWPORT_SOCKET_DROPIN + " >/dev/null <<'EOF'",
                "[Socket]",
                "ListenStream=" + str(port),
                "EOF",
                *socket_switch_commands(),
                "ss -tlnp | grep sshd",
            ]
        else:
            new_commands = [
                "# 本机布局：传统 sshd 服务。写入端口配置（旧端口保留）：",
                "# 注意：一旦显式声明 Port，默认 22 不再隐式生效，所以现有端口与目标端口都要列出。",
                "sudo install -d -m 755 " + SSHD_CONFIG_D,
                "sudo tee " + NEWPORT_DROPIN + " >/dev/null <<'EOF'",
                *(["Port " + old_text] if old_text else []),
                "Port " + str(port),
                "EOF",
                "sudo sshd -t && sudo systemctl reload ssh.service",
                "ss -tlnp | grep sshd",
            ]
        new_commands += ["", "# 本机防火墙（按实际检测结果选择；云安全组放行新端口需到云控制台人工完成）："]
        fw = ctx["firewall"]
        if fw["ufw"].get("active"):
            new_commands += ["sudo ufw allow " + str(port) + "/tcp comment 'stage1 新端口过渡'"]
        elif fw["nft_input"]:
            new_commands += ["# 检测到 nft input 链：不猜测链、不追加可能位于 drop 后的规则。",
                             "# 人工检查 sudo nft -a list ruleset，逐个协调 ip/ip6/inet 的所有 input 拦截链。",
                             "# 保留旧端口；以 nft 文件事务插入确实位于拒绝之前的放行，使用文件内 comment 字符串。",
                             "# 需覆盖 IPv4/IPv6，并从新端口新建公钥会话后重跑；未验证前保持阻断。"]
            if not (new_listening and ctx.get("auth") == "publickey" and ctx["connection"] and ctx["connection"]["port"] == port):
                new_status = BLOCKED
                nft_review_required = True
                new_commands = [x for x in new_commands if x.startswith("#")][-4:]
                new_note += "；nft 多链放行需人工协调并以新入口连接证明"
        else:
            new_commands += ["# 未检测到本地放行需求（input 默认 accept 或无法采集）；请以云安全组为准"]
    else:
        new_commands = ["# 被门槛阻塞：请先完成 1-backup（备份）"]
    if backup_ok and old_port is None and not socket_activation:
        new_status = BLOCKED
        new_commands = ["# 无法唯一识别旧端口；先用 --old-port 指定，确认没有旧端口则传 --old-port none。"]
    if backup_ok and not account_ok:
        new_status = BLOCKED
        new_commands = ["# 先完成 2-account：修复账户、公钥权限并验证登录，再切端口。"]
    new_undo = recovery_commands(restore_path)
    step("3-new-port", "开启新端口（旧端口保留）",
         new_status, new_note,
         "新入口必须先被证明可用，旧入口才能关闭。这里只新增监听与放行，不动旧入口。",
         new_commands,
         ["服务器：ss -tlnp 应同时看到 " + str(port) + ((" 与 " + str(old_port)) if isinstance(old_port, int) else "") + " 在 sshd 进程下监听",
          "服务器：sudo sshd -t 通过；socket 激活时 systemctl show ssh.socket -p Listen 含新端口",
          "客户端：ssh -o PreferredAuthentications=publickey -p " + str(port) + " " + user + "@" + host + " true"],
         new_undo,
         blocked_by=(["1-backup"] if not backup_ok else []) + (["2-account"] if not account_ok else []) + (["--old-port"] if old_port is None and not socket_activation else []) + (["nft-input-review"] if nft_review_required else []))

    session = ctx["connection"]
    auth = ctx["auth"]
    if session and session["port"] == port and auth == "publickey":
        path = "经已核实的 tailnet 接口" if options.tailnet_session_confirmed else "入口接口未证实（地址段不足为证）"
        verify_status, verify_note = DONE, "当前会话即新端口 %d 的公钥登录（%s，journal 已匹配四元组），硬门槛已满足" % (port, path)
    elif session and session["port"] == port and auth is None:
        if options.tailnet_session_confirmed:
            verify_status, verify_note = UNKNOWN, ("当前会话来自 tailnet 且在新端口 %d 上，但 journal 没有 sshd 公钥认证记录："
                                                    "可能是 Tailscale SSH（由 tailscaled 终结，不经过 sshd），不能作为 sshd 路径的验证证据；"
                                                    "请改用该账户公钥登录 sshd 后重跑" % port)
        else:
            verify_status, verify_note = UNKNOWN, "当前会话在新端口 %d 上，但认证方式无法从 journal 证实；请核对 journal 或重试" % port
    else:
        verify_status, verify_note = TODO, "当前会话不在新端口 %d 上（或非公钥认证）" % port
    step("4-verify-new", "从新端口外部公钥登录验证（硬门槛）",
         verify_status, verify_note,
         "这是整个流程的防锁死闸门：必须从新端口、以公钥、从一个全新外部会话登录成功，才允许关闭旧端口。工具无法代替你在客户端操作，只能用“你从这个会话重跑脚本”作为证据。",
         ["# 客户端（保持旧会话不关）新开终端：",
          "ssh -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -p " + str(port) + " " + user + "@" + host,
          "# 在新会话里执行 sudo，并在提示符确认后重跑本脚本（同一参数）：",
          continuation_command(options, old_port=old_port)],
         ["同一命令下，本步骤状态变为“已完成”（脚本核对当前会话端口与 journal 公钥证据）"],
         ["无需撤销；登录尝试是只读操作"],
         blocked_by=[] if new_listening else ["3-new-port"])

    if old_port == "none":
        no_other_ports = ctx["listeners"] == [port] and (socket_activation or not (set(ctx["disk_ports"]) - {port}))
        old_close_status = DONE if no_other_ports and verify_status == DONE else TODO
        old_close_note = "已显式声明无旧端口；仍要求唯一新监听与新公钥会话验证"
        old_close_evidence = "listeners=%s" % ctx["listeners"]
    elif old_port is None:
        old_close_status, old_close_note, old_close_evidence = BLOCKED, "无法唯一识别旧端口；请用 --old-port 指明（若无需关闭用 --old-port none）", "推断失败"
    elif old_port not in ctx["listeners"] and (socket_activation or old_port not in ctx["disk_ports"]):
        old_close_status, old_close_note, old_close_evidence = DONE, "端口 %d 已不在监听且不在磁盘配置中" % old_port, "listeners=%s" % ctx["listeners"]
    else:
        old_close_status, old_close_note, old_close_evidence = TODO, "端口 %d 仍在监听或仍在磁盘配置中" % old_port, "listeners=%s" % ctx["listeners"]

    old_close_why = "完成端口切换的最后一步：确认新入口被外部证实可用（第 4 步）之后，才移除旧入口。保持至少一条已验证会话开着直到这一步结束。"
    if options.tailnet:
        old_close_why += (" 已声明 --tailnet：如果最终只保留 tailnet 入口，公网侧的彻底关闭由 stage2 的 1b-close-public 负责；"
                          "本步仍按端口切换处理，不要在 tailnet 路径未被验证前先行切断公网。")
    if old_port == "none":
        old_close_do = ["# 已明确声明没有旧端口，无需关闭。"]
        old_close_verify = ["重跑本脚本核对唯一新端口"]
        old_close_undo = ["无需撤销"]
    elif old_port is None:
        old_close_do = ["# 旧端口未知；核对监听后，把下面模板中的端口替换为真实旧端口再执行：",
                        "# " + continuation_command(options) + " --old-port REPLACE_WITH_OLD_PORT",
                        "# 只有确认没有旧端口时才显式声明 --old-port none；脚本不会把未知自动变成 none。"]
        old_close_verify = ["重跑本脚本，本步骤应变为“已完成”或给出明确可执行命令"]
        old_close_undo = ["无需撤销：本步骤尚未执行"]
    else:
        if socket_activation:
            old_close_do = ["# 编辑 " + NEWPORT_SOCKET_DROPIN + "，先清空继承的 Listen 再只保留新端口：",
                            "systemctl cat ssh.socket | grep -n ListenStream  # 先核对主单元是否声明过其它 Listen（地址绑定/多栈），如有需一并镜像",
                            "sudo tee " + NEWPORT_SOCKET_DROPIN + " >/dev/null <<'EOF'",
                            "[Socket]",
                            "ListenStream=",
                            "ListenStream=" + str(port),
                            "EOF",
                            *socket_switch_commands(),
                            "ss -tlnp | grep sshd",
                            "",
                            "# 防火墙与云安全组同步收口旧端口：",
                            "sudo ufw delete allow " + old_text + "/tcp 2>/dev/null || true",
                            "# 云控制台：删除旧端口 " + old_text + " 的放行规则"]
        else:
            locations = ctx["disk_ports"].get(old_port, [])
            files = sorted({location.rsplit(":", 1)[0] for location in locations})
            edit_commands = (["# 移除以下位置的旧 Port 声明，保留目标端口和其它配置：", "# " + "; ".join(locations)]
                             + ["sudoedit -- " + shlex.quote(path) for path in files])
            old_close_do = [*edit_commands, "sudo tee " + NEWPORT_DROPIN + " >/dev/null <<'EOF'",
                            "Port " + str(port),
                            "EOF",
                            "sudo sshd -t && sudo systemctl reload ssh.service",
                            "ss -tlnp | grep sshd",
                            "sudo ufw delete allow " + old_text + "/tcp 2>/dev/null || true",
                            "# 云控制台：删除旧端口 " + old_text + " 的放行规则"]
        old_close_verify = ["sudo ss -H -ltn 'sport = :" + old_text + "'  # 命令成功且无输出才代表无 TCP 监听；失败不算通过",
                            "客户端：ssh -p " + old_text + " " + user + "@" + host + "  # 应连接失败（预期）",
                            "客户端：ssh -p " + str(port) + " " + user + "@" + host + "  # 应仍可用"]
        old_close_undo = recovery_commands(restore_path)
    blocked = []
    if old_close_status != DONE:
        if not rescue:
            blocked.append("0-rescue")
        if verify_status != DONE:
            blocked.append("4-verify-new")
    if old_port != "none":
        if not backup_ok:
            blocked.append("1-backup")
        if not account_ok:
            blocked.append("2-account")
    step("5-close-old", "关闭旧端口",
         old_close_status, old_close_note,
         old_close_why,
         old_close_do,
         old_close_verify,
         old_close_undo,
         blocked_by=blocked)
    return steps


def resolve_context(system, options):
    ctx = {}
    ctx["connection"] = find_connection(system)
    ctx["auth"] = session_auth(system, ctx["connection"], options.user)
    ctx["socket"] = socket_state(system)
    ports = set(sshd_listeners(system))
    if ctx["socket"]["active"] == "active":
        # socket 激活时监听由 systemd 持有，ss 里没有 sshd 进程归属
        ports.update(ctx["socket"]["listen_ports"])
    ctx["listeners"] = sorted(ports)
    ctx["disk_ports"] = disk_port_directives(system)
    ctx["account"] = account_facts(system, options.user)
    ctx["backup"] = backup_facts(system, options.backup_dir)
    ctx["firewall"] = firewall_summary(system)
    ctx["tailnet"] = tailnet_facts(system)
    ctx["match_blocks"] = match_blocks(system)
    valid, error = sshd_valid(system)
    ctx["sshd_valid"] = valid
    ctx["sshd_error"] = error
    ctx["legacy"], ctx["legacy_traces"] = legacy_blocking(system)
    # 旧端口推断：显式 > 当前会话 > 唯一其它监听
    if options.old_port == "none":
        ctx["old_port"] = "none"
    elif options.old_port:
        ctx["old_port"] = int(options.old_port)
    elif ctx["connection"] and ctx["connection"]["port"] != options.port:
        ctx["old_port"] = ctx["connection"]["port"]
    else:
        candidates = [p for p in ctx["listeners"] if p != options.port]
        ctx["old_port"] = candidates[0] if len(candidates) == 1 else None
    return ctx


# ---------------------------------------------------------------- 输出

def render_text(ctx, options, steps):
    print("SSH 加固只读指导（stage1-port-key.sh：切端口 / 装公钥 / 验证 sudo 用户）")
    print("本脚本只读：不修改任何配置、不代执行命令；下列操作由你（或你监督下的智能体）手工执行。")
    print("目标：新端口 %d，账户 %s，旧端口 %s" % (options.port, options.user,
          ctx["old_port"] if ctx["old_port"] else "未识别（--old-port）"))
    connection = ctx["connection"]
    if connection:
        print("当前会话：%s:%d -> %s:%d，认证=%s" % (connection["source"], connection["source_port"],
              connection["local"], connection["port"], ctx["auth"] or "未证实"))
    else:
        print("当前会话：未检测到 SSH 连接（请从真实 SSH 会话运行本脚本）")
    print("布局：%s" % ("ssh.socket 激活" if ctx["socket"]["active"] == "active" else "传统 sshd 服务"))
    tailnet = ctx.get("tailnet", {})
    if tailnet.get("present"):
        print("tailscale0：%s（Tailscale SSH 不经过 sshd，不能作为 sshd 验证证据）" % (tailnet.get("state") or "状态不可读"))
    elif options.tailnet:
        print("tailscale0：未发现（已声明 --tailnet，请先完成 2b-tailnet）")
    print("\n步骤清单：")
    for item in steps:
        print("  [%s] %s —— %s" % (STATUS_LABEL[item["status"]], item["title"], item["evidence"]))
    current = next((item for item in steps if item["status"] != DONE), None)
    if current is None:
        print("\nstage1 目标全部达成。下一步（收紧：nft 白名单 / 禁 root / 禁密码）：")
        command = continuation_command(options, script=STAGE2)
        if options.tailnet or options.allow:
            print("  " + command)
        else:
            print("  尚未声明可信来源：用 stage1 --allow CIDR（可重复）续跑后再进入 stage2。")
            print("  以下是模板，必须先替换可信来源；不会自动把当前 IP 或整个私网加入白名单：")
            print("  # " + command + " --allow REPLACE_WITH_TRUSTED_CIDR")
    else:
        print("\n当前步骤：%s（%s）" % (current["title"], STATUS_LABEL[current["status"]]))
        if current["blocked_by"]:
            print("  门槛未满足：" + "；".join(current["blocked_by"]) + " —— 先完成这些步骤再回来")
        print("  为什么：" + current["why"])
        print("  执行：")
        for line in current["do"]:
            print("    " + line if line else "")
        print("  验证：")
        for line in current["verify"]:
            print("    " + line)
        print("  手工撤销（如需）：")
        for line in current["undo"]:
            print("    " + line)
    if not ctx["sshd_valid"]:
        print("\n[阻断] sshd -t 失败：" + (ctx["sshd_error"] or ""))
    if ctx["match_blocks"]:
        print("[注意] 存在 Match 块，端口与认证改动可能被上下文规则覆盖，需人工复核：" + "; ".join(ctx["match_blocks"][:6]))
    if ctx.get("legacy_traces"):
        print("[信息] 旧版体系痕迹：" + "；".join(ctx["legacy_traces"][:8]))
    if ctx["legacy"]:
        print("[阻断] 旧版残留：" + "；".join(ctx["legacy"]))
    print("\n常备纪律：")
    print("- 每一步只做一件事，做完重跑本脚本核对，不跳步。")
    print("- 保持当前会话不关；云安全组放行必须到云控制台人工完成。")
    print("- 本脚本永远不会替你 reboot、reload、rollback 或安装任何东西。")


def main(argv=None):
    options = parse_args(argv if argv is not None else sys.argv[1:])
    system = System()
    if not is_root():
        print("需要完整读取权限。请运行：")
        print("  sudo bash " + shlex.quote(os.environ.get("REINFORCE_SELF", SCRIPT)) + " " + " ".join(shlex.quote(a) for a in (argv if argv is not None else sys.argv[1:])))
        return 2
    ctx = resolve_context(system, options)
    steps = build_steps(system, options, ctx)
    complete = all(item["status"] == DONE for item in steps)
    report = {
        "schema": 1, "script": SCRIPT, "read_only": True,
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "goals": {"port": options.port, "user": options.user, "old_port": ctx["old_port"],
                  "host": options.host, "tailnet": options.tailnet},
        "rescue_confirmed": options.rescue_confirmed,
        "layout": "socket" if ctx["socket"]["active"] == "active" else "service",
        "session": ctx["connection"], "session_auth": ctx["auth"],
        "tailnet": ctx["tailnet"],
        "listeners": ctx["listeners"], "disk_ports": sorted(ctx["disk_ports"]),
        "steps": steps, "complete": complete,
        "next_step": next((item["id"] for item in steps if item["status"] != DONE), None),
    }
    if options.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
    else:
        render_text(ctx, options, steps)
    if not ctx["sshd_valid"] or ctx["legacy"]:
        return 1
    return 0 if complete else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n已中断；本脚本只读，系统未发生任何变更。", file=sys.stderr)
        sys.exit(130)
REINFORCE_STAGE1_PY
