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
STAGE0 = "stage0-check.sh"
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
        if args[0] not in READ_ONLY_COMMANDS:
            raise EvidenceError("拒绝执行非只读白名单命令：" + args[0])
        allowed_sub = READ_ONLY_COMMANDS[args[0]]
        if allowed_sub is not None and (len(args) < 2 or args[1] not in allowed_sub):
            raise EvidenceError("拒绝执行非只读子命令：" + " ".join(args[:2]))
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
        return Path(path).exists()

    def is_dir(self, path):
        return Path(path).is_dir()

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
    return int(text.rsplit(":", 1)[1])


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
                m = re.match(r"\s*Port\s+(\d+)\s*$", line)
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
                        ports.setdefault(endpoint_port(m.group(1)), []).append("%s:%d" % (path, number))
                    except ValueError:
                        continue
    except EvidenceError:
        pass
    return ports


def account_facts(system, user):
    facts = {"user": user}
    try:
        uid = system.run("id", "-u", user).strip()
    except EvidenceError as exc:
        facts["exists"] = False
        facts["detail"] = str(exc)
        return facts
    facts["exists"] = True
    facts["uid"] = int(uid) if uid.isdigit() else uid
    try:
        groups = system.run("id", "-nG", user).split()
    except EvidenceError:
        groups = []
    facts["groups"] = groups
    facts["sudo"] = "sudo" in groups
    try:
        home = system.run("getent", "passwd", user).split(":")[5]
    except (EvidenceError, IndexError):
        home = None
    facts["home"] = home
    if home:
        keyfile = Path(home) / ".ssh" / "authorized_keys"
        try:
            content = system.read(str(keyfile))
            facts["authorized_keys_count"] = len([line for line in content.splitlines() if line.strip() and not line.strip().startswith("#")])
            st = system.stat(str(keyfile))
            facts["authorized_keys_mode"] = oct(st.st_mode & 0o777)
            facts["ssh_dir_mode"] = oct(system.stat(str(keyfile.parent)).st_mode & 0o777)
            facts["authorized_keys_owner_ok"] = (st.st_uid == facts["uid"])
        except EvidenceError:
            facts["authorized_keys_count"] = 0
    return facts


def backup_facts(system, backup_root):
    facts = {"root": backup_root, "latest": None, "has_sshd_config": False}
    if not system.is_dir(backup_root):
        return facts
    try:
        names = system.list_dir(backup_root)
    except EvidenceError:
        return facts
    if names:
        latest = backup_root.rstrip("/") + "/" + names[-1]
        facts["latest"] = latest
        facts["has_sshd_config"] = system.exists(latest + "/sshd_config")
        try:
            facts["entries"] = system.list_dir(latest)[:12]
        except EvidenceError:
            facts["entries"] = []
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
        active = unit_probe(system, unit, "is-active")
        traces.append("旧版恢复定时器 %s（%s）" % (unit, active))
        if active == "active":
            reasons.append("旧版自动恢复定时器仍在运行：" + unit)
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
    parser.add_argument("--old-port", help="旧端口；默认从当前会话或现有监听推断；无旧端口用 none")
    parser.add_argument("--host", help="客户端连接地址或 SSH 别名，仅用于生成提示命令")
    parser.add_argument("--rescue-confirmed", action="store_true", help="已实际演练 VNC/串口救援登录（硬门槛）")
    parser.add_argument("--tailnet", action="store_true", help="管理通路经 Tailscale tailnet；增加接入与验证步骤")
    parser.add_argument("--backup-dir", default=BACKUP_ROOT, help="备份约定目录（默认 " + BACKUP_ROOT + "）")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    options = parser.parse_args(argv)
    if not 1 <= options.port <= 65535:
        parser.error("--port 超出范围")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*\$?", options.user) or options.user == "root":
        parser.error("--user 必须是非 root 的合法账户名")
    if options.old_port not in (None, "none"):
        if not re.fullmatch(r"\d+", options.old_port) or not 1 <= int(options.old_port) <= 65535:
            parser.error("--old-port 必须是端口号或 none")
        if int(options.old_port) == options.port:
            parser.error("旧端口不能等于目标端口")
    if options.host and not re.fullmatch(r"[A-Za-z0-9_.:\[\]-]+", options.host):
        parser.error("--host 含不支持的字符")
    return options


# ---------------------------------------------------------------- 步骤方案

def build_steps(system, options, ctx):
    """按内置只读方案构造步骤；每步含状态确认/为什么/执行/验证/撤销。"""
    host = options.host or "SERVER"
    port = options.port
    user = options.user
    old_port = ctx["old_port"]
    sock = ctx["socket"]
    socket_activation = sock["load"] == "loaded" and sock["active"] == "active"
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
    backup_ok = backup.get("has_sshd_config")
    step("1-backup", "手工全量备份",
         DONE if backup_ok else TODO,
         ("最近备份：%s（含 sshd_config）" % backup.get("latest")) if backup_ok else "未发现 %s 下的完整备份" % options.backup_dir,
         "此后每一步都改动系统；任何撤销都只依赖这份备份。工具不替你回滚，备份是唯一退路。",
         ["TS=$(date +%Y%m%d-%H%M%S); DIR=/var/backups/ssh-hardening/$TS",
          "sudo install -d -m 700 $DIR",
          "sudo cp -a /etc/ssh/sshd_config $DIR/",
          "sudo cp -a /etc/ssh/sshd_config.d $DIR/ 2>/dev/null || true",
          "sudo cp -a /etc/systemd/system/ssh.socket.d $DIR/ 2>/dev/null || true",
          "sudo sh -c 'nft list ruleset > $DIR/nft-ruleset.nft'",
          "sudo sh -c 'ufw status verbose > $DIR/ufw-status.txt' 2>/dev/null || true",
          "sudo sh -c 'systemctl show ssh.service ssh.socket > $DIR/units.txt'",
          "echo 备份完成: $DIR"],
         ["ls " + options.backup_dir + "/  # 出现时间戳目录，且其中 sshd_config 与本机一致"],
         ["sudo rm -rf " + options.backup_dir + "/<时间戳>  # 备份本身不改变系统，不需要撤销"])

    account = ctx["account"]
    if not account.get("exists"):
        account_ok, account_note = False, "账户 %s 不存在" % user
    elif not account.get("sudo"):
        account_ok, account_note = False, "账户 %s 不在 sudo 组" % user
    elif not account.get("authorized_keys_count"):
        account_ok, account_note = False, "账户 %s 未安装公钥" % user
    else:
        account_ok = True
        account_note = "uid=%s，sudo 组，authorized_keys %d 个公钥" % (account.get("uid"), account["authorized_keys_count"])
        if account.get("authorized_keys_mode") not in ("0o600", "0o400") or account.get("ssh_dir_mode") != "0o700":
            account_note += "；[注意] 权限异常（目录 %s / 文件 %s）" % (account.get("ssh_dir_mode"), account.get("authorized_keys_mode"))
    step("2-account", "sudo 组非 root 账户与公钥",
         DONE if account_ok else TODO,
         account_note,
         "加固的终点是“只有非 root 账户 + 公钥”能登录。这一步先把新账户和公钥准备好并在旧端口上验证，之后才谈切端口。",
         ["# 服务器（账户不存在时）：",
          "sudo adduser --gecos '' " + user,
          "sudo usermod -aG sudo " + user,
          "# 客户端（本地机器）安装公钥，出现提示时输入该账户密码：",
          "ssh-copy-id -i ~/.ssh/<你的公钥> -p " + (str(old_port) if isinstance(old_port, int) else "22") + " " + user + "@" + host,
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
    old_text = str(old_port) if isinstance(old_port, int) else "OLD_PORT"
    if backup_ok:
        if socket_activation:
            new_commands = [
                "# 本机布局：ssh.socket 激活。新增监听端口（旧端口保留）：",
                "sudo install -d -m 755 " + SOCKET_DROPIN_DIR,
                "sudo tee " + NEWPORT_SOCKET_DROPIN + " >/dev/null <<'EOF'",
                "[Socket]",
                "ListenStream=" + str(port),
                "EOF",
                "sudo systemctl daemon-reload",
                "sudo systemctl restart ssh.socket",
                "ss -tlnp | grep sshd",
            ]
        else:
            new_commands = [
                "# 本机布局：传统 sshd 服务。写入端口配置（旧端口保留）：",
                "# 注意：一旦显式声明 Port，默认 22 不再隐式生效，所以现有端口与目标端口都要列出。",
                "sudo install -d -m 755 " + SSHD_CONFIG_D,
                "sudo tee " + NEWPORT_DROPIN + " >/dev/null <<'EOF'",
                "Port " + old_text,
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
            first = fw["nft_input"][0]
            new_commands += ["sudo nft add rule %s %s %s tcp dport %d ct state new accept comment \"stage1 new-port bridge\"" % (
                first.get("family", "inet"), first.get("table", "<表>"), first.get("chain", "<链>"), port)]
        else:
            new_commands += ["# 未检测到本地放行需求（input 默认 accept 或无法采集）；请以云安全组为准"]
    else:
        new_commands = ["# 被门槛阻塞：请先完成 1-backup（备份）"]
    new_undo = (["# 从备份恢复并重启（或直接删除覆盖文件后重启）：",
                 "sudo cp -a " + options.backup_dir + "/<时间戳>/ssh.socket.d/. " + SOCKET_DROPIN_DIR + "/ 2>/dev/null || sudo rm -f " + NEWPORT_SOCKET_DROPIN,
                 "sudo systemctl daemon-reload && sudo systemctl restart ssh.socket",
                 "sudo ufw delete allow " + str(port) + "/tcp 2>/dev/null || true"]
                if socket_activation else
                ["# 从备份恢复并重启（或直接删除覆盖文件后重启）：",
                 "sudo cp -a " + options.backup_dir + "/<时间戳>/sshd_config.d/. " + SSHD_CONFIG_D + "/ 2>/dev/null || sudo rm -f " + NEWPORT_DROPIN,
                 "sudo sshd -t && sudo systemctl reload ssh.service",
                 "sudo ufw delete allow " + str(port) + "/tcp 2>/dev/null || true"])
    step("3-new-port", "开启新端口（旧端口保留）",
         new_status, new_note,
         "新入口必须先被证明可用，旧入口才能关闭。这里只新增监听与放行，不动旧入口。",
         new_commands,
         ["服务器：ss -tlnp 应同时看到 " + str(port) + ((" 与 " + str(old_port)) if isinstance(old_port, int) else "") + " 在 sshd 进程下监听",
          "服务器：sudo sshd -t 通过；socket 激活时 systemctl show ssh.socket -p Listen 含新端口",
          "客户端：ssh -o PreferredAuthentications=publickey -p " + str(port) + " " + user + "@" + host + " true"],
         new_undo,
         blocked_by=[] if backup_ok else ["1-backup"])

    session = ctx["connection"]
    auth = ctx["auth"]
    if session and session["port"] == port and auth == "publickey":
        path = "经 tailnet 接口" if is_tailnet_address(session["source"]) else "经公网接口"
        verify_status, verify_note = DONE, "当前会话即新端口 %d 的公钥登录（%s，journal 已匹配四元组），硬门槛已满足" % (port, path)
    elif session and session["port"] == port and auth is None:
        if is_tailnet_address(session["source"]):
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
          "sudo bash " + entry_dir() + "/" + SCRIPT + " --port " + str(port) + " --user " + user
          + ((" --old-port " + str(old_port)) if isinstance(old_port, int) else " --old-port none")
          + ((" --host " + shlex.quote(options.host)) if options.host else "")
          + (" --rescue-confirmed" if rescue else "")
          + (" --tailnet" if options.tailnet else "")],
         ["同一命令下，本步骤状态变为“已完成”（脚本核对当前会话端口与 journal 公钥证据）"],
         ["无需撤销；登录尝试是只读操作"],
         blocked_by=[] if new_listening else ["3-new-port"])

    if old_port == "none":
        old_close_status, old_close_note = DONE, "已声明无旧端口（--old-port none）"
        old_close_evidence = "无需关闭"
    elif old_port is None:
        old_close_status, old_close_note, old_close_evidence = BLOCKED, "无法唯一识别旧端口；请用 --old-port 指明（若无需关闭用 --old-port none）", "推断失败"
    elif old_port not in ctx["listeners"] and old_port not in ctx["disk_ports"]:
        old_close_status, old_close_note, old_close_evidence = DONE, "端口 %d 已不在监听且不在磁盘配置中" % old_port, "listeners=%s" % ctx["listeners"]
    else:
        old_close_status, old_close_note, old_close_evidence = TODO, "端口 %d 仍在监听或仍在磁盘配置中" % old_port, "listeners=%s" % ctx["listeners"]

    old_close_why = "完成端口切换的最后一步：确认新入口被外部证实可用（第 4 步）之后，才移除旧入口。保持至少一条已验证会话开着直到这一步结束。"
    if options.tailnet:
        old_close_why += (" 已声明 --tailnet：如果最终只保留 tailnet 入口，公网侧的彻底关闭由 stage2 的 1b-close-public 负责；"
                          "本步仍按端口切换处理，不要在 tailnet 路径未被验证前先行切断公网。")
    if old_port is None:
        old_close_do = ["# 先指明旧端口（当前会话或现有监听无法唯一识别）：",
                        "sudo bash " + entry_dir() + "/" + SCRIPT + " --port " + str(port) + " --user " + user + " --old-port <旧端口>",
                        "# 若确认没有旧端口需要关闭：--old-port none"]
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
                            "sudo systemctl daemon-reload && sudo systemctl restart ssh.socket",
                            "ss -tlnp | grep sshd",
                            "",
                            "# 防火墙与云安全组同步收口旧端口：",
                            "sudo ufw delete allow " + old_text + "/tcp 2>/dev/null || true",
                            "# 云控制台：删除旧端口 " + old_text + " 的放行规则"]
        else:
            old_close_do = ["sudo tee " + NEWPORT_DROPIN + " >/dev/null <<'EOF'",
                            "Port " + str(port),
                            "EOF",
                            "sudo sshd -t && sudo systemctl reload ssh.service",
                            "ss -tlnp | grep sshd",
                            "sudo ufw delete allow " + old_text + "/tcp 2>/dev/null || true",
                            "# 云控制台：删除旧端口 " + old_text + " 的放行规则"]
        old_close_verify = ["ss -tlnp | grep -E ':(" + old_text + ")\\\\b'  # 应无输出",
                            "客户端：ssh -p " + old_text + " " + user + "@" + host + "  # 应连接失败（预期）",
                            "客户端：ssh -p " + str(port) + " " + user + "@" + host + "  # 应仍可用"]
        old_close_undo = ["# 恢复旧入口 = 从 1-backup 备份目录拷回对应文件并重启：",
                          "sudo cp -a " + options.backup_dir + "/<时间戳>/sshd_config.d/. " + SSHD_CONFIG_D + "/",
                          "sudo cp -a " + options.backup_dir + "/<时间戳>/ssh.socket.d/. " + SOCKET_DROPIN_DIR + "/ 2>/dev/null || true",
                          "sudo sshd -t && sudo systemctl daemon-reload && sudo systemctl restart ssh.socket 2>/dev/null || sudo systemctl reload ssh.service"]
    blocked = []
    if old_close_status != DONE:
        if not rescue:
            blocked.append("0-rescue")
        if verify_status != DONE:
            blocked.append("4-verify-new")
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
        command = "sudo bash %s/%s --port %d --user %s" % (entry_dir(), STAGE2, options.port, options.user)
        if options.host:
            command += " --host " + shlex.quote(options.host)
        if options.tailnet:
            command += " --tailnet"
        print("  " + command)
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
