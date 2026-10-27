#!/usr/bin/env bash
# stage0-check.sh —— SSH 加固三步指导体系：第 0 步，只读现状检查
#
# 本脚本【纯只读】：不修改 SSH/防火墙/systemd 配置，不写状态文件，
# 不安装定时器，不代执行任何命令，也没有任何形式的自动回滚。
# 它只做三件事：
#   1. 采集当前系统事实（会话、监听、认证、防火墙、账户、备份、旧版痕迹、重启证据）；
#   2. 对照声明的目标（--port/--user/--allow）判断当前处于加固流程的哪一步；
#   3. 打印下一步应运行的指导脚本（stage1-port-key.sh / stage2-lockdown.sh）。
# 所有建议命令由操作员本人（或其监督下的智能体）手工执行。
#
# 退出码：0=检查完成；1=发现阻断性异常（如旧版待确认事务、sshd 配置损坏）；
#         2=检查不完整（权限不足或必要采集失败）。
# 设计文档：plans/DESIGN-v2.md。旧版自动执行体系已废弃，见 legacy/README.md。

set -uo pipefail
umask 077

if ! command -v python3 >/dev/null 2>&1; then
  echo "缺少 python3；请先安装：sudo apt-get install python3" >&2
  exit 2
fi

SELF_PATH=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/$(basename -- "${BASH_SOURCE[0]}")
export REINFORCE_SELF="$SELF_PATH"

exec python3 - "$@" <<'REINFORCE_STAGE0_PY'
"""stage0-check.sh：只读现状检查与加固阶段定位；绝不修改系统。"""
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

SCRIPT = "stage0-check.sh"
STAGE1 = "stage1-port-key.sh"
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
LEGACY_SCHEME_TRACES = (
    "/etc/systemd/system/ssh-firewall.service",
    "/etc/systemd/system/ssh.socket.d/override.conf",
    "/etc/ssh/sshd_config.d/99-hardening.conf",
)
SSHD_CONFIG = "/etc/ssh/sshd_config"
SSHD_CONFIG_D = "/etc/ssh/sshd_config.d"
SOCKET_DROPIN_DIR = "/etc/systemd/system/ssh.socket.d"

PASS, FAIL, WARN, UNKNOWN = "pass", "fail", "warn", "unknown"
LABELS = {PASS: "已达标", FAIL: "未达标", WARN: "需注意", UNKNOWN: "无法证实"}

# 只读命令白名单：第二个元素是允许的首个子命令集合（None 表示不限制）。
READ_ONLY_COMMANDS = {
    "ss": None,
    "id": None,
    "getent": None,
    "sshd": {"-t", "-T"},
    "nft": {"list", "-j"},
    "ufw": {"status"},
    "systemctl": {"show", "is-active", "is-enabled", "list-timers", "cat", "status"},
    "journalctl": None,
}


class EvidenceError(Exception):
    pass


class System:
    """只执行白名单内的只读命令；一切失败都以证据异常上报，不猜测。"""

    def __init__(self):
        self.calls = []

    def run(self, *args):
        if args[0] not in READ_ONLY_COMMANDS:
            raise EvidenceError("拒绝执行非只读白名单命令：" + args[0])
        allowed_sub = READ_ONLY_COMMANDS[args[0]]
        if allowed_sub is not None and (len(args) < 2 or args[1] not in allowed_sub):
            raise EvidenceError("拒绝执行非只读子命令：" + " ".join(args[:2]))
        self.calls.append(list(args))
        try:
            result = subprocess.run(list(args), capture_output=True, text=True, timeout=60)
        except OSError as exc:
            raise EvidenceError("无法运行 " + args[0] + "：" + str(exc))
        except subprocess.TimeoutExpired:
            raise EvidenceError("命令超时：" + args[0])
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip().splitlines()
            raise EvidenceError(args[0] + " 退出码 " + str(result.returncode) + "：" + (detail[0][:180] if detail else "无输出"))
        return result.stdout

    def run_allow_fail(self, *args):
        """供 is-active/is-enabled 这类"非零退出也是有效答案"的只读查询使用。"""
        if args[0] not in READ_ONLY_COMMANDS:
            raise EvidenceError("拒绝执行非只读白名单命令：" + args[0])
        allowed_sub = READ_ONLY_COMMANDS[args[0]]
        if allowed_sub is not None and (len(args) < 2 or args[1] not in allowed_sub):
            raise EvidenceError("拒绝执行非只读子命令：" + " ".join(args[:2]))
        self.calls.append(list(args))
        try:
            result = subprocess.run(list(args), capture_output=True, text=True, timeout=60)
        except OSError as exc:
            raise EvidenceError("无法运行 " + args[0] + "：" + str(exc))
        except subprocess.TimeoutExpired:
            raise EvidenceError("命令超时：" + args[0])
        return result

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


# ---------------------------------------------------------------- 会话事实

def find_connection(system):
    """当前 SSH 连接四元组；sudo 会清掉环境，从祖先进程 environ 恢复。"""
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
    """在本 boot 的 sshd journal 中匹配当前连接四元组的认证方式。"""
    if not connection or not user:
        return None
    try:
        logs = system.run("journalctl", "-b", "-u", "ssh", "-u", "sshd", "-u", "ssh@*",
                          "-o", "cat", "--no-pager")
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


# ---------------------------------------------------------------- 监听与服务

def endpoint_port(text):
    return int(text.rsplit(":", 1)[1])


def sshd_listeners(system):
    """ss 中带 sshd 归属的 TCP 监听端口集合（(Stream)/进程列解析按 BUG-001 教训处理）。"""
    ports = set()
    for line in system.run("ss", "-tlnpH").splitlines():
        words = line.split()
        if len(words) >= 5 and re.search(r'"sshd(?:-session)?"', line):
            try:
                port = endpoint_port(words[3])
            except (ValueError, IndexError):
                continue
            if 1 <= port <= 65535:
                ports.add(port)
    return sorted(ports)


def socket_listen_ports(system):
    props = system.run("systemctl", "show", "ssh.socket", "-p", "Listen", "-p", "ActiveState", "-p", "LoadState")
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
    return data.get("LoadState", "unknown"), data.get("ActiveState", "unknown"), sorted(ports)


def unit_state(system, unit):
    """is-active/is-enabled 对 inactive/disabled 返回非零退出但标准输出仍是有效答案。"""
    def probe(sub):
        try:
            result = system.run_allow_fail("systemctl", sub, unit)
        except EvidenceError:
            return "unknown"
        value = (result.stdout or "").strip().splitlines()
        return value[0] if value else "unknown"
    return probe("is-active"), probe("is-enabled")


# ---------------------------------------------------------------- sshd 配置

def sshd_effective(system, config, context=None):
    args = ["sshd", "-T", "-f", config]
    if context:
        args += ["-C", context]
    options = {}
    for line in system.run(*args).splitlines():
        key, sep, value = line.partition(" ")
        if sep:
            options.setdefault(key, []).append(value.strip())
    return options


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
    """磁盘配置里显式声明的 Port/ListenStream（解释重启后仍会监听的端口）。"""
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
        for path in sorted(Path(SOCKET_DROPIN_DIR).glob("*.conf")):
            for number, line in enumerate(system.read(str(path)).splitlines(), 1):
                m = re.match(r"\s*ListenStream\s*=\s*(\S+)\s*$", line)
                if m:
                    try:
                        ports.setdefault(endpoint_port(m.group(1)), []).append("%s:%d" % (path, number))
                    except ValueError:
                        continue
    except OSError:
        pass
    return ports


# ---------------------------------------------------------------- 账户与公钥

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
    facts["sudo"] = "sudo" in groups or (isinstance(facts["uid"], int) and facts["uid"] == 0)
    try:
        home = system.run("getent", "passwd", user).split(":")[5]
    except (EvidenceError, IndexError):
        home = None
    facts["home"] = home
    if home:
        keyfile = Path(home) / ".ssh" / "authorized_keys"
        facts["authorized_keys_path"] = str(keyfile)
        try:
            content = system.read(str(keyfile))
            keys = [line for line in content.splitlines() if line.strip() and not line.strip().startswith("#")]
            facts["authorized_keys_count"] = len(keys)
            st = system.stat(str(keyfile))
            facts["authorized_keys_mode"] = oct(st.st_mode & 0o777)
            facts["ssh_dir_mode"] = oct(system.stat(str(keyfile.parent)).st_mode & 0o777)
            facts["authorized_keys_owner_ok"] = st.st_uid == facts["uid"]
        except EvidenceError:
            facts["authorized_keys_count"] = 0
    return facts


# ---------------------------------------------------------------- 防火墙

def nft_ruleset_summary(system):
    """nft -j list ruleset 的指导级摘要：表、input 策略、与 dport/saddr 相关的规则。"""
    summary = {"tables": [], "input_policy": [], "rules": [], "raw_rule_count": 0}
    js = json.loads(system.run("nft", "-j", "list", "ruleset"))
    for item in js.get("nftables", []):
        if "table" in item:
            summary["tables"].append(item["table"].get("family", "?") + " " + item["table"].get("name", "?"))
        if "chain" in item and item["chain"].get("hook") == "input":
            summary["input_policy"].append("%s %s chain %s policy=%s" % (
                item["chain"].get("family"), item["chain"].get("table"),
                item["chain"].get("name"), item["chain"].get("policy", "?")))
        if "rule" in item:
            summary["raw_rule_count"] += 1
            digest = rule_digest(item["rule"])
            if digest:
                summary["rules"].append({
                    "location": "%s %s chain %s" % (item["rule"].get("family"), item["rule"].get("table"), item["rule"].get("chain")),
                    **digest,
                })
    return summary


def literal_values(value):
    """nft JSON 右值可能是标量、列表或 {"set": [...]}；统一为字面量列表。"""
    if isinstance(value, dict):
        if "set" in value:
            out = []
            for item in value["set"] if isinstance(value["set"], list) else [value["set"]]:
                out.extend(literal_values(item))
            return out
        return []
    if isinstance(value, list):
        out = []
        for item in value:
            out.extend(literal_values(item))
        return out
    return [value]


def rule_digest(rule):
    verdict = None
    dports, saddrs, ct_state, iif_lo = set(), set(), set(), False
    for expr in rule.get("expr", []):
        if "accept" in expr:
            verdict = "accept"
        elif "drop" in expr:
            verdict = "drop"
        elif "reject" in expr:
            verdict = "reject"
        if "match" in expr or "v" in expr:
            node = expr.get("match", expr)
            left, right = node.get("left", {}), node.get("right", {})
            if isinstance(left, dict) and "payload" in left:
                payload = left["payload"]
                field = payload.get("field")
                values = [str(v) for v in literal_values(right)]
                if field == "dport" and payload.get("protocol") in ("tcp", "udp"):
                    dports.update(values)
                if field == "saddr" and payload.get("protocol") in ("ip", "ip6"):
                    saddrs.update(values)
            if isinstance(left, dict) and "ct" in left and left["ct"].get("key") == "state":
                ct_state.update(str(v) for v in literal_values(right))
            if isinstance(left, dict) and "meta" in left and left["meta"].get("key") == "iifname":
                if any(v in ("lo", '"lo"') for v in literal_values(right)):
                    iif_lo = True
    if verdict is None and not dports and not saddrs:
        return None
    return {"verdict": verdict, "dports": sorted(dports), "saddrs": sorted(saddrs),
            "ct_state": sorted(ct_state), "loopback": iif_lo}


def ufw_status(system):
    try:
        text = system.run("ufw", "status", "verbose")
    except EvidenceError as exc:
        return {"available": False, "detail": str(exc)}
    active = not re.search(r"Status:\s*inactive", text)
    return {"available": True, "active": active, "text": text.strip()}


def allowlist_assessment(nft_summary, ufw, port, allows):
    """指导级判断：目标端口是否已被来源白名单约束。只做字面量比较，不确定就报 unknown。"""
    if not allows:
        return {"status": UNKNOWN, "detail": "未声明 --allow，不判定白名单合规"}
    networks = [ipaddress.ip_network(item) for item in allows]
    port_s = str(port)
    offenders, restricting_drop, saw_accept = [], False, False
    for rule in nft_summary.get("rules", []):
        if port_s not in rule["dports"]:
            continue
        if rule["verdict"] == "accept":
            saw_accept = True
            if not rule["saddrs"]:
                offenders.append(rule["location"] + "：accept dport " + port_s + " 无来源限制")
            for literal in rule["saddrs"]:
                try:
                    net = ipaddress.ip_network(literal)
                except ValueError:
                    offenders.append(rule["location"] + "：无法解析来源 " + literal)
                    continue
                if not any(net.subnet_of(declared) or net == declared for declared in networks):
                    offenders.append(rule["location"] + "：来源 " + literal + " 超出声明白名单")
        if rule["verdict"] in ("drop", "reject"):
            restricting_drop = True
    policy_drop = any("policy=drop" in item for item in nft_summary.get("input_policy", []))
    if ufw.get("active"):
        for line in ufw.get("text", "").splitlines():
            m = re.match(r"^%s(/tcp)?\s+(ALLOW|DENY|REJECT)\s*(\S*)" % re.escape(port_s), line.strip())
            if not m:
                continue
            if m.group(2) == "ALLOW":
                saw_accept = True
                literal = m.group(3)
                if literal not in ("Anywhere", "/ ::/0", "::/0", "0.0.0.0/0"):
                    try:
                        net = ipaddress.ip_network(literal.split()[0])
                        if not any(net.subnet_of(d) or net == d for d in networks):
                            offenders.append("ufw：来源 " + literal + " 超出声明白名单")
                    except ValueError:
                        offenders.append("ufw：无法解析来源 " + literal)
                else:
                    offenders.append("ufw：ALLOW " + port_s + " 无来源限制")
            else:
                restricting_drop = True
    if offenders:
        return {"status": FAIL, "detail": "；".join(offenders[:4])}
    if saw_accept and (restricting_drop or policy_drop):
        return {"status": PASS, "detail": "运行规则字面量比较：目标端口仅对声明白名单放行且存在默认拒绝；集合/区间写法请人工复核证据"}
    if saw_accept:
        return {"status": FAIL, "detail": "存在放行规则但未发现默认拒绝/drop，白名单不成立"}
    return {"status": UNKNOWN, "detail": "未发现涉及目标端口的放行规则；无法证实白名单"}


# ---------------------------------------------------------------- 旧版痕迹

def legacy_facts(system):
    facts = {"state": None, "managed_files": [], "traces": [], "recovery_timers": [], "blocking": None}
    state_path = LEGACY_STATE_ROOT + "/state.conf"
    if system.exists(state_path):
        state = {}
        for line in system.read(state_path).splitlines():
            key, sep, value = line.partition("=")
            if sep:
                state[key.strip()] = value.strip()
        facts["state"] = state
        if state.get("STAGE", "").endswith("-pending"):
            facts["blocking"] = ("旧版事务处于待确认状态（STAGE=%s TX=%s）：可能仍有自动恢复定时器武装。"
                                 "先按 legacy/README.md 与事故记录处置，不要在其上叠加新指导流程。" % (state.get("STAGE"), state.get("TX")))
    for path in LEGACY_MANAGED + LEGACY_SCHEME_TRACES:
        if system.exists(path):
            facts["managed_files"].append(path)
    try:
        for name in system.list_dir("/etc/systemd/system"):
            if name.startswith("reinforce-my-ssh-") and name.endswith(".timer"):
                active, enabled = unit_state(system, name)
                facts["recovery_timers"].append({"unit": name, "active": active, "enabled": enabled})
    except EvidenceError:
        pass
    if facts["recovery_timers"]:
        facts["blocking"] = ((facts["blocking"] + " " if facts["blocking"] else "")
                             + "发现旧版自动恢复定时器残留：%s。它会无人值守改写 SSH/防火墙，必须先人工核对并清理。"
                             % ", ".join(item["unit"] + "(" + item["active"] + ")" for item in facts["recovery_timers"]))
    return facts


# ---------------------------------------------------------------- 备份与重启证据

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


def reboot_facts(system):
    facts = {}
    try:
        facts["btime"] = int(re.search(r"^btime (\d+)$", system.read("/proc/stat"), re.M)[1])
        facts["boot_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(facts["btime"]))
    except (EvidenceError, AttributeError, TypeError, ValueError):
        return facts
    facts["boot_id"] = None
    try:
        facts["boot_id"] = system.read("/proc/sys/kernel/random/boot_id").strip()
    except EvidenceError:
        pass
    hardened = []
    for path in sshd_config_files(system):
        if path == SSHD_CONFIG:
            continue
        hardened.append(path)
    for directory in (SOCKET_DROPIN_DIR, "/etc/nftables.d"):
        try:
            hardened += [directory + "/" + name for name in system.list_dir(directory)]
        except EvidenceError:
            continue
    mtimes = [(system.mtime(p), p) for p in hardened]
    mtimes = [(m, p) for m, p in mtimes if m is not None]
    if mtimes:
        latest = max(mtimes)
        facts["hardened_latest_mtime"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(latest[0]))
        facts["hardened_latest_file"] = latest[1]
        facts["booted_after_hardening"] = facts["btime"] > latest[0]
    return facts


# ---------------------------------------------------------------- 目标与定位

def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog=SCRIPT,
        description="只读检查 SSH 加固现状并定位所处步骤；不修改系统、不代执行。",
        epilog="退出码：0=检查完成；1=阻断性异常（旧版待确认事务/恢复定时器、sshd 配置损坏）；2=检查不完整（需要 sudo 或必要采集失败）。")
    parser.add_argument("--port", type=int, help="目标 SSH 端口（加固后唯一保留的端口）")
    parser.add_argument("--user", help="目标非 root 管理账户")
    parser.add_argument("--allow", action="append", default=[], help="允许来源 CIDR，可重复；声明后才判定白名单")
    parser.add_argument("--closed-port", action="append", type=int, default=[], help="必须关闭的端口（通常是旧端口），可重复")
    parser.add_argument("--host", help="客户端连接地址或 SSH 别名，仅用于生成提示命令")
    parser.add_argument("--backup-dir", default=BACKUP_ROOT, help="备份约定目录（默认 " + BACKUP_ROOT + "）")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    options = parser.parse_args(argv)
    if options.port is not None and not 1 <= options.port <= 65535:
        parser.error("--port 超出范围")
    if any(not 1 <= port <= 65535 for port in options.closed_port):
        parser.error("--closed-port 超出范围")
    if options.port in options.closed_port:
        parser.error("目标端口不能同时声明为关闭")
    if options.user is not None and not re.fullmatch(r"[a-z_][a-z0-9_-]*\$?", options.user):
        parser.error("--user 必须是合法账户名")
    try:
        options.allow = sorted({str(ipaddress.ip_network(item, strict=True)) for item in options.allow})
    except ValueError as exc:
        parser.error(str(exc))
    if options.host and not re.fullmatch(r"[A-Za-z0-9_.:\[\]-]+", options.host):
        parser.error("--host 含不支持的字符")
    return options


def assess(facts, options):
    """目标比较；只在声明了对应目标时判定。返回 (assessments, position, next_step)。"""
    items = []

    def add(name, status, detail):
        items.append({"item": name, "status": status, "detail": detail})

    goals_user = options.user or facts["session"].get("sudo_user")
    goals_port = options.port

    if goals_user:
        account = facts.get("account", {})
        if not account.get("exists"):
            add("sudo 账户与公钥", FAIL, "账户 %s 不存在" % goals_user)
        elif not account.get("sudo"):
            add("sudo 账户与公钥", FAIL, "账户 %s 不在 sudo 组" % goals_user)
        elif not account.get("authorized_keys_count"):
            add("sudo 账户与公钥", FAIL, "账户 %s 没有已安装的公钥" % goals_user)
        elif account.get("authorized_keys_mode") not in ("0o600", "0o400") or account.get("ssh_dir_mode") != "0o700":
            add("sudo 账户与公钥", WARN, "公钥已安装但权限异常（目录 %s / 文件 %s）" % (account.get("ssh_dir_mode"), account.get("authorized_keys_mode")))
        else:
            add("sudo 账户与公钥", PASS, "%s 在 sudo 组，authorized_keys 有 %d 个公钥，权限正确" % (goals_user, account["authorized_keys_count"]))

    listeners = facts.get("listeners", {}).get("sshd_ports", [])
    if goals_port is not None:
        if goals_port in listeners:
            add("新端口监听", PASS, "端口 %d 正在监听" % goals_port)
        else:
            add("新端口监听", FAIL, "端口 %d 未在监听（当前 sshd 监听：%s）" % (goals_port, listeners or "无"))
    for port in options.closed_port:
        if port in listeners:
            add("旧端口 %d 已关闭" % port, FAIL, "端口 %d 仍在监听" % port)
        else:
            add("旧端口 %d 已关闭" % port, PASS, "端口 %d 未监听" % port)

    effective = facts.get("effective", {}).get("user_context", {})
    root_context = facts.get("effective", {}).get("root_context", {})
    if effective or root_context:
        def first(options_dict, key):
            values = options_dict.get(key)
            return values[0] if values else None
        permit_root = first(root_context or effective, "permitrootlogin")
        if permit_root is None:
            add("禁止 root 登录", UNKNOWN, "无法读取有效配置（需要 sudo）")
        elif permit_root == "no":
            add("禁止 root 登录", PASS, "PermitRootLogin no")
        else:
            add("禁止 root 登录", FAIL, "PermitRootLogin " + permit_root)
        password = first(effective, "passwordauthentication")
        kbd = first(effective, "kbdinteractiveauthentication")
        if password is None:
            add("禁止密码/键盘交互登录", UNKNOWN, "无法读取有效配置（需要 sudo）")
        elif password == "no" and kbd in (None, "no"):
            add("禁止密码/键盘交互登录", PASS, "PasswordAuthentication no，KbdInteractive %s" % (kbd or "no"))
        else:
            add("禁止密码/键盘交互登录", FAIL, "PasswordAuthentication=%s KbdInteractiveAuthentication=%s" % (password, kbd))
        methods = first(effective, "authenticationmethods")
        pubkey = first(effective, "pubkeyauthentication")
        if pubkey == "yes" and (methods in (None, "any") or "publickey" in (methods or "")):
            add("公钥认证可用", PASS, "PubkeyAuthentication yes，AuthenticationMethods %s" % (methods or "any"))
        elif pubkey is None:
            add("公钥认证可用", UNKNOWN, "无法读取有效配置（需要 sudo）")
        else:
            add("公钥认证可用", FAIL, "PubkeyAuthentication=%s AuthenticationMethods=%s" % (pubkey, methods))

    if options.allow:
        wl = facts.get("allowlist", {})
        add("来源白名单", wl.get("status", UNKNOWN), wl.get("detail", "未评估"))

    backup = facts.get("backup", {})
    if backup.get("has_sshd_config"):
        add("手工备份", PASS, "备份目录 %s 含 sshd_config" % backup.get("latest"))
    elif backup.get("latest"):
        add("手工备份", WARN, "备份目录 %s 存在但缺 sshd_config 副本" % backup.get("latest"))
    else:
        add("手工备份", FAIL, "未发现 %s 下的备份" % backup.get("root"))

    statuses = {item["item"]: item["status"] for item in items}

    def ok(name):
        return statuses.get(name) == PASS

    user_ok = ok("sudo 账户与公钥") if "sudo 账户与公钥" in statuses else None
    port_ok = ok("新端口监听") if "新端口监听" in statuses else None
    old_ok = all(ok("旧端口 %d 已关闭" % port) for port in options.closed_port) if options.closed_port else None
    auth_ok = None
    if "禁止 root 登录" in statuses or "禁止密码/键盘交互登录" in statuses:
        auth_ok = ok("禁止 root 登录") and ok("禁止密码/键盘交互登录")
    allow_ok = ok("来源白名单") if "来源白名单" in statuses else None

    def not_failed(value):
        return value is not False

    stage1_done = user_ok is True and not_failed(port_ok) and not_failed(old_ok)
    hardened_done = stage1_done and auth_ok is True and not_failed(allow_ok)

    reboot = facts.get("reboot", {})
    reboot_ok = False
    if hardened_done:
        reboot_ok = reboot.get("booted_after_hardening") is True
        if reboot_ok:
            add("跨重启持久化", PASS, "本次启动（%s）晚于全部加固文件修改，且运行态达标" % reboot.get("boot_time"))
        else:
            add("跨重启持久化", FAIL, "运行态达标，但尚未跨过一次真实重启验证（或无法证实）")

    if facts.get("legacy", {}).get("blocking"):
        position = "legacy-blocking"
    elif not goals_port and not options.user:
        position = "goals-undeclared"
    elif hardened_done and reboot_ok:
        position = "verified"
    elif hardened_done:
        position = "hardened"
    elif stage1_done:
        position = "stage1-done"
    elif user_ok is not None or port_ok is not None:
        position = "stage1-progress"
    else:
        position = "stage0"

    host = options.host or "SERVER"
    stage1_cmd = "sudo bash %s/%s --port %s --user %s" % (
        entry_dir(), STAGE1,
        goals_port if goals_port is not None else "NEW_PORT",
        goals_user or "deploy")
    if options.host:
        stage1_cmd += " --host " + shlex.quote(options.host)
    stage2_cmd = "sudo bash %s/%s --port %s --user %s" % (
        entry_dir(), STAGE2,
        goals_port if goals_port is not None else "NEW_PORT",
        goals_user or "deploy")
    for cidr in options.allow:
        stage2_cmd += " --allow " + shlex.quote(cidr)
    if options.host:
        stage2_cmd += " --host " + shlex.quote(options.host)

    if position == "legacy-blocking":
        next_step = {"summary": "先处置旧版残留，再开始新流程", "commands": []}
    elif position == "goals-undeclared":
        next_step = {"summary": "声明目标后重新检查以定位进度，例如：", "commands": [
            "sudo bash %s/%s --port 2222 --user deploy --allow 203.0.113.0/24 --closed-port 22" % (entry_dir(), SCRIPT)]}
    elif position in ("stage0", "stage1-progress"):
        next_step = {"summary": "运行 stage1 指导（切端口、装公钥、验证 sudo 用户）：", "commands": [stage1_cmd]}
    elif position == "stage1-done":
        next_step = {"summary": "stage1 目标已达成；运行 stage2 指导（nft 白名单、禁 root、禁密码、最终确认）：", "commands": [stage2_cmd]}
    elif position == "hardened":
        next_step = {"summary": "配置已达标但尚未跨重启验证；运行 stage2 指导完成第 4 步（重启复验）：", "commands": [stage2_cmd]}
    else:
        next_step = {"summary": "加固完成且已跨重启验证；日常可重跑本脚本做只读体检", "commands": []}
    return items, position, next_step


POSITION_TEXT = {
    "legacy-blocking": "旧版残留待处置（阻断）",
    "goals-undeclared": "未声明目标，仅报告现状",
    "stage0": "尚未开始加固",
    "stage1-progress": "stage1 进行中（账户/端口未完全就绪）",
    "stage1-done": "stage1 目标已达成（认证尚未收紧）",
    "hardened": "stage2 配置已达标（待跨重启验证）",
    "verified": "已完成并通过跨重启验证",
}


# ---------------------------------------------------------------- 采集与输出

def collect(system, options):
    facts = {"collected": [], "failed": []}

    def attempt(name, callback):
        try:
            callback()
            facts["collected"].append(name)
        except (EvidenceError, ValueError, KeyError, TypeError, IndexError, AttributeError) as exc:
            facts["failed"].append({"name": name, "detail": str(exc)})

    facts["session"] = {}

    def session():
        connection = find_connection(system)
        facts["session"]["connection"] = connection
        facts["session"]["sudo_user"] = os.environ.get("SUDO_USER") or (None if is_root() else os.environ.get("USER"))
        facts["session"]["running_as_root"] = is_root()
        if connection:
            user = facts["session"]["sudo_user"] or "root"
            facts["session"]["auth"] = session_auth(system, connection, user)
    attempt("会话采集", session)

    def services():
        load, active, listen = socket_listen_ports(system)
        facts["socket"] = {"load": load, "active": active, "listen_ports": listen}
        facts["ssh_service"] = dict(zip(("active", "enabled"), unit_state(system, "ssh.service")))
        facts["listeners"] = {"sshd_ports": sshd_listeners(system)}
    attempt("监听采集", services)

    def config():
        facts["sshd_config_valid"] = None
        try:
            system.run("sshd", "-t", "-f", SSHD_CONFIG)
            facts["sshd_config_valid"] = True
        except EvidenceError as exc:
            facts["sshd_config_valid"] = False
            facts["sshd_config_error"] = str(exc)
        facts["disk_ports"] = {str(port): where for port, where in disk_port_directives(system).items()}
        facts["match_blocks"] = match_blocks(system)
        if is_root():
            connection = facts["session"].get("connection")
            addr = connection["source"] if connection else "192.0.2.1"
            laddr = connection["local"] if connection else ("127.0.0.1" if ipaddress.ip_address(addr).version == 4 else "::1")
            base_context = "user=%s,host=stage0.invalid,addr=%s" % (
                options.user or facts["session"].get("sudo_user") or "root", addr)
            facts["effective"] = {"user_context": sshd_effective(system, SSHD_CONFIG, base_context)}
            root_context = "user=root,host=stage0.invalid,addr=%s" % addr
            facts["effective"]["root_context"] = sshd_effective(system, SSHD_CONFIG, root_context)
            keep = ("permitrootlogin", "passwordauthentication", "kbdinteractiveauthentication",
                    "authenticationmethods", "pubkeyauthentication", "authorizedkeysfile", "port")
            for context in facts["effective"].values():
                for key in list(context):
                    if key not in keep:
                        del context[key]
    attempt("认证采集", config)

    def account():
        user = options.user or facts["session"].get("sudo_user")
        if user:
            facts["account"] = account_facts(system, user)
    attempt("账户采集", account)

    def firewall():
        facts["nft"] = nft_ruleset_summary(system)
        facts["ufw"] = ufw_status(system)
        if options.allow and options.port is not None:
            facts["allowlist"] = allowlist_assessment(facts["nft"], facts["ufw"], options.port, options.allow)
    attempt("防火墙采集", firewall)

    def backup():
        facts["backup"] = backup_facts(system, options.backup_dir)
    attempt("备份采集", backup)

    def legacy():
        facts["legacy"] = legacy_facts(system)
    attempt("旧版痕迹采集", legacy)

    def reboot():
        facts["reboot"] = reboot_facts(system)
    attempt("重启证据采集", reboot)

    return facts


def render_text(facts, options, items, position, next_step):
    print("SSH 加固只读检查（stage0-check.sh）—— 本脚本不修改任何配置、不代执行任何命令")
    print("检查时间：" + time.strftime("%Y-%m-%d %H:%M:%S") + "（本地时区）")
    if not is_root():
        print("当前非 root：sshd 有效配置、journal 认证证据等无法采集。请运行：")
        print("  sudo bash " + shlex.quote(os.environ.get("REINFORCE_SELF", SCRIPT)))
    session = facts.get("session", {})
    connection = session.get("connection")
    print("\n-- 当前会话 --")
    if connection:
        print("连接：%s:%d -> 本机 %s:%d" % (connection["source"], connection["source_port"], connection["local"], connection["port"]))
    else:
        print("连接：未检测到 SSH 会话（本机终端或环境不可读）")
    print("sudo 用户：%s；认证方式：%s" % (session.get("sudo_user") or "未识别", session.get("auth") or "未证实"))
    print("\n-- 监听与服务 --")
    listeners = facts.get("listeners", {})
    print("sshd 监听端口：%s" % (listeners.get("sshd_ports") or "未采集"))
    socket = facts.get("socket", {})
    if socket:
        print("ssh.socket：%s/%s，Listen 端口：%s" % (socket.get("load"), socket.get("active"), socket.get("listen_ports")))
    service = facts.get("ssh_service", {})
    if service:
        print("ssh.service：%s/%s" % (service.get("active"), service.get("enabled")))
    if facts.get("sshd_config_valid") is False:
        print("[阻断] sshd -t 失败：" + facts.get("sshd_config_error"))
    elif facts.get("sshd_config_valid"):
        print("sshd 配置有效性（sshd -t）：通过")
    disk_ports = facts.get("disk_ports") or {}
    if disk_ports:
        print("磁盘配置声明的端口：" + ", ".join("%s（%s）" % (port, ", ".join(where)) for port, where in sorted(disk_ports.items(), key=lambda kv: int(kv[0]))))
    print("\n-- 认证（有效配置）--")
    effective = facts.get("effective", {})
    if effective:
        for label, context in (("目标用户上下文", "user_context"), ("root 上下文", "root_context")):
            values = effective.get(context, {})
            print(label + "：" + "，".join("%s=%s" % (key, ",".join(value)) for key, value in sorted(values.items()) if key != "authorizedkeysfile") or "未采集")
    else:
        print("未采集（需要 sudo）")
    if facts.get("match_blocks"):
        print("[注意] 存在 Match 块，有效配置随上下文变化，需人工复核：" + "; ".join(facts["match_blocks"][:6]))
    account = facts.get("account")
    if account:
        print("\n-- 账户与公钥 --")
        if not account.get("exists"):
            print("账户 %s：不存在（%s）" % (account.get("user"), account.get("detail", "")))
        else:
            print("账户 %s：uid=%s，sudo 组=%s，authorized_keys=%d 个公钥（目录 %s / 文件 %s）" % (
                account["user"], account["uid"], "是" if account.get("sudo") else "否",
                account.get("authorized_keys_count", 0), account.get("ssh_dir_mode", "?"), account.get("authorized_keys_mode", "?")))
    print("\n-- 防火墙 --")
    nft = facts.get("nft", {})
    print("nft 表：%s" % (", ".join(nft.get("tables", [])) or "无"))
    for policy in nft.get("input_policy", []):
        print("input 链策略：" + policy)
    relevant = [rule for rule in nft.get("rules", []) if rule.get("dports") or rule.get("verdict") in ("drop", "reject")]
    for rule in relevant[:10]:
        print("  规则：%s verdict=%s dport=%s saddr=%s ct=%s" % (
            rule["location"], rule.get("verdict"), ",".join(rule.get("dports", [])) or "-",
            ",".join(rule.get("saddrs", [])) or "-", ",".join(rule.get("ct_state", [])) or "-"))
    ufw = facts.get("ufw", {})
    if ufw.get("available"):
        print("UFW：%s" % ("active" if ufw.get("active") else "inactive"))
    print("\n-- 备份 / 旧版痕迹 / 重启 --")
    backup = facts.get("backup", {})
    if backup.get("latest"):
        print("备份：%s%s" % (backup.get("latest"), "（含 sshd_config）" if backup.get("has_sshd_config") else "（缺 sshd_config 副本）"))
    else:
        print("备份：%s 下未发现备份" % backup.get("root", options.backup_dir))
    legacy = facts.get("legacy", {})
    if legacy.get("state"):
        print("旧版受管状态：STAGE=%s TX=%s（%s/state.conf）" % (legacy["state"].get("STAGE"), legacy["state"].get("TX"), LEGACY_STATE_ROOT))
    if legacy.get("managed_files"):
        print("旧版/ legacy 方案文件：" + ", ".join(legacy["managed_files"]))
    if legacy.get("recovery_timers"):
        print("[阻断] 旧版自动恢复定时器残留：" + ", ".join(item["unit"] for item in legacy["recovery_timers"]))
    if not legacy.get("state") and not legacy.get("managed_files") and not legacy.get("traces"):
        print("旧版受管状态：无")
    reboot = facts.get("reboot", {})
    if reboot.get("btime"):
        print("本次启动：%s；boot_id=%s" % (reboot.get("boot_time"), (reboot.get("boot_id") or "?")[:8]))
        if reboot.get("hardened_latest_mtime"):
            print("最近修改的 SSH 相关配置文件：%s（%s）；本次启动晚于该修改：%s（仅是信息性比较，只有在加固已完成时才作为持久化证据）" % (
                reboot["hardened_latest_mtime"], reboot.get("hardened_latest_file"),
                {True: "是", False: "否"}.get(reboot.get("booted_after_hardening"), "未知")))
    for failure in facts.get("failed", []):
        print("[采集缺口] %s：%s" % (failure["name"], failure["detail"]))
    if items:
        print("\n-- 目标比较 --")
        for item in items:
            print("[%s] %s：%s" % (LABELS[item["status"]], item["item"], item["detail"]))
    print("\n当前位置：" + POSITION_TEXT.get(position, position))
    print("下一步：" + next_step["summary"])
    for command in next_step.get("commands", []):
        print("  " + command)
    print("\n常备提醒：")
    print("- 云安全组/云防火墙在本地不可检测：改动端口前后都要在云控制台核对放行规则。")
    print("- 执行任何变更前保留当前会话，并确认 VNC/串口等救援通道真实可用（不是假设可用）。")
    if legacy.get("blocking"):
        print("\n[阻断] " + legacy["blocking"])


def main(argv=None):
    options = parse_args(argv if argv is not None else sys.argv[1:])
    system = System()
    facts = collect(system, options)
    items, position, next_step = assess(facts, options)
    blocking = bool(facts.get("legacy", {}).get("blocking")) or facts.get("sshd_config_valid") is False
    report = {
        "schema": 1,
        "script": SCRIPT,
        "read_only": True,
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "running_as_root": is_root(),
        "goals": {"port": options.port, "user": options.user, "allow": options.allow,
                  "closed_port": options.closed_port, "host": options.host},
        "facts": facts,
        "assessment": items,
        "position": position,
        "position_text": POSITION_TEXT.get(position, position),
        "next_step": next_step,
    }
    if options.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
    else:
        render_text(facts, options, items, position, next_step)
    if blocking:
        return 1
    critical = {"会话采集", "监听采集"}
    if any(failure["name"] in critical for failure in facts.get("failed", [])) or not facts.get("collected"):
        return 2
    if not is_root():
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n已中断；本脚本只读，系统未发生任何变更。", file=sys.stderr)
        sys.exit(130)
REINFORCE_STAGE0_PY
