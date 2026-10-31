#!/usr/bin/env bash
# stage2-lockdown.sh —— SSH 加固三步指导体系：第 2 步，nft 白名单 / 禁 root / 禁密码 / 最终确认
#
# 本脚本【纯只读】：不修改 SSH/防火墙/systemd 配置，不写状态文件，不安装定时器，
# 不代执行任何命令，也没有任何形式的自动回滚。它按内置的只读步骤方案：
#   0. 前置检查（stage1 成果：仅新端口在听、当前会话为新端口公钥登录、备份存在、救援通道已确认）
#   1. nft 来源白名单（仅放行 --allow 网段到新端口；含当前来源不在白名单时的硬性阻断）
#   2. 禁止 root / 禁止密码 / 禁止键盘交互（新会话公钥验证为验证门槛）
#   3. 最终确认清单（运行态逐项比对目标）
#   4. 重启后复验（操作员自行重启；以启动时间晚于全部加固文件修改 + 运行态达标为持久化证据）
# 逐步打印：当前步骤的状态确认、为什么、手工命令、验证命令与预期、手工撤销命令（恢复只依赖
# 操作员自己的备份，永远由人执行）。所有命令由操作员本人（或其监督下的智能体）手工执行。
#
# 退出码：0=stage2 全部达成（含跨重启复验）；1=阻断性异常（旧版残留、sshd 配置损坏、白名单锁死风险）；
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

exec python3 - "$@" <<'REINFORCE_STAGE2_PY'
"""stage2-lockdown.sh：nft 白名单/禁 root/禁密码/最终确认的只读分步指导；绝不修改系统。"""
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

SCRIPT = "stage2-lockdown.sh"
STAGE1 = "stage1-port-key.sh"
BACKUP_ROOT = "/var/backups/ssh-hardening"
LEGACY_STATE_ROOT = "/var/lib/reinforce-my-ssh"
SSHD_CONFIG = "/etc/ssh/sshd_config"
SSHD_CONFIG_D = "/etc/ssh/sshd_config.d"
SOCKET_DROPIN_DIR = "/etc/systemd/system/ssh.socket.d"
HARDEN_DROPIN = SSHD_CONFIG_D + "/20-hardening.conf"
ALLOWLIST_FILE = "/etc/nftables.d/ssh-allowlist.nft"
NFTABLES_CONF = "/etc/nftables.conf"
MANAGED_HINT_FILES = (
    "/usr/local/sbin/reinforce-my-ssh-firewall",
    "/etc/ssh/sshd_config.d/00-reinforce-my-ssh.conf",
    "/etc/nftables.d/reinforce-my-ssh.nft",
    "/etc/systemd/system/reinforce-my-ssh-firewall.service",
    "/etc/systemd/system/ssh.socket.d/00-reinforce-my-ssh.conf",
)
TAILSCALE_IFACE = "/sys/class/net/tailscale0"
CGNAT = ipaddress.ip_network("100.64.0.0/10")
TAILSCALE_V6 = ipaddress.ip_network("fd7a:115c:a1e0::/48")

DONE, TODO, BLOCKED, WARN, UNKNOWN = "done", "todo", "blocked", "warn", "unknown"
STATUS_LABEL = {DONE: "已完成", TODO: "未完成", BLOCKED: "被门槛阻塞", WARN: "需注意", UNKNOWN: "无法证实"}
PASS, FAIL = "pass", "fail"

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


def sshd_effective(system, context, keep):
    options = {}
    for line in system.run("sshd", "-T", "-f", SSHD_CONFIG, "-C", context).splitlines():
        key, sep, value = line.partition(" ")
        if sep and key in keep:
            options[key] = value.strip()
    return options


def sshd_valid(system):
    try:
        system.run("sshd", "-t", "-f", SSHD_CONFIG)
        return True, None
    except EvidenceError as exc:
        return False, str(exc)


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


# ---------------------------------------------------------------- nft/ufw

def literal_values(value):
    if isinstance(value, dict):
        if "prefix" in value:
            prefix = value["prefix"]
            return [str(prefix["addr"]) + "/" + str(prefix["len"])]
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
    dports, saddrs, ct_state, iifs = set(), set(), set(), set()
    iif_negated, iif_unknown = False, False
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
            if isinstance(left, dict) and "meta" in left and left["meta"].get("key") in ("iifname", "iif"):
                values = literal_values(right)
                if (left["meta"]["key"] == "iifname" and values
                        and all(isinstance(v, str) and not v.startswith("@") for v in values)
                        and node.get("op") in (None, "==", "!=", "in")):
                    iifs.update(v.strip('"') for v in values)
                else:
                    # 数值索引不能证明实际入口；即使右值无法解析，也不得抹掉接口条件。
                    iif_unknown = True
                    iifs.add("unresolved:" + json.dumps(left["meta"]) + ":" + json.dumps(right))
                if node.get("op") == "!=":
                    iif_negated = True
    if verdict is None and not dports and not saddrs:
        return None
    return {"verdict": verdict, "dports": sorted(dports), "saddrs": sorted(saddrs),
            "ct_state": sorted(ct_state), "iifs": sorted(iifs), "iif_negated": iif_negated,
            "iif_unknown": iif_unknown,
            "loopback": "lo" in iifs}


def nft_ruleset_summary(system):
    summary = {"tables": [], "input_policy": [], "rules": []}
    js = json.loads(system.run("nft", "-j", "list", "ruleset"))
    for item in js.get("nftables", []):
        if "table" in item:
            summary["tables"].append(item["table"].get("family", "?") + " " + item["table"].get("name", "?"))
        if "chain" in item and item["chain"].get("hook") == "input":
            summary["input_policy"].append("%s %s chain %s policy=%s" % (
                item["chain"].get("family"), item["chain"].get("table"),
                item["chain"].get("name"), item["chain"].get("policy", "?")))
        if "rule" in item:
            digest = rule_digest(item["rule"])
            if digest:
                summary["rules"].append({
                    "location": "%s %s chain %s" % (item["rule"].get("family"), item["rule"].get("table"), item["rule"].get("chain")),
                    "identity": [item["rule"].get(key) for key in ("family", "table", "chain")],
                    "handle": item["rule"].get("handle"), "comment": item["rule"].get("comment"),
                    **digest,
                })
    return summary


def ufw_status(system):
    try:
        text = system.run("ufw", "status", "verbose")
    except EvidenceError as exc:
        return {"available": False, "detail": str(exc)}
    return {"available": True, "active": not re.search(r"Status:\s*inactive", text), "text": text.strip()}


def allowlist_assessment(nft_summary, ufw, port, allows, tailnet=False):
    """核对全部声明来源与默认拒绝；复杂条件和拒绝后的放行不作为可达证据。"""
    if not allows and not tailnet:
        return {"status": UNKNOWN, "detail": "未声明 --allow，不判定白名单合规"}
    networks = [ipaddress.ip_network(item) for item in allows]
    port_s = str(port)
    offenders, restricting_drop, saw_accept, tailnet_accept = [], False, False, False
    accepted, stopped = [], set()
    for rule in nft_summary.get("rules", []):
        if port_s not in rule["dports"]:
            continue
        if rule["verdict"] == "accept":
            saw_accept = True
            reachable = rule["location"] not in stopped
            if tailnet and "tailscale0" in rule.get("iifs", []) and not rule.get("iif_negated") and not rule.get("iif_unknown"):
                tailnet_accept |= reachable
                continue
            if not rule["saddrs"]:
                offenders.append(rule["location"] + "：accept dport " + port_s + " 无来源限制")
            for literal in rule["saddrs"]:
                try:
                    net = ipaddress.ip_network(literal)
                except ValueError:
                    offenders.append(rule["location"] + "：无法解析来源 " + literal)
                    continue
                if not any(net.version == declared.version and net.subnet_of(declared) for declared in networks):
                    offenders.append(rule["location"] + "：来源 " + literal + " 超出声明白名单")
                elif reachable and not rule.get("iifs") and not rule.get("iif_negated"):
                    accepted.append(net)
        if rule["verdict"] in ("drop", "reject"):
            restricting_drop |= not rule["saddrs"] and not rule.get("iif_unknown") and (not rule.get("iifs") or rule.get("iif_negated", False))
            # 拒绝之后的放行不能作为可达证据；复杂条件保守判为待复核。
            stopped.add(rule["location"])
    policy_drop = any("policy=drop" in item for item in nft_summary.get("input_policy", []))
    if ufw.get("active"):
        ufw_stopped = set()
        for line in ufw.get("text", "").splitlines():
            m = re.match(r"^%s(/tcp)?(?:\s+\(v6\))?(?:\s+on\s+(\S+))?\s+(ALLOW|DENY|REJECT)(?:\s+(IN|OUT|FWD))?\s+(\S+)" % re.escape(port_s), line.strip())
            if not m:
                continue
            iface, verdict, direction, literal = m.group(2), m.group(3), m.group(4), m.group(5)
            if direction in ("OUT", "FWD"):
                continue
            version = 6 if "(v6)" in line or ":" in literal else 4
            if verdict == "ALLOW":
                saw_accept = True
                if tailnet and iface == "tailscale0":
                    tailnet_accept |= version not in ufw_stopped
                    continue
                if literal in ("Anywhere", "::/0", "0.0.0.0/0"):
                    offenders.append("ufw：ALLOW " + port_s + " 无来源限制")
                else:
                    try:
                        net = ipaddress.ip_network(literal.split()[0])
                        if not any(net.version == d.version and net.subnet_of(d) for d in networks):
                            offenders.append("ufw：来源 " + literal + " 超出声明白名单")
                        elif not iface and version not in ufw_stopped:
                            accepted.append(net)
                    except ValueError:
                        offenders.append("ufw：无法解析来源 " + literal)
            else:
                restricting_drop |= not iface and literal in ("Anywhere", "::/0", "0.0.0.0/0")
                ufw_stopped.add(version)
    if offenders:
        return {"status": FAIL, "detail": "；".join(offenders[:4])}
    if saw_accept:
        missing = []
        for declared in networks:
            merged = ipaddress.collapse_addresses(net for net in accepted if net.version == declared.version)
            if not any(declared.subnet_of(net) for net in merged):
                missing.append(str(declared))
        if tailnet and not tailnet_accept:
            missing.append("tailscale0")
        if missing:
            return {"status": FAIL, "detail": "未证实全部声明来源放行（含规则顺序）：" + ", ".join(missing)}
    if tailnet_accept and (restricting_drop or policy_drop):
        return {"status": PASS, "detail": "tailscale0 放行，全部声明 CIDR 放行 + 默认拒绝；Tailscale SSH 与 sshd 仍需分开验证"}
    if saw_accept and (restricting_drop or policy_drop):
        return {"status": PASS, "detail": "运行规则字面量比较：目标端口仅对声明白名单放行且存在默认拒绝；集合/区间写法请人工复核证据"}
    if saw_accept:
        return {"status": FAIL, "detail": "存在放行规则但未发现默认拒绝/drop，白名单不成立"}
    return {"status": UNKNOWN, "detail": "未发现涉及目标端口的放行规则；无法证实白名单"}


def legacy_blocking(system):
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
    for path in MANAGED_HINT_FILES:
        if system.exists(path):
            traces.append(path)
    return reasons, traces


def reboot_facts(system):
    facts = {"evidence_scope": "仅比较磁盘文件；不能检测启动后的纯运行态变更，须实际冷启动及外部验收"}
    try:
        facts["btime"] = int(re.search(r"^btime (\d+)$", system.read("/proc/stat"), re.M)[1])
        facts["boot_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(facts["btime"]))
        hardened = set(sshd_config_files(system))
        for path in ("/etc/nftables.conf", "/etc/systemd/system/ssh-allowlist.service"):
            if system.exists(path):
                hardened.add(path)
        for directory in (SSHD_CONFIG_D, SOCKET_DROPIN_DIR, "/etc/nftables.d",
                          "/etc/systemd/system/ssh-allowlist.service.d"):
            if system.is_dir(directory):
                for name in system.list_dir(directory):
                    path = directory + "/" + name
                    if not system.is_dir(path):
                        hardened.add(path)
        mtimes = [(system.mtime(path), path) for path in sorted(hardened)]
        if not mtimes or any(m is None for m, _ in mtimes):
            facts["detail"] = "加固文件时间采集不完整，不能证实文件早于启动"
            return facts
        latest = max(mtimes)
        facts["hardened_latest_mtime"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(latest[0]))
        facts["hardened_latest_file"] = latest[1]
        facts["booted_after_hardening"] = facts["btime"] > latest[0]
    except (EvidenceError, AttributeError, TypeError, ValueError):
        facts.pop("booted_after_hardening", None)
    return facts


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


def is_tailnet_network(value):
    """CIDR 是否完全落在 Tailscale 的 v4/v6 段内。"""
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return any(network.version == declared.version and network.subnet_of(declared)
               for declared in (CGNAT, TAILSCALE_V6))


def sshd_bindings(system):
    """SSH 监听地址与端口；socket 激活时监听由 systemd 持有，必须一并计入。"""
    found = []
    for line in system.run("ss", "-tlnpH").splitlines():
        words = line.split()
        match = re.search(r'"([a-zA-Z0-9_.-]+)"', line)
        process = match.group(1) if match else ""
        if len(words) >= 4 and process in ("sshd", "sshd-session", "systemd"):
            host, _, port = words[3].rpartition(":")
            try:
                number = int(port)
            except ValueError:
                continue
            if 1 <= number <= 65535:
                found.append({"address": host.strip("[]"), "port": number, "process": process})
    return found


def socket_listen_ports(system):
    """ssh.socket 的 Listen 端口；socket 激活时用它补足 ss 里没有 sshd 归属的监听。"""
    try:
        props = system.run("systemctl", "show", "ssh.socket", "-p", "Listen", "-p", "ActiveState", "-p", "LoadState")
    except EvidenceError:
        return "unknown", "unknown", []
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


def ssh_listener_ports(system):
    ports = {item["port"] for item in sshd_bindings(system)}
    _, active, listen = socket_listen_ports(system)
    if active == "active":
        ports.update(listen)
    return sorted(ports)


def public_exposure(bindings, port):
    """该端口上仍非回环、非 tailnet 的监听地址（通配地址视为公网暴露）。"""
    exposed = []
    for item in bindings:
        if item["port"] != port:
            continue
        address = item["address"]
        if address in ("127.0.0.1", "::1") or is_tailnet_address(address):
            continue
        exposed.append(address or "<未知>")
    return exposed


def nft_public_verdict(nft_summary, port):
    """按链内顺序判断“非 tailnet 来源”能否进入该端口：True=能，False=被拒，None=无法证实。"""
    chains = {}
    for rule in nft_summary.get("rules", []):
        if str(port) in rule["dports"]:
            chains.setdefault(rule["location"], []).append(rule)
    verdicts = []
    for rules in chains.values():
        verdict = None
        for rule in rules:
            if rule.get("iif_unknown"):
                continue  # 未解析的入口条件不能证明公网开放或全局拒绝。
            if "tailscale0" in rule.get("iifs", []) and not rule.get("iif_negated"):
                continue
            if rule.get("iifs") and "tailscale0" not in rule.get("iifs", []):
                continue
            if rule["verdict"] == "accept":
                if not rule["saddrs"]:
                    verdict = True
                    break
                if rule["saddrs"]:  # 来源地址不能证明入站接口，CGNAT 也可能来自云内网
                    verdict = True
                    break
            elif rule["verdict"] in ("drop", "reject"):
                if not rule["saddrs"]:
                    verdict = False
                    break
        verdicts.append(verdict)
    if True in verdicts:
        return True
    if verdicts and all(item is False for item in verdicts):
        return False
    return None


def ufw_public_verdict(ufw, port):
    """每个地址族按首条匹配判定，IPv4 拒绝不能掩盖 IPv6 放行。"""
    decisions = {}
    for line in ufw.get("text", "").splitlines():
        match = re.match(r"^%s(/tcp)?(?:\s+\(v6\))?(?:\s+on\s+(\S+))?\s+(ALLOW|DENY|REJECT)(?:\s+(IN|OUT|FWD))?\s+(\S+)" % re.escape(str(port)), line.strip())
        if not match:
            continue
        iface, verdict, direction, source = match.group(2), match.group(3), match.group(4), match.group(5)
        if direction in ("OUT", "FWD") or iface == "tailscale0":
            continue
        family = 6 if "(v6)" in line or ":" in source else 4
        if family in decisions:
            continue
        if verdict == "ALLOW":  # 非 tailscale0 接口放行属于外部入口，不能按地址段跳过
            decisions[family] = True
        elif verdict in ("DENY", "REJECT") and source in ("Anywhere", "0.0.0.0/0", "::/0") and not iface:
            decisions[family] = False
    if True in decisions.values():
        return True
    return False if decisions and all(v is False for v in decisions.values()) else None


def public_entry_verdict(nft_summary, ufw, port):
    """综合 nft 与 UFW：任一通道的显式拒绝即为关闭；否则任一放行即为开放。"""
    results = [nft_public_verdict(nft_summary, port)]
    if ufw.get("active"):
        results.append(ufw_public_verdict(ufw, port))
    if False in results:
        return False
    if True in results:
        return True
    return None


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog=SCRIPT,
        description="只读指导：nft 白名单 / 禁 root / 禁密码 / 最终确认；不修改系统、不代执行。",
        epilog="退出码：0=stage2 全部达成（含跨重启复验）；1=阻断性异常；2=步骤未完成或需要 sudo。")
    parser.add_argument("--port", type=int, required=True, help="加固后的唯一 SSH 端口（stage1 成果）")
    parser.add_argument("--user", required=True, help="非 root 管理账户（stage1 成果）")
    parser.add_argument("--allow", action="append", default=[], help="可信来源 IP/CIDR，可重复声明云内网和指定公网来源；与 --tailnet 至少给一个")
    parser.add_argument("--tailnet", action="store_true",
                        help="额外放行 Tailscale 接口，保留全部 --allow 云内网/指定公网来源，并拒绝白名单外来源")
    parser.add_argument("--host", help="客户端连接地址或 SSH 别名，仅用于生成提示命令")
    parser.add_argument("--rescue-confirmed", action="store_true", help="已实际演练 VNC/串口救援登录（硬门槛）")
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
    try:
        options.allow = sorted({str(ipaddress.ip_network(item, strict=True)) for item in options.allow})
    except ValueError as exc:
        parser.error(str(exc))
    if not options.allow and not options.tailnet:
        parser.error("--allow 至少一个来源，或使用 --tailnet 声明经 Tailscale 管理")
    if options.host and not re.fullmatch(r"[A-Za-z0-9_.:\[\]-]+", options.host):
        parser.error("--host 含不支持的字符")
    if (not options.backup_dir.startswith("/") or options.backup_dir.startswith("//")
            or options.backup_dir.rstrip("/") == "" or any(part in (".", "..") for part in options.backup_dir.split("/"))
            or any(ord(c) < 32 or ord(c) == 127 for c in options.backup_dir)):
        parser.error("--backup-dir 必须是非根目录的绝对路径，不含 .、.. 或控制字符")
    options.backup_dir = options.backup_dir.rstrip("/")
    return options


# ---------------------------------------------------------------- 步骤方案

def transition_cleanup(nft_summary, port):
    commands = ["# 先保留当前会话，从声明来源建立新的公钥会话验证成功，再清理过渡规则。",
                "sudo nft -a list ruleset  # 核对下面的 handle 未变化；不要 flush ruleset"]
    for rule in nft_summary.get("rules", []):
        if (rule.get("comment") == "stage1 new-port bridge" and rule.get("verdict") == "accept"
                and rule.get("dports") == [str(port)] and not rule.get("saddrs") and not rule.get("iifs")
                and rule.get("ct_state") == ["new"]):
            identity = rule.get("identity", [])
            handle = rule.get("handle")
            if len(identity) == 3 and all(isinstance(x, str) for x in identity) and isinstance(handle, int):
                commands.append("sudo nft delete rule " + " ".join(shlex.quote(x) for x in identity)
                                + " handle " + str(handle))
            else:
                commands.append("# stage1 过渡规则的 handle 无法读取；用上面命令定位后人工精确删除。")
    commands += ["# 若还有非 stage1 的宽泛放行，人工核对其用途与持久化文件；按 handle 精确收口，再重跑。",
                 "# nft 跨基链 accept 不能绕过 drop；当前检查保守拒绝未清理的宽泛规则。"]
    return commands


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
if loader_enabled in ("enabled", "enabled-runtime", "static"):
    # 清理本工具新旧安装目标的持久链接，再按备份单元重建；static 不应留下工具的开机启用。
    for wanted in ("multi-user.target", "sysinit.target"):
        remove_file(target("/etc/systemd/system/" + wanted + ".wants/ssh-allowlist.service"))
if loader_enabled in ("enabled", "enabled-runtime"):
    args = ["systemctl", "enable"]
    if loader_enabled == "enabled-runtime":
        args.append("--runtime")
    run(*args, "ssh-allowlist.service")
elif loader_enabled == "disabled":
    run("systemctl", "disable", "ssh-allowlist.service")
elif loader_enabled == "not-found":
    # 删除 unit 后只能精确清理本工具生成的链接，不能 disable 不存在的服务。
    for directory in ("/etc/systemd/system", "/run/systemd/system"):
        for wanted in ("multi-user.target", "sysinit.target"):
            remove_file(target(directory + "/" + wanted + ".wants/ssh-allowlist.service"))
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
    host = options.host or "SERVER"
    port, user = options.port, options.user
    restore_path = ctx["backup"].get("latest") or options.backup_dir + "/REPLACE_WITH_TIMESTAMP"
    steps = []

    def step(sid, title, status, evidence, why, do, verify, undo, blocked_by=None):
        steps.append({"id": sid, "title": title, "status": status, "evidence": evidence,
                      "why": why, "do": do, "verify": verify, "undo": undo, "blocked_by": blocked_by or []})

    session = ctx["connection"]
    listen_ok = ctx["listeners"] == [port]
    session_ok = bool(session and session["port"] == port and ctx["auth"] == "publickey")
    backup_ok = ctx["backup"].get("complete")
    account = ctx["account"]
    account_ok = bool(account.get("exists") and account.get("sudo") and account.get("authorized_keys_count") and account.get("permissions_safe"))
    preconditions = {
        "仅新端口 %d 在监听" % port: listen_ok,
        "当前会话为新端口公钥登录": session_ok,
        "备份存在（%s）" % options.backup_dir: bool(backup_ok),
        "账户 %s 具备 sudo 与公钥" % user: account_ok,
        "救援通道已演练（--rescue-confirmed）": options.rescue_confirmed,
    }
    if options.tailnet:
        preconditions["Tailscale 已接入（tailscale0 up）"] = ctx["tailnet"].get("up") is True
    pre_fail = [name for name, ok in preconditions.items() if not ok]
    step("0-preconditions", "前置检查（stage1 成果与救援纪律）",
         DONE if not pre_fail else BLOCKED,
         "；".join(("%s：%s" % (name, "已满足" if ok else "未满足")) for name, ok in preconditions.items()),
         "stage2 会禁用密码与限制来源；任何一个前置条件不成立都可能把自己关在门外。先回到 stage1 补齐，或从新端口的公钥会话重跑。",
         (["# 前置未满足时的处置：",
           "sudo bash " + shlex.quote(entry_dir() + "/" + STAGE1) + " --port " + str(port) + " --user " + user
           + ((" --host " + shlex.quote(options.host)) if options.host else "")
           + (" --rescue-confirmed" if options.rescue_confirmed else "")
           + " --backup-dir " + shlex.quote(options.backup_dir)
          + (" --tailnet" if options.tailnet else "")]
          if pre_fail else ["# 全部满足；继续检查下一步"]),
         ["重跑本脚本：0-preconditions 应显示已完成"],
         ["无需撤销：本步骤只读"],
         blocked_by=[])

    # 1. nft 来源白名单
    assessment = ctx["allowlist"]
    if assessment["status"] == PASS:
        allow_status, allow_note = DONE, assessment["detail"]
    else:
        allow_status, allow_note = TODO, assessment["detail"]
    source = session["source"] if session else None
    source_in_allow = None
    tailnet_source = bool(source and is_tailnet_address(source))
    if source:
        if options.tailnet and options.tailnet_session_confirmed and tailnet_source:
            source_in_allow = True
        else:
            source_in_allow = any(ipaddress.ip_address(source) in ipaddress.ip_network(item) for item in options.allow)
    if source_in_allow is False:
        allow_status, allow_note = BLOCKED, "当前会话来源 %s 不在声明白名单内；应用白名单将立即断掉你现在的连接" % source
        allow_do = ["# 硬性阻断：当前来源 %s 不在 --allow 内。" % source,
                    "# 处置（任选其一，都由你手工执行）：",
                    "1) 让你的当前来源进入白名单：在 --allow 中补上包含 %s 的网段（注意：这只在你确认该来源可信时）" % source,
                    "2) 或先切换到已在白名单内的来源（如跳板机 / Tailscale 出口）再重跑本脚本",
                    "# 在你确认之前，本步骤不会给出可执行的白名单命令；白名单写错即失联。"]
    else:
        v4 = [item for item in options.allow if ipaddress.ip_network(item).version == 4]
        v6 = [item for item in options.allow if ipaddress.ip_network(item).version == 6]
        if ctx["ufw"].get("active"):
            allow_do = ["# 本机 UFW 处于 active，用 UFW 等效命令（保持其统一管理，勿混用 nft 文件）："]
            if options.tailnet:
                allow_do += ["sudo ufw insert 1 allow in on tailscale0 to any port %d proto tcp comment 'ssh allowlist tailnet'" % port]
            allow_do += ["sudo ufw insert 1 allow from %s to any port %d proto tcp comment 'ssh allowlist'" % (item, port)
                         for item in options.allow]
            allow_do += ["sudo ufw deny %d/tcp comment 'ssh allowlist default-deny'" % port,
                         "# 先从每个声明来源验证新的公钥会话成功，再移除 stage1 的全来源允许（IPv4/IPv6）：",
                         "sudo ufw delete allow %d/tcp" % port,
                         "sudo ufw status numbered  # 逐条核对：白名单 allow 在 deny 之前的语义生效"]
        else:
            allow_do = ["# 本机无 active UFW：用独立 nft 链（只影响本端口的“新连接”，不改全局策略）：",
                        "sudo install -d -m 755 /etc/nftables.d",
                        "sudo tee " + ALLOWLIST_FILE + " >/dev/null <<'EOF'",
                        "table inet sshguard",
                        "delete table inet sshguard",
                        "table inet sshguard {",
                        "  chain ssh_allow {",
                        "    type filter hook input priority filter - 10; policy accept;",
                        "    ct state established,related accept"]
            if options.tailnet:
                allow_do += ["    iifname \"tailscale0\" tcp dport " + str(port) + " accept"]
            if v4:
                allow_do += ["    tcp dport " + str(port) + " ip saddr { " + ", ".join(v4) + " } accept"]
            if v6:
                allow_do += ["    tcp dport " + str(port) + " ip6 saddr { " + ", ".join(v6) + " } accept"]
            allow_do += ["    tcp dport " + str(port) + " drop",
                         "  }",
                         "}",
                         "EOF",
                         "sudo nft -c -f " + ALLOWLIST_FILE + "  # 仅校验：失败时停止，旧表不变",
                         "sudo nft -f " + ALLOWLIST_FILE + "  # 单次事务替换，只影响 inet sshguard",
                         "# 先核对现有启动加载器：禁止全局 flush、禁止两个加载器重复装载同一文件。",
                         "# 若 /etc/nftables.conf 已包含本文件，先人工协调移除该专用 include；不要修改无关表。",
                         "# 已启用的全局加载器若会 flush ruleset，先人工协调其启动配置；不要直接启用/重启它。",
                         "test -x /usr/sbin/nft  # 确认专用加载器中的实际 nft 路径；失败则先修正路径",
                         "sudo tee /etc/systemd/system/ssh-allowlist.service >/dev/null <<'EOF'",
                         "[Unit]", "Description=SSH source allowlist", "DefaultDependencies=no",
                         "Wants=network-pre.target", "After=local-fs.target network-pre.target",
                         "Before=ssh.service ssh.socket shutdown.target", "Conflicts=shutdown.target",
                         "[Service]", "Type=oneshot", "RemainAfterExit=yes",
                         "ExecStart=/usr/sbin/nft -f /etc/nftables.d/ssh-allowlist.nft",
                         "ExecReload=/usr/sbin/nft -f /etc/nftables.d/ssh-allowlist.nft",
                         "[Install]", "WantedBy=sysinit.target", "EOF",
                         "# 无 ExecStop：停止服务不得清空过滤规则；显式早期依赖避免 socket/basic.target 排序环。",
                         "# Before 只提供顺序，不保证加载失败时 SSH 停止；仍须做真实冷启动与外部连接验收。",
                         "sudo systemctl daemon-reload",
                         "sudo python3 - <<'SSH_LOADER_PY'\n" + 'import json\nimport subprocess\nunit = "ssh-allowlist.service"\nresult = subprocess.run(["systemctl", "show", unit, "-p", "FragmentPath", "-p", "DropInPaths"], check=True, text=True, capture_output=True)\nprops = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)\nif props.get("FragmentPath") != "/etc/systemd/system/ssh-allowlist.service" or props.get("DropInPaths") != "":\n    raise SystemExit("实际加载器路径或 drop-in 不明确，停止，未启用/重启服务")\nfor name in ("ExecStop", "ExecStopPost"):\n    result = subprocess.run(["busctl", "--json=short", "get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/ssh_2dallowlist_2eservice", "org.freedesktop.systemd1.Service", name], check=True, text=True, capture_output=True)\n    value = json.loads(result.stdout)\n    if value.get("type") != "a(sasbttttuii)" or value.get("data") != []:\n        raise SystemExit("无法证明停止钩子为空，停止，未启用/重启服务")\nsubprocess.run(["systemctl", "enable", unit], check=True)\nsubprocess.run(["systemctl", "restart", unit], check=True)\n' + "SSH_LOADER_PY"]

            allow_do += transition_cleanup(ctx["nft"], port)
    if ctx.get("loader", {}).get("status") == FAIL and not ctx["ufw"].get("active"):
        allow_status = BLOCKED
        allow_note = ctx["loader"]["detail"]
        allow_do = ["# 先从已验证的救援通道核对并协调原白名单加载器及 drop-in，重跑后才生成加载命令。"]
    step("1-allowlist", "nft 来源白名单（Tailscale 接口与声明的云内网/公网来源）",
         allow_status, allow_note,
         "白名单把“知道端口”变成“还得来自允许的来源”。这是 login 前的第一道闸门；写错顺序或写错来源会直接断掉你自己的连接，因此本步先做链条自检再执行。",
         allow_do,
         ["重跑本脚本：1-allowlist 应显示已完成（字面量比较）",
          "sudo nft list ruleset  # 或 sudo ufw status verbose，逐条核对来源与端口",
          "客户端：ssh -p " + str(port) + " " + user + "@" + host + "  # 白名单内来源应仍可登录",
          "# 可选：从白名单外的网络（如手机热点）尝试连接，应被拒绝"],
         recovery_commands(restore_path),
         blocked_by=["0-preconditions"] if pre_fail else [])

    # 1b. 关闭公网入口（仅 --tailnet）
    if options.tailnet:
        exposed = public_exposure(ctx["bindings"], port)
        verdict = public_entry_verdict(ctx["nft"], ctx["ufw"], port) if not options.allow else None
        if not exposed:
            close_status = DONE
            close_note = "SSH 只监听回环/tailnet 地址，公网接口上没有该端口的监听"
        elif verdict is False:
            close_status = DONE
            close_note = "监听仍为通配地址 %s，但按规则顺序，非 tailnet 来源在端口 %d 上会被拒绝" % (", ".join(exposed), port)
        elif verdict is True:
            close_status = TODO
            close_note = "端口 %d 在 %s 上监听，且存在先于拒绝规则放行非 tailnet 来源的规则；公网仍可进入" % (port, ", ".join(exposed))
        else:
            close_status = UNKNOWN
            close_note = "端口 %d 在 %s 上监听，但未找到能证明非 tailnet 来源被拒绝的规则" % (port, ", ".join(exposed))
        if ctx["ufw"].get("active"):
            close_do = ["# 本机 UFW active：用 UFW 规则收口（第 1 步若已生成，跳过对应行）：",
                        "sudo ufw allow in on tailscale0 to any port %d proto tcp comment 'ssh tailnet only'" % port,
                        "sudo ufw deny %d/tcp comment 'ssh public deny'" % port,
                        "sudo ufw status numbered  # 核对 allow tailscale0 在 deny 之前生效"]
        else:
            close_do = ["# 方案 A（推荐，可逆）：在第 1 步的链内，先放行 tailscale0，再丢弃该端口的其余来源。",
                        "# 若第 1 步已生成相同规则，跳过对应行：",
                        "sudo nft add rule inet sshguard ssh_allow iifname \"tailscale0\" tcp dport " + str(port) + " accept",
                        "sudo nft add rule inet sshguard ssh_allow tcp dport " + str(port) + " drop",
                        "# 把上面两行写进 " + ALLOWLIST_FILE + " 后重新装载，避免重启丢失：",
                        "sudo nft -f " + ALLOWLIST_FILE,
                        "",
                        "# 方案 B：让 sshd 只绑定 tailnet 地址（先查询地址；socket 布局需改写 ListenStream）：",
                        "tailscale ip -4",
                        "# 在 " + SSHD_CONFIG + " 或其 drop-in 中写：ListenAddress <tailnet-ip>"]
        mixed_sources = bool(options.allow)
        if mixed_sources:
            close_status = DONE if allow_status == DONE else TODO
            close_note = ("保留 tailscale0 与声明来源 " + ", ".join(options.allow)
                          + "；白名单外来源拒绝；" + assessment["detail"])
            close_do = ["# 按 1-allowlist 的完整规则操作：保留 tailscale0 和每个 --allow，再拒绝其余来源。",
                        "# 云内网来源必须填写可信的实际 IP/CIDR；不要自动放行全部私网。",
                        "# 清理已有宽泛放行，逐条核对顺序；不要将 sshd 仅绑定到 tailnet 地址。"]
        close_verify = (["sudo nft list ruleset  # 或 sudo ufw status numbered：核对完整白名单与最终拒绝",
                         "# 分别从 tailnet、声明的云内网、指定公网来源建立新的公钥 SSH 会话，应成功",
                         "# 从白名单外来源连接，应被拒绝；保留当前会话直到全部验证完成"]
                        if mixed_sources else
                        ["sudo nft list chain inet sshguard ssh_allow  # 或 sudo ufw status numbered：tailscale0 放行应在该端口的拒绝之前",
                         "# 客户端（非 tailnet 网络，例如手机热点）：ssh -p " + str(port) + " " + user + "@<公网地址>  # 应失败/超时",
                         "# 客户端（tailnet 内）：ssh -p " + str(port) + " " + user + "@<tailnet-ip>  # 应成功"])
        step("1b-close-public", "拒绝白名单外 SSH 来源（保留全部声明入口）" if mixed_sources else "关闭公网 SSH 入口（只保留 tailnet 通路）",
             close_status, close_note,
             ("Tailscale 接口和 --allow 是累加关系；只收口白名单外来源，保留云内网和指定公网管理入口。" if mixed_sources else
              "把 sshd 从公网撤下，管理只走 tailnet，减少暴露面。") +
             "前提是 tailnet 通路已被真实验证；Tailscale SSH（tailscaled 终结）不能作为 sshd 路径的验证证据。"
             "云安全组与本地防火墙是两个规则域，本步只动本机。",
             close_do,
             close_verify,
             recovery_commands(restore_path),
             blocked_by=(["0-preconditions"] if pre_fail else []) + (["1-allowlist"] if allow_status != DONE else []))
        close_block = ["1b-close-public"] if close_status != DONE else []
    else:
        close_block = []

    # 2. 禁 root / 禁密码 / 禁键盘交互
    auth = ctx["auth_facts"]
    root_ok = auth.get("permitrootlogin") == "no"
    pass_ok = auth.get("passwordauthentication") == "no"
    kbd_ok = auth.get("kbdinteractiveauthentication") in (None, "no")
    methods = auth.get("authenticationmethods")
    methods_ok = methods in (None, "any") or "publickey" in (methods or "")
    pubkey_ok = auth.get("pubkeyauthentication") == "yes"
    if root_ok and pass_ok and kbd_ok and methods_ok and pubkey_ok:
        auth_status, auth_note = DONE, "PermitRootLogin=%s PasswordAuthentication=%s KbdInteractive=%s AuthenticationMethods=%s" % (
            auth.get("permitrootlogin"), auth.get("passwordauthentication"),
            auth.get("kbdinteractiveauthentication"), methods or "any")
    else:
        auth_status, auth_note = TODO, "PermitRootLogin=%s PasswordAuthentication=%s KbdInteractive=%s AuthenticationMethods=%s" % (
            auth.get("permitrootlogin"), auth.get("passwordauthentication"),
            auth.get("kbdinteractiveauthentication"), methods or "any")
    auth_note += " PubkeyAuthentication=%s" % auth.get("pubkeyauthentication")
    if source_in_allow is False:
        auth_status = BLOCKED
        auth_note += "；当前来源不在白名单内，先完成第 1 步"
    elif not session_ok:
        auth_status = BLOCKED
        auth_note += "；当前会话不是新端口公钥登录，禁用密码前必须先有一个已验证的公钥会话"
    auth_do = ["sudo tee " + HARDEN_DROPIN + " >/dev/null <<'EOF'",
               "PermitRootLogin no",
               "PubkeyAuthentication yes",
               "PasswordAuthentication no",
               "KbdInteractiveAuthentication no",
               "AuthenticationMethods publickey",
               "EOF",
               "sudo sshd -t && sudo systemctl reload ssh.service"]
    step("2-auth", "禁止 root / 密码 / 键盘交互登录",
         auth_status, auth_note,
         "到这里，登录只剩“非 root 账户 + 公钥”一条路：与 stage1 已验证的外部公钥会话完全一致，风险可控。reload 不打断现有会话，但之后的任何新连接都必须满足新策略。",
         auth_do,
         ["服务器重跑本脚本：2-auth 应显示已完成（sshd -T -C 上下文核对）",
          "客户端：ssh -o PreferredAuthentications=publickey -p " + str(port) + " " + user + "@" + host + " true  # 成功",
          "客户端：ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -p " + str(port) + " " + user + "@" + host + "  # 必须失败（Permission denied）",
          "客户端：ssh -p " + str(port) + " root@" + host + "  # 必须失败"],
         recovery_commands(restore_path),
         blocked_by=[b for b in (["0-preconditions"] if pre_fail else []) + (["1-allowlist"] if allow_status != DONE else []) + close_block])

    # 3. 最终确认清单
    checks = []
    checks.append(("仅新端口在监听", PASS if listen_ok else FAIL, "listeners=%s" % ctx["listeners"]))
    checks.append(("账户与公钥", PASS if account_ok else FAIL, "uid=%s sudo=%s keys=%s" % (
        account.get("uid"), account.get("sudo"), account.get("authorized_keys_count"))))
    checks.append(("来源白名单", assessment["status"], assessment["detail"]))
    checks.append(("禁 root", PASS if root_ok else FAIL, "PermitRootLogin=%s" % auth.get("permitrootlogin")))
    checks.append(("禁密码/键盘交互", PASS if (pass_ok and kbd_ok) else FAIL, "Password=%s Kbd=%s" % (
        auth.get("passwordauthentication"), auth.get("kbdinteractiveauthentication"))))
    checks.append(("公钥认证生效", PASS if (methods_ok and pubkey_ok) else FAIL, "PubkeyAuthentication=%s AuthenticationMethods=%s" % (auth.get("pubkeyauthentication"), methods or "any")))
    checks.append(("sshd 配置有效", PASS if ctx["sshd_valid"] else FAIL, ctx["sshd_error"] or "sshd -t 通过"))
    if options.tailnet:
        checks.append(("Tailscale 接入", PASS if ctx["tailnet"].get("up") else FAIL,
                       "tailscale0=%s" % (ctx["tailnet"].get("state") or "未发现")))
        checks.append(("白名单外入口已关闭" if options.allow else "公网入口已关闭", PASS if close_status == DONE else FAIL, close_note))
    if not ctx["ufw"].get("active"):
        checks.append(("专用白名单加载器", ctx["loader"]["status"], ctx["loader"]["detail"]))
    if ctx["match_blocks"]:
        checks.append(("Match 覆盖风险", UNKNOWN, "存在 Match 块，需人工复核：" + "; ".join(ctx["match_blocks"][:4])))
    confirm_ok = all(status == PASS for _, status, _ in checks)
    step("3-confirm", "最终确认清单（运行态逐项比对）",
         DONE if confirm_ok else TODO,
         "；".join("%s=%s" % (name, status) for name, status, _ in checks),
         "这是“加固效果”的验收：每一项都来自只读运行态证据，不依赖任何状态文件。任何一项不是 pass，就不要继续第 4 步。",
         ["# 无需执行命令；按上方清单逐项修正对应步骤后重跑本脚本"],
         ["重跑后清单应全部为 pass"],
         ["无需撤销：本步骤只读"])

    # 4. 重启后复验
    reboot = ctx["reboot"]
    reboot_ok = bool(reboot.get("booted_after_hardening")) and options.reboot_confirmed and confirm_ok
    if reboot_ok:
        reboot_evidence = "本次启动（%s）晚于全部加固文件修改，且确认清单全部通过" % reboot.get("boot_time")
    else:
        reboot_evidence = "尚无完整文件早于启动或冷启动后外部验收声明（--reboot-confirmed）；当前启动 %s" % reboot.get("boot_time", "未知")
    step("4-reboot-verify", "重启后复验（持久化证据）",
         DONE if reboot_ok else TODO,
         reboot_evidence,
         "只有真的重启一次并重连成功，才能证明“重启后仍然按加固后的配置运行”。这一步必须由你自行重启；工具从不代为重启，也不安排定时任务。",
         [(("# 前置：确认云控制台 VNC/串口可用（--rescue-confirmed 已声明）。"
            if options.rescue_confirmed else
            "# 前置未满足：先在云控制台演练 VNC/串口登录，然后加 --rescue-confirmed 重跑。")),
          "sudo reboot",
          "# 等待重启完成，从客户端重新连接（务必用公钥、新端口）：",
          "ssh -o PreferredAuthentications=publickey -p " + str(port) + " " + user + "@" + host,
          "# 冷启动后分别验证允许/拒绝来源的新连接，期间未改运行规则后，重跑并手动加 --reboot-confirmed：",
          "sudo bash " + shlex.quote(entry_dir() + "/" + SCRIPT) + " --port " + str(port) + " --user " + user
          + "".join(" --allow " + shlex.quote(item) for item in options.allow)
          + ((" --host " + shlex.quote(options.host)) if options.host else "")
          + (" --rescue-confirmed" if options.rescue_confirmed else "")
          + " --backup-dir " + shlex.quote(options.backup_dir)
          + (" --tailnet" if options.tailnet else "")
          + (" --tailnet-session-confirmed" if options.tailnet_session_confirmed else "")],
         ["重跑后本步骤应显示已完成"],
         recovery_commands(restore_path),
         blocked_by=[b for b in (["0-preconditions"] if pre_fail else []) + ([] if confirm_ok else ["3-confirm"])])
    return steps


def loader_facts(system):
    path = "/etc/systemd/system/ssh-allowlist.service"
    try:
        if system.exists(NFTABLES_CONF):
            global_config = system.read(NFTABLES_CONF)
            enabled = system.run_allow_fail("systemctl", "is-enabled", "nftables.service").stdout.strip()
            if enabled not in ("disabled", "masked", "not-found"):
                active_lines = [line.split("#", 1)[0] for line in global_config.splitlines()]
                if any("flush ruleset" in line or ("include" in line and "/etc/nftables.d/" in line)
                       for line in active_lines):
                    return {"status": FAIL, "detail": "另有已启用或状态未知的全局加载器可能清表/重复装载，先人工协调，禁止直接继续"}
        text = system.read(path)
        directory = path + ".d"
        if system.is_dir(directory) and system.list_dir(directory):
            return {"status": FAIL, "detail": "存在未知加载器 drop-in；先人工核对，不得直接 restart"}
        if re.search(r"^\s*Exec(?:StartPre|StartPost|Stop|StopPost)\s*=\s*\S", text, re.M):
            return {"status": FAIL, "detail": "专用加载器不应配置清理规则的 ExecStop"}
        for line in ("ExecStart=/usr/sbin/nft -f /etc/nftables.d/ssh-allowlist.nft",
                     "ExecReload=/usr/sbin/nft -f /etc/nftables.d/ssh-allowlist.nft"):
            if line not in text.splitlines():
                return {"status": UNKNOWN, "detail": "加载器不是已知的专用事务配置，需人工核对实际加载路径"}
        for sub, want in (("is-active", "active"), ("is-enabled", "enabled")):
            if system.run("systemctl", sub, "ssh-allowlist.service").strip() != want:
                return {"status": FAIL, "detail": "专用加载器未 active/enabled"}
        return {"status": PASS, "detail": "专用加载器 active/enabled；仍需核对其它加载器顺序并做冷启动验证"}
    except EvidenceError as exc:
        return {"status": UNKNOWN, "detail": str(exc)}


def resolve_context(system, options):
    ctx = {}
    ctx["connection"] = find_connection(system)
    ctx["auth"] = session_auth(system, ctx["connection"], options.user)
    ctx["listeners"] = ssh_listener_ports(system)
    ctx["bindings"] = sshd_bindings(system)
    ctx["tailnet"] = tailnet_facts(system)
    ctx["account"] = account_facts(system, options.user)
    ctx["backup"] = backup_facts(system, options.backup_dir)
    ctx["match_blocks"] = match_blocks(system)
    valid, error = sshd_valid(system)
    ctx["sshd_valid"] = valid
    ctx["sshd_error"] = error
    try:
        ctx["nft"] = nft_ruleset_summary(system)
    except (EvidenceError, ValueError):
        ctx["nft"] = {"tables": [], "input_policy": [], "rules": []}
    ctx["ufw"] = ufw_status(system)
    ctx["allowlist"] = allowlist_assessment(ctx["nft"], ctx["ufw"], options.port, options.allow, tailnet=options.tailnet)
    ctx["legacy"], ctx["legacy_traces"] = legacy_blocking(system)
    ctx["reboot"] = reboot_facts(system)
    ctx["loader"] = loader_facts(system)
    addr = ctx["connection"]["source"] if ctx["connection"] else (options.allow[0].split("/")[0] if options.allow else "192.0.2.1")
    keep = ("permitrootlogin", "passwordauthentication", "kbdinteractiveauthentication",
            "authenticationmethods", "pubkeyauthentication")
    try:
        ctx["auth_facts"] = sshd_effective(system, "user=%s,host=stage2.invalid,addr=%s" % (options.user, addr), keep)
    except EvidenceError:
        ctx["auth_facts"] = {}
    return ctx


# ---------------------------------------------------------------- 输出

def render_text(ctx, options, steps):
    print("SSH 加固只读指导（stage2-lockdown.sh：nft 白名单 / 禁 root / 禁密码 / 最终确认）")
    print("本脚本只读：不修改任何配置、不代执行命令；下列操作由你（或你监督下的智能体）手工执行。")
    host = options.host or "SERVER"
    allow_text = ", ".join(options.allow)
    if options.tailnet and not options.allow:
        allow_text = "（经 tailnet 接口）"
    print("目标：端口 %d，账户 %s，白名单 %s%s" % (
        options.port, options.user, allow_text,
        ("，客户端别名 " + host) if options.host else ""))
    session = ctx["connection"]
    if session:
        print("当前会话：%s:%d -> %s:%d，认证=%s" % (session["source"], session["source_port"],
              session["local"], session["port"], ctx["auth"] or "未证实"))
    else:
        print("当前会话：未检测到 SSH 连接")
    print("监听：%s" % (ctx["listeners"] or "未采集"))
    print("防火墙：%s" % ("UFW active" if ctx["ufw"].get("active") else ("nft（%d 张表）" % len(ctx["nft"].get("tables", [])))))
    if options.tailnet:
        tailnet = ctx["tailnet"]
        print("tailnet：tailscale0 %s；公网暴露：%s" % (
            tailnet.get("state") or "未发现",
            ", ".join(public_exposure(ctx["bindings"], options.port)) or "无（仅回环/tailnet）"))
    print("\n步骤清单：")
    for item in steps:
        print("  [%s] %s —— %s" % (STATUS_LABEL[item["status"]], item["title"], item["evidence"][:110]))
    current = next((item for item in steps if item["status"] != DONE), None)
    if current is None:
        print("\nstage2 全部达成：加固完成且已通过跨重启复验。")
    else:
        print("\n当前步骤：%s（%s）" % (current["title"], STATUS_LABEL[current["status"]]))
        if current["blocked_by"]:
            print("  门槛未满足：" + "；".join(current["blocked_by"]) + " —— 先完成这些步骤再回来")
        print("  为什么：" + current["why"])
        print("  执行：")
        for line in current["do"]:
            print("    " + line)
        print("  验证：")
        for line in current["verify"]:
            print("    " + line)
        print("  手工撤销（如需）：")
        for line in current["undo"]:
            print("    " + line)
    if not ctx["sshd_valid"]:
        print("\n[阻断] sshd -t 失败：" + (ctx["sshd_error"] or ""))
    if ctx["match_blocks"]:
        print("[注意] Match 块风险：" + "; ".join(ctx["match_blocks"][:6]))
    if ctx.get("legacy_traces"):
        print("[信息] 旧版体系痕迹：" + "；".join(ctx["legacy_traces"][:8]))
    if ctx["legacy"]:
        print("[阻断] 旧版残留：" + "；".join(ctx["legacy"]))
    print("\n常备纪律：")
    print("- 每一步只做一件事，做完重跑本脚本核对，不跳步。")
    print("- 保持当前会话不关；任何放行/阻断要在云安全组与本地防火墙两处一致。")
    print("- Tailscale SSH 由 tailscaled 终结，不经过 sshd：可作救援/管理通道，但不能作为 sshd 加固通过的证据。")
    print("- 443/tcp、3478/udp 等 DERP/STUN 端口属于独立规则域，不要套用 SSH 白名单；DERP 也不能充当 SSH 救援通道。")
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
        "goals": {"port": options.port, "user": options.user, "allow": options.allow,
                  "host": options.host, "tailnet": options.tailnet},
        "rescue_confirmed": options.rescue_confirmed,
        "session": ctx["connection"], "session_auth": ctx["auth"],
        "tailnet": ctx["tailnet"], "bindings": ctx["bindings"],
        "listeners": ctx["listeners"], "allowlist": ctx["allowlist"],
        "auth_facts": ctx["auth_facts"], "reboot": ctx["reboot"],
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
REINFORCE_STAGE2_PY
