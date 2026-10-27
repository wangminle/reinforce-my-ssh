#!/usr/bin/env bash
# stage0-audit.sh — 独立只读审计；审计实现内嵌，无外部 Python 文件依赖。
# 默认只读；--guide 调用同目录阶段脚本执行，权限/新会话/重启边界明确提示。
set -euo pipefail
REINFORCE_SSH_ENTRY=$(cd -- "$(dirname -- "$0")" && pwd)/${0##*/}
export REINFORCE_SSH_ENTRY
exec python3 - "$@" <<'REINFORCE_SSH_AUDIT_PY'
#!/usr/bin/env python3
"""默认只读 SSH 现状审计；显式 --guide 按状态调用阶段脚本并提供续跑指引。"""
import argparse
from dataclasses import asdict, dataclass, field
import glob
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

STATE_ROOT = "/var/lib/reinforce-my-ssh"
MANAGED = (
    "/etc/ssh/sshd_config.d/00-reinforce-my-ssh.conf",
    "/etc/nftables.d/reinforce-my-ssh.nft",
    "/usr/local/sbin/reinforce-my-ssh-firewall",
    "/etc/systemd/system/reinforce-my-ssh-firewall.service",
    "/etc/systemd/system/ssh.socket.d/00-reinforce-my-ssh.conf",
)
PASS, FAIL, UNKNOWN = "pass", "fail", "unknown"
LABELS = {PASS: "通过", FAIL: "不符合", UNKNOWN: "证据不足"}


class EvidenceError(Exception):
    pass


@dataclass
class Check:
    name: str
    result: str
    detail: str


@dataclass
class Policy:
    port: int
    user: str
    allows: list
    closed_ports: list = field(default_factory=list)
    sources: list = field(default_factory=list)
    firewall_units: list = field(default_factory=list)
    sshd_config: str = "/etc/ssh/sshd_config"
    nft_table: str = "sshguard"
    mode: str = "policy"


def combine(checks):
    if any(item.result == FAIL for item in checks):
        return FAIL
    return UNKNOWN if any(item.result == UNKNOWN for item in checks) else PASS


class System:
    """所有外部命令都为固定的读取操作，不使用 shell、eval 或提权命令。"""
    def run(self, *args):
        permitted = (
            args[0] in {"sshd", "ss", "id", "journalctl"}
            or args == ("ip", "-j", "address", "show")
            or args[:2] == ("systemctl", "show")
            or args[:2] == ("systemctl", "is-enabled")
            or args == ("ufw", "status", "verbose")
            or args == ("nft", "-j", "-s", "list", "ruleset")
            or (args[:6] == ("nft", "-s", "-y", "list", "table", "inet") and len(args) == 7)
            or args[:4] == ("systemd-analyze", "--man=no", "--generators=no", "verify")
        )
        if not permitted:
            raise EvidenceError("拒绝非只读命令")
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=20, encoding="utf-8", errors="replace")
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise EvidenceError(f"{args[0]} 无法采集：{exc}") from exc
        if result.returncode and not (args[:2] == ("systemctl", "is-enabled") and result.stdout.strip() in {"disabled", "masked", "enabled-runtime", "static", "indirect", "generated", "not-found"}):
            detail = (result.stderr or result.stdout).strip()[:600]
            raise EvidenceError(f"{' '.join(args)}：{detail or '命令失败'}")
        if len(result.stdout) > 8 * 1024 * 1024:
            raise EvidenceError("输出超过审计上限，无法完整核验")
        return result.stdout

    def read(self, path):
        try:
            return Path(path).read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise EvidenceError(f"{path} 不可读：{exc}") from exc

    def exists(self, path):
        try:
            return Path(path).stat() is not None
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise EvidenceError(f"无法判断 {path} 是否存在") from exc

    def expand(self, pattern):
        return sorted(glob.glob(pattern))

    def mtime(self, path):
        try:
            return Path(path).stat().st_mtime
        except OSError as exc:
            raise EvidenceError(f"无法读取 {path} 时间") from exc

    def process_start(self, pid):
        text = self.read(f"/proc/{pid}/stat")
        ticks = int(text.rsplit(")", 1)[1].split()[19])
        boot = int(re.search(r"^btime (\d+)$", self.read("/proc/stat"), re.M)[1])
        return boot + ticks / os.sysconf("SC_CLK_TCK")


def parse_kv(text):
    result = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key in result:
            raise EvidenceError("记录格式错误或键重复")
        result[key] = value
    return result


def scan_config(system, main):
    files, directives, uncertain = [], [], []
    active = set()

    def visit(path, depth=0):
        if depth > 16 or path in active:
            raise EvidenceError("Include 递归过深或成环")
        active.add(path)
        files.append(path)
        for number, line in enumerate(system.read(path).splitlines(), 1):
            # sshd 也接受 keyword=value，无法解释的语法保留为未知。
            lexer = shlex.shlex(line, posix=True)
            lexer.whitespace_split = True
            lexer.commenters = "#"
            try:
                words = list(lexer)
            except ValueError as exc:
                raise EvidenceError(f"{path}:{number} 无法解析") from exc
            if not words:
                continue
            if "=" in words[0]:
                key, value = words[0].split("=", 1)
                words = [key, value, *words[1:]]
            key = words[0].lower()
            if len(words) < 2:
                raise EvidenceError(f"{path}:{number} 缺少指令参数")
            if key == "include":
                for pattern in words[1:]:
                    if not pattern.startswith("/"):
                        pattern = "/etc/ssh/" + pattern
                    for child in system.expand(pattern):
                        visit(child, depth + 1)
            elif key == "match":
                uncertain.append(f"{path}:{number} 有 Match，已采集上下文但无法证明全部分支")
            else:
                directives.append((path, number, key))
        active.remove(path)

    visit(main)
    return list(dict.fromkeys(files)), directives, uncertain


def endpoint(text):
    host, port = text.rsplit(":", 1)
    return host.strip("[]"), int(port)


def nft_text(text, table):
    """仅供核对受支持纯加载器的磁盘/内核一致性；不执行磁盘规则。"""
    lines, body = [], False
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not body and line in {f"add table inet {table}", f"delete table inet {table}", f"flush table inet {table}"}:
            continue
        body = True
        line = re.sub(r"\bcounter(?:\s+packets\s+\d+\s+bytes\s+\d+)?\b", "", line)
        lines.append(line)
    tokens = re.findall(r'"(?:\\.|[^"\\])*"|[^\s{};,]+|[{};,]', "\n".join(lines))
    out, i = [], 0
    while i < len(tokens):
        token = tokens[i]
        if token in {"saddr", "daddr"} and i + 1 < len(tokens):
            out.append(token)
            i += 1
            try:
                net = ipaddress.ip_network(tokens[i], strict=False)
                token = str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)
            except ValueError:
                token = tokens[i]
        elif token == "{" and out and out[-1] == "dport" and i + 2 < len(tokens) and tokens[i + 1].isdigit() and tokens[i + 2] == "}":
            token = tokens[i + 1]
            i += 2
        out.append(token)
        i += 1
    return out


def networks(value, version):
    if isinstance(value, dict) and set(value) == {"set"}:
        return [net for item in value["set"] for net in networks(item, version)]
    if isinstance(value, dict) and set(value) == {"prefix"}:
        value = f"{value['prefix']['addr']}/{value['prefix']['len']}"
    if isinstance(value, dict) and set(value) == {"range"}:
        lo, hi = [ipaddress.ip_address(x) for x in value["range"]]
        if lo.version != version or hi.version != version:
            raise EvidenceError("nft 地址族不匹配")
        return list(ipaddress.summarize_address_range(lo, hi))
    if not isinstance(value, str) or value.startswith("@"):
        raise EvidenceError("不支持的 nft 地址表达式或命名集合")
    net = ipaddress.ip_network(value, strict=False)
    if net.version != version:
        raise EvidenceError("nft 地址族不匹配")
    return [net]


def values(value):
    if isinstance(value, list):
        return value
    return value["set"] if isinstance(value, dict) and set(value) == {"set"} else [value]


def parse_rule(expressions):
    predicates, verdict = [], None
    for item in expressions:
        if set(item) == {"counter"}:
            continue
        if len(item) == 1 and next(iter(item)) in {"accept", "drop", "reject"}:
            if verdict is not None:
                raise EvidenceError("nft 存在多个 verdict")
            verdict = next(iter(item))
            continue
        if verdict is not None or set(item) != {"match"}:
            raise EvidenceError("不支持的 nft 表达式、jump/goto 或额外副作用")
        match = item["match"]
        if set(match) != {"op", "left", "right"} or match["op"] not in {"==", "in"}:
            raise EvidenceError("不支持的 nft 比较操作")
        left, right = match["left"], match["right"]
        if left in ({"payload": {"protocol": "ip", "field": "saddr"}}, {"payload": {"protocol": "ip6", "field": "saddr"}}):
            version = 4 if left["payload"]["protocol"] == "ip" else 6
            predicates.append(("source", networks(right, version)))
        elif left == {"payload": {"protocol": "tcp", "field": "dport"}}:
            ports = values(right)
            if any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
                raise EvidenceError("不支持的 nft 端口集合")
            predicates.append(("port", ports))
        elif left == {"ct": {"key": "state"}}:
            states = values(right)
            if not all(isinstance(state, str) and state in {"new", "established", "related", "invalid", "untracked"} for state in states):
                raise EvidenceError("不支持的 nft ct state")
            predicates.append(("state", states))
        elif left in ({"meta": {"key": "iif"}}, {"meta": {"key": "iifname"}}):
            if right not in {"lo", 1}:
                raise EvidenceError("非回环接口规则需要额外路径证据")
            predicates.append(("loopback", True))
        elif left == {"meta": {"key": "nfproto"}} and right in {"ipv4", "ipv6"}:
            predicates.append(("family", 4 if right == "ipv4" else 6))
        else:
            raise EvidenceError("不支持的 nft 匹配条件")
    if verdict is None:
        raise EvidenceError("无法解释无终止判决的 nft 规则")
    return predicates, verdict


def firewall_policy(data, policy):
    """对受支持的无跳转规则按顺序求值；用全部 CIDR 边界划分来源区间。"""
    objects = data.get("nftables")
    if not isinstance(objects, list):
        raise EvidenceError("nft JSON 缺少完整规则集")
    relevant, foreign = [], []
    table_present = False
    for entry in objects:
        if "table" in entry and entry["table"].get("family") == "inet" and entry["table"].get("name") == policy.nft_table:
            table_present = True
        for kind, obj in entry.items():
            own = obj.get("family") == "inet" and obj.get("table") == policy.nft_table if isinstance(obj, dict) else False
            if kind == "chain" and obj.get("hook") in {"input", "prerouting", "ingress"} and not own:
                foreign.append(obj.get("name", "未知链"))
            if own:
                relevant.append((kind, obj))
    if not table_present:
        # 可能有等价但未被指定的其他防火墙；不能把不存在专用表当作没有防线。
        raise EvidenceError("未发现指定 inet 表；请指定实际表，其他实现尚未核验")
    chains = [obj for kind, obj in relevant if kind == "chain"]
    if len(chains) != 1 or chains[0].get("type") != "filter" or chains[0].get("hook") != "input":
        raise EvidenceError("需要一个可完整解释的 input/filter base chain")
    chain = chains[0]
    if chain.get("policy") not in {"accept", "drop"} or type(chain.get("prio")) is not int:
        raise EvidenceError("nft base chain 属性不完整")
    if any(kind not in {"chain", "rule"} for kind, _ in relevant):
        raise EvidenceError("表包含命名集合、映射或其他未支持对象")
    rules = []
    for kind, obj in relevant:
        if kind == "rule":
            if obj.get("chain") != chain["name"]:
                raise EvidenceError("规则属于其他链")
            rules.append(parse_rule(obj["expr"]))
    allows = [ipaddress.ip_network(item) for item in policy.allows]
    bypass_loopback = False
    for version in (4, 6):
        maximum = 2 ** (32 if version == 4 else 128)
        loop = ipaddress.ip_network("127.0.0.0/8" if version == 4 else "::1/128")
        nets = [n for n in allows if n.version == version] + [loop]
        for predicates, _ in rules:
            nets += [n for key, items in predicates if key == "source" for n in items if n.version == version]
        bounds = {0, maximum}
        for net in nets:
            bounds.update((int(net.network_address), int(net.broadcast_address) + 1))
        bounds = sorted(bounds)
        if len(bounds) > 4096:
            raise EvidenceError("规则分区超过审计上限")
        for start, end in zip(bounds, bounds[1:]):
            address = ipaddress.ip_address(start) if version == 4 else ipaddress.IPv6Address(start)
            if address.is_loopback or address.is_multicast:
                continue
            expected = any(address in net for net in allows)
            verdict = chain["policy"]
            for predicates, action in rules:
                matched = True
                for key, constraint in predicates:
                    if key == "source":
                        matched &= any(address in net for net in constraint)
                    elif key == "port":
                        matched &= policy.port in constraint
                    elif key == "state":
                        matched &= "new" in constraint
                    elif key == "loopback":
                        matched = False  # 外部新连接审计，不把 lo 放行当外部入口。
                    elif key == "family":
                        matched &= constraint == version
                if matched:
                    verdict = action
                    break
            accepted = verdict == "accept"
            if accepted != expected:
                if accepted and foreign:
                    return Check("防火墙新连接策略", UNKNOWN, "专用链额外放行，但其他前置/input 链可能继续拒绝；需整体解释，不能直接判定最终可达")
                return Check("防火墙新连接策略", FAIL, f"{address} → TCP/{policy.port} 判决 {verdict}，期望 {'accept' if expected else 'deny'}")
    # 旧模板只按回环源地址放行，保留为单独的无法证明事项。
    for predicates, action in rules:
        if action == "accept" and not any(key == "loopback" for key, _ in predicates):
            for key, items in predicates:
                if key == "source" and any(net.is_loopback for net in items):
                    bypass_loopback = True
    if foreign or bypass_loopback:
        detail = "专用链新连接策略匹配；"
        detail += "其他 input/prerouting/ingress 链尚未完整解释：" + ",".join(foreign) if foreign else "回环源地址放行缺少 lo 接口约束，防伪造路径未核验"
        return Check("防火墙新连接策略", UNKNOWN, detail)
    return Check("防火墙新连接策略", PASS, "按规则顺序核对全部来源区间；允许网段可建立新连接，其余来源拒绝；既有连接不视为撤销")


class Auditor:
    def __init__(self, policy, system=None):
        self.policy, self.system = policy, system or System()
        self.checks, self.units = [], {}
        self.files, self.directives = [], []
        self.connection = None
        self.collection_issues = []
        self.report = {"schema": 1, "policy": asdict(policy), "read_only": True, "mode": policy.mode, "observed": {}}

    def add(self, name, result, detail):
        self.checks.append(Check(name, result, detail))

    def collect(self, name, callback):
        try:
            callback()
        except (EvidenceError, ValueError, KeyError, TypeError, IndexError, AttributeError) as exc:
            self.add(name, UNKNOWN, str(exc))
            if name in {"会话采集", "自动识别", "认证采集", "监听采集", "防火墙采集"}:
                self.collection_issues.append(name)

    def unit(self, name):
        if name not in self.units:
            props = ("LoadState", "ActiveState", "Type", "MainPID", "Requires", "BindsTo", "After", "Before", "Listen", "BindIPv6Only", "ExecStart", "ExecStartPre", "ExecStartPost", "ExecCondition", "FragmentPath", "DropInPaths", "NeedDaemonReload")
            args = ["systemctl", "show", name]
            for prop in props:
                args.extend(("-p", prop))
            text = self.system.run(*args)
            # Listen 可重复，不把 systemctl 的正常重复属性当损坏状态。
            data = {}
            for line in text.splitlines():
                key, sep, value = line.partition("=")
                if sep:
                    data[key] = (data.get(key, "") + "\n" + value).strip() if key == "Listen" else value
            if not data or "LoadState" not in data:
                raise EvidenceError(f"{name} 有效属性不完整")
            self.units[name] = data
        return self.units[name]

    def ownership(self):
        state_path = STATE_ROOT + "/state.conf"
        if self.system.exists(state_path) or self.system.exists(STATE_ROOT + "/policy.conf"):
            state = parse_kv(self.system.read(state_path))
            self.report["ownership"] = {"kind": "managed-record", "detail": "发现新版记录，真实性/一致性另行核验", "stage": state.get("STAGE", "未知")}
        else:
            old = any(self.system.exists(path) for path in (
                "/etc/systemd/system/ssh-firewall.service", "/etc/systemd/system/ssh.socket.d/override.conf",
                "/etc/ssh/sshd_config.d/99-hardening.conf"))
            self.report["ownership"] = {"kind": "legacy" if old else "unmanaged", "detail": "发现旧方案痕迹，未被新版接管" if old else "无新版管理记录，配置归属未确认"}

    def find_connection(self):
        value = os.environ.get("SSH_CONNECTION")
        pid, seen = os.getpid(), set()
        while not value and pid > 1 and pid not in seen:
            seen.add(pid)
            try:
                for item in self.system.read(f"/proc/{pid}/environ").split("\0"):
                    if item.startswith("SSH_CONNECTION="):
                        value = item.split("=", 1)[1]
                        break
                pid = int(re.search(r"^PPid:\s+(\d+)", self.system.read(f"/proc/{pid}/status"), re.M)[1])
            except (EvidenceError, TypeError):
                break
        if value:
            client, client_port, local, local_port = value.split()
            ipaddress.ip_address(client)
            ipaddress.ip_address(local)
            if not 1 <= int(client_port) <= 65535 or not 1 <= int(local_port) <= 65535:
                raise EvidenceError("当前 SSH_CONNECTION 端口无效")
            self.connection = (client, int(client_port), local, int(local_port))
            self.report["observed"]["connection"] = {"source": client, "source_port": int(client_port), "local": local, "port": int(local_port)}

    def resolve_target(self):
        origins = {"user": "explicit" if self.policy.user else "unknown", "port": "explicit" if self.policy.port else "unknown"}
        if not self.policy.user:
            for variable in ("SUDO_USER", "USER"):
                candidate = os.environ.get(variable, "")
                if re.fullmatch(r"[a-z_][a-z0-9_-]*\$?", candidate):
                    self.policy.user = candidate
                    origins["user"] = variable
                    break
        if self.policy.port is None and self.connection:
            self.policy.port = self.connection[3]
            origins["port"] = "SSH_CONNECTION"
        if self.policy.port is None:
            candidates = set()
            try:
                for line in self.unit("ssh.socket").get("Listen", "").splitlines():
                    if line.endswith(" (Stream)"):
                        candidates.add(endpoint(line.rsplit(" (Stream)", 1)[0])[1])
            except EvidenceError as exc:
                self.report["observed"]["discovery_note"] = str(exc)
            try:
                # 配套服务可能不是 socket 激活；只采集有明确 sshd 归属的监听。
                for line in self.system.run("ss", "-tlnpH").splitlines():
                    words = line.split()
                    if len(words) >= 5 and re.search(r'"sshd(?:-session)?"', line):
                        candidates.add(endpoint(words[3])[1])
            except EvidenceError as exc:
                self.report["observed"]["discovery_note"] = str(exc)
            candidates = {port for port in candidates if 1 <= port <= 65535}
            self.report["observed"]["port_candidates"] = sorted(candidates)
            if len(candidates) == 1:
                self.policy.port = next(iter(candidates))
                origins["port"] = "unique-live-listener"
        self.report["target_origin"] = origins
        self.report["policy"] = asdict(self.policy)
        if not self.policy.user or self.policy.port is None:
            self.add("检查对象识别", UNKNOWN, "无法唯一识别普通管理账户/SSH 端口；其余可采集项继续，必要时补 --user 或 --port")
        if self.policy.port in self.policy.closed_ports:
            self.add("检查目标冲突", FAIL, "当前识别的目标端口同时声明为关闭；请核对 --closed-port")

    def authentication(self):
        if not self.policy.user or self.policy.port is None:
            raise EvidenceError("认证上下文需要明确的账户和端口，当前无法自动识别")
        uid = self.system.run("id", "-u", self.policy.user).strip()
        if not uid.isdigit():
            raise EvidenceError("无法读取账户 UID")
        if self.policy.user == "root" or int(uid) == 0:
            self.add("管理账户", FAIL, "目标账户必须是非 root、非 UID 0 账户")
        self.files, self.directives, uncertain = scan_config(self.system, self.policy.sshd_config)
        self.system.run("sshd", "-t", "-f", self.policy.sshd_config)
        sources = list(self.policy.sources)
        if self.connection:
            sources.append(self.connection[0])
        sources = list(dict.fromkeys(sources or ["127.0.0.1", "::1"]))
        for user in dict.fromkeys((self.policy.user, "root")):
            for source in sources:
                family = ipaddress.ip_address(source).version
                local = self.connection[2] if self.connection and ipaddress.ip_address(self.connection[2]).version == family else ("127.0.0.1" if family == 4 else "::1")
                context = f"user={user},host=audit.invalid,addr={source},laddr={local},lport={self.policy.port}"
                output = self.system.run("sshd", "-T", "-f", self.policy.sshd_config, "-C", context)
                options = {}
                for line in output.splitlines():
                    key, sep, value = line.partition(" ")
                    if sep:
                        options[key] = value.strip()
                shown = ("permitrootlogin", "passwordauthentication", "kbdinteractiveauthentication", "pubkeyauthentication", "authenticationmethods", "hostbasedauthentication", "gssapiauthentication")
                self.report["observed"].setdefault("authentication", []).append({"user": user, "source": source, "values": {key: options[key] for key in shown if key in options}})
                expected = {"permitrootlogin": "no", "passwordauthentication": "no", "kbdinteractiveauthentication": "no", "pubkeyauthentication": "yes"}
                missing = [key for key in expected if key not in options]
                wrong = [f"{key}={options[key]}" for key, value in expected.items() if key in options and options[key] != value]
                method = options.get("authenticationmethods")
                if method == "any":
                    alternatives = ("hostbasedauthentication", "gssapiauthentication", "permitemptypasswords")
                    missing += [key for key in alternatives if key not in options]
                    wrong += [f"{key}={options[key]}" for key in alternatives if key in options and options[key] != "no"]
                elif not method or not method.strip():
                    missing.append("authenticationmethods")
                elif not all(all(part == "publickey" for part in path.split(",")) for path in method.split()):
                    wrong.append("authenticationmethods=" + method)
                name = f"磁盘认证配置 {user}@{source}"
                result = UNKNOWN if uncertain else FAIL if wrong else UNKNOWN if missing else PASS
                self.add(name, result, "; ".join(wrong + ["缺少 " + key for key in missing]) or "禁 root/密码/键盘交互，只允许公钥；按 sshd 实际解析，文件名不参与判定")
        self.add("认证上下文覆盖", UNKNOWN if uncertain else PASS, "; ".join(uncertain) if uncertain else "未发现活动 Match；Include 已遍历；sshd -t 通过")

    def listeners(self):
        output = self.system.run("ss", "-tlnpH")
        found, extras = [], []
        self.report["observed"]["ssh_listeners"] = []
        for line in output.splitlines():
            words = line.split()
            if len(words) < 5:
                raise EvidenceError("无法完整解析 ss 监听输出")
            host, port = endpoint(words[3])
            if re.search(r'"sshd(?:-session)?"', line) or port == self.policy.port and '"systemd"' in line:
                self.report["observed"]["ssh_listeners"].append(words[3])
            if port in self.policy.closed_ports:
                self.add(f"禁止端口 {port}", FAIL, f"仍有监听 {words[3]}")
            if port == self.policy.port:
                found.append((host, line))
            elif re.search(r'"sshd(?:-session)?"', line):
                extras.append(words[3])
        if self.policy.port is None:
            raise EvidenceError("已采集实际 SSH 监听；多端口或无唯一入口，未任意选择一个作为目标")
        if not found:
            self.add("目标端口监听", FAIL, f"TCP/{self.policy.port} 没有监听")
        elif not all(re.search(r'"(?:sshd(?:-session)?|systemd)"', line) for _, line in found):
            self.add("目标端口监听", UNKNOWN, "监听存在，但无法确认全部监听者属于 SSH")
        else:
            self.add("目标端口监听", PASS, "实际监听：" + ", ".join(host for host, _ in found) + "；未要求固定两条 socket")
        for port in self.policy.closed_ports:
            if not any(item.name == f"禁止端口 {port}" for item in self.checks):
                self.add(f"禁止端口 {port}", PASS, "无 TCP 监听")
        if extras:
            self.add("其他 SSH 端口", FAIL if self.policy.mode == "policy" else PASS,
                     ", ".join(extras) + ("；现状模式只展示，未声明这些端口必须关闭" if self.policy.mode == "inspect" else ""))
        socket = self.unit("ssh.socket")
        ports = {endpoint(line.rsplit(" (Stream)", 1)[0])[1] for line in socket.get("Listen", "").splitlines() if line.endswith(" (Stream)")}
        if ports - {self.policy.port}:
            self.add("SSH socket 端口", FAIL if self.policy.mode == "policy" else PASS, f"有效 socket 端口：{sorted(ports)}")
        families, dual_unknown = set(), False
        for version in (4, 6):
            family_output = self.system.run("ss", f"-{version}", "-tlnpeH")
            for line in family_output.splitlines():
                words = line.split()
                if len(words) < 5:
                    raise EvidenceError("无法解析地址族监听")
                host, port = endpoint(words[3])
                if port == self.policy.port and (host == "*" or not ipaddress.ip_address(host).is_loopback):
                    families.add(version)
                    if version == 6 and host in {"::", "*"}:
                        option = re.search(r"\bv6only:([01])\b", line)
                        if option and option[1] == "0":
                            families.add(4)
                        elif not option:
                            dual_unknown = True
        required = {ipaddress.ip_network(item).version for item in self.policy.allows}
        missing = required - families
        result = UNKNOWN if missing == {4} and dual_unknown else FAIL if missing else PASS
        self.add("来源地址族监听", result,
                 (f"策略需要 IPv{sorted(required)}，" if required else "未声明来源地址族目标，") + f"内核证据覆盖 IPv{sorted(families)}；用 ss 的 v6only 标记核对双栈，不由当前 sysctl 推断已创建 socket")

    def firewall(self):
        data = json.loads(self.system.run("nft", "-j", "-s", "list", "ruleset"))
        if self.policy.mode == "policy":
            if self.policy.port is None:
                raise EvidenceError("白名单比较需要明确目标端口")
            self.checks.append(firewall_policy(data, self.policy))
            return
        objects = data.get("nftables")
        if not isinstance(objects, list):
            raise EvidenceError("nft JSON 不完整")
        tables = [f"{item['table'].get('family')} {item['table'].get('name')}" for item in objects if isinstance(item.get("table"), dict)]
        chains = [item["chain"] for item in objects if isinstance(item.get("chain"), dict) and item["chain"].get("hook") == "input"]
        sources, rule_count, unsupported = set(), 0, 0
        for item in objects:
            obj = item.get("rule")
            if not isinstance(obj, dict) or obj.get("table") != self.policy.nft_table or obj.get("family") != "inet":
                continue
            rule_count += 1
            try:
                predicates, verdict = parse_rule(obj["expr"])
                if verdict == "accept":
                    sources.update(str(net) for key, nets in predicates if key == "source" for net in nets)
            except (EvidenceError, ValueError, TypeError, KeyError):
                unsupported += 1
        self.report["observed"]["firewall"] = {"tables": tables, "input_chains": [{key: chain.get(key) for key in ("family", "table", "name", "prio", "policy")} for chain in chains],
                                                "selected_table_rule_count": rule_count, "accept_source_literals": sorted(sources), "unparsed_rules": unsupported}
        self.add("防火墙现状采集", PASS, f"读取到 {len(tables)} 张 nft 表、{len(chains)} 个 input 链；未指定 --allow，仅展示现状，不判定来源白名单合规")

    def persistence(self):
        socket = self.unit("ssh.socket")
        if socket.get("LoadState") != "loaded" or socket.get("ActiveState") != "active":
            raise EvidenceError("当前审计支持 ssh.socket 激活布局；未发现活跃 socket")
        if self.system.run("systemctl", "is-enabled", "ssh.socket").strip() != "enabled":
            self.add("SSH 持久自启", FAIL, "socket 未持久 enabled")
        else:
            self.add("SSH 持久自启", PASS, "ssh.socket 持久 enabled")
        names = self.policy.firewall_units or ["reinforce-my-ssh-firewall.service", "ssh-firewall.service"]
        loaded = [name for name in names if self.unit(name).get("LoadState") == "loaded"]
        if len(loaded) > 1:
            persistent = [name for name in loaded if self.system.run("systemctl", "is-enabled", name).strip() != "disabled"]
            if persistent:
                loaded = persistent
        self.report["firewall_units"] = loaded
        if len(loaded) != 1:
            raise EvidenceError("需要明确唯一防火墙加载单元；未发现或存在多个加载者")
        name = loaded[0]
        unit = self.unit(name)
        if unit.get("ActiveState") != "active" or self.system.run("systemctl", "is-enabled", name).strip() != "enabled":
            self.add("防火墙持久自启", FAIL, f"{name} 未同时 active、持久 enabled")
        else:
            self.add("防火墙持久自启", PASS, name)
        required = set((socket.get("Requires", "") + " " + socket.get("BindsTo", "")).split())
        ordered = name in socket.get("After", "").split() or "ssh.socket" in unit.get("Before", "").split()
        if name not in required or not ordered:
            self.add("防火墙先于 SSH", UNKNOWN, "未证实直接需求及先后依赖；传递依赖或其他启动机制需另行核验")
        else:
            self.add("防火墙先于 SSH", PASS, "有效依赖包含加载需求及先后顺序")
        if any(self.unit(item).get("NeedDaemonReload") == "yes" for item in ("ssh.socket", name)):
            self.add("单元磁盘一致性", UNKNOWN, "systemd 提示 NeedDaemonReload，磁盘与有效配置可能不同")
        try:
            self.system.run("systemd-analyze", "--man=no", "--generators=no", "verify", "ssh.socket", name)
            self.add("启动图验证", PASS, "systemd-analyze verify 通过；未执行启动或重启")
        except EvidenceError as exc:
            self.add("启动图验证", FAIL if re.search(r"ordering cycle|cyclic", str(exc), re.I) else UNKNOWN, str(exc))
        self.collect("持久规则加载", lambda: self.loader(unit))

    def firewall_managers(self):
        managers = []
        for name in ("ufw.service", "firewalld.service", "nftables.service"):
            try:
                unit = self.unit(name)
                if unit.get("LoadState") == "loaded":
                    managers.append({"unit": name, "active": unit.get("ActiveState", "unknown"),
                                     "enabled": self.system.run("systemctl", "is-enabled", name).strip()})
            except (EvidenceError, KeyError) as exc:
                managers.append({"unit": name, "evidence": str(exc)})
        self.report["observed"]["firewall_managers"] = managers
        if any(item.get("unit") == "ufw.service" and item.get("active") == "active" for item in managers):
            try:
                self.report["observed"]["ufw_status"] = self.system.run("ufw", "status", "verbose")
            except EvidenceError as exc:
                self.report["observed"]["ufw_status"] = str(exc)

    def loader(self, unit):
        if unit.get("Type") != "oneshot" or any(unit.get(key, "") for key in ("ExecStartPre", "ExecStartPost", "ExecCondition")):
            raise EvidenceError("加载单元不是可证明完成的纯 oneshot，或包含额外前后置命令")
        if "ignore_errors=no" not in unit.get("ExecStart", ""):
            raise EvidenceError("无法证明加载失败会阻止单元启动")
        starts = re.findall(r"argv\[\]=([^;]+);", unit.get("ExecStart", ""))
        if len(starts) != 1:
            raise EvidenceError("无法完整解释防火墙 ExecStart")
        args = shlex.split(starts[0])
        if len(args) == 1 and args[0].startswith("/"):
            code = self.system.read(args[0])
            commands = [line.strip() for line in code.splitlines() if line.strip() and not line.lstrip().startswith("#")]
            if len(commands) != 1:
                raise EvidenceError("加载器含循环、清表或其他命令，未证明其重放语义；需人工复核")
            args = shlex.split(commands[0])
            if args and args[0] == "exec":
                args = args[1:]
        if len(args) != 3 or args[0] not in {"/usr/sbin/nft", "/sbin/nft"} or args[1] not in {"-f", "--file"} or not args[2].startswith("/"):
            raise EvidenceError("仅自动证明直接 nft -f 或单条 exec nft -f 的纯加载器")
        disk = self.system.read(args[2])
        created = False
        for raw in disk.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line == f"add table inet {self.policy.nft_table}":
                created = True
            elif line in {f"flush table inet {self.policy.nft_table}", f"delete table inet {self.policy.nft_table}"}:
                if not created:
                    raise EvidenceError("加载文件先 flush/delete 未保证存在的表，无法证明首次开机可加载")
            else:
                break
        runtime = self.system.run("nft", "-s", "-y", "list", "table", "inet", self.policy.nft_table)
        if nft_text(disk, self.policy.nft_table) != nft_text(runtime, self.policy.nft_table):
            self.add("持久规则与内核", UNKNOWN, "加载文件与已采集内核不一致或超出支持语法；不执行文件来推测结果")
        else:
            self.add("持久规则与内核", PASS, "纯加载器引用文件与当前表一致；支持旧/新文件名，不执行加载")

    def runtime_config(self):
        unit = self.unit("ssh.service")
        pid = int(unit.get("MainPID", "0"))
        if pid <= 1 or not self.files:
            raise EvidenceError("无法关联存活 sshd 主进程和已解析配置")
        command = self.system.read(f"/proc/{pid}/cmdline").replace("\0", " ")
        environment = self.system.read(f"/proc/{pid}/environ").split("\0")
        opts = next((item.partition("=")[2] for item in environment if item.startswith("SSHD_OPTS=")), "")
        if opts.strip() or re.search(r"(?:^|\s)-(?:f|o)\S*", command) or self.policy.sshd_config != "/etc/ssh/sshd_config":
            raise EvidenceError("存在启动参数覆盖或非默认配置入口，未证明它与本次磁盘解析一致")
        if "sshd" not in command:
            raise EvidenceError("MainPID 不是可识别的 sshd")
        started = self.system.process_start(pid)
        changed = [path for path in self.files if self.system.mtime(path) > started]
        if changed:
            raise EvidenceError("配置晚于主进程启动；缺少可靠的重载证据：" + ", ".join(changed))
        self.add("主进程与配置", PASS, "默认入口、无已知参数覆盖；配置未晚于存活主进程启动，未用磁盘解析替代进程检查")

    def session(self):
        if not self.connection:
            raise EvidenceError("没有当前 SSH 会话；无法证明公钥登录与真实 sudo")
        client, cp, local, sp = self.connection
        if sp != self.policy.port or ipaddress.ip_address(client).is_loopback:
            raise EvidenceError("当前连接不是目标端口的外部会话")
        links = json.loads(self.system.run("ip", "-j", "address", "show"))
        locals_ = {ipaddress.ip_address(item["local"]) for link in links for item in link.get("addr_info", [])}
        if ipaddress.ip_address(client) in locals_ or self.policy.mode == "policy" and not any(ipaddress.ip_address(client) in ipaddress.ip_network(net) for net in self.policy.allows):
            raise EvidenceError("当前来源是本机自连或不在目标白名单，不能证明目标外部通道")
        root_session = self.policy.user == "root" and not os.environ.get("SUDO_USER") and os.geteuid() == 0
        if not root_session and os.environ.get("SUDO_USER") != self.policy.user:
            raise EvidenceError("请由目标用户在其 SSH 会话中直接 sudo 执行")
        uid = self.system.run("id", "-u", self.policy.user).strip()
        if not root_session and os.environ.get("SUDO_UID") != uid:
            raise EvidenceError("sudo UID 不匹配")
        pid, ancestors = os.getpid(), set()
        while pid > 1 and str(pid) not in ancestors:
            ancestors.add(str(pid))
            pid = int(re.search(r"^PPid:\s+(\d+)", self.system.read(f"/proc/{pid}/status"), re.M)[1])
        live = set()
        for line in self.system.run("ss", "-tnpH", "state", "established", f"( sport = :{sp} )").splitlines():
            words = line.split()
            if len(words) >= 5 and endpoint(words[2]) == (local, sp) and endpoint(words[3]) == (client, cp):
                live.update(re.findall(r'"sshd(?:-session|-auth)?",pid=(\d+)', line))
        candidates = live & ancestors
        if not candidates:
            raise EvidenceError("存活连接不属于当前 sudo 的 sshd 进程链")
        since = min(self.system.process_start(int(item)) for item in candidates)
        boot = self.system.read("/proc/sys/kernel/random/boot_id").strip().replace("-", "")
        logs = self.system.run("journalctl", "-b", "-u", "ssh", "-u", "sshd", "-u", "ssh@*", "--since", f"@{since:.6f}", "--no-pager", "-o", "json")
        pattern = re.compile(r"^Accepted (\S+) for (\S+) from (\S+) port (\d+)(?:\s|$)")
        for line in logs.splitlines():
            event = json.loads(line)
            if event.get("_BOOT_ID") != boot or str(event.get("_PID")) not in ancestors:
                continue
            message = event.get("MESSAGE")
            match = pattern.search(message) if isinstance(message, str) else None
            if match and match[2] == self.policy.user and ipaddress.ip_address(match[3]) == ipaddress.ip_address(client) and int(match[4]) == cp:
                self.report["observed"]["login_method"] = match[1]
                self.add("当前认证与 sudo", PASS if match[1] == "publickey" else FAIL,
                         f"当前会话认证方式={match[1]}；同 boot 日志、存活四元组和进程链匹配；" + ("root 直接执行，未使用 sudo" if root_session else "sudo UID 匹配") + "；基线要求公钥")
                return
        raise EvidenceError("没有与当前连接进程链匹配的认证成功日志；不把其他 established 连接当作已登录证据")

    def migration(self):
        changes, blockers = [], []
        controlled = {"port", "listenaddress", "permitrootlogin", "passwordauthentication", "kbdinteractiveauthentication", "pubkeyauthentication", "authenticationmethods"}
        changes += [f"{path}:{number} {key} 将由 stage1 备份迁移" for path, number, key in self.directives if key in controlled and path != MANAGED[0]]
        blockers += [f"{path}:{number} 活动 Match 暂不支持自动迁移" for path, number, key in self.directives if key == "match"]
        for path in ("/etc/systemd/system/ssh.socket.d/override.conf", "/etc/systemd/system/ssh-firewall.service"):
            if self.system.exists(path):
                changes.append(path + " 纳入 stage1 迁移与回滚")
        self.report["migration"] = {"status": "blocked" if blockers else "migration-planned" if changes else "new-deployment" if self.report.get("ownership", {}).get("kind") != "managed-record" else "managed",
                                    "blockers": blockers, "changes": changes,
                                    "detail": "无新版状态是首次部署正常起点；具体变更和备份由 stage1 预检生成，本报告不推进阶段"}

    def reboot(self):
        self.report["reboot"] = {"status": UNKNOWN, "detail": "未取得可独立关联配置与跨启动的验证记录；自启检查不等于真实重启验证"}
        path = STATE_ROOT + "/state.conf"
        if not self.system.exists(path):
            return
        state = parse_kv(self.system.read(path))
        if state.get("STAGE") != "verified":
            self.report["reboot"]["detail"] = "新版当前未登记 verified；不否定旧方案曾完成重启"
            return
        digest = hashlib.sha256()
        digest.update(b"POLICY\n" + self.system.read(STATE_ROOT + "/policy.conf").encode())
        files = list(MANAGED)
        migration = STATE_ROOT + "/migration.json"
        if self.system.exists(migration):
            plan = json.loads(self.system.read(migration))
            paths = [item["path"] for item in plan["files"]]
            if plan.get("schema") != 1 or len(paths) != len(set(paths)) or any(os.path.normpath(path) != path or not path.startswith(("/etc/ssh/", "/etc/systemd/system/ssh.socket.d/", "/etc/ufw/")) and path not in {"/etc/default/ufw", "/etc/systemd/system/ssh.socket"} for path in paths):
                raise EvidenceError("迁移路径记录无效")
            files += sorted(paths) + [migration]
        for file in files:
            digest.update(f"FILE {file}\n".encode() + self.system.read(file).encode())
        boot = self.system.read("/proc/sys/kernel/random/boot_id").strip()
        if state.get("CONFIG_SHA") != digest.hexdigest() or state.get("VERIFIED_BOOT") != boot or state.get("PENDING_BOOT") == boot:
            self.report["reboot"]["detail"] = "新版记录与当前 boot/配置不一致，历史 verified 不能复用"
            return
        for key, kind, expected_boot in (("PRE_BASELINE", "pre", state.get("PENDING_BOOT")), ("POST_BASELINE", "post", boot)):
            baseline = state.get(key, "")
            if not baseline.startswith(STATE_ROOT + "/baselines/") or "/../" in baseline:
                raise EvidenceError("基线引用不在受管目录")
            meta = parse_kv(self.system.read(baseline + "/META"))
            expected = {"KIND": kind, "BOOT_ID": expected_boot, "CONFIG_SHA": state.get("CONFIG_SHA"), "TX": state.get("TX"), "RESULT": "complete"}
            if any(meta.get(k) != v or not v for k, v in expected.items()):
                raise EvidenceError("基线元数据与 verified 不一致")
        self.report["reboot"] = {"status": "managed-record-consistent", "detail": "新版 pre/post 记录与当前 boot/配置一致；属于本机记录核对，本次未执行重启"}

    def audit(self):
        self.collect("会话采集", self.find_connection)
        self.collect("自动识别", self.resolve_target)
        self.collect("防火墙管理器", self.firewall_managers)
        try:
            self.ownership()
        except (EvidenceError, ValueError, KeyError, TypeError) as exc:
            self.report["ownership"] = {"kind": "unknown", "detail": str(exc)}
        for name, callback in (("认证采集", self.authentication),
                               ("监听采集", self.listeners), ("防火墙采集", self.firewall),
                               ("启动保护采集", self.persistence), ("主进程采集", self.runtime_config),
                               ("公钥会话采集", self.session)):
            self.collect(name, callback)
        try:
            self.migration()
        except (EvidenceError, ValueError, KeyError, TypeError) as exc:
            self.report["migration"] = {"status": "not-assessed", "blockers": [], "detail": str(exc)}
        # 重启历史独立于当前安全效果，不把缺少新版记录当作不安全。
        try:
            self.reboot()
        except (EvidenceError, ValueError, KeyError, TypeError) as exc:
            self.report["reboot"] = {"status": UNKNOWN, "detail": str(exc)}
        self.report.setdefault("ownership", {"kind": "unknown", "detail": "无法读取完整归属证据"})
        self.report.setdefault("migration", {"status": "not-assessed", "blockers": [], "detail": "证据不足，未评估接管准备"})
        self.report["checks"] = [asdict(item) for item in self.checks]
        self.report["security_result"] = combine(self.checks)
        self.report["baseline_result"] = self.report["security_result"]
        self.report["collection_result"] = UNKNOWN if self.collection_issues or not self.policy.user or self.policy.port is None else PASS
        self.report["collection_issues"] = self.collection_issues
        self.report["policy_result"] = self.report["security_result"] if self.policy.mode == "policy" else UNKNOWN
        self.report["scope"] = ("本机显式策略与当前通道" if self.policy.mode == "policy" else "当前 SSH 现状及禁 root/禁密码/公钥基线；未指定来源策略，白名单合规未评估") + "；不代替云安全组、拒绝来源外测或整机重启验收"
        return self.report


STAGE_SCRIPTS = {1: "stage1-newport.sh", 2: "stage2-harden.sh", 3: "stage3-reboot-check.sh"}


def entry_path():
    return Path(os.environ.get("REINFORCE_SSH_ENTRY", __file__)).resolve()


def setup_values(text):
    """只解析数据，不 source/eval 用户配置；与阶段 KEY=VALUE 契约一致。"""
    if text and (not text.endswith("\n") or "\r" in text):
        raise EvidenceError("配置需要纯 LF 且以换行结束")
    values = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or key not in {"PORT", "OLD_PORT", "USER", "ALLOW", "RECOVERY_SECONDS", "RESCUE_CONFIRMED"}:
            raise EvidenceError("配置行无法解析：" + line)
        if key == "ALLOW":
            values.setdefault(key, []).append(value)
        elif key in values:
            raise EvidenceError("配置键重复：" + key)
        else:
            values[key] = value
    return validate_setup(values)


def validate_setup(values):
    result = dict(values)
    for key in ("PORT", "OLD_PORT"):
        if key in result:
            value = str(result[key])
            if key == "OLD_PORT" and value == "none":
                continue
            if not re.fullmatch(r"[0-9]{1,5}", value) or not 1 <= int(value) <= 65535:
                raise EvidenceError(key + " 需要 1–65535 的端口")
            result[key] = str(int(value))
    if result.get("USER") is not None and (result["USER"] == "root" or not re.fullmatch(r"[a-z_][a-z0-9_-]*\$?", result["USER"])):
        raise EvidenceError("部署目标需要非 root 管理账户；stage0 采集 root 不代表使用 root 部署")
    try:
        if "ALLOW" in result:
            result["ALLOW"] = sorted({str(ipaddress.ip_network(net, strict=True)) for net in result["ALLOW"]})
    except ValueError as exc:
        raise EvidenceError(str(exc)) from exc
    if "RECOVERY_SECONDS" in result:
        value = str(result["RECOVERY_SECONDS"])
        if not value.isdigit() or not 60 <= int(value) <= 86400:
            raise EvidenceError("确认窗口需要 60–86400 秒")
        result["RECOVERY_SECONDS"] = str(int(value))
    if "RESCUE_CONFIRMED" in result and result["RESCUE_CONFIRMED"] not in {"yes", "no"}:
        raise EvidenceError("RESCUE_CONFIRMED 只能为 yes/no，不能用 --yes 代替实际救援演练")
    return result


def guide_goals(options, system):
    values = setup_values(system.read(options.conf)) if options.conf else {}
    for option, key in (("port", "PORT"), ("user", "USER"), ("old_port", "OLD_PORT"), ("recovery_seconds", "RECOVERY_SECONDS")):
        if getattr(options, option) is not None:
            values[key] = str(getattr(options, option))
    if options.allow:
        values["ALLOW"] = list(options.allow)
    return validate_setup(values)


def workflow_plan(system, entry, goals=None, host=None, connection=None, root=None):
    """推导下一步，不执行；每次动作之后重新读取状态，阶段脚本仍是提交权威。"""
    root = hasattr(os, "geteuid") and os.geteuid() == 0 if root is None else root
    entry = Path(entry)
    resume = ["sudo", "bash", str(entry), "--guide"] + (["--host", host] if host else [])
    plan = {"state": "unknown", "can_execute": False, "commands": [shlex.join(resume)], "argv": [], "resume": resume}
    if not root:
        return {**plan, "status": "sudo-required", "detail": "需要完整读取权限；在自己的终端 sudo 继续，无需开放 root SSH 登录"}
    try:
        if system.exists(STATE_ROOT + "/state.conf"):
            state = parse_kv(system.read(STATE_ROOT + "/state.conf"))
            if not {"STAGE", "TX", "CONFIG_SHA"} <= state.keys():
                raise EvidenceError("状态缺少 STAGE/TX/CONFIG_SHA")
        else:
            if any(system.exists(path) for path in MANAGED) or system.exists(STATE_ROOT + "/migration.json"):
                raise EvidenceError("发现受管配置但状态缺失；需要从事务备份恢复，不能伪造阶段")
            state = {"STAGE": "unconfigured", "TX": "", "CONFIG_SHA": ""}
        stage = state["STAGE"]
        if stage not in {"unconfigured", "candidate-pending", "candidate-ready", "hardening-pending", "hardened", "reboot-pending", "verified"}:
            raise EvidenceError("未知阶段：" + stage)
        if stage == "unconfigured":
            if state["TX"] or state["CONFIG_SHA"]:
                raise EvidenceError("unconfigured 含有未结束的事务记录")
            policy = validate_setup(goals or {})
        else:
            if not re.fullmatch(r"[A-Za-z0-9_-]+", state["TX"]):
                raise EvidenceError("事务 ID 无效")
            if stage not in {"candidate-pending", "hardening-pending"} and not re.fullmatch(r"[0-9a-f]{64}", state["CONFIG_SHA"]):
                raise EvidenceError("已提交阶段缺少有效摘要")
            policy = setup_values(system.read(STATE_ROOT + "/policy.conf"))
            if not {"PORT", "OLD_PORT", "USER", "ALLOW", "RECOVERY_SECONDS", "RESCUE_CONFIRMED"} <= policy.keys() or not policy["ALLOW"]:
                raise EvidenceError("权威策略不完整")
            for key, value in (goals or {}).items():
                if key != "RESCUE_CONFIRMED" and key in policy and policy[key] != value:
                    raise EvidenceError("所给目标与已存策略冲突：" + key + "；省略该参数可沿用当前策略")
        plan.update(state=stage, policy=policy)
        if stage == "unconfigured":
            number, action, detail = 1, "apply", "建立候选通道，自动备份迁移现有配置"
        elif stage == "candidate-pending":
            number, action, detail = 1, "confirm", "候选已部署；从部署后的新公钥会话确认"
        elif stage == "candidate-ready":
            number, action, detail = 2, "apply", "候选已确认；收紧 root/密码认证和旧端口"
        elif stage == "hardening-pending":
            number, action, detail = 2, "confirm", "认证已收紧；再次建立全新公钥会话确认"
        elif stage == "hardened":
            number, action, detail = 3, "apply", "记录重启前基线，不修改 SSH 或代为重启"
        else:
            boot = system.read("/proc/sys/kernel/random/boot_id").strip()
            if not re.fullmatch(r"[0-9a-fA-F-]{36}", boot):
                raise EvidenceError("无法读取当前 boot_id")
            if stage == "reboot-pending":
                if not re.fullmatch(r"[0-9a-fA-F-]{36}", state.get("PENDING_BOOT", "")):
                    raise EvidenceError("缺少有效的重启前 boot_id")
                if state["PENDING_BOOT"] == boot:
                    return {**plan, "status": "reboot-required", "detail": "重启前基线已记录；确认救援通道后由管理员重启，重连再继续", "commands": ["sudo reboot", shlex.join(resume)]}
                number, action, detail = 3, "verify", "已跨过重启；执行重启后完整验证"
            elif state.get("VERIFIED_BOOT") == boot:
                number, action, detail = 3, "check", "已有验证记录；复验当前状态后报告完成"
            else:
                number, action, detail = 3, "apply", "verified 属于其他启动；开始新一轮重启验证"
        script = entry.parent / STAGE_SCRIPTS[number]
        argv = ["bash", str(script)]
        if number == 1 and action == "apply":
            for key, flag in (("PORT", "--port"), ("USER", "--user"), ("OLD_PORT", "--old-port"), ("RECOVERY_SECONDS", "--recovery-seconds")):
                if key in policy:
                    argv += [flag, policy[key]]
            for net in policy.get("ALLOW", []):
                argv += ["--allow", net]
        if action != "check":
            argv.append("--" + action)
        plan.update(status="ready", can_execute=True, number=number, action=action, detail=detail, argv=argv,
                    commands=[shlex.join(["sudo", *argv]), shlex.join(resume)])
        if stage == "unconfigured":
            missing = [key for key in ("PORT", "USER", "ALLOW") if not policy.get(key)]
            if missing:
                plan.update(status="parameters-required", can_execute=False, missing=missing,
                            detail="缺少目标 " + ", ".join(missing) + "；运行 --guide 可现场填写，无需手工改现有配置",
                            commands=[shlex.join(resume)])
        if stage in {"candidate-pending", "candidate-ready", "hardening-pending"}:
            destination = policy["USER"] + "@" + (host or "SERVER")
            ssh = ["ssh", "-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "-p", policy["PORT"], destination]
            plan["connect"] = shlex.join(ssh)
            matching = connection and str(connection[3]) == policy["PORT"] and os.environ.get("SUDO_USER") == policy["USER"]
            if not matching:
                plan.update(status="new-session-required", can_execute=False,
                            commands=[plan["connect"], shlex.join(resume)],
                            detail="请在客户端另开公钥连接，保留旧会话；在新会话 sudo 继续。SERVER 需替换为实际地址或用 --host 指定")
        if not script.is_file():
            plan.update(status="scripts-required", can_execute=False, detail="缺少同目录脚本 " + script.name + "；请同步四个 stage 文件")
        if stage != "unconfigured":
            rollback_number = 1 if stage.startswith("candidate") else 2 if stage in {"hardening-pending", "hardened"} else 3
            plan["rollback"] = shlex.join(["sudo", "bash", str(entry.parent / STAGE_SCRIPTS[rollback_number]), "--rollback"])
        return plan
    except (EvidenceError, OSError, ValueError, KeyError, TypeError) as exc:
        return {**plan, "status": "repair-required", "can_execute": False, "detail": str(exc),
                "commands": [shlex.join(["sudo", "bash", str(entry)]), "sudo ls -la " + shlex.quote(STATE_ROOT + "/transactions")]}


def print_workflow(plan):
    print("\n当前进度：" + plan["state"] + "；下一步：" + plan["detail"])
    if plan.get("connect"):
        print("客户端新终端：" + plan["connect"])
        print("新会话继续：" + shlex.join(plan["resume"]))
    for command in plan["commands"]:
        print("  " + command)
    if plan.get("rollback"):
        print("需要撤销本阶段时：" + plan["rollback"])


class GuideTerminal:
    """Python 源码通过 stdin heredoc 加载；交互与阶段子进程使用真正的终端。"""
    def __init__(self):
        self.reader = open("/dev/tty", "rb", buffering=0)
        try:
            self.writer = open("/dev/tty", "wb", buffering=0)
        except OSError:
            self.reader.close()
            raise

    def write(self, value):
        self.writer.write(value.encode("utf-8"))

    def flush(self):
        self.writer.flush()

    def readline(self):
        return self.reader.readline().decode("utf-8", errors="replace")

    def fileno(self):
        return self.reader.fileno()

    def close(self):
        self.reader.close()
        self.writer.close()


class Workflow:
    def __init__(self, options, system, entry, report, terminal=None, runner=None):
        self.options, self.system, self.entry, self.report = options, system, Path(entry), report
        self.terminal, self.runner = terminal, runner

    def ask(self, prompt, default=None):
        if self.terminal is None or self.options.yes:
            raise EvidenceError("需要填写参数；可在交互终端运行 --guide，或显式提供目标参数")
        self.terminal.write(prompt + (" [" + str(default) + "]" if default is not None else "") + "：")
        self.terminal.flush()
        answer = self.terminal.readline()
        if not answer:
            raise EvidenceError("没有收到输入，已停止；未把空输入当作授权")
        return answer.strip() or default

    def execute(self, argv):
        print("执行：" + shlex.join(argv), flush=True)
        if self.runner:
            return self.runner(argv)
        try:
            return subprocess.call(argv, stdin=self.terminal if self.terminal is not None else subprocess.DEVNULL)
        except OSError as exc:
            print("命令无法运行：" + str(exc))
            return 2

    def show(self, plan, goals, connection):
        if plan.get("connect") and not self.options.host and self.terminal is not None and not self.options.yes:
            host = self.ask("客户端使用的服务器地址或 SSH 别名（留空则自行替换 SERVER）", "")
            if host:
                if not re.fullmatch(r"[A-Za-z0-9_.:\[\]-]+", host):
                    raise EvidenceError("连接地址含不支持的字符；请重新运行并用 --host 指定")
                self.options.host = host
                plan = workflow_plan(self.system, self.entry, goals, host, connection, root=True)
        print_workflow(plan)
        return plan

    def run(self, argv):
        root = hasattr(os, "geteuid") and os.geteuid() == 0
        if not root:
            command = ["sudo", "--", "bash", str(self.entry), *argv]
            print("需要管理员权限，请在自己的终端完成 sudo 验证：" + shlex.join(command))
            if self.terminal is None or not shutil.which("sudo"):
                print("请自行执行上述命令，或交给管理员；不需要给通用 bash 配置 NOPASSWD。")
                return 2
            code = self.execute(command)
            if code:
                print("命令未完成；请依据 sudo/阶段输出处理后重试，不启动后续阶段。")
            return code
        if self.terminal is None and not self.options.yes:
            print("当前没有交互终端。请在 SSH 终端运行 sudo bash " + shlex.quote(str(self.entry)) + " --guide；本次未执行配置变更。")
            return 2
        goals = guide_goals(self.options, self.system)
        for _ in range(8):
            observer = Auditor(Policy(None, None, [], mode="inspect"), self.system)
            observer.collect("会话采集", observer.find_connection)
            plan = workflow_plan(self.system, self.entry, goals, self.options.host, observer.connection, root=True)
            if plan["state"] == "unconfigured" and plan["status"] in {"ready", "parameters-required"}:
                if not goals.get("PORT"):
                    goals["PORT"] = self.ask("目标 SSH 端口（可保持当前端口）", self.report.get("policy", {}).get("port"))
                if not goals.get("USER"):
                    default = os.environ.get("SUDO_USER") or self.report.get("policy", {}).get("user")
                    goals["USER"] = self.ask("目标非 root 管理账户", default if default != "root" else None)
                if not goals.get("ALLOW"):
                    source = self.report.get("observed", {}).get("connection", {}).get("source", "未知")
                    print("当前来源 " + source + " 仅供参考，不会自动变成白名单。")
                    goals["ALLOW"] = (self.ask("允许来源 CIDR，多个用空格分开") or "").split()
                goals = validate_setup(goals)
                plan = workflow_plan(self.system, self.entry, goals, self.options.host, observer.connection, root=True)
            plan = self.show(plan, goals, observer.connection)
            if not plan["can_execute"]:
                return 2
            command = list(plan["argv"])
            if plan["action"] == "apply":
                if self.options.yes and plan["state"] == "unconfigured" and goals.get("RESCUE_CONFIRMED") != "yes":
                    raise EvidenceError("首次无人值守执行需在 --conf 中声明已经实际演练的 RESCUE_CONFIRMED=yes；或去掉 --yes 交互运行")
                # 首次部署后权威策略已落盘；原输入可能只是部分配置，不能再传给
                # 要求完整匹配的 stage3，也不能覆盖交互中已确认的救援事实。
                if self.options.conf and plan["state"] == "unconfigured":
                    command += ["--conf", self.options.conf]
                if self.options.yes:
                    command.append("--yes")
            code = self.execute(command)
            if code:
                print("本步未完成，停止推进。按上方阶段输出处理后可重试：" + shlex.join(plan["resume"]))
                # 失败可能发生在写入 pending 后，也可能已自动恢复；以当前状态给恢复命令。
                print_workflow(workflow_plan(self.system, self.entry, goals, self.options.host, observer.connection, root=True))
                if plan.get("connect"):
                    print("若是会话确认问题，请真正重连：" + plan["connect"])
                if plan.get("rollback"):
                    print("需要撤销时：" + plan["rollback"])
                missing = [package for tool, package in (("nft", "nftables"), ("sshd", "openssh-server"), ("ss", "iproute2"), ("ip", "iproute2")) if not shutil.which(tool)]
                if missing:
                    print("依赖缺失时由管理员安装（先核对包变更）：" + shlex.join(["sudo", "apt-get", "install", *sorted(set(missing))]))
                if plan["number"] == 1 and plan.get("policy", {}).get("USER"):
                    user = plan["policy"]["USER"]
                    try:
                        self.system.run("id", "-u", user)
                    except EvidenceError:
                        print("目标账户尚未准备，请由管理员在服务器依次执行：")
                        print("  " + shlex.join(["sudo", "adduser", user]))
                        print("  " + shlex.join(["sudo", "usermod", "-aG", "sudo", user]))
                        print("随后安装该用户的客户端公钥并保留 sudo 密码，再运行向导；不要上传私钥或给通用 shell 配 NOPASSWD。")
                return code
            expected = {(1, "apply"): "candidate-pending", (1, "confirm"): "candidate-ready", (2, "apply"): "hardening-pending", (2, "confirm"): "hardened", (3, "apply"): "reboot-pending", (3, "verify"): "verified", (3, "check"): "verified"}[(plan["number"], plan["action"])]
            after = workflow_plan(self.system, self.entry, goals, self.options.host, observer.connection, root=True)
            if after["state"] != expected or after["status"] == "repair-required":
                print("阶段未按预期推进或状态被其他会话改变；停止，重新运行 --guide 核对。")
                self.show(after, goals, observer.connection)
                return 2
            if plan["number"] == 3 and plan["action"] in {"verify", "check"}:
                print("流程完成：stage3 完整复验通过。")
                return 0
            if expected in {"candidate-pending", "hardening-pending", "reboot-pending"}:
                self.show(after, goals, observer.connection)
                return 2
        print("状态推进次数异常，已停止，请重新检查实际状态。")
        return 2


def arguments(argv=None):
    parser = argparse.ArgumentParser(prog="stage0-audit.sh", description=__doc__, epilog="默认：0=采集完成，2=采集不完整。显式比较目标：0=通过，1=不符合，2=证据不足。--guide：0=全流程复验完成，1=阶段失败，2=需补输入/权限/新会话/重启或阶段未完成，130=中断。")
    parser.add_argument("--check-baseline", action="store_true", help="显式比较禁 root/密码、公钥基线；默认只采集现状与展示差距")
    parser.add_argument("--guide", action="store_true", help="按状态执行下一阶段；缺参数交互询问，遇新会话或重启时给出命令")
    parser.add_argument("--host", help="客户端连接地址或 SSH 别名，只用于生成重连指引")
    parser.add_argument("--old-port", help="执行向导中显式保留的旧端口（n/none）")
    parser.add_argument("--conf", help="执行向导的阶段配置文件")
    parser.add_argument("--recovery-seconds", type=int, help="执行向导的确认窗口")
    parser.add_argument("--yes", action="store_true", help="执行向导不再询问；首次部署仍须配置 RESCUE_CONFIRMED=yes")
    parser.add_argument("--port", type=int, help="目标端口；默认从当前 SSH_CONNECTION 自动识别，无会话时只接受唯一监听")
    parser.add_argument("--user", help="目标管理账户；默认从 SUDO_USER 自动识别")
    parser.add_argument("--allow", action="append", help="可选的预期来源 CIDR；填写后进入策略比较模式，不自动把当前 IP 当白名单")
    parser.add_argument("--closed-port", action="append", type=int, default=[], help="必须关闭的 TCP 端口，可重复；不从 --old-port 推断")
    parser.add_argument("--source", action="append", default=[], help="补充 sshd 上下文来源 IP，可重复；Match 全覆盖仍需另验")
    parser.add_argument("--firewall-unit", action="append", default=[], help="实际防火墙加载服务，可重复；默认识别新旧服务名")
    parser.add_argument("--sshd-config", default="/etc/ssh/sshd_config", help="显式磁盘配置入口；非默认入口的进程关联会保留未知")
    parser.add_argument("--nft-table", default="sshguard", help="实际 inet 表名")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    options = parser.parse_args(argv)
    if options.guide and (options.format != "text" or options.check_baseline or options.closed_port or options.source or options.firewall_unit or options.sshd_config != "/etc/ssh/sshd_config" or options.nft_table != "sshguard"):
        parser.error("--guide 使用 text，并采用实际部署布局；合规审计参数请单独运行")
    if not options.guide and any((options.old_port, options.conf, options.recovery_seconds, options.yes)):
        parser.error("--old-port/--conf/--recovery-seconds/--yes 用于 --guide")
    if options.host and not re.fullmatch(r"[A-Za-z0-9_.:\[\]-]+", options.host):
        parser.error("--host 需要主机地址或 SSH 别名，不能包含空白或控制字符")
    if options.port is not None and not 1 <= options.port <= 65535 or any(not 1 <= port <= 65535 or port == options.port for port in options.closed_port):
        parser.error("端口范围错误，或目标端口同时声明为关闭")
    if options.user is not None and not re.fullmatch(r"[a-z_][a-z0-9_-]*\$?", options.user):
        parser.error("--user 必须是合法账户；root 也可采集，其加固差距单列")
    if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_-]*", options.nft_table):
        parser.error("非法 nft 表名")
    if any(not re.fullmatch(r"[a-zA-Z0-9_.@:-]+\.service", unit) for unit in options.firewall_unit):
        parser.error("非法防火墙单元名")
    if not options.sshd_config.startswith("/"):
        parser.error("--sshd-config 必须是绝对路径")
    try:
        allows = sorted({str(ipaddress.ip_network(item, strict=True)) for item in options.allow or []})
        sources = [str(ipaddress.ip_address(item)) for item in options.source]
    except ValueError as exc:
        parser.error(str(exc))
    policy = Policy(options.port, options.user, allows, sorted(set(options.closed_port)), sources,
                    options.firewall_unit, options.sshd_config, options.nft_table, "policy" if options.allow else "baseline" if options.check_baseline or options.closed_port else "inspect")
    return options, policy


def main(argv=None):
    replay = list(sys.argv[1:] if argv is None else argv)
    options, policy = arguments(argv)
    entry, system = entry_path(), System()
    if options.guide:
        # --port/--user/--allow 在向导中是部署目标；先采集当前连接的真实现状。
        policy = Policy(None, None, [], mode="inspect")
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        report = {"schema": 1, "read_only": True, "mode": policy.mode, "policy": asdict(policy), "security_result": UNKNOWN, "collection_result": UNKNOWN, "baseline_result": UNKNOWN, "policy_result": UNKNOWN,
                  "checks": [asdict(Check("完整读取权限", UNKNOWN, "请以目标普通用户登录后 sudo bash stage0-audit.sh；不必开放 root SSH 登录"))]}
    else:
        observer = Auditor(policy, system)
        report = observer.audit()
    connection = report.get("observed", {}).get("connection", {})
    current = (connection["source"], connection["source_port"], connection["local"], connection["port"]) if connection else None
    report["next_step"] = workflow_plan(system, entry, host=options.host, connection=current)
    if options.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        inspect = report.get("mode") == "inspect"
        print("SSH 只读现状检查（自动识别，不写状态）" if inspect else "SSH 只读目标策略审计（不写状态、不接管配置）")
        target = report.get("policy", {})
        current = report.get("observed", {}).get("connection", {})
        print(f"检查对象：账户={target.get('user') or '未识别'}，端口={target.get('port') or '未识别'}，当前登录来源={current.get('source', '未识别')}")
        for item in report["checks"]:
            label = {PASS: "已核实", FAIL: "待加固", UNKNOWN: "未证实"}[item["result"]] if inspect else LABELS[item["result"]]
            print(f"[{label}] {item['name']}：{item['detail']}")
        print(("现状采集：" + ("完成" if report["collection_result"] == PASS else "部分完成，见采集缺口") + "；加固差距供后续阶段处理") if inspect else "目标检查结果：" + LABELS[report["security_result"]])
        if inspect:
            print("来源白名单目标：未指定，未判定合规；当前登录来源仅作事实，不自动生成 --allow")
            firewall = report.get("observed", {}).get("firewall", {})
            print("观察到的 nft 表：" + (", ".join(firewall.get("tables", [])) or "无/未采集"))
            print("观察到的 accept 来源（非完整可达性证明）：" + (", ".join(firewall.get("accept_source_literals", [])) or "无/无法提取"))
            for manager in report.get("observed", {}).get("firewall_managers", []):
                print("防火墙管理器：" + json.dumps(manager, ensure_ascii=False))
            if report.get("observed", {}).get("ufw_status"):
                print("UFW 现状：" + report["observed"]["ufw_status"].strip())
        print("管理归属：" + report.get("ownership", {}).get("detail", "未采集"))
        migration = report.get("migration", {})
        print("部署衔接：" + migration.get("status", "not-assessed"))
        for item in migration.get("changes", []):
            print("  - " + item)
        for item in migration.get("blockers", []):
            print("  - " + item)
        print("重启证据：" + report.get("reboot", {}).get("detail", "未采集"))
        print_workflow(report["next_step"])
    if options.guide:
        terminal = None
        try:
            try:
                terminal = GuideTerminal()
            except OSError:
                pass
            return Workflow(options, system, entry, report, terminal).run(replay)
        except (EvidenceError, OSError, ValueError) as exc:
            print("向导暂停：" + str(exc))
            print("继续执行：" + shlex.join(["sudo", "bash", str(entry), *replay]))
            return 2
        except KeyboardInterrupt:
            print("\n已停止推进；重新运行 --guide 查看实际事务状态及回滚命令。")
            return 130
        finally:
            if terminal is not None:
                terminal.close()
    return {PASS: 0, FAIL: 1, UNKNOWN: 2}[report["collection_result"] if policy.mode == "inspect" else report["security_result"]]


if __name__ == "__main__":
    sys.exit(main())
REINFORCE_SSH_AUDIT_PY
