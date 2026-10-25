#!/usr/bin/env python3
"""独立只读 SSH 现状审计：不初始化 state，不接管配置，不执行任何部署动作。"""
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
        self.report = {"schema": 1, "policy": asdict(policy), "read_only": True}

    def add(self, name, result, detail):
        self.checks.append(Check(name, result, detail))

    def collect(self, name, callback):
        try:
            callback()
        except (EvidenceError, ValueError, KeyError, TypeError, IndexError, AttributeError) as exc:
            self.add(name, UNKNOWN, str(exc))

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
            self.connection = (client, int(client_port), local, int(local_port))

    def authentication(self):
        uid = self.system.run("id", "-u", self.policy.user).strip()
        if not uid.isdigit() or int(uid) == 0:
            self.add("管理账户", FAIL, "目标账户必须是非 root、非 UID 0 账户")
            return
        self.files, self.directives, uncertain = scan_config(self.system, self.policy.sshd_config)
        self.system.run("sshd", "-t", "-f", self.policy.sshd_config)
        sources = list(self.policy.sources)
        if self.connection:
            sources.append(self.connection[0])
        sources = list(dict.fromkeys(sources or ["127.0.0.1", "::1"]))
        for user in (self.policy.user, "root"):
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
                name = f"有效认证 {user}@{source}"
                result = UNKNOWN if uncertain else FAIL if wrong else UNKNOWN if missing else PASS
                self.add(name, result, "; ".join(wrong + ["缺少 " + key for key in missing]) or "禁 root/密码/键盘交互，只允许公钥；按 sshd 实际解析，文件名不参与判定")
        self.add("认证上下文覆盖", UNKNOWN if uncertain else PASS, "; ".join(uncertain) if uncertain else "未发现活动 Match；Include 已遍历；sshd -t 通过")

    def listeners(self):
        output = self.system.run("ss", "-tlnpH")
        found, extras = [], []
        for line in output.splitlines():
            words = line.split()
            if len(words) < 5:
                raise EvidenceError("无法完整解析 ss 监听输出")
            host, port = endpoint(words[3])
            if port in self.policy.closed_ports:
                self.add(f"禁止端口 {port}", FAIL, f"仍有监听 {words[3]}")
            if port == self.policy.port:
                found.append((host, line))
            elif re.search(r'"sshd(?:-session)?"', line):
                extras.append(words[3])
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
            self.add("额外 SSH 端口", FAIL, ", ".join(extras))
        socket = self.unit("ssh.socket")
        ports = {endpoint(line.rsplit(" (Stream)", 1)[0])[1] for line in socket.get("Listen", "").splitlines() if line.endswith(" (Stream)")}
        if ports - {self.policy.port}:
            self.add("SSH socket 端口", FAIL, f"有效 socket 还有其他端口：{sorted(ports)}")
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
                 f"策略需要 IPv{sorted(required)}，内核证据覆盖 IPv{sorted(families)}；用 ss 的 v6only 标记核对双栈，不由当前 sysctl 推断已创建 socket")

    def firewall(self):
        data = json.loads(self.system.run("nft", "-j", "-s", "list", "ruleset"))
        self.checks.append(firewall_policy(data, self.policy))

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
        if ipaddress.ip_address(client) in locals_ or not any(ipaddress.ip_address(client) in ipaddress.ip_network(net) for net in self.policy.allows):
            raise EvidenceError("当前来源是本机自连或不在目标白名单，不能证明目标外部通道")
        if os.environ.get("SUDO_USER") != self.policy.user:
            raise EvidenceError("请由目标用户在其 SSH 会话中直接 sudo 执行")
        uid = self.system.run("id", "-u", self.policy.user).strip()
        if os.environ.get("SUDO_UID") != uid:
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
        pattern = re.compile(r"^Accepted publickey for (\S+) from (\S+) port (\d+)(?:\s|$)")
        for line in logs.splitlines():
            event = json.loads(line)
            if event.get("_BOOT_ID") != boot or str(event.get("_PID")) not in ancestors:
                continue
            message = event.get("MESSAGE")
            match = pattern.search(message) if isinstance(message, str) else None
            if match and match[1] == self.policy.user and ipaddress.ip_address(match[2]) == ipaddress.ip_address(client) and int(match[3]) == cp:
                self.add("当前公钥与 sudo", PASS, "同 boot 的公钥日志、存活四元组和当前 sudo 进程链匹配；只证明本条通道")
                return
        raise EvidenceError("没有与当前连接进程链匹配的公钥日志")

    def migration(self):
        blockers = []
        if self.report.get("ownership", {}).get("kind") != "managed-record":
            blockers.append("无新版管理记录；现有配置不能直接当作已完成新版阶段")
        controlled = {"port", "listenaddress", "permitrootlogin", "passwordauthentication", "kbdinteractiveauthentication", "pubkeyauthentication", "authenticationmethods"}
        blockers += [f"{path}:{number} 非受管 {key}（仅阻止直接接管）" for path, number, key in self.directives if key in controlled and path != MANAGED[0]]
        for path in ("/etc/systemd/system/ssh.socket.d/override.conf", "/etc/systemd/system/ssh-firewall.service"):
            if self.system.exists(path):
                blockers.append(path + " 需要专门迁移备份及冲突处理")
        self.report["migration"] = {"status": "blocked" if blockers else "not-assessed", "blockers": blockers,
                                    "detail": "本审计不授权 apply，也不证明回滚备份已准备好"}

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
        for file in MANAGED:
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
        self.report["scope"] = "本机显式策略与当前通道；不代替云安全组、拒绝来源外测或整机重启验收"
        return self.report


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, epilog="退出码：0=当前审计范围通过，1=明确不符合，2=证据/权限/支持范围不足。归属与重启记录另列。")
    parser.add_argument("--port", type=int, required=True, help="目标 SSH 端口")
    parser.add_argument("--user", required=True, help="目标非 root 管理用户")
    parser.add_argument("--allow", action="append", required=True, help="预期来源 CIDR，可重复")
    parser.add_argument("--closed-port", action="append", type=int, default=[], help="必须关闭的 TCP 端口，可重复；不从 --old-port 推断")
    parser.add_argument("--source", action="append", default=[], help="补充 sshd 上下文来源 IP，可重复；Match 全覆盖仍需另验")
    parser.add_argument("--firewall-unit", action="append", default=[], help="实际防火墙加载服务，可重复；默认识别新旧服务名")
    parser.add_argument("--sshd-config", default="/etc/ssh/sshd_config", help="显式磁盘配置入口；非默认入口的进程关联会保留未知")
    parser.add_argument("--nft-table", default="sshguard", help="实际 inet 表名")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    options = parser.parse_args(argv)
    if not 1 <= options.port <= 65535 or any(not 1 <= port <= 65535 or port == options.port for port in options.closed_port):
        parser.error("端口范围错误，或目标端口同时声明为关闭")
    if options.user == "root" or not re.fullmatch(r"[a-z_][a-z0-9_-]*\$?", options.user):
        parser.error("--user 必须是合法的非 root 账户")
    if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_-]*", options.nft_table):
        parser.error("非法 nft 表名")
    if any(not re.fullmatch(r"[a-zA-Z0-9_.@:-]+\.service", unit) for unit in options.firewall_unit):
        parser.error("非法防火墙单元名")
    if not options.sshd_config.startswith("/"):
        parser.error("--sshd-config 必须是绝对路径")
    try:
        allows = sorted({str(ipaddress.ip_network(item, strict=True)) for item in options.allow})
        sources = [str(ipaddress.ip_address(item)) for item in options.source]
    except ValueError as exc:
        parser.error(str(exc))
    policy = Policy(options.port, options.user, allows, sorted(set(options.closed_port)), sources,
                    options.firewall_unit, options.sshd_config, options.nft_table)
    return options, policy


def main(argv=None):
    options, policy = arguments(argv)
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        report = {"schema": 1, "read_only": True, "security_result": UNKNOWN,
                  "checks": [asdict(Check("完整读取权限", UNKNOWN, "请以目标普通用户登录后 sudo python3 audit.py；不必开放 root SSH 登录"))]}
    else:
        report = Auditor(policy).audit()
    if options.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print("SSH 独立只读审计（不写状态、不接管配置）")
        for item in report["checks"]:
            print(f"[{LABELS[item['result']]}] {item['name']}：{item['detail']}")
        print("安全效果：" + LABELS[report["security_result"]])
        print("管理归属：" + report.get("ownership", {}).get("detail", "未采集"))
        migration = report.get("migration", {})
        print("迁移准备：" + ("存在阻断" if migration.get("status") == "blocked" else "未评估/未授权迁移"))
        for item in migration.get("blockers", []):
            print("  - " + item)
        print("重启证据：" + report.get("reboot", {}).get("detail", "未采集"))
    return {PASS: 0, FAIL: 1, UNKNOWN: 2}[report["security_result"]]


if __name__ == "__main__":
    sys.exit(main())
