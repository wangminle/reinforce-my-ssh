"""仅供测试：提取三个指导脚本的内嵌实现并提供只读桩件；不属于部署文件。

约定与脚本本身一致：每个脚本的 Python 实现位于唯一的 heredoc 边界内，
测试直接 exec 该段源码为模块，并把 System 替换为 StubSystem，
从而在不接触真实系统的前提下验证探测、判定与输出逻辑。
"""
from pathlib import Path
import json
import sys
import types

ROOT = Path(__file__).resolve().parents[1]
MARKERS = {
    "stage0-check.sh": "REINFORCE_STAGE0_PY",
    "stage1-port-key.sh": "REINFORCE_STAGE1_PY",
    "stage2-lockdown.sh": "REINFORCE_STAGE2_PY",
}
_CACHE = {}


def script_source(name):
    return (ROOT / name).read_text(encoding="utf-8")


def load_script(name):
    """按 heredoc 边界提取内嵌 Python 并加载为模块。"""
    if name in _CACHE:
        return _CACHE[name]
    marker = MARKERS[name]
    text = script_source(name)
    prefix = 'exec python3 - "$@" <<\'%s\'\n' % marker
    suffix = marker + "\n"
    if text.count(prefix) != 1 or not text.endswith(suffix):
        raise ValueError(name + " 的内嵌边界不完整")
    source = text.split(prefix, 1)[1][:-len(suffix)]
    module = types.ModuleType("guide_%s" % name.replace("-", "_").replace(".", "_"))
    module.__file__ = str(ROOT / name)
    sys.modules[module.__name__] = module
    exec(compile(source, str(ROOT / name), "exec"), module.__dict__)
    module.SOURCE = source
    _CACHE[name] = module
    return module


class StubSystem:
    """只读桩件：命令按前缀匹配给出预置输出，文件系统全部内存化。"""

    def __init__(self):
        self.calls = []
        self.canned = {}
        self.reads = {}
        self.dirs = {}
        self.files = set()
        self.mtimes = {}
        self.stats = {}

    def can(self, prefix, stdout="", returncode=0, stderr=""):
        self.canned[prefix] = types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)
        return self

    def run_allow_fail(self, *args):
        self.calls.append(list(args))
        key = " ".join(str(a) for a in args)
        if hasattr(self, "_mod"):
            allowed = self._mod.READ_ONLY_COMMANDS
            if args[0] not in allowed:
                raise self._mod.EvidenceError("桩件拒绝非白名单命令：" + args[0])
            subs = allowed[args[0]]
            if subs is not None and (len(args) < 2 or args[1] not in subs):
                raise self._mod.EvidenceError("桩件拒绝非白名单子命令：" + " ".join(args[:2]))
        for prefix, result in self.canned.items():
            if key.startswith(prefix):
                return result
        raise self._mod.EvidenceError("桩件未预置命令输出：" + key)

    def run(self, *args):
        result = self.run_allow_fail(*args)
        if result.returncode != 0:
            raise self._mod.EvidenceError("%s 退出码 %d" % (args[0], result.returncode))
        return result.stdout

    def read(self, path):
        for prefix, value in self.reads.items():
            if path.startswith(prefix):
                return value
        raise self._mod.EvidenceError("桩件无法读取 " + path)

    def exists(self, path):
        return path in self.files

    def is_dir(self, path):
        return path in self.dirs

    def list_dir(self, path):
        if path in self.dirs:
            return sorted(self.dirs[path])
        raise self._mod.EvidenceError("桩件无目录 " + path)

    def stat(self, path):
        if path in self.stats:
            return self.stats[path]
        raise self._mod.EvidenceError("桩件无属性 " + path)

    def mtime(self, path):
        return self.mtimes.get(path)

    def touch_dir(self, path, names):
        self.dirs[path] = list(names)
        return self

    def touch_file(self, path):
        self.files.add(path)
        return self

    def set_read(self, prefix, value):
        self.reads[prefix] = value
        return self

    def set_stat(self, path, mode, uid):
        self.stats[path] = types.SimpleNamespace(st_mode=mode, st_uid=uid)
        return self


def bind_stub(module, stub):
    stub._mod = module
    return stub


def packet_nft(rules):
    """把简写的规则列表渲染为 nft -j 输出；rules 元素形如 (verdict, dport, saddr, ct)。"""
    items = [{"table": {"family": "inet", "name": "sshguard"}},
             {"chain": {"family": "inet", "table": "sshguard", "name": "ssh_allow", "hook": "input", "policy": "accept"}}]
    for verdict, dport, saddr, ct in rules:
        expr = []
        if ct:
            expr.append({"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": {"set": list(ct)}}})
        if dport is not None:
            expr.append({"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": dport}})
        if saddr:
            expr.append({"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"set": list(saddr)}}})
        expr.append({verdict: None})
        items.append({"rule": {"family": "inet", "table": "sshguard", "chain": "ssh_allow", "expr": expr}})
    return json.dumps({"nftables": items})