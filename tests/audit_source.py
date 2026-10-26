"""仅供开发测试：提取 stage0 内嵌实现，不属于部署文件。"""
from pathlib import Path
import sys
import types

STAGE0 = Path(__file__).resolve().parents[1] / "stage0-audit.sh"
PREFIX = 'exec python3 - "$@" <<\'REINFORCE_SSH_AUDIT_PY\'\n'
SUFFIX = "REINFORCE_SSH_AUDIT_PY\n"


def audit_source():
    text = STAGE0.read_text(encoding="utf-8")
    if text.count(PREFIX) != 1 or not text.endswith(SUFFIX):
        raise ValueError("stage0 的内嵌审计边界不完整")
    return text.split(PREFIX, 1)[1][:-len(SUFFIX)]


def load_audit():
    name = "reinforce_ssh_audit_test"
    module = types.ModuleType(name)
    module.__file__ = str(STAGE0)
    sys.modules[name] = module
    exec(compile(audit_source(), str(STAGE0), "exec"), module.__dict__)
    return module
