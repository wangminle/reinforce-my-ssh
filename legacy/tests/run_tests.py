#!/usr/bin/env python3
"""统一运行三阶段回归和独立审计回归；集成模式仅操作隔离测试资源。"""
import argparse
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--integration", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    for name in ("test_regressions.py", "test_audit.py", "test_workflow.py"):
        command = [sys.executable, str(root / name)]
        if args.integration and name == "test_regressions.py":
            command.append("--integration")
        result = subprocess.run(command)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == "__main__":
    sys.exit(main())
