#!/usr/bin/env python3
"""统一运行三个只读指导脚本的回归测试。

用法：python3 tests/run-tests.py
命名约定：连字符风格（如 stage0-check.sh）。由于 unittest 的发现机制拒绝
非标识符文件名，这里改为按路径显式加载 test-*.py，并以模块对象注册。
全部测试使用内存桩件，不接触真实系统；真实服务器验收见 README 与 plans/DESIGN-v2.md。
"""
import importlib.util
import sys
import unittest
from pathlib import Path

if __name__ == "__main__":
    root = Path(__file__).resolve().parent
    sys.path.insert(0, str(root))
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for path in sorted(root.glob("test-*.py")):
        name = path.stem.replace("-", "_")
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        suite.addTests(loader.loadTestsFromModule(module))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)