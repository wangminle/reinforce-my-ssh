"""BUG-072/073：`Match=...` 关键字写法与 stage1 遗漏 `sudo` 的监听提示。"""
import importlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
g = importlib.import_module("test-guides")


class TestBug072MatchKeywordValue(unittest.TestCase):
    def test_equals_forms_are_detected_in_all_scripts(self):
        for module in (g.STAGE0, g.STAGE1, g.STAGE2):
            system = g.make_stub(module)
            system.set_read(
                "/etc/ssh/sshd_config",
                "Match=User bob\nMatch =Address 10.0.0.0/8\nmatch=all\n")
            system.touch_dir("/etc/ssh/sshd_config.d", [])
            with self.subTest(script=module.SCRIPT):
                self.assertEqual(len(module.match_blocks(system)), 3)

    def test_stage0_does_not_verify_with_match_equals(self):
        system = g.make_stub(
            g.STAGE0, session_port=62207, listeners=[62207], disk_ports=(62207,), backup=True,
            auth=g.HARDENED_AUTH, allowlist_rules=g.ALLOW_RULES, hardening_mtime=999999999)
        system.set_read(
            "/etc/ssh/sshd_config",
            "Port 62207\nMatch=User bob\n  PasswordAuthentication yes\n")
        code, output = g.run_main(
            g.STAGE0,
            ["--port", "62207", "--user", "fenix", "--allow", "203.0.113.0/24",
             "--reboot-confirmed", "--format", "json"],
            system)
        report = json.loads(output)
        self.assertEqual(code, 2)
        self.assertEqual(report["position"], "match-review")
        statuses = {item["item"]: item["status"] for item in report["assessment"]}
        self.assertEqual(statuses["Match 块"], "warn")

    def test_plain_match_still_detected(self):
        for module in (g.STAGE0, g.STAGE1, g.STAGE2):
            system = g.make_stub(module)
            system.set_read("/etc/ssh/sshd_config", "Match User bob\n")
            system.touch_dir("/etc/ssh/sshd_config.d", [])
            with self.subTest(script=module.SCRIPT):
                self.assertEqual(len(module.match_blocks(system)), 1)


class TestBug073NewPortSudoHint(unittest.TestCase):
    def test_new_port_verification_hint_uses_sudo(self):
        text = g.script_source("stage1-port-key.sh")
        self.assertIn("服务器：sudo ss -tlnp 应同时看到 ", text)
        self.assertNotIn("服务器：ss -tlnp 应同时看到 ", text)


if __name__ == "__main__":
    unittest.main()