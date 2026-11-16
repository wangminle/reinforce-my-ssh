"""BUG-078~080：UFW active 时仍检查可解释的 nft 基链、Include 跟随、socket 监听提示。"""
import importlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
g = importlib.import_module("test-guides")

UFW_OK = (
    "Status: active\n\nTo Action From\n-- ----- ----\n"
    "62207/tcp ALLOW IN 203.0.113.0/24\n"
    "62207/tcp DENY IN Anywhere\n"
    "62207/tcp (v6) DENY IN Anywhere (v6)\n"
)


def extra_drop_nft():
    raw = json.loads(g.packet_nft(g.ALLOW_RULES))
    raw["nftables"].extend([
        {"table": {"family": "inet", "name": "filter"}},
        {"chain": {"family": "inet", "table": "filter", "name": "input",
                   "type": "filter", "hook": "input", "policy": "drop"}},
        {"rule": {"family": "inet", "table": "filter", "chain": "input", "expr": [
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 62207}},
            {"drop": None},
        ]}},
    ])
    return raw


def ufw_jump_nft():
    return {
        "nftables": [
            {"table": {"family": "ip", "name": "filter"}},
            {"chain": {"family": "ip", "table": "filter", "name": "INPUT",
                       "type": "filter", "hook": "input", "policy": "drop"}},
            {"rule": {"family": "ip", "table": "filter", "chain": "INPUT", "expr": [
                {"jump": {"target": "ufw-user-input"}},
            ]}},
        ]
    }


class TestBug078UfwStillSeesNativeNftChains(unittest.TestCase):
    def assess(self, module, nft_raw, ufw_text=UFW_OK):
        system = g.make_stub(module, ufw_active=True, ufw_text=ufw_text)
        system.can("nft -j list ruleset", json.dumps(nft_raw))
        summary = module.nft_ruleset_summary(system)
        ufw = module.ufw_status(system)
        return module.allowlist_assessment(summary, ufw, 62207, ["203.0.113.0/24"])

    def test_extra_input_drop_cannot_pass_when_ufw_looks_complete(self):
        for module in (g.STAGE0, g.STAGE2):
            with self.subTest(script=module.SCRIPT):
                result = self.assess(module, extra_drop_nft())
                self.assertEqual(result["status"], "fail", result)
                self.assertIn("input 基链", result["detail"])

    def test_stage0_and_stage2_entries_do_not_complete(self):
        raw = extra_drop_nft()
        system = g.make_stub(
            g.STAGE0, session_port=62207, listeners=[62207], disk_ports=(62207,), backup=True,
            auth=g.HARDENED_AUTH, allowlist_rules=g.ALLOW_RULES, hardening_mtime=999999999,
            ufw_active=True, ufw_text=UFW_OK)
        system.can("nft -j list ruleset", json.dumps(raw))
        code, output = g.run_main(
            g.STAGE0,
            ["--port", "62207", "--user", "fenix", "--allow", "203.0.113.0/24",
             "--reboot-confirmed", "--format", "json"],
            system)
        report = json.loads(output)
        self.assertEqual(code, 2)
        self.assertNotEqual(report["position"], "verified")
        allow = next(item for item in report["assessment"] if item["item"] == "来源白名单")
        self.assertEqual(allow["status"], "fail")

        system = g.make_stub(
            g.STAGE2, session_port=62207, listeners=[62207], disk_ports=(62207,), backup=True,
            auth=g.HARDENED_AUTH, allowlist_rules=g.ALLOW_RULES, hardening_mtime=999999999,
            ufw_active=True, ufw_text=UFW_OK)
        system.can("nft -j list ruleset", json.dumps(raw))
        g.patch_environment(g.STAGE2, system)
        options = g.STAGE2.parse_args(
            ["--port", "62207", "--user", "fenix", "--host", "h", "--rescue-confirmed",
             "--allow", "203.0.113.0/24", "--reboot-confirmed"])
        ctx = g.STAGE2.resolve_context(system, options)
        steps = {step["id"]: step for step in g.STAGE2.build_steps(system, options, ctx)}
        self.assertEqual(steps["1-allowlist"]["status"], "todo")
        self.assertFalse(all(step["status"] == "done" for step in steps.values()))

    def test_ufw_iptables_nft_jumps_do_not_block_ufw_pass(self):
        for module in (g.STAGE0, g.STAGE2):
            with self.subTest(script=module.SCRIPT):
                result = self.assess(module, ufw_jump_nft())
                self.assertEqual(result["status"], "pass", result)

    def test_empty_nft_with_ufw_still_passes(self):
        for module in (g.STAGE0, g.STAGE2):
            with self.subTest(script=module.SCRIPT):
                result = module.allowlist_assessment(
                    {"rules": [], "input_policy": [], "chains": []},
                    {"active": True, "available": True, "text": UFW_OK},
                    62207, ["203.0.113.0/24"])
                self.assertEqual(result["status"], "pass", result)


class TestBug079IncludeFollowed(unittest.TestCase):
    def test_extra_include_match_is_detected(self):
        for module in (g.STAGE0, g.STAGE1, g.STAGE2):
            system = g.make_stub(module)
            system.touch_dir("/etc/ssh/sshd_config.d", [])
            system.set_read("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_custom.conf\nPort 62207\n")
            system.touch_file("/etc/ssh/sshd_custom.conf")
            system.set_read("/etc/ssh/sshd_custom.conf", "Match Address 198.51.100.0/24\n  PasswordAuthentication yes\n")
            with self.subTest(script=module.SCRIPT):
                self.assertTrue(any("sshd_custom.conf" in item for item in module.sshd_config_files(system)))
                self.assertEqual(len(module.match_blocks(system)), 1)

    def test_stage0_does_not_verify_with_included_match(self):
        system = g.make_stub(
            g.STAGE0, session_port=62207, listeners=[62207], disk_ports=(62207,), backup=True,
            auth=g.HARDENED_AUTH, allowlist_rules=g.ALLOW_RULES, hardening_mtime=999999999)
        system.touch_dir("/etc/ssh/sshd_config.d", [])
        system.set_read("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_custom.conf\nPort 62207\n")
        system.touch_file("/etc/ssh/sshd_custom.conf")
        system.set_read("/etc/ssh/sshd_custom.conf", "Match Address 198.51.100.0/24\n  PasswordAuthentication yes\n")
        code, output = g.run_main(
            g.STAGE0,
            ["--port", "62207", "--user", "fenix", "--allow", "203.0.113.0/24",
             "--reboot-confirmed", "--format", "json"],
            system)
        report = json.loads(output)
        self.assertEqual(code, 2)
        self.assertEqual(report["position"], "match-review")

    def test_included_old_port_keeps_close_old_open(self):
        system = g.make_stub(
            g.STAGE1, session_port=62207, listeners=[62207], disk_ports=(), backup=True,
            socket_active=False)
        system.touch_dir("/etc/ssh/sshd_config.d", [])
        system.touch_dir("/etc/systemd/system/ssh.socket.d", [])
        system.set_read("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_custom.conf\n")
        system.touch_file("/etc/ssh/sshd_custom.conf")
        system.set_read("/etc/ssh/sshd_custom.conf", "Port 22\nPort 62207\n")
        self.assertIn(22, g.STAGE1.disk_port_directives(system))
        g.patch_environment(g.STAGE1, system)
        options = g.STAGE1.parse_args(
            ["--port", "62207", "--user", "fenix", "--host", "h",
             "--rescue-confirmed", "--old-port", "22"])
        ctx = g.STAGE1.resolve_context(system, options)
        steps = {step["id"]: step for step in g.STAGE1.build_steps(system, options, ctx)}
        self.assertEqual(steps["5-close-old"]["status"], "todo")


class TestBug080SocketListenerHint(unittest.TestCase):
    def test_generated_ss_hint_does_not_grep_only_sshd(self):
        text = g.script_source("stage1-port-key.sh")
        self.assertNotIn("sudo ss -tlnp | grep sshd", text)
        self.assertIn('"sudo ss -tlnp"', text)


if __name__ == "__main__":
    unittest.main()
