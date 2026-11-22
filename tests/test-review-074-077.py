"""BUG-074~077：nft 集合部分不可解析元素、stage0 缺 --port 定位、stage2 loader_facts 与 sshd -C 本地端点。"""
import importlib
import json
import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
g = importlib.import_module("test-guides")


def nft_ruleset(extra_rules):
    return {
        "nftables": [
            {"table": {"family": "inet", "name": "sshguard"}},
            {"chain": {"family": "inet", "table": "sshguard", "name": "ssh_allow",
                       "type": "filter", "hook": "input", "policy": "accept"}},
            *extra_rules,
            {"rule": {"family": "inet", "table": "sshguard", "chain": "ssh_allow", "handle": 90, "expr": [
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 62207}},
                {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                           "right": {"prefix": {"addr": "203.0.113.0", "len": 24}}}},
                {"accept": None},
            ]}},
            {"rule": {"family": "inet", "table": "sshguard", "chain": "ssh_allow", "handle": 91, "expr": [
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 62207}},
                {"drop": None},
            ]}},
        ]
    }


class TestBug074NftPartialSetElements(unittest.TestCase):
    def test_port_range_inside_set_is_never_skipped(self):
        rules = nft_ruleset([
            {"rule": {"family": "inet", "table": "sshguard", "chain": "ssh_allow", "handle": 1, "expr": [
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                           "right": {"set": [80, {"range": [60000, 65000]}]}}},
                {"accept": None},
            ]}}
        ])
        for module in (g.STAGE0, g.STAGE2):
            with self.subTest(script=module.SCRIPT):
                self.assertEqual(module.literal_values({"set": [80, {"range": [60000, 65000]}]}), [])
                system = g.make_stub(module)
                system.can("nft -j list ruleset", json.dumps(rules))
                summary = module.nft_ruleset_summary(system)
                result = module.nft_allowlist_assessment(summary, 62207, ["203.0.113.0/24"])
                self.assertEqual(result["status"], "fail", result)

    def test_unknown_element_inside_saddr_set_is_rejected(self):
        rules = {
            "nftables": [
                {"table": {"family": "inet", "name": "sshguard"}},
                {"chain": {"family": "inet", "table": "sshguard", "name": "ssh_allow",
                           "type": "filter", "hook": "input", "policy": "accept"}},
                {"rule": {"family": "inet", "table": "sshguard", "chain": "ssh_allow", "handle": 2, "expr": [
                    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 62207}},
                    {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                               "right": {"set": [{"prefix": {"addr": "203.0.113.0", "len": 24}},
                                                 {"concat": ["unknown"]}]}}},
                    {"accept": None},
                ]}},
                {"rule": {"family": "inet", "table": "sshguard", "chain": "ssh_allow", "handle": 3, "expr": [
                    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 62207}},
                    {"drop": None},
                ]}},
            ]
        }
        for module in (g.STAGE0, g.STAGE2):
            with self.subTest(script=module.SCRIPT):
                self.assertEqual(
                    module.literal_values({"set": [{"prefix": {"addr": "203.0.113.0", "len": 24}},
                                                   {"concat": ["unknown"]}]}, addresses=True),
                    [])
                system = g.make_stub(module)
                system.can("nft -j list ruleset", json.dumps(rules))
                summary = module.nft_ruleset_summary(system)
                result = module.nft_allowlist_assessment(summary, 62207, ["203.0.113.0/24"])
                self.assertEqual(result["status"], "fail", result)

    def test_valid_multi_ports_and_mixed_address_ranges_still_pass(self):
        rules = nft_ruleset([
            {"rule": {"family": "inet", "table": "sshguard", "chain": "ssh_allow", "handle": 1, "expr": [
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                           "right": {"set": [80, 443]}}},
                {"accept": None},
            ]}}
        ])
        for module in (g.STAGE0, g.STAGE2):
            with self.subTest(script=module.SCRIPT):
                self.assertEqual(module.literal_values({"set": [80, 443]}), [80, 443])
                self.assertEqual(module.literal_values({"set": []}, addresses=True), [])
                self.assertEqual(module.literal_values([], addresses=True), [])
                self.assertEqual(module.literal_values(None, addresses=True), [])
                system = g.make_stub(module)
                system.can("nft -j list ruleset", json.dumps(rules))
                summary = module.nft_ruleset_summary(system)
                result = module.nft_allowlist_assessment(summary, 62207, ["203.0.113.0/24"])
                self.assertEqual(result["status"], "pass", result)


class TestBug075Stage0IncompleteGoals(unittest.TestCase):
    def test_user_only_without_port_never_verifies_or_suggests_new_port_placeholder(self):
        system = g.make_stub(
            g.STAGE0, listeners=[22], session_port=22, backup=True,
            auth=g.HARDENED_AUTH, hardening_mtime=999999999)
        code, output = g.run_main(
            g.STAGE0, ["--user", "fenix", "--reboot-confirmed", "--format", "json"], system)
        report = json.loads(output)
        self.assertEqual(code, 2)
        self.assertEqual(report["position"], "goals-undeclared")
        self.assertFalse(any("NEW_PORT" in cmd for cmd in report["next_step"]["commands"]))
        self.assertIn("--user fenix", report["next_step"]["commands"][0])

    def test_tailnet_or_allow_without_port_returns_2_and_keeps_flags(self):
        system = g.make_stub(g.STAGE0, listeners=[22], session_port=22)
        code, output = g.run_main(
            g.STAGE0, ["--tailnet", "--allow", "203.0.113.0/24", "--format", "json"], system)
        report = json.loads(output)
        self.assertEqual(code, 2)
        self.assertEqual(report["position"], "goals-undeclared")
        wl = next(x for x in report["assessment"] if x["item"] == "来源白名单")
        self.assertEqual(wl["status"], "unknown")
        self.assertIn("未声明 --port", wl["detail"])
        cmd = report["next_step"]["commands"][0]
        self.assertIn("--tailnet", cmd)
        self.assertIn("--allow 203.0.113.0/24", cmd)

    def test_no_goals_still_returns_0(self):
        system = g.make_stub(g.STAGE0)
        code, output = g.run_main(g.STAGE0, ["--format", "json"], system)
        report = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual(report["position"], "goals-undeclared")


class TestBug076Stage2LoaderFacts(unittest.TestCase):
    @staticmethod
    def prepend_can(system, prefix, stdout="", returncode=0, stderr=""):
        rest = dict(system.canned)
        system.canned = {prefix: types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)}
        system.canned.update(rest)

    def test_inactive_or_disabled_standard_loader_is_unknown_not_fail(self):
        # BUG-076：不再因 run() 抛错落入 unknown；BUG-082：标准加载器未激活不得用 fail 阻断命令生成。
        for sub, value, rc in (("is-active", "inactive", 3), ("is-enabled", "disabled", 1)):
            with self.subTest(sub=sub, value=value):
                system = g.make_stub(g.STAGE2)
                system.touch_file("/etc/systemd/system/ssh-allowlist.service")
                system.set_read(
                    "/etc/systemd/system/ssh-allowlist.service",
                    "[Service]\nExecStart=/usr/sbin/nft -f /etc/nftables.d/ssh-allowlist.nft\n"
                    "ExecReload=/usr/sbin/nft -f /etc/nftables.d/ssh-allowlist.nft\n")
                self.prepend_can(system, "systemctl " + sub + " ssh-allowlist.service",
                                 stdout=value + "\n", returncode=rc)
                result = g.STAGE2.loader_facts(system)
                self.assertEqual(result["status"], "unknown", result)
                self.assertIn(value, result["detail"])
                self.assertNotIn("禁止直接覆盖", result["detail"])

    def test_missing_nftables_service_does_not_block_when_load_state_is_not_found(self):
        system = g.make_stub(g.STAGE2)
        system.touch_file("/etc/nftables.conf")
        system.set_read("/etc/nftables.conf", "#!/usr/sbin/nft -f\nflush ruleset\n")
        self.prepend_can(system, "systemctl show nftables.service", stdout="not-found\n", returncode=0)
        self.prepend_can(system, "systemctl is-enabled nftables.service",
                         stdout="", stderr="No such file or directory", returncode=4)
        system.touch_file("/etc/systemd/system/ssh-allowlist.service")
        system.set_read(
            "/etc/systemd/system/ssh-allowlist.service",
            "[Service]\nExecStart=/usr/sbin/nft -f /etc/nftables.d/ssh-allowlist.nft\n"
            "ExecReload=/usr/sbin/nft -f /etc/nftables.d/ssh-allowlist.nft\n")
        result = g.STAGE2.loader_facts(system)
        self.assertEqual(result["status"], "pass", result)

    def test_enabled_nftables_service_with_flush_still_blocks(self):
        system = g.make_stub(g.STAGE2)
        system.touch_file("/etc/nftables.conf")
        system.set_read("/etc/nftables.conf", "#!/usr/sbin/nft -f\nflush ruleset\n")
        self.prepend_can(system, "systemctl show nftables.service", stdout="loaded\n", returncode=0)
        self.prepend_can(system, "systemctl is-enabled nftables.service", stdout="enabled\n", returncode=0)
        result = g.STAGE2.loader_facts(system)
        self.assertEqual(result["status"], "fail", result)


class TestBug077SshdContextLocalEndpoint(unittest.TestCase):
    def test_stage0_and_stage2_pass_laddr_and_lport_to_sshd_t(self):
        for module, argv in (
            (g.STAGE0, ["--port", "62207", "--user", "fenix", "--format", "json"]),
            (g.STAGE2, ["--port", "62207", "--user", "fenix", "--allow", "203.0.113.0/24", "--format", "json"]),
        ):
            with self.subTest(script=module.SCRIPT):
                system = g.make_stub(module, session_port=62207, listeners=[62207])
                g.run_main(module, argv, system)
                t_calls = [call for call in system.calls if call[:2] == ["sshd", "-T"]]
                self.assertTrue(t_calls)
                for call in t_calls:
                    ctx = call[call.index("-C") + 1]
                    self.assertIn("laddr=10.0.0.5", ctx)
                    self.assertIn("lport=62207", ctx)


if __name__ == "__main__":
    unittest.main()
