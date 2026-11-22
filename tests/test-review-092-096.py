"""BUG-092~096：root 上下文 fail-open、Include 单引号崩溃、blocked heredoc 注释、未监听误判 done、inet jump 误跳过。"""
import importlib
import json
import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
g = importlib.import_module("test-guides")

PORT = 62207
UFW_OK = (
    "Status: active\n\nTo Action From\n-- ----- ----\n"
    "62207/tcp ALLOW IN 203.0.113.0/24\n"
    "62207/tcp DENY IN Anywhere\n"
    "62207/tcp (v6) DENY IN Anywhere (v6)\n"
)


class TestBug092RootContextFailClosed(unittest.TestCase):
    def test_root_context_collection_failure_keeps_auth_open(self):
        system = g.make_stub(
            g.STAGE2, session_port=PORT, listeners=[PORT], disk_ports=(PORT,), backup=True,
            auth=g.HARDENED_AUTH, allowlist_rules=g.ALLOW_RULES, hardening_mtime=999999999)
        original = system.run_allow_fail

        def routed(*args):
            if args and args[0] == "sshd" and "-T" in args and "-C" in args:
                ctx = args[args.index("-C") + 1]
                if "user=root" in ctx:
                    return types.SimpleNamespace(returncode=255, stdout="", stderr="sshd: connection failed")
            return original(*args)

        system.run_allow_fail = routed
        g.patch_environment(g.STAGE2, system)
        options = g.STAGE2.parse_args(
            ["--port", str(PORT), "--user", "fenix", "--host", "h", "--rescue-confirmed",
             "--allow", "203.0.113.0/24", "--reboot-confirmed"])
        ctx = g.STAGE2.resolve_context(system, options)
        self.assertEqual(ctx.get("root_auth_facts"), {})
        steps = {s["id"]: s for s in g.STAGE2.build_steps(system, options, ctx)}
        self.assertNotEqual(steps["2-auth"]["status"], "done")
        self.assertIn("禁 root=fail", steps["3-confirm"]["evidence"])


class TestBug093IncludeSingleQuote(unittest.TestCase):
    def test_single_quote_in_include_path_does_not_crash(self):
        for module in (g.STAGE0, g.STAGE1, g.STAGE2):
            with self.subTest(script=module.SCRIPT):
                system = g.make_stub(module)
                system.touch_dir("/etc/ssh/sshd_config.d", [])
                system.touch_file("/etc/ssh/o'reilly.conf")
                system.set_read("/etc/ssh/sshd_config", "Include /etc/ssh/o'reilly.conf\n")
                system.set_read("/etc/ssh/o'reilly.conf", "Match Address 198.51.100.0/24\n")
                files = module.sshd_config_files(system)
                self.assertTrue(any("o'reilly.conf" in path for path in files), files)
                self.assertEqual(len(module.match_blocks(system)), 1)

    def test_stage1_and_stage2_main_survive_unclosed_quote_include(self):
        for module, argv in (
            (g.STAGE1, ["--port", str(PORT), "--user", "fenix", "--format", "json"]),
            (g.STAGE2, ["--port", str(PORT), "--user", "fenix", "--allow", "203.0.113.0/24",
                        "--format", "json"]),
        ):
            with self.subTest(script=module.SCRIPT):
                system = g.make_stub(module)
                system.touch_dir("/etc/ssh/sshd_config.d", [])
                system.set_read("/etc/ssh/sshd_config", 'Include "/etc/ssh/broken.conf\n')
                code, output = g.run_main(module, argv, system)
                self.assertNotIn("Traceback", output)
                self.assertIn(code, (0, 2))
                json.loads(output)


class TestBug094BlockedHeredocFullyCommented(unittest.TestCase):
    def test_stage1_close_old_comments_every_heredoc_line(self):
        system = g.make_stub(
            g.STAGE1, session_port=PORT, listeners=[22, PORT], disk_ports=(22, PORT), backup=True)
        g.patch_environment(g.STAGE1, system)
        options = g.STAGE1.parse_args(
            ["--port", str(PORT), "--user", "fenix", "--host", "h", "--old-port", "22"])
        ctx = g.STAGE1.resolve_context(system, options)
        steps = {s["id"]: s for s in g.STAGE1.build_steps(system, options, ctx)}
        close = steps["5-close-old"]
        self.assertEqual(close["status"], "blocked")
        for line in close["do"]:
            for part in line.splitlines() or [line]:
                stripped = part.strip()
                if not stripped:
                    continue
                self.assertTrue(stripped.startswith("#"), part)

    def test_stage2_allowlist_comments_loader_heredoc_lines(self):
        system = g.make_stub(g.STAGE2)
        g.patch_environment(g.STAGE2, system)
        options = g.STAGE2.parse_args(
            ["--port", str(PORT), "--user", "fenix", "--host", "h", "--rescue-confirmed",
             "--allow", "203.0.113.0/24"])
        ctx = g.STAGE2.resolve_context(system, options)
        steps = {s["id"]: s for s in g.STAGE2.build_steps(system, options, ctx)}
        allow = steps["1-allowlist"]
        self.assertEqual(allow["status"], "blocked")
        for line in allow["do"]:
            for part in line.splitlines() or [line]:
                stripped = part.strip()
                if not stripped:
                    continue
                self.assertTrue(stripped.startswith("#"), part)
        # 多行 loader heredoc 不得留下未注释的可执行首行以外的内容。
        self.assertTrue(any("subprocess.run" in part for line in allow["do"] for part in line.splitlines()))
        self.assertTrue(all(
            (not part.strip()) or part.strip().startswith("#")
            for line in allow["do"] for part in (line.splitlines() or [line])))


class TestBug095ClosePublicWithoutListener(unittest.TestCase):
    def test_missing_target_listener_is_unknown_not_done(self):
        system = g.make_stub(
            g.STAGE2, session_source="100.64.1.9", session_port=22, listeners=[22],
            backup=True, tailnet=True, socket_active=False)
        g.patch_environment(g.STAGE2, system)
        options = g.STAGE2.parse_args(
            ["--port", str(PORT), "--user", "fenix", "--host", "h", "--rescue-confirmed",
             "--tailnet", "--tailnet-session-confirmed"])
        ctx = g.STAGE2.resolve_context(system, options)
        self.assertNotIn(PORT, ctx["listeners"])
        steps = {s["id"]: s for s in g.STAGE2.build_steps(system, options, ctx)}
        close = steps["1b-close-public"]
        # 前置未满足时 step() 会标 blocked，但不得因 exposed=[] 误判 done。
        self.assertNotEqual(close["status"], "done")
        self.assertIn("不能证明", close["evidence"])
        self.assertIn(str(PORT), close["evidence"])
        self.assertNotIn("只监听回环", close["evidence"])


class TestBug096InetJumpNotTransparentUnderUfw(unittest.TestCase):
    def test_inet_policy_drop_with_icmp_jump_fails(self):
        nft = {
            "nftables": [
                {"table": {"family": "inet", "name": "filter"}},
                {"chain": {"family": "inet", "table": "filter", "name": "input",
                           "type": "filter", "hook": "input", "policy": "drop"}},
                {"rule": {"family": "inet", "table": "filter", "chain": "input", "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "icmp"}},
                    {"jump": {"target": "icmp_allow"}},
                ]}},
            ]
        }
        for module in (g.STAGE0, g.STAGE2):
            with self.subTest(script=module.SCRIPT):
                system = g.make_stub(module, ufw_active=True, ufw_text=UFW_OK)
                system.can("nft -j list ruleset", json.dumps(nft))
                result = module.allowlist_assessment(
                    module.nft_ruleset_summary(system), module.ufw_status(system),
                    PORT, ["203.0.113.0/24"])
                self.assertEqual(result["status"], "fail", result)

    def test_ip_family_ufw_jump_still_transparent(self):
        nft = {
            "nftables": [
                {"table": {"family": "ip", "name": "filter"}},
                {"chain": {"family": "ip", "table": "filter", "name": "INPUT",
                           "type": "filter", "hook": "input", "policy": "drop"}},
                {"rule": {"family": "ip", "table": "filter", "chain": "INPUT", "expr": [
                    {"jump": {"target": "ufw-user-input"}},
                ]}},
            ]
        }
        for module in (g.STAGE0, g.STAGE2):
            with self.subTest(script=module.SCRIPT):
                system = g.make_stub(module, ufw_active=True, ufw_text=UFW_OK)
                system.can("nft -j list ruleset", json.dumps(nft))
                result = module.allowlist_assessment(
                    module.nft_ruleset_summary(system), module.ufw_status(system),
                    PORT, ["203.0.113.0/24"])
                self.assertEqual(result["status"], "pass", result)


if __name__ == "__main__":
    unittest.main()
