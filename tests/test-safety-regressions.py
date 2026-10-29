"""京东云反馈回归：证据不足、备份失败、阶段衔接与生成命令的实际 shell 行为。"""
import contextlib
import importlib.util
import io
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# 统一入口复用已加载模块，也支持单独运行此文件。
if "test_guides" in sys.modules:
    g = sys.modules["test_guides"]
else:
    spec = importlib.util.spec_from_file_location("test_guides", Path(__file__).with_name("test-guides.py"))
    g = importlib.util.module_from_spec(spec)
    sys.modules["test_guides"] = g
    spec.loader.exec_module(g)


class TestSafetyRegressions(unittest.TestCase):
    def test_system_permission_errors_are_evidence_errors(self):
        for module in (g.STAGE0, g.STAGE1, g.STAGE2):
            # 直接使用类；其它用例可能临时替换 module.System。
            namespace = {}
            exec(module.SOURCE.split("def entry_dir", 1)[0], namespace)
            with patch.object(Path, "stat", side_effect=PermissionError("EACCES")):
                for method in ("exists", "is_dir"):
                    with self.assertRaises(namespace["EvidenceError"]):
                        getattr(namespace["System"](), method)("/private/file")

    def test_nonroot_does_not_claim_missing_listener_is_closed(self):
        module = g.STAGE0
        system = g.make_stub(module, socket_active=False, sshd_config_valid=False)
        system.can("ss -tlnpH", "LISTEN 0 4096 0.0.0.0:62207 0.0.0.0:*\n")
        with patch.object(module, "System", return_value=system), patch.object(module, "is_root", return_value=False):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = module.main(["--port", "62207", "--closed-port", "22", "--format", "json"])
        report = json.loads(output.getvalue())
        self.assertEqual(code, 2)
        statuses = {x["item"]: x["status"] for x in report["assessment"]}
        for item in ("新端口监听", "旧端口 22 已关闭", "禁止 root 登录", "公钥认证可用"):
            self.assertEqual(statuses[item], "unknown")
        self.assertFalse(any(call[:2] == ["sshd", "-t"] for call in system.calls))

    def test_nonroot_retains_positive_socket_evidence(self):
        module = g.STAGE0
        system = g.make_stub(module, listeners=[62207])
        with patch.object(module, "is_root", return_value=False):
            facts = module.collect(system, module.parse_args(["--port", "62207"]))
            items, _, _ = module.assess(facts, module.parse_args(["--port", "62207"]))
        self.assertEqual(next(x["status"] for x in items if x["item"] == "新端口监听"), "pass")

    def test_collect_catches_raw_oserror(self):
        system = g.make_stub(g.STAGE0)
        system.exists = lambda path: (_ for _ in ()).throw(PermissionError("private"))
        facts = g.STAGE0.collect(system, g.STAGE0.parse_args([]))
        self.assertTrue(facts["failed"])

    def test_disabled_pubkey_cannot_complete_auth_or_confirmation(self):
        for value in ("no", None):
            auth = dict(g.HARDENED_AUTH)
            if value is None:
                del auth["pubkeyauthentication"]
            else:
                auth["pubkeyauthentication"] = value
            _, _, _, steps = g.TestStage2Steps().build(
                session_port=62207, listeners=[62207], disk_ports=(62207,), backup=True,
                auth=auth, allowlist_rules=g.ALLOW_RULES)
            self.assertNotEqual(steps["2-auth"]["status"], "done")
            self.assertNotEqual(steps["3-confirm"]["status"], "done")
            self.assertIn("PubkeyAuthentication yes", steps["2-auth"]["do"])

    def test_stage0_disabled_pubkey_is_not_verified(self):
        for value in ("no", None):
            auth = dict(g.HARDENED_AUTH)
            if value is None:
                del auth["pubkeyauthentication"]
            else:
                auth["pubkeyauthentication"] = value
            code, output, _ = g.TestStage0Assessment().run_stage0(
                ["--port", "62207", "--user", "fenix", "--allow", "203.0.113.0/24", "--format", "json"],
                session_port=62207, listeners=[62207], disk_ports=(62207,), backup=True,
                auth=auth, allowlist_rules=g.ALLOW_RULES, hardening_mtime=999999999)
            report = json.loads(output)
            statuses = {item["item"]: item["status"] for item in report["assessment"]}
            self.assertNotEqual(statuses["公钥认证可用"], "pass", value)
            self.assertEqual(report["position"], "stage1-done", value)
            self.assertEqual(code, 2, value)

    def test_declared_goals_unmet_exit_2_without_goals_exit_0(self):
        code, output, _ = g.TestStage0Assessment().run_stage0(
            ["--port", "62207", "--user", "fenix", "--allow", "203.0.113.0/24", "--format", "json"])
        report = json.loads(output)
        self.assertEqual(report["position"], "stage1-progress")
        self.assertEqual(code, 2)
        code, output, _ = g.TestStage0Assessment().run_stage0(["--format", "json"])
        report = json.loads(output)
        self.assertEqual(report["position"], "goals-undeclared")
        self.assertEqual(code, 0)

    def test_unsafe_permissions_and_owners_block_account_and_port_change(self):
        for path, mode, uid in (("/home/fenix", 0o40777, 1000),
                                ("/home/fenix/.ssh", 0o40777, 1000),
                                ("/home/fenix/.ssh/authorized_keys", 0o100666, 1000),
                                ("/home/fenix/.ssh/authorized_keys", 0o100600, 2000)):
            system = g.make_stub(g.STAGE1, backup=True)
            system.set_stat(path, mode, uid)
            options = g.STAGE1.parse_args(["--port", "62207", "--user", "fenix"])
            ctx = g.STAGE1.resolve_context(system, options)
            steps = {x["id"]: x for x in g.STAGE1.build_steps(system, options, ctx)}
            self.assertEqual(steps["2-account"]["status"], "todo")
            self.assertEqual(steps["3-new-port"]["status"], "blocked")
            self.assertIn("2-account", steps["3-new-port"]["blocked_by"])
            commands = "\n".join(steps["2-account"]["do"])
            self.assertIn("sudo chmod 600", commands)
            self.assertNotIn("chown -R", commands)

    def test_safe_noncanonical_permissions_are_accepted(self):
        system = g.make_stub(g.STAGE1)
        system.set_stat("/home/fenix/.ssh", 0o40755, 1000)
        system.set_stat("/home/fenix/.ssh/authorized_keys", 0o100644, 1000)
        self.assertTrue(g.STAGE1.account_facts(system, "fenix")["permissions_safe"])

    def test_stage2_also_rejects_unsafe_account(self):
        system, options, ctx, _ = g.TestStage2Steps().build(
            session_port=62207, listeners=[62207], backup=True, auth=g.HARDENED_AUTH)
        ctx["account"]["permissions_safe"] = False
        steps = {x["id"]: x for x in g.STAGE2.build_steps(system, options, ctx)}
        self.assertEqual(steps["0-preconditions"]["status"], "blocked")

    def test_partial_backup_never_unlocks(self):
        for module in (g.STAGE0, g.STAGE1, g.STAGE2):
            for missing in ("units.txt", "backup-complete", "nft-ruleset.nft", "ssh.socket.d.absent"):
                system = g.make_stub(module, backup=True)
                system.files.remove("/var/backups/ssh-hardening/20261027-160000/" + missing)
                self.assertFalse(module.backup_facts(system, module.BACKUP_ROOT)["complete"])

    def test_unavailable_firewall_tools_are_explicit_backup_evidence(self):
        system = g.make_stub(g.STAGE1, backup=True)
        root = "/var/backups/ssh-hardening/20261027-160000/"
        for name in ("nft-ruleset.nft", "ufw-status.txt"):
            system.files.remove(root + name)
            system.touch_file(root + name + ".unavailable")
        self.assertTrue(g.STAGE1.backup_facts(system, g.STAGE1.BACKUP_ROOT)["complete"])

    def test_unknown_old_port_blocks_traditional_config(self):
        system, options, ctx, _ = g.TestStage1Steps().steps(backup=True, socket_active=False)
        ctx["old_port"] = None
        steps = {x["id"]: x for x in g.STAGE1.build_steps(system, options, ctx)}
        self.assertEqual(steps["3-new-port"]["status"], "blocked")
        self.assertNotIn("Port OLD_PORT", "\n".join(steps["3-new-port"]["do"]))

    def test_unknown_old_port_resume_does_not_claim_none(self):
        _, _, ctx, steps = g.TestStage1Steps().steps(
            socket_active=False, session_port=62207, listeners=[22, 2222, 62207],
            disk_ports=(22, 2222, 62207), backup=True)
        self.assertIsNone(ctx["old_port"])
        resume = next(line for line in steps["4-verify-new"]["do"] if "stage1-port-key.sh" in line)
        self.assertNotIn("--old-port", resume)
        executable = [line for line in steps["4-verify-new"]["do"] + steps["5-close-old"]["do"]
                      if line.strip() and not line.lstrip().startswith("#")]
        for line in executable:
            self.assertNotIn("--old-port none", line)
        _, _, explicit, explicit_steps = g.TestStage1Steps().steps(
            socket_active=False, session_port=62207, listeners=[62207], extra=["--old-port", "none"])
        self.assertEqual(explicit["old_port"], "none")
        explicit_resume = next(line for line in explicit_steps["4-verify-new"]["do"] if "stage1-port-key.sh" in line)
        self.assertIn("--old-port none", explicit_resume)

    def test_explicit_no_old_port_has_no_placeholder_config(self):
        _, _, _, steps = g.TestStage1Steps().steps(backup=True, socket_active=False, extra=["--old-port", "none"])
        self.assertNotIn("Port OLD_PORT", "\n".join(steps["3-new-port"]["do"]))
        self.assertNotEqual(steps["5-close-old"]["status"], "done")

    def test_old_port_cleanup_names_main_and_dropin_files(self):
        _, _, _, steps = g.TestStage1Steps().steps(
            session_port=62207, listeners=[22, 62207], backup=True, socket_active=False,
            disk_ports=(22, 62207), extra=["--rescue-confirmed"])
        commands = steps["5-close-old"]["do"]
        self.assertIn("sudoedit -- /etc/ssh/sshd_config", commands)
        self.assertIn("sudoedit -- /etc/ssh/sshd_config.d/10-newport.conf", commands)
        self.assertIn("sport = :22", steps["5-close-old"]["verify"][0])
        self.assertNotIn("grep", steps["5-close-old"]["verify"][0])

    def test_socket_override_does_not_require_removing_shadowed_port(self):
        _, _, _, steps = g.TestStage1Steps().steps(
            session_port=62207, listeners=[62207], backup=True, disk_ports=(22, 62207),
            extra=["--old-port", "22", "--rescue-confirmed"])
        self.assertEqual(steps["5-close-old"]["status"], "done")

    def test_timer_state_consistency(self):
        for module in (g.STAGE0, g.STAGE1, g.STAGE2):
            for active, enabled, expected in (("inactive", "enabled", True), ("active", "disabled", True),
                                               ("inactive", "disabled", False), ("unknown", "unknown", True)):
                system = g.make_stub(module, timer_active=True)
                system.canned["systemctl is-active"] = type("Result", (), {"stdout": active, "returncode": 0})()
                system.canned["systemctl is-enabled"] = type("Result", (), {"stdout": enabled, "returncode": 0})()
                result = module.legacy_facts(system)["blocking"] if module is g.STAGE0 else module.legacy_blocking(system)[0]
                self.assertEqual(bool(result), expected, (module.SCRIPT, active, enabled))

    def test_ufw_handoff_installs_specific_rules_before_removing_bridge(self):
        text = "Status: active\n62207/tcp ALLOW Anywhere\n"
        _, _, _, steps = g.TestStage2Steps().build(
            session_port=62207, listeners=[62207], backup=True, ufw_active=True, ufw_text=text)
        commands = steps["1-allowlist"]["do"]
        allow = next(i for i, x in enumerate(commands) if "insert 1 allow from" in x)
        deny = next(i for i, x in enumerate(commands) if "ufw deny" in x)
        delete = commands.index("sudo ufw delete allow 62207/tcp")
        self.assertLess(allow, deny)
        self.assertLess(deny, delete)
        # 收口后的实际规则文本可以通过当前检查器。
        assessment = g.STAGE2.allowlist_assessment({"rules": [], "input_policy": []},
            {"active": True, "text": "62207/tcp ALLOW 203.0.113.0/24\n62207/tcp DENY Anywhere"},
            62207, ["203.0.113.0/24"])
        self.assertEqual(assessment["status"], "pass")

    def test_nft_handoff_only_deletes_owned_bridge_handle(self):
        raw = json.loads(g.packet_nft(g.ALLOW_RULES + [("accept", 62207, None, ("new",))]))
        bridge = raw["nftables"][-1]["rule"]
        bridge.update(comment="stage1 new-port bridge", handle=42)
        system, options, ctx, _ = g.TestStage2Steps().build(
            session_port=62207, listeners=[62207], backup=True)
        system.canned["nft -j list ruleset"].stdout = json.dumps(raw)
        ctx["nft"] = g.STAGE2.nft_ruleset_summary(system)
        commands = {x["id"]: x for x in g.STAGE2.build_steps(system, options, ctx)}["1-allowlist"]["do"]
        delete = "sudo nft delete rule inet sshguard ssh_allow handle 42"
        self.assertIn(delete, commands)
        self.assertLess(next(i for i, x in enumerate(commands) if x.startswith("sudo nft -f")), commands.index(delete))
        bridge["comment"] = "unrelated rule"
        system.canned["nft -j list ruleset"].stdout = json.dumps(raw)
        self.assertNotIn(delete, g.STAGE2.transition_cleanup(g.STAGE2.nft_ruleset_summary(system), 62207))

    def test_backup_path_validation_and_resume_quoting(self):
        for module in (g.STAGE0, g.STAGE1, g.STAGE2):
            base = [] if module is g.STAGE0 else ["--port", "62207", "--user", "fenix"]
            if module is g.STAGE2:
                base += ["--allow", "203.0.113.0/24"]
            for path in ("relative", "/", "/var/../etc", "/var/a\nb"):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    module.parse_args(base + ["--backup-dir", path])
            value = "/var/backups/ssh guide's $(id);x"
            self.assertEqual(module.parse_args(base + ["--backup-dir", value]).backup_dir, value)
        _, _, _, steps = g.TestStage1Steps().steps(extra=["--backup-dir", value])
        self.assertIn("--backup-dir " + shlex.quote(value), "\n".join(steps["4-verify-new"]["do"]))

    def test_generated_nft_rules_compile_in_isolated_network_namespace(self):
        if os.name == "nt":
            self.skipTest("实际 nft 语法检查由 Linux/WSL 执行")
        _, _, _, steps = g.TestStage2Steps().build(
            session_port=62207, listeners=[62207], backup=True,
            extra=["--tailnet"], tailnet=True, allow=["203.0.113.0/24", "2001:db8::/32"])
        commands = steps["1-allowlist"]["do"]
        start = commands.index("table inet sshguard {")
        end = commands.index("EOF", start)
        rules = "\n".join(commands[start:end]) + "\n"
        result = subprocess.run(["unshare", "-Urn", "--", "nft", "-c", "-f", "-"],
                                input=rules, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_generated_backup_executes_in_shell_and_stops_on_failure(self):
        if os.name == "nt":
            self.skipTest("实际 shell 回归由 Linux/WSL 执行")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bindir = root / "bin"
            bindir.mkdir()
            programs = {
                "sudo": '#!/bin/sh\nexec "$@"\n',
                "cp": '#!/usr/bin/env python3\nimport sys,pathlib\np=pathlib.Path(sys.argv[-1])\nif sys.argv[-2].endswith(".d"): p.mkdir()\nelse: p.write_text("fixture")\n',
                "nft": '#!/bin/sh\n[ "${FAIL_NFT:-0}" = 0 ] || exit 7\nprintf "table inet fixture {}\\n"\n',
                "ufw": '#!/bin/sh\nprintf "Status: inactive\\n"\n',
                "systemctl": '#!/bin/sh\nprintf "ActiveState=active\\n"\n',
            }
            for name, body in programs.items():
                path = bindir / name
                path.write_text(body)
                path.chmod(0o755)
            env = dict(os.environ, PATH=str(bindir) + ":" + os.environ["PATH"])
            destination = root / "backup space's $(touch BAD);x"
            command = g.STAGE1.backup_commands(str(destination))[0]
            result = subprocess.run(["sh", "-c", command], env=env, capture_output=True, text=True, cwd=root)
            self.assertEqual(result.returncode, 0, result.stderr)
            snapshot = next(destination.iterdir())
            for name in ("sshd_config", "units.txt", "backup-complete", "nft-ruleset.nft", "ufw-status.txt"):
                self.assertTrue((snapshot / name).is_file(), name)
            self.assertFalse((root / "BAD").exists())
            failed_root = root / "failed backup"
            result = subprocess.run(["sh", "-c", g.STAGE1.backup_commands(str(failed_root))[0]],
                                    env=dict(env, FAIL_NFT="1"), capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(any(failed_root.glob("*/backup-complete")))


if __name__ == "__main__":
    unittest.main()
