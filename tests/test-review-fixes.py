"""BUG-042～056：真实格式、来源授权、生成指令与保守证据的回归。"""
import contextlib
import importlib.util
import io
import shlex
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

if "test_guides" in sys.modules:
    g = sys.modules["test_guides"]
else:
    spec = importlib.util.spec_from_file_location("test_guides", Path(__file__).with_name("test-guides.py"))
    g = importlib.util.module_from_spec(spec)
    sys.modules["test_guides"] = g
    spec.loader.exec_module(g)


class TestReviewFixes(unittest.TestCase):
    def test_ufw_verbose_in_sources_and_default_deny_are_parsed(self):
        for module in (g.STAGE0, g.STAGE2):
            for suffix in ("", " IN"):
                with self.subTest(module=module.SCRIPT, direction=suffix):
                    ufw = {"active": True, "text": "62207/tcp ALLOW%s 203.0.113.0/24\n62207/tcp DENY%s Anywhere\n" % (suffix, suffix)}
                    result = module.allowlist_assessment({"rules": [], "input_policy": []}, ufw, 62207, ["203.0.113.0/24"])
                    self.assertEqual(result["status"], "pass", result)

    def test_ufw_out_and_forward_are_not_input_evidence(self):
        for module in (g.STAGE0, g.STAGE2):
            for direction in ("OUT", "FWD"):
                with self.subTest(module=module.SCRIPT, direction=direction):
                    ufw = {"active": True, "text": "62207/tcp ALLOW %s 203.0.113.0/24\n62207/tcp DENY %s Anywhere\n" % (direction, direction)}
                    result = module.allowlist_assessment({"rules": [], "input_policy": []}, ufw, 62207, ["203.0.113.0/24"])
                    self.assertNotEqual(result["status"], "pass")

    def test_ufw_tailnet_then_verbose_in_deny_closes_public(self):
        ufw = {"active": True, "text": "62207/tcp on tailscale0 ALLOW IN Anywhere\n62207/tcp DENY IN Anywhere\n"}
        self.assertIs(g.STAGE2.ufw_public_verdict(ufw, 62207), False)
        for direction in ("OUT", "FWD"):
            with self.subTest(direction=direction):
                ufw["text"] = "62207/tcp DENY %s Anywhere\n" % direction
                self.assertIsNot(g.STAGE2.ufw_public_verdict(ufw, 62207), False)

    def test_cgnat_address_does_not_prove_tailnet_ingress(self):
        _, _, _, steps = g.TestStage2Steps().build(
            session_source="100.64.9.9", tailnet=True, allow=[],
            session_port=62207, listeners=[62207], backup=True, extra=["--tailnet"])
        self.assertEqual(steps["1-allowlist"]["status"], "blocked")
        self.assertFalse(any("sudo nft" in line for line in steps["1-allowlist"]["do"]))

    def test_explicit_cloud_source_remains_authorized_without_tailnet_claim(self):
        _, _, _, steps = g.TestStage2Steps().build(
            session_source="100.64.9.9", tailnet=True, allow=["100.64.9.9/32"],
            session_port=62207, listeners=[62207], backup=True, extra=["--tailnet"])
        self.assertNotEqual(steps["1-allowlist"]["status"], "blocked")

    def test_stage1_never_appends_bridge_to_first_accept_chain(self):
        system, options, ctx, _ = g.TestStage1Steps().steps(backup=True)
        ctx["firewall"]["ufw"] = {"active": False}
        ctx["firewall"]["nft_input"] = [
            {"family": "ip", "table": "filter", "chain": "INPUT", "policy": "accept"},
            {"family": "inet", "table": "filter", "chain": "input", "policy": "drop"},
            {"family": "ip6", "table": "v6", "chain": "input", "policy": "drop"}]
        steps = {s["id"]: s for s in g.STAGE1.build_steps(system, options, ctx)}
        commands = "\n".join(steps["3-new-port"]["do"])
        self.assertNotIn("nft add rule ip filter INPUT", commands)
        self.assertNotIn("nft add rule", commands)
        # 若不能可靠选择链，安全实现也可以仅给人工核对说明而不打印桥接命令。
        if "stage1 new-port bridge" in commands:
            self.assertIn("inet", commands)
            self.assertIn("ip6", commands)
            self.assertIn("insert rule", commands)

    def test_stage1_bridge_keeps_nft_comment_string_delimiters(self):
        system, options, ctx, _ = g.TestStage1Steps().steps(backup=True)
        ctx["firewall"]["ufw"] = {"active": False}
        ctx["firewall"]["nft_input"] = [{"family": "inet", "table": "filter", "chain": "input", "policy": "drop"}]
        steps = {s["id"]: s for s in g.STAGE1.build_steps(system, options, ctx)}
        for command in steps["3-new-port"]["do"]:
            if command.startswith("sudo nft") and "comment" in command:
                arguments = shlex.split(command)
                self.assertIn('"stage1 new-port bridge"', arguments)

    def test_stage2_replaces_only_owned_table_and_avoids_global_loader(self):
        _, _, _, steps = g.TestStage2Steps().build(
            session_port=62207, listeners=[62207], backup=True)
        commands = "\n".join(steps["1-allowlist"]["do"])
        self.assertNotIn("enable --now nftables.service", commands)
        self.assertFalse(any("flush ruleset" in " ".join(shlex.split(line, comments=True))
                             for line in commands.splitlines() if line.startswith("sudo ")))
        self.assertIn("delete table inet sshguard", commands)
        self.assertIn("ssh-allowlist.service", commands)

    def test_loader_backup_and_recovery_cover_unit_dropins_and_states(self):
        backup = "\n".join(g.STAGE1.backup_commands("/var/backups/test"))
        self.assertIn("/etc/systemd/system/ssh-allowlist.service", backup)
        self.assertIn("ssh-allowlist.service.d", backup)
        self.assertIn("is-active", backup)
        self.assertIn("is-enabled", backup)
        for module in (g.STAGE1, g.STAGE2):
            with self.subTest(module=module.SCRIPT):
                recovery = "\n".join(module.recovery_commands("/var/backups/test"))
                self.assertIn("/etc/systemd/system/ssh-allowlist.service", recovery)
                self.assertIn("ssh-allowlist.service.d", recovery)
                self.assertIn("systemctl", recovery)

    def test_dedicated_loader_has_no_stop_flush_and_atomic_replace(self):
        _, _, _, steps = g.TestStage2Steps().build(
            session_port=62207, listeners=[62207], backup=True)
        commands = "\n".join(steps["1-allowlist"]["do"])
        self.assertIn("delete table inet sshguard", commands)
        self.assertLess(commands.index("delete table inet sshguard"), commands.index("table inet sshguard {"))
        self.assertNotIn("ExecStop=", commands)
        self.assertIn("ExecStart=", commands)
        self.assertIn("nft -f", commands)

    def test_ufw_verbose_ipv6_after_ipv4_deny_remains_independent(self):
        text = ("62207/tcp ALLOW IN 203.0.113.9\n62207/tcp DENY IN Anywhere\n"
                "62207/tcp (v6) ALLOW IN 2001:db8::9\n62207/tcp (v6) DENY IN Anywhere (v6)\n")
        for module in (g.STAGE0, g.STAGE2):
            with self.subTest(module=module.SCRIPT):
                result = module.allowlist_assessment({"rules": [], "input_policy": []},
                    {"active": True, "text": text}, 62207,
                    ["203.0.113.9/32", "2001:db8::9/128"])
                self.assertEqual(result["status"], "pass", result)

    def test_loader_unknown_stop_dropin_cannot_pass(self):
        module = g.STAGE2
        system = g.make_stub(module)
        system.set_read("/etc/systemd/system/ssh-allowlist.service",
            "[Service]\nExecStart=/usr/sbin/nft -f /etc/nftables.d/ssh-allowlist.nft\n"
            "ExecReload=/usr/sbin/nft -f /etc/nftables.d/ssh-allowlist.nft\n")
        system.touch_dir("/etc/systemd/system/ssh-allowlist.service.d", ["90-old.conf"])
        system.set_read("/etc/systemd/system/ssh-allowlist.service.d/90-old.conf",
                        "[Service]\nExecStop=/usr/sbin/nft flush ruleset\n")
        self.assertNotEqual(module.loader_facts(system)["status"], "pass")

    def test_ufw_ipv4_deny_cannot_hide_ipv6_public_allow(self):
        ufw = {"active": True, "text":
            "62207/tcp on tailscale0 ALLOW IN Anywhere\n"
            "62207/tcp DENY IN Anywhere\n"
            "62207/tcp (v6) ALLOW IN Anywhere (v6)\n"}
        self.assertIsNot(g.STAGE2.ufw_public_verdict(ufw, 62207), False)

    def test_stage0_port_comments_match_stage1(self):
        values = []
        for module in (g.STAGE0, g.STAGE1):
            system = g.make_stub(module, disk_ports=())
            system.set_read("/etc/ssh/sshd_config", "Port 22 # old\nPort 62207 # new\n")
            system.touch_dir("/etc/ssh/sshd_config.d", [])
            values.append(module.disk_port_directives(system))
        self.assertEqual(set(values[0]), {22, 62207})
        self.assertEqual(values[0], values[1])

    def test_primary_config_and_loader_mtime_block_reboot_evidence(self):
        for module in (g.STAGE0, g.STAGE2):
            for changed in ("/etc/ssh/sshd_config", "/etc/systemd/system/ssh-allowlist.service"):
                with self.subTest(module=module.SCRIPT, changed=changed):
                    system = g.make_stub(module, disk_ports=(62207,), allowlist_rules=g.ALLOW_RULES,
                                         btime=1000000000, hardening_mtime=999999999)
                    system.touch_file(changed)
                    system.mtimes["/etc/ssh/sshd_config"] = 999999999
                    system.mtimes[changed] = 1000000001
                    self.assertIsNot(module.reboot_facts(system).get("booted_after_hardening"), True)

    def test_old_file_mtime_alone_cannot_certify_reboot_validation(self):
        _, _, _, steps = g.TestStage2Steps().build(
            session_port=62207, listeners=[62207], backup=True, disk_ports=(62207,),
            auth=g.HARDENED_AUTH, allowlist_rules=g.ALLOW_RULES, hardening_mtime=999999999)
        self.assertNotEqual(steps["4-reboot-verify"]["status"], "done")

    def test_stage0_missing_sources_produces_commented_template(self):
        system = g.make_stub(g.STAGE0, session_port=62207, listeners=[62207], disk_ports=(62207,), backup=True)
        options = g.STAGE0.parse_args(["--port", "62207", "--user", "fenix"])
        facts = g.STAGE0.collect(system, options)
        _, _, next_step = g.STAGE0.assess(facts, options)
        commands = [x for x in next_step["commands"] if "stage2-lockdown.sh" in x]
        self.assertTrue(commands)
        self.assertTrue(all(x.lstrip().startswith("#") for x in commands))
        self.assertTrue(any("REPLACE_WITH_TRUSTED_CIDR" in x for x in commands))
        self.assertFalse(any("--rescue-confirmed" in shlex.split(x.lstrip("# ")) for x in commands))

    def test_read_only_execution_rejects_hidden_mutating_arguments(self):
        for module in (g.STAGE0, g.STAGE1, g.STAGE2):
            namespace = {}
            exec(module.SOURCE.split("def entry_dir", 1)[0], namespace)
            system = namespace["System"]()
            for command in (("nft", "-j", "flush", "ruleset"), ("ss", "-K"),
                            ("journalctl", "--rotate"), ("journalctl", "--vacuum-time=1s")):
                with self.subTest(module=module.SCRIPT, command=command):
                    with patch("subprocess.run") as run:
                        with self.assertRaises(namespace["EvidenceError"]):
                            system.run_allow_fail(*command)
                        run.assert_not_called()


    def test_interface_bound_source_allow_does_not_cover_declared_network(self):
        ufw = {"active": True, "text":
            "62207/tcp on lo ALLOW IN 203.0.113.0/24\n62207/tcp DENY IN Anywhere\n"}
        rules = [("accept", 62207, ["203.0.113.0/24"], None, "lo"),
                 ("drop", 62207, None, None)]
        for module in (g.STAGE0, g.STAGE2):
            with self.subTest(module=module.SCRIPT, firewall="ufw"):
                result = module.allowlist_assessment({"rules": [], "input_policy": []}, ufw,
                                                     62207, ["203.0.113.0/24"])
                self.assertNotEqual(result["status"], "pass", result)
                self.assertIn("未证实全部声明来源", result["detail"])
            with self.subTest(module=module.SCRIPT, firewall="nft"):
                summary = module.nft_ruleset_summary(g.make_stub(module, allowlist_rules=rules))
                result = module.allowlist_assessment(summary, {}, 62207, ["203.0.113.0/24"])
                self.assertNotEqual(result["status"], "pass", result)
                self.assertIn("未证实全部声明来源", result["detail"])

    def test_loader_early_boot_unit_and_transaction_have_no_ordering_cycle(self):
        import os
        import shutil
        import subprocess
        import tempfile

        _, _, _, steps = g.TestStage2Steps().build(session_port=62207, listeners=[62207], backup=True)
        commands = "\n".join(steps["1-allowlist"]["do"])
        for expected in ("DefaultDependencies=no", "Wants=network-pre.target",
                         "After=local-fs.target network-pre.target",
                         "Before=ssh.service ssh.socket shutdown.target",
                         "Conflicts=shutdown.target", "WantedBy=sysinit.target"):
            self.assertIn(expected, commands)
        self.assertNotIn("WantedBy=multi-user.target", commands)
        if os.name == "nt" or not shutil.which("systemd-analyze"):
            self.skipTest("真实启动事务检查需要 Linux systemd-analyze")
        unit_text = commands.split("sudo tee /etc/systemd/system/ssh-allowlist.service >/dev/null <<'EOF'\n", 1)[1]
        unit_text = unit_text.split("\nEOF", 1)[0] + "\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixtures = {
                "ssh-allowlist.service": unit_text,
                "ssh.service": "[Service]\nExecStart=/bin/true\n",
                "ssh.socket": "[Socket]\nListenStream=127.0.0.1:62207\n",
                # 保留排序环涉及的 target 边；空的 basic.target 无法复现旧配置缺陷。
                "basic.target": "[Unit]\nRequires=sysinit.target\nWants=sockets.target\n"
                                "After=sysinit.target sockets.target\n",
                "sockets.target": "[Unit]\n",
                "sysinit.target": "[Unit]\nWants=local-fs.target\nAfter=local-fs.target\n",
                "local-fs.target": "[Unit]\nDefaultDependencies=no\n",
                "network-pre.target": "[Unit]\n",
                "multi-user.target": "[Unit]\nRequires=basic.target\nAfter=basic.target\n",
                "shutdown.target": "[Unit]\nDefaultDependencies=no\n",
            }
            for name, text in fixtures.items():
                (root / name).write_text(text)
            # 模拟 enable 的安装链接，只在临时树内建图，不加载或启动宿主单元。
            sockets = root / "sockets.target.wants"
            sockets.mkdir()
            (sockets / "ssh.socket").symlink_to(root / "ssh.socket")
            legacy_link = root / "multi-user.target.wants/ssh-allowlist.service"
            current_link = root / "sysinit.target.wants/ssh-allowlist.service"
            legacy_link.parent.mkdir()
            current_link.parent.mkdir()
            # 从实际启动目标展开依赖，不把每个夹具单元人为当成启动根。
            paths = [str(root / "multi-user.target")]
            env = dict(os.environ, SYSTEMD_UNIT_PATH=str(root))
            legacy = unit_text.replace(
                "DefaultDependencies=no\nWants=network-pre.target\nAfter=local-fs.target network-pre.target\n"
                "Before=ssh.service ssh.socket shutdown.target\nConflicts=shutdown.target",
                "Before=ssh.service ssh.socket").replace("WantedBy=sysinit.target", "WantedBy=multi-user.target")
            (root / "ssh-allowlist.service").write_text(legacy)
            legacy_link.symlink_to(root / "ssh-allowlist.service")
            old = subprocess.run(["systemd-analyze", "verify", *paths], env=env,
                                 capture_output=True, text=True)
            # Wants 任务可能被删除以解环，verify 仍返回 0；旧图必须检查环诊断，不能只看退出码。
            self.assertIn("ordering cycle", (old.stdout + old.stderr).lower(), old.stdout + old.stderr)
            self.assertIn("ssh-allowlist.service", old.stdout + old.stderr)
            legacy_link.unlink()
            (root / "ssh-allowlist.service").write_text(unit_text)
            current_link.symlink_to(root / "ssh-allowlist.service")
            current = subprocess.run(["systemd-analyze", "verify", *paths], env=env,
                                     capture_output=True, text=True)
            output = current.stdout + current.stderr
            self.assertEqual(current.returncode, 0, output)
            self.assertNotIn("ordering cycle", output.lower(), output)

    def test_numeric_and_unparsed_input_interfaces_never_prove_source_reachability(self):
        for module in (g.STAGE0, g.STAGE2):
            for right in (1, "lo", {"set": [1, 2]}, {"range": [1, 3]}, {"set": "@interfaces"}):
                for op in ("==", "!="):
                    with self.subTest(module=module.SCRIPT, right=right, op=op):
                        rule = {"expr": [
                            {"match": {"left": {"meta": {"key": "iif"}}, "op": op, "right": right}},
                            {"match": {"left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 62207}},
                            {"match": {"left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "203.0.113.0/24"}},
                            {"accept": None}]}
                        digest = module.rule_digest(rule)
                        digest["location"] = "inet/filter/input"
                        drop = module.rule_digest({"expr": [
                            {"match": {"left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 62207}},
                            {"drop": None}]})
                        drop["location"] = digest["location"]
                        result = module.allowlist_assessment({"rules": [digest, drop], "input_policy": []}, {}, 62207, ["203.0.113.0/24"])
                        self.assertNotEqual(result["status"], "pass", result)
                        self.assertTrue(digest["iifs"], digest)

    def test_unknown_numeric_interface_is_not_tailnet_or_global_drop_evidence(self):
        for module in (g.STAGE0, g.STAGE2):
            for verdict in ("accept", "drop"):
                guarded = module.rule_digest({"expr": [
                    {"match": {"left": {"meta": {"key": "iif"}}, "op": "!=", "right": 1}},
                    *([{"match": {"left": {"meta": {"key": "iifname"}}, "op": "==", "right": "tailscale0"}}] if verdict == "accept" else []),
                    {"match": {"left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 62207}},
                    {verdict: None}]})
                plain = module.rule_digest({"expr": [
                    {"match": {"left": {"meta": {"key": "iifname"}}, "op": "==", "right": "tailscale0"}},
                    {"match": {"left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 62207}},
                    {"accept": None}]})
                for digest in (guarded, plain):
                    digest["location"] = "inet/filter/input"
                unconditional_drop = dict(plain, iifs=[], verdict="drop")
                rules = [guarded, unconditional_drop] if verdict == "accept" else [plain, guarded]
                result = module.allowlist_assessment({"rules": rules, "input_policy": []}, {}, 62207, [], tailnet=True)
                self.assertNotEqual(result["status"], "pass", result)

    def test_kernel_nft_numeric_interface_json_keeps_source_restricted(self):
        import os
        import shutil
        import subprocess
        if os.name == "nt" or not shutil.which("unshare") or not shutil.which("nft"):
            self.skipTest("真实 nft JSON 验证需要 Linux 用户/网络命名空间")
        script = '''import subprocess
subprocess.run(['nft','-f','-'],input='table inet review { chain input { type filter hook input priority 0; policy accept; iif 1 tcp dport 62207 ip saddr 203.0.113.0/24 accept; tcp dport 62207 drop; }; }\\n',text=True,check=True)
print(subprocess.check_output(['nft','-j','-n','list','ruleset'],text=True))
'''
        result = subprocess.run(["unshare", "-Urn", "--", sys.executable, "-c", script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        for module in (g.STAGE0, g.STAGE2):
            system = g.make_stub(module)
            system.can("nft -j list ruleset", result.stdout)
            summary = module.nft_ruleset_summary(system)
            assessment = module.allowlist_assessment(summary, {}, 62207, ["203.0.113.0/24"])
            self.assertNotEqual(assessment["status"], "pass", assessment)


if __name__ == "__main__":
    unittest.main()
