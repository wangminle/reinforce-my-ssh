"""BUG-082~091：loader 阻断语义、UFW nft 跳过、公网收口证据、重启扫描、Include、root 上下文、属主、端口落盘、门槛与 EvidenceError。"""
import importlib
import json
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
g = importlib.import_module("test-guides")

PORT = 62207
ALLOWS = ["203.0.113.0/24", "2001:db8::/32"]
UFW_OK = (
    "Status: active\n\nTo Action From\n-- ----- ----\n"
    "62207/tcp ALLOW IN 203.0.113.0/24\n"
    "62207/tcp ALLOW IN 2001:db8::/32\n"
    "62207/tcp DENY IN Anywhere\n"
    "62207/tcp (v6) DENY IN Anywhere (v6)\n"
)
STANDARD_LOADER = (
    "[Service]\nExecStart=/usr/sbin/nft -f /etc/nftables.d/ssh-allowlist.nft\n"
    "ExecReload=/usr/sbin/nft -f /etc/nftables.d/ssh-allowlist.nft\n"
)


def prepend_can(system, prefix, stdout="", returncode=0, stderr=""):
    rest = dict(system.canned)
    system.canned = {prefix: types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)}
    system.canned.update(rest)


def native_drop_with_icmp():
    return {
        "nftables": [
            {"table": {"family": "inet", "name": "filter"}},
            {"chain": {"family": "inet", "table": "filter", "name": "input",
                       "type": "filter", "hook": "input", "policy": "drop"}},
            {"rule": {"family": "inet", "table": "filter", "chain": "input", "expr": [
                {"match": {"op": "in", "left": {"ct": {"key": "state"}},
                           "right": {"set": ["established", "related"]}}},
                {"accept": None},
            ]}},
            {"rule": {"family": "inet", "table": "filter", "chain": "input", "expr": [
                {"match": {"op": "==", "left": {"payload": {"protocol": "icmp", "field": "type"}},
                           "right": "echo-request"}},
                {"accept": None},
            ]}},
        ]
    }


class TestBug082LoaderAllowlistSemantics(unittest.TestCase):
    def test_standard_inactive_loader_does_not_block_allowlist_commands(self):
        system = g.make_stub(
            g.STAGE2, session_port=PORT, listeners=[PORT], disk_ports=(PORT,), backup=True,
            auth=g.HARDENED_AUTH)
        system.touch_file("/etc/systemd/system/ssh-allowlist.service")
        system.set_read("/etc/systemd/system/ssh-allowlist.service", STANDARD_LOADER)
        prepend_can(system, "systemctl is-active ssh-allowlist.service",
                    stdout="inactive\n", returncode=3)
        facts = g.STAGE2.loader_facts(system)
        self.assertNotEqual(facts["status"], "fail", facts)
        g.patch_environment(g.STAGE2, system)
        options = g.STAGE2.parse_args(
            ["--port", str(PORT), "--user", "fenix", "--host", "h", "--rescue-confirmed",
             "--allow", "203.0.113.0/24"])
        ctx = g.STAGE2.resolve_context(system, options)
        steps = {s["id"]: s for s in g.STAGE2.build_steps(system, options, ctx)}
        self.assertNotEqual(steps["1-allowlist"]["status"], "blocked")
        self.assertTrue(any("sudo tee /etc/systemd/system/ssh-allowlist.service" in line
                            for line in steps["1-allowlist"]["do"]))

    def test_custom_loader_blocks_overwrite(self):
        system = g.make_stub(
            g.STAGE2, session_port=PORT, listeners=[PORT], disk_ports=(PORT,), backup=True,
            auth=g.HARDENED_AUTH)
        system.touch_file("/etc/systemd/system/ssh-allowlist.service")
        system.set_read("/etc/systemd/system/ssh-allowlist.service",
                        "[Service]\nExecStart=/usr/local/bin/custom-nft.sh\n")
        facts = g.STAGE2.loader_facts(system)
        self.assertEqual(facts["status"], "fail", facts)
        g.patch_environment(g.STAGE2, system)
        options = g.STAGE2.parse_args(
            ["--port", str(PORT), "--user", "fenix", "--host", "h", "--rescue-confirmed",
             "--allow", "203.0.113.0/24"])
        ctx = g.STAGE2.resolve_context(system, options)
        steps = {s["id"]: s for s in g.STAGE2.build_steps(system, options, ctx)}
        self.assertEqual(steps["1-allowlist"]["status"], "blocked")
        joined = "\n".join(steps["1-allowlist"]["do"])
        self.assertNotIn("sudo tee /etc/systemd/system/ssh-allowlist.service", joined)


class TestBug083UfwSkipOnlyJumps(unittest.TestCase):
    def test_native_policy_drop_with_icmp_fails_under_ufw(self):
        for module in (g.STAGE0, g.STAGE2):
            with self.subTest(script=module.SCRIPT):
                system = g.make_stub(module, ufw_active=True, ufw_text=UFW_OK)
                system.can("nft -j list ruleset", json.dumps(native_drop_with_icmp()))
                summary = module.nft_ruleset_summary(system)
                ufw = module.ufw_status(system)
                result = module.allowlist_assessment(summary, ufw, PORT, ALLOWS)
                self.assertEqual(result["status"], "fail", result)

    def test_pure_iptables_nft_jump_still_transparent(self):
        jump_only = {
            "nftables": [
                {"table": {"family": "ip", "name": "filter"}},
                {"chain": {"family": "ip", "table": "filter", "name": "INPUT",
                           "type": "filter", "hook": "input", "policy": "drop"}},
                {"rule": {"family": "ip", "table": "filter", "chain": "INPUT", "expr": [
                    {"jump": {"target": "ufw-user-input"}},
                ]}},
            ]
        }
        ufw_v4 = (
            "Status: active\n\nTo Action From\n-- ----- ----\n"
            "62207/tcp ALLOW IN 203.0.113.0/24\n"
            "62207/tcp DENY IN Anywhere\n"
            "62207/tcp (v6) DENY IN Anywhere (v6)\n"
        )
        for module in (g.STAGE0, g.STAGE2):
            with self.subTest(script=module.SCRIPT):
                system = g.make_stub(module, ufw_active=True, ufw_text=ufw_v4)
                system.can("nft -j list ruleset", json.dumps(jump_only))
                result = module.allowlist_assessment(
                    module.nft_ruleset_summary(system), module.ufw_status(system), PORT, ["203.0.113.0/24"])
                self.assertEqual(result["status"], "pass", result)


class TestBug084ClosePublicEvidence(unittest.TestCase):
    def test_missing_binding_evidence_is_unknown_not_done(self):
        system = g.make_stub(
            g.STAGE2, session_source="100.64.1.9", session_port=PORT, listeners=[PORT],
            backup=True, tailnet=True, bind_address="0.0.0.0", listener_process="sshd")
        # 多进程共享：首个进程名不是 sshd/systemd，旧正则会丢掉整行。
        system.can(
            "ss -tlnpH",
            'LISTEN 0 4096 0.0.0.0:%d 0.0.0.0:* users:(("other",pid=9,fd=3),("sshd",pid=1,fd=4))\n' % PORT)
        system.can("systemctl show ssh.socket",
                   "LoadState=loaded\nActiveState=active\nAccept=no\nListen=0.0.0.0:%d (Stream)\n" % PORT)
        g.patch_environment(g.STAGE2, system)
        options = g.STAGE2.parse_args(
            ["--port", str(PORT), "--user", "fenix", "--host", "h", "--rescue-confirmed",
             "--tailnet", "--tailnet-session-confirmed"])
        ctx = g.STAGE2.resolve_context(system, options)
        self.assertTrue(any(item["port"] == PORT for item in ctx["bindings"]), ctx["bindings"])
        steps = {s["id"]: s for s in g.STAGE2.build_steps(system, options, ctx)}
        self.assertNotEqual(steps["1b-close-public"]["status"], "done")

    def test_socket_listen_without_ss_process_merges_into_bindings(self):
        system = g.make_stub(
            g.STAGE2, session_source="100.64.1.9", session_port=PORT, listeners=[PORT],
            backup=True, tailnet=True)
        system.can("ss -tlnpH", "LISTEN 0 4096 0.0.0.0:%d 0.0.0.0:*\n" % PORT)
        system.can("systemctl show ssh.socket",
                   "LoadState=loaded\nActiveState=active\nAccept=no\nListen=0.0.0.0:%d (Stream)\n" % PORT)
        bindings = g.STAGE2.sshd_bindings(system)
        self.assertTrue(any(item["port"] == PORT for item in bindings), bindings)
        exposed = g.STAGE2.public_exposure(bindings, PORT)
        self.assertTrue(exposed)


class TestBug085RebootScansUfw(unittest.TestCase):
    def test_ufw_rules_mtime_after_boot_blocks_booted_after_hardening(self):
        for module in (g.STAGE0, g.STAGE2):
            with self.subTest(script=module.SCRIPT):
                system = g.make_stub(module, btime=1000000000, hardening_mtime=999999999)
                system.touch_file("/etc/ufw/user.rules")
                system.mtimes["/etc/ufw/user.rules"] = 1000000500
                system.touch_dir("/etc/ufw", ["user.rules"])
                facts = module.reboot_facts(system)
                self.assertFalse(facts.get("booted_after_hardening"), facts)


class TestBug086IncludeQuotedAndParentGlob(unittest.TestCase):
    def test_quoted_and_parent_glob_includes_are_followed(self):
        for module in (g.STAGE0, g.STAGE1, g.STAGE2):
            with self.subTest(script=module.SCRIPT):
                system = g.make_stub(module)
                system.touch_dir("/etc/ssh/sshd_config.d", [])
                system.touch_dir("/etc/ssh", ["sshd_config", "quoted.conf", "subdir"])
                system.touch_dir("/etc/ssh/subdir", ["extra.conf"])
                system.touch_file("/etc/ssh/quoted.conf")
                system.touch_file("/etc/ssh/subdir/extra.conf")
                system.set_read(
                    "/etc/ssh/sshd_config",
                    'Include "/etc/ssh/quoted.conf"\nInclude /etc/ssh/sub*/*.conf\n')
                system.set_read("/etc/ssh/quoted.conf", "Match Address 198.51.100.0/24\n")
                system.set_read("/etc/ssh/subdir/extra.conf", "Port 22\n")
                files = module.sshd_config_files(system)
                self.assertTrue(any(path.endswith("quoted.conf") for path in files), files)
                self.assertTrue(any(path.endswith("extra.conf") for path in files), files)
                self.assertEqual(len(module.match_blocks(system)), 1)

    def test_exists_permission_error_does_not_abort(self):
        for module in (g.STAGE0, g.STAGE1, g.STAGE2):
            with self.subTest(script=module.SCRIPT):
                system = g.make_stub(module)
                system.touch_dir("/etc/ssh/sshd_config.d", [])
                system.set_read("/etc/ssh/sshd_config", "Include /etc/ssh/secret.conf\n")
                original = system.exists

                def flaky(path):
                    if path == "/etc/ssh/secret.conf":
                        raise module.EvidenceError("无法检查路径 " + path)
                    return original(path)

                system.exists = flaky
                self.assertEqual(module.sshd_config_files(system), ["/etc/ssh/sshd_config"])


class TestBug087Stage2RootContext(unittest.TestCase):
    def test_root_match_permit_root_yes_keeps_auth_open(self):
        system = g.make_stub(
            g.STAGE2, session_port=PORT, listeners=[PORT], disk_ports=(PORT,), backup=True,
            auth=g.HARDENED_AUTH, allowlist_rules=g.ALLOW_RULES, hardening_mtime=999999999)

        def sshd_t(*args):
            ctx = args[args.index("-C") + 1] if "-C" in args else ""
            auth = dict(g.HARDENED_AUTH)
            if "user=root" in ctx:
                auth["permitrootlogin"] = "yes"
            return types.SimpleNamespace(
                returncode=0, stdout="".join("%s %s\n" % (k, v) for k, v in auth.items()), stderr="")

        original = system.run_allow_fail

        def routed(*args):
            if args and args[0] == "sshd" and "-T" in args:
                return sshd_t(*args)
            return original(*args)

        system.run_allow_fail = routed
        g.patch_environment(g.STAGE2, system)
        options = g.STAGE2.parse_args(
            ["--port", str(PORT), "--user", "fenix", "--host", "h", "--rescue-confirmed",
             "--allow", "203.0.113.0/24", "--reboot-confirmed"])
        ctx = g.STAGE2.resolve_context(system, options)
        self.assertEqual(ctx["auth_facts"].get("permitrootlogin"), "no")
        self.assertEqual(ctx.get("root_auth_facts", {}).get("permitrootlogin"), "yes")
        steps = {s["id"]: s for s in g.STAGE2.build_steps(system, options, ctx)}
        self.assertNotEqual(steps["2-auth"]["status"], "done")
        self.assertIn("禁 root=fail", steps["3-confirm"]["evidence"])


class TestBug088RootOwnedKeysUnsafe(unittest.TestCase):
    def test_root_owned_ssh_dir_and_keys_are_unsafe(self):
        for module in (g.STAGE0, g.STAGE1, g.STAGE2):
            with self.subTest(script=module.SCRIPT):
                system = g.make_stub(module)
                system.set_stat("/home/fenix/.ssh", 0o40700, 0)
                system.set_stat("/home/fenix/.ssh/authorized_keys", 0o100600, 0)
                facts = module.account_facts(system, "fenix")
                self.assertFalse(facts["permissions_safe"], facts)
                self.assertFalse(facts.get("ssh_dir_owner_ok"))
                self.assertFalse(facts.get("authorized_keys_owner_ok"))


class TestBug089DiskPortsRespectLayout(unittest.TestCase):
    def test_socket_mode_requires_listenstream_not_just_sshd_port(self):
        system = g.make_stub(
            g.STAGE1, session_port=PORT, listeners=[PORT], disk_ports=(PORT,),
            backup=True, socket_active=True)
        system.touch_dir("/etc/systemd/system/ssh.socket.d", [])
        system.set_read("/etc/ssh/sshd_config", "Port %d\n" % PORT)
        system.touch_dir("/etc/ssh/sshd_config.d", [])
        g.patch_environment(g.STAGE1, system)
        options = g.STAGE1.parse_args(
            ["--port", str(PORT), "--user", "fenix", "--host", "h", "--rescue-confirmed"])
        ctx = g.STAGE1.resolve_context(system, options)
        self.assertNotIn(PORT, ctx["disk_ports"])
        steps = {s["id"]: s for s in g.STAGE1.build_steps(system, options, ctx)}
        self.assertNotEqual(steps["3-new-port"]["status"], "done")

    def test_listenstream_clear_and_range_validation(self):
        system = g.make_stub(g.STAGE1, socket_active=True)
        system.touch_dir("/etc/ssh/sshd_config.d", [])
        system.set_read("/etc/ssh/sshd_config", "")
        system.touch_dir("/etc/systemd/system/ssh.socket.d", ["10-a.conf", "20-b.conf"])
        system.set_read("/etc/systemd/system/ssh.socket.d/10-a.conf",
                        "ListenStream=22\nListenStream=99999\n")
        system.set_read("/etc/systemd/system/ssh.socket.d/20-b.conf",
                        "ListenStream=\nListenStream=%d\n" % PORT)
        ports = g.STAGE1.disk_port_directives(system, source="socket")
        self.assertEqual(set(ports), {PORT})
        self.assertNotIn(22, ports)
        self.assertNotIn(99999, ports)


class TestBug090BlockedStepsHideCommands(unittest.TestCase):
    def test_stage1_close_old_blocked_has_no_executable_commands(self):
        system = g.make_stub(
            g.STAGE1, session_port=PORT, listeners=[22, PORT], disk_ports=(22, PORT), backup=True)
        g.patch_environment(g.STAGE1, system)
        options = g.STAGE1.parse_args(
            ["--port", str(PORT), "--user", "fenix", "--host", "h", "--old-port", "22"])
        ctx = g.STAGE1.resolve_context(system, options)
        steps = {s["id"]: s for s in g.STAGE1.build_steps(system, options, ctx)}
        close = steps["5-close-old"]
        self.assertEqual(close["status"], "blocked")
        self.assertTrue(close["blocked_by"])
        self.assertIn("门槛未满足", "\n".join(close["do"]))
        for line in close["do"]:
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            self.assertFalse(stripped.startswith("sudo"), line)

    def test_stage2_gated_steps_blocked_when_preconditions_fail(self):
        system = g.make_stub(g.STAGE2)
        g.patch_environment(g.STAGE2, system)
        options = g.STAGE2.parse_args(
            ["--port", str(PORT), "--user", "fenix", "--host", "h", "--rescue-confirmed",
             "--allow", "203.0.113.0/24"])
        ctx = g.STAGE2.resolve_context(system, options)
        steps = {s["id"]: s for s in g.STAGE2.build_steps(system, options, ctx)}
        for sid in ("1-allowlist", "2-auth", "4-reboot-verify"):
            step = steps[sid]
            self.assertEqual(step["status"], "blocked", sid)
            self.assertTrue(step["blocked_by"], sid)
            self.assertIn("门槛未满足", "\n".join(step["do"]))
            for line in step["do"]:
                stripped = line.strip()
                if stripped.startswith("#") or not stripped:
                    continue
                self.assertFalse(stripped.startswith("sudo"), "%s: %s" % (sid, line))


class TestBug091MainCatchesEvidenceError(unittest.TestCase):
    def test_stage1_and_stage2_return_2_on_resolve_evidence_error(self):
        for module, argv in (
            (g.STAGE1, ["--port", str(PORT), "--user", "fenix", "--format", "json"]),
            (g.STAGE2, ["--port", str(PORT), "--user", "fenix", "--allow", "203.0.113.0/24",
                        "--format", "json"]),
        ):
            with self.subTest(script=module.SCRIPT):
                system = g.make_stub(module)
                system.can("ss -tlnpH", "", returncode=127, stderr="ss: not found")
                code, output = g.run_main(module, argv, system)
                self.assertEqual(code, 2)
                self.assertNotIn("Traceback", output)
                report = json.loads(output)
                self.assertIn("error", report)


if __name__ == "__main__":
    unittest.main()
