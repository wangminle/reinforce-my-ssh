"""三个只读指导脚本的回归测试：解析、判定、门槛、退出码与只读保证。

全部通过 StubSystem 内存桩件运行，不接触真实系统、不改动仓库。
运行：python3 tests/run-tests.py
"""
import contextlib
import ast
import importlib
import io
import json
import subprocess
import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
guide_support = importlib.import_module("guide-support")  # 连字符文件名：按模块名导入
ROOT = guide_support.ROOT
StubSystem = guide_support.StubSystem
bind_stub = guide_support.bind_stub
load_script = guide_support.load_script
packet_nft = guide_support.packet_nft
script_source = guide_support.script_source

STAGE0 = load_script("stage0-check.sh")
STAGE1 = load_script("stage1-port-key.sh")
STAGE2 = load_script("stage2-lockdown.sh")

MUTATING_VERBS = {"start", "stop", "restart", "reload", "enable", "disable", "mask", "unmask",
                  "kill", "daemon-reload", "edit", "set-property", "reset-failed"}


def make_stub(module, *, session_port=22, session_source="203.0.113.9", journal_method="publickey",
              listeners=None, socket_active=True, disk_ports=(), account=True, backup=False,
              auth=None, allowlist_rules=None, ufw_active=False, ufw_text=None, legacy_pending=False,
              timer_active=False, btime=1000000000, hardening_mtime=None, sshd_config_valid=True,
              tailnet=False, tailnet_state="up", tailnet_flags=None, bind_address="0.0.0.0",
              listener_process="sshd"):
    system = bind_stub(module, StubSystem())
    listen_ports = sorted(set(listeners if listeners is not None else [session_port, 22]))

    ss = "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
    for port in listen_ports:
        ss += 'LISTEN 0 4096 %s:%d 0.0.0.0:* users:(("%s",pid=1,fd=3))\n' % (bind_address, port, listener_process)
    ss += 'LISTEN 0 4096 127.0.0.1:631 0.0.0.0:* users:(("cupsd",pid=900,fd=3))\n'
    system.can("ss -tlnpH", ss)

    if tailnet:
        system.touch_file("/sys/class/net/tailscale0")
        system.set_read("/sys/class/net/tailscale0/operstate", tailnet_state + "\n")
        if tailnet_flags is None:
            tailnet_flags = 0x1003 if tailnet_state == "up" else 0x1002
        system.set_read("/sys/class/net/tailscale0/flags", "0x%x\n" % tailnet_flags)

    if socket_active:
        listen_lines = "".join("0.0.0.0:%d (Stream)\n" % p for p in listen_ports)
        system.can("systemctl show ssh.socket",
                   "LoadState=loaded\nActiveState=active\nAccept=no\n" + "".join("Listen=" + line for line in listen_lines.splitlines(True)))
    else:
        system.can("systemctl show ssh.socket", "LoadState=not-found\nActiveState=inactive\nAccept=no\n")
    system.can("systemctl show", "LoadState=loaded\nActiveState=active\n")
    system.can("systemctl is-active", "active\n")
    system.can("systemctl is-enabled", "enabled\n")
    system.can("systemctl cat", "ListenStream=22\n")

    if account:
        system.can("id -u fenix", "1000\n")
        system.can("id -nG fenix", "fenix sudo\n")
        system.can("getent passwd fenix", "fenix:x:1000:1000::/home/fenix:/bin/bash\n")
        system.set_read("/home/fenix/.ssh/authorized_keys", "ssh-ed25519 AAAATEST key fenix\n")
        system.set_stat("/home/fenix/.ssh/authorized_keys", 0o100600, 1000)
        system.set_stat("/home/fenix/.ssh", 0o40700, 1000)
        system.set_stat("/home/fenix", 0o40750, 1000)
    else:
        system.can("id -u fenix", "", returncode=1, stderr="no such user")

    if sshd_config_valid:
        system.can("sshd -t", "")
    else:
        system.can("sshd -t", "", returncode=1, stderr="line 5: Bad configuration option")

    auth = auth if auth is not None else {
        "permitrootlogin": "prohibit-password", "passwordauthentication": "yes",
        "kbdinteractiveauthentication": "yes", "authenticationmethods": "any",
        "pubkeyauthentication": "yes", "authorizedkeysfile": ".ssh/authorized_keys",
        "port": str(session_port),
    }
    system.can("sshd -T", "".join("%s %s\n" % (k, v) for k, v in auth.items()))

    system.can("nft -j list ruleset", packet_nft(allowlist_rules or []))
    system.can("nft list tables", "table inet sshguard\n")
    if ufw_active:
        system.can("ufw status verbose", ufw_text or
                   "Status: active\n\nTo Action From\n-- ----- ----\n62207/tcp ALLOW 203.0.113.0/24\n62207/tcp DENY Anywhere\n")
    else:
        system.can("ufw status verbose", "Status: inactive\n")

    journal = ("Accepted %s for fenix from %s port 54321 ssh2\n" % (journal_method, session_source)) if journal_method else ""
    system.can("journalctl", journal)

    system.set_read("/proc/stat", "btime %d\n" % btime)
    system.set_read("/proc/", "SSH_CONNECTION=%s 54321 10.0.0.5 %d\x00" % (session_source, session_port))
    system.set_read("/etc/ssh/sshd_config", "".join("Port %s\n" % p for p in disk_ports))
    system.set_read("/etc/ssh/sshd_config.d/10-newport.conf", "".join("Port %s\n" % p for p in disk_ports))
    system.touch_dir("/etc/ssh/sshd_config.d", ["10-newport.conf"] if disk_ports else [])
    system.touch_dir("/etc/systemd/system", ["reinforce-my-ssh-old.timer"] if timer_active else [])
    system.touch_dir("/etc/systemd/system/ssh.socket.d", [])
    system.touch_dir("/etc/nftables.d", [])
    if allowlist_rules:
        system.touch_dir("/etc/nftables.d", ["ssh-allowlist.nft"])
    if backup:
        system.touch_dir("/var/backups/ssh-hardening", ["20261027-160000"])
        system.touch_dir("/var/backups/ssh-hardening/20261027-160000", ["sshd_config", "nft-ruleset.nft"])
        for name in ("sshd_config", "units.txt", "backup-complete", "nft-ruleset.nft", "ufw-status.txt",
                     "sshd_config.d.absent", "ssh.socket.d.absent", "nftables.conf.absent",
                     "nftables.d.absent", "ufw.absent", "ssh.socket.active", "nftables.enabled",
                     "nft-ruleset.json", "sshguard.nft.absent"):
            system.touch_file("/var/backups/ssh-hardening/20261027-160000/" + name)
    if hardening_mtime is not None:
        for path in ("/etc/ssh/sshd_config.d/10-newport.conf", "/etc/nftables.d/ssh-allowlist.nft"):
            system.mtimes[path] = hardening_mtime
    if legacy_pending:
        system.touch_file("/var/lib/reinforce-my-ssh/state.conf")
        system.set_read("/var/lib/reinforce-my-ssh/state.conf",
                        "STAGE=candidate-pending\nTX=20261027-013955-433794809-195911\nCONFIG_SHA=\nPENDING_BOOT=\nVERIFIED_BOOT=\n")
    return system


def patch_environment(module, system):
    module.System = lambda: system
    module.is_root = lambda: True


def run_main(module, argv, system):
    patch_environment(module, system)
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = module.main(argv)
    return code, buffer.getvalue()


HARDENED_AUTH = {
    "permitrootlogin": "no", "passwordauthentication": "no",
    "kbdinteractiveauthentication": "no", "authenticationmethods": "publickey",
    "pubkeyauthentication": "yes", "authorizedkeysfile": ".ssh/authorized_keys",
    "port": "62207",
}
ALLOW_RULES = [("accept", None, None, ("established", "related")),
               ("accept", 62207, ["203.0.113.0/24"], None),
               ("drop", 62207, None, None)]


class TestScriptIntegrity(unittest.TestCase):
    def test_bash_syntax(self):
        for name in ("stage0-check.sh", "stage1-port-key.sh", "stage2-lockdown.sh"):
            result = subprocess.run(["bash", "-n", str(ROOT / name)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, name + ": " + result.stderr)

    def test_embedded_boundaries(self):
        for name in ("stage0-check.sh", "stage1-port-key.sh", "stage2-lockdown.sh"):
            load_script(name)  # 边界不完整会抛 ValueError

    def test_read_only_command_whitelist(self):
        for module in (STAGE0, STAGE1, STAGE2):
            table = module.READ_ONLY_COMMANDS
            self.assertLessEqual(set(table), {"ss", "id", "getent", "sshd", "nft", "ufw", "systemctl", "journalctl"})
            for tool, subs in table.items():
                if subs is not None:
                    self.assertFalse(set(subs) & MUTATING_VERBS, "%s 含可写子命令" % tool)
            self.assertEqual(table["nft"], {"list", "-j"})
            self.assertEqual(table["sshd"], {"-t", "-T"})
            self.assertEqual(table["ufw"], {"status"})

    def test_no_shell_or_write_surface(self):
        for module in (STAGE0, STAGE1, STAGE2):
            source = module.SOURCE
            self.assertNotIn("shell=True", source)
            self.assertNotIn("os.system", source)
            # 恢复指令是字符串数据；只检查指导程序自身的可执行调用。
            for node in ast.walk(ast.parse(source)):
                if isinstance(node, ast.Call) and len(node.args) >= 2:
                    values = [arg.value if isinstance(arg, ast.Constant) else None for arg in node.args[:2]]
                    if values[0] == "systemctl":
                        self.assertNotIn(values[1], MUTATING_VERBS)

    def test_all_executed_calls_stay_read_only(self):
        system = make_stub(STAGE0, account=True)
        options = STAGE0.parse_args(["--port", "62207", "--user", "fenix", "--allow", "203.0.113.0/24"])
        STAGE0.collect(system, options)
        self.assertTrue(system.calls)
        for call in system.calls:
            subs = STAGE0.READ_ONLY_COMMANDS[call[0]]
            if subs is not None:
                self.assertIn(call[1], subs)


class TestParsing(unittest.TestCase):
    def test_connection_env(self):
        system = make_stub(STAGE1)
        connection = STAGE1.find_connection(system)
        self.assertEqual(connection, {"source": "203.0.113.9", "source_port": 54321, "local": "10.0.0.5", "port": 22})

    def test_connection_invalid_raises(self):
        system = make_stub(STAGE1)
        system.set_read("/proc/", "SSH_CONNECTION=not-an-ip 54321 10.0.0.5 22\x00")
        with self.assertRaises(STAGE1.EvidenceError):
            STAGE1.find_connection(system)

    def test_journal_auth_matching(self):
        system = make_stub(STAGE1, session_source="198.51.100.7")
        connection = {"source": "198.51.100.7", "source_port": 54321, "local": "10.0.0.5", "port": 22}
        self.assertEqual(STAGE1.session_auth(system, connection, "fenix"), "publickey")
        other = {"source": "198.51.100.8", "source_port": 54321, "local": "10.0.0.5", "port": 22}
        self.assertIsNone(STAGE1.session_auth(system, other, "fenix"))

    def test_ss_attribution_and_stream_suffix(self):
        system = make_stub(STAGE1, listeners=[22, 62207])
        self.assertEqual(STAGE1.sshd_listeners(system), [22, 62207])
        socket = STAGE1.socket_state(system)
        self.assertEqual(socket["listen_ports"], [22, 62207])

    def test_account_permissions(self):
        system = make_stub(STAGE1, account=True)
        facts = STAGE1.account_facts(system, "fenix")
        self.assertTrue(facts["exists"])
        self.assertTrue(facts["sudo"])
        self.assertEqual(facts["authorized_keys_count"], 1)
        self.assertEqual(facts["authorized_keys_mode"], "0o600")
        self.assertEqual(facts["ssh_dir_mode"], "0o700")

    def test_nft_single_element_folding(self):
        system = make_stub(STAGE2, allowlist_rules=ALLOW_RULES)
        summary = STAGE2.nft_ruleset_summary(system)
        dport_rules = [rule for rule in summary["rules"] if rule["dports"] == ["62207"]]
        self.assertEqual(len(dport_rules), 2)
        accept = [rule for rule in dport_rules if rule["verdict"] == "accept"][0]
        self.assertEqual(accept["saddrs"], ["203.0.113.0/24"])

    def test_allowlist_assessment_paths(self):
        system = make_stub(STAGE2, allowlist_rules=ALLOW_RULES)
        summary = STAGE2.nft_ruleset_summary(system)
        result = STAGE2.allowlist_assessment(summary, {"available": False}, 62207, ["203.0.113.0/24"])
        self.assertEqual(result["status"], "pass")

        offender_rules = [("accept", 62207, None, None)]
        summary = STAGE2.nft_ruleset_summary(make_stub(STAGE2, allowlist_rules=offender_rules))
        result = STAGE2.allowlist_assessment(summary, {"available": False}, 62207, ["203.0.113.0/24"])
        self.assertEqual(result["status"], "fail")
        self.assertIn("无来源限制", result["detail"])

        no_drop_rules = [("accept", 62207, ["203.0.113.0/24"], None)]
        summary = STAGE2.nft_ruleset_summary(make_stub(STAGE2, allowlist_rules=no_drop_rules))
        result = STAGE2.allowlist_assessment(summary, {"available": False}, 62207, ["203.0.113.0/24"])
        self.assertEqual(result["status"], "fail")
        self.assertIn("未发现默认拒绝", result["detail"])

        outside_rules = [("accept", 62207, ["198.51.100.0/24"], None), ("drop", 62207, None, None)]
        summary = STAGE2.nft_ruleset_summary(make_stub(STAGE2, allowlist_rules=outside_rules))
        result = STAGE2.allowlist_assessment(summary, {"available": False}, 62207, ["203.0.113.0/24"])
        self.assertEqual(result["status"], "fail")
        self.assertIn("超出声明白名单", result["detail"])

        empty = STAGE2.nft_ruleset_summary(make_stub(STAGE2))
        result = STAGE2.allowlist_assessment(empty, {"available": False}, 62207, ["203.0.113.0/24"])
        self.assertEqual(result["status"], "unknown")

    def test_allowlist_ufw_variant(self):
        system = make_stub(STAGE2, ufw_active=True)
        result = STAGE2.allowlist_assessment({"rules": [], "input_policy": []}, STAGE2.ufw_status(system),
                                             62207, ["203.0.113.0/24"])
        self.assertEqual(result["status"], "pass")


class TestStage1Steps(unittest.TestCase):
    def steps(self, **kwargs):
        extra = kwargs.pop("extra", None)
        system = make_stub(STAGE1, **kwargs)
        patch_environment(STAGE1, system)
        options = STAGE1.parse_args(["--port", "62207", "--user", "fenix", "--host", "h", *(extra or [])])
        ctx = STAGE1.resolve_context(system, options)
        return system, options, ctx, {step["id"]: step for step in STAGE1.build_steps(system, options, ctx)}

    def test_early_state_all_todo_with_gates(self):
        _, _, ctx, steps = self.steps(account=False)
        self.assertEqual(ctx["old_port"], 22)
        for step in steps.values():
            self.assertEqual(step["status"], "todo")
        self.assertEqual(steps["3-new-port"]["blocked_by"], ["1-backup", "2-account"])
        self.assertEqual(steps["5-close-old"]["blocked_by"], ["0-rescue", "4-verify-new", "1-backup", "2-account"])

    def test_existing_account_counts_as_done(self):
        _, _, _, steps = self.steps()
        self.assertEqual(steps["2-account"]["status"], "done")

    def test_mid_state_new_port_verified(self):
        _, _, ctx, steps = self.steps(session_port=62207, listeners=[22, 62207], disk_ports=(22, 62207),
                                      backup=True, extra=["--rescue-confirmed"])
        self.assertEqual(ctx["old_port"], 22)
        for name in ("0-rescue", "1-backup", "2-account", "3-new-port", "4-verify-new"):
            self.assertEqual(steps[name]["status"], "done", name + "：" + steps[name]["evidence"])
        self.assertEqual(steps["5-close-old"]["status"], "todo")
        self.assertEqual(steps["5-close-old"]["blocked_by"], [])

    def test_password_session_does_not_satisfy_hard_gate(self):
        _, _, ctx, steps = self.steps(session_port=62207, listeners=[22, 62207], disk_ports=(22, 62207),
                                      backup=True, journal_method="password", extra=["--rescue-confirmed"])
        self.assertEqual(ctx["auth"], "password")
        self.assertEqual(steps["4-verify-new"]["status"], "todo")
        self.assertEqual(steps["5-close-old"]["blocked_by"], ["4-verify-new"])

    def test_old_port_none_marks_step_done(self):
        _, _, _, steps = self.steps(session_port=62207, listeners=[62207], extra=["--rescue-confirmed", "--old-port", "none"])
        self.assertEqual(steps["5-close-old"]["status"], "done")

    def test_listening_but_not_persisted_is_warn(self):
        _, _, _, steps = self.steps(session_port=62207, listeners=[22, 62207], backup=True, disk_ports=())
        self.assertEqual(steps["3-new-port"]["status"], "warn")
        self.assertIn("重启后会丢失", steps["3-new-port"]["evidence"])

    def test_tailnet_step_only_when_declared(self):
        _, _, _, plain = self.steps()
        self.assertNotIn("2b-tailnet", plain)
        _, _, _, declared = self.steps(extra=["--tailnet"], tailnet=True)
        self.assertEqual(declared["2b-tailnet"]["status"], "done")

    def test_tailnet_step_reports_missing_interface(self):
        _, _, _, steps = self.steps(extra=["--tailnet"], tailnet=False)
        self.assertEqual(steps["2b-tailnet"]["status"], "todo")
        self.assertIn("未发现 tailscale0", steps["2b-tailnet"]["evidence"])

    def test_tailnet_operstate_unknown_with_flags_up(self):
        _, _, _, steps = self.steps(extra=["--tailnet"], tailnet=True,
                                    tailnet_state="unknown", tailnet_flags=0x1003)
        self.assertEqual(steps["2b-tailnet"]["status"], "done")

    def test_tailnet_flags_down_is_not_ready(self):
        _, _, _, steps = self.steps(extra=["--tailnet"], tailnet=True,
                                    tailnet_state="up", tailnet_flags=0x1002)
        self.assertEqual(steps["2b-tailnet"]["status"], "todo")

    def test_tailnet_step_verifies_via_current_port(self):
        _, _, _, steps = self.steps(extra=["--tailnet"], tailnet=True)
        joined = "\n".join(steps["2b-tailnet"]["do"] + steps["2b-tailnet"]["verify"])
        self.assertIn("-p 22", joined)
        self.assertNotIn("62207", joined)
        self.assertIn("第 4 步", joined)

    def test_verify_resume_command_keeps_tailnet(self):
        _, _, _, steps = self.steps(session_port=22, extra=["--tailnet"], tailnet=True)
        joined = "\n".join(steps["4-verify-new"]["do"])
        self.assertIn("--tailnet", joined)


class TestStage2Steps(unittest.TestCase):
    def build(self, **kwargs):
        extra = kwargs.pop("extra", None)
        allow = kwargs.pop("allow", ["203.0.113.0/24"])
        system = make_stub(STAGE2, **kwargs)
        patch_environment(STAGE2, system)
        argv = ["--port", "62207", "--user", "fenix", "--host", "h", "--rescue-confirmed"]
        for item in allow:
            argv += ["--allow", item]
        options = STAGE2.parse_args(argv + (extra or []))
        ctx = STAGE2.resolve_context(system, options)
        return system, options, ctx, {step["id"]: step for step in STAGE2.build_steps(system, options, ctx)}

    def test_unhardened_preconditions_block(self):
        _, _, _, steps = self.build()
        self.assertEqual(steps["0-preconditions"]["status"], "blocked")
        self.assertEqual(steps["1-allowlist"]["blocked_by"], ["0-preconditions"])
        self.assertEqual(steps["2-auth"]["status"], "blocked")

    def test_source_outside_allowlist_is_hard_block(self):
        _, _, _, steps = self.build(session_port=62207, listeners=[22, 62207], backup=True,
                                    session_source="198.51.100.7")
        self.assertEqual(steps["1-allowlist"]["status"], "blocked")
        self.assertIn("不在声明白名单内", steps["1-allowlist"]["evidence"])

    def test_complete_without_reboot(self):
        _, _, _, steps = self.build(session_port=62207, listeners=[62207], backup=True, disk_ports=(62207,),
                                    auth=HARDENED_AUTH, allowlist_rules=ALLOW_RULES, hardening_mtime=1000000001)
        for name in ("0-preconditions", "1-allowlist", "2-auth", "3-confirm"):
            self.assertEqual(steps[name]["status"], "done", name + "：" + steps[name]["evidence"])
        self.assertEqual(steps["4-reboot-verify"]["status"], "todo")
        self.assertIn("尚无", steps["4-reboot-verify"]["evidence"])

    def test_complete_after_reboot(self):
        _, _, _, steps = self.build(session_port=62207, listeners=[62207], backup=True, disk_ports=(62207,),
                                    auth=HARDENED_AUTH, allowlist_rules=ALLOW_RULES, hardening_mtime=999999999)
        self.assertEqual(steps["4-reboot-verify"]["status"], "done")
        self.assertTrue(all(step["status"] == "done" for step in steps.values()))

    def test_auth_step_requires_verified_session(self):
        _, _, _, steps = self.build(session_port=62207, listeners=[62207], backup=True, disk_ports=(62207,),
                                    auth=HARDENED_AUTH, allowlist_rules=ALLOW_RULES, journal_method=None)
        self.assertNotEqual(steps["0-preconditions"]["status"], "done")
        self.assertEqual(steps["2-auth"]["status"], "blocked")

    def test_tailnet_declared_without_allow_uses_interface_rule(self):
        _, _, _, steps = self.build(session_source="100.64.1.9", tailnet=True, allow=[],
                                    session_port=62207, listeners=[62207], backup=True,
                                    extra=["--tailnet"])
        self.assertNotEqual(steps["1-allowlist"]["status"], "blocked")
        self.assertTrue(any('iifname "tailscale0"' in line for line in steps["1-allowlist"]["do"]))
        self.assertEqual(steps["1b-close-public"]["status"], "unknown")
        self.assertIn("0.0.0.0", steps["1b-close-public"]["evidence"])

    def test_socket_activated_listener_is_not_mistaken_for_closed(self):
        _, _, _, steps = self.build(session_source="100.64.1.9", tailnet=True, allow=[],
                                    session_port=62207, listeners=[62207], backup=True,
                                    listener_process="systemd", extra=["--tailnet"])
        self.assertEqual(steps["1b-close-public"]["status"], "unknown")
        self.assertIn("0.0.0.0", steps["1b-close-public"]["evidence"])

    def test_ufw_broad_allow_keeps_public_open(self):
        text = ("Status: active\n\nTo Action From\n-- ----- ----\n"
                "62207/tcp on tailscale0 ALLOW Anywhere\n"
                "62207/tcp ALLOW Anywhere\n"
                "62207/tcp DENY Anywhere\n")
        _, _, _, steps = self.build(session_source="100.64.1.9", tailnet=True, allow=[],
                                    session_port=62207, listeners=[62207], backup=True,
                                    ufw_active=True, ufw_text=text, extra=["--tailnet"])
        self.assertEqual(steps["1b-close-public"]["status"], "todo")
        self.assertIn("公网仍可进入", steps["1b-close-public"]["evidence"])

    def test_ufw_tailnet_then_deny_closes_public(self):
        text = ("Status: active\n\nTo Action From\n-- ----- ----\n"
                "62207/tcp on tailscale0 ALLOW Anywhere\n"
                "62207/tcp DENY Anywhere\n")
        _, _, _, steps = self.build(session_source="100.64.1.9", tailnet=True, allow=[],
                                    session_port=62207, listeners=[62207], backup=True,
                                    ufw_active=True, ufw_text=text, extra=["--tailnet"])
        self.assertEqual(steps["1b-close-public"]["status"], "done")

    def test_tailnet_ipv6_session_is_accepted(self):
        _, _, _, steps = self.build(session_source="fd7a:115c:a1e0::1", tailnet=True, allow=[],
                                    session_port=62207, listeners=[62207], backup=True,
                                    extra=["--tailnet"])
        self.assertNotEqual(steps["1-allowlist"]["status"], "blocked")

    def test_tailnet_ipv6_binding_is_not_public(self):
        _, _, _, steps = self.build(session_source="fd7a:115c:a1e0::1", tailnet=True, allow=[],
                                    session_port=62207, listeners=[62207], backup=True,
                                    bind_address="fd7a:115c:a1e0::1", extra=["--tailnet"])
        self.assertEqual(steps["1b-close-public"]["status"], "done")

    def test_nft_negated_tailscale_drop_closes_public(self):
        rules = [("accept", None, None, ("established", "related")),
                 ("accept", 62207, None, None, "tailscale0"),
                 ("drop", 62207, None, None, "tailscale0", True)]
        _, _, _, steps = self.build(session_source="100.64.1.9", tailnet=True, allow=[],
                                    session_port=62207, listeners=[62207], backup=True,
                                    allowlist_rules=rules, extra=["--tailnet"])
        self.assertEqual(steps["1b-close-public"]["status"], "done")

    def test_resume_commands_keep_tailnet_flag(self):
        _, _, _, steps = self.build(session_source="100.64.1.9", tailnet=True, allow=[],
                                    session_port=62207, listeners=[62207], backup=True,
                                    journal_method=None, extra=["--tailnet"])
        self.assertTrue(any("--tailnet" in line for line in steps["4-reboot-verify"]["do"]))
        self.assertTrue(any("--tailnet" in line for line in steps["0-preconditions"]["do"]))

    def mixed(self, rules, **kwargs):
        return self.build(session_source="100.64.1.9", tailnet=True,
                          allow=["10.20.0.0/16", "203.0.113.9/32", "2001:db8::9/128"],
                          session_port=62207, listeners=[62207], backup=True,
                          disk_ports=(62207,), auth=HARDENED_AUTH,
                          hardening_mtime=999999999, allowlist_rules=rules,
                          extra=["--tailnet"], **kwargs)

    def mixed_rules(self):
        return [("accept", 62207, None, None, "tailscale0"),
                ("accept", 62207, ["10.20.0.0/16", "203.0.113.9/32", "2001:db8::9/128"], None),
                ("drop", 62207, None, None)]

    def test_mixed_sources_can_complete_all_steps(self):
        _, _, _, steps = self.mixed(self.mixed_rules())
        self.assertTrue(all(s["status"] == "done" for s in steps.values()), steps)

    def test_mixed_guidance_preserves_all_sources(self):
        _, _, _, steps = self.mixed([])
        commands = "\n".join(steps["1-allowlist"]["do"])
        for source in ("10.20.0.0/16", "203.0.113.9/32", "2001:db8::9/128"):
            self.assertIn(source, commands)
            self.assertIn("--allow " + source, "\n".join(steps["4-reboot-verify"]["do"]))
        self.assertIn('iifname "tailscale0"', commands)
        close = "\n".join(steps["1b-close-public"]["do"] + steps["1b-close-public"]["verify"])
        self.assertNotIn("ListenAddress", close)
        self.assertNotIn("应失败/超时", close)
        self.assertIn("白名单外", steps["1b-close-public"]["title"])

    def test_mixed_missing_declared_source_cannot_pass(self):
        rules = self.mixed_rules()
        rules[1] = ("accept", 62207, ["10.20.0.0/16", "2001:db8::9/128"], None)
        _, _, ctx, steps = self.mixed(rules)
        self.assertNotEqual(ctx["allowlist"]["status"], "pass")
        self.assertNotEqual(steps["3-confirm"]["status"], "done")

    def test_mixed_missing_tailnet_rule_cannot_pass(self):
        _, _, ctx, _ = self.mixed(self.mixed_rules()[1:])
        self.assertNotEqual(ctx["allowlist"]["status"], "pass")

    def test_mixed_unlisted_public_source_cannot_pass(self):
        rules = self.mixed_rules()
        rules.insert(1, ("accept", 62207, ["198.51.100.9/32"], None))
        _, _, ctx, steps = self.mixed(rules)
        self.assertEqual(ctx["allowlist"]["status"], "fail")
        self.assertNotEqual(steps["1b-close-public"]["status"], "done")

    def test_mixed_accept_after_drop_cannot_pass(self):
        rules = self.mixed_rules()
        rules.insert(0, ("drop", 62207, None, None))
        _, _, ctx, _ = self.mixed(rules)
        self.assertNotEqual(ctx["allowlist"]["status"], "pass")

    def test_mixed_ufw_sources_can_complete(self):
        text = ("Status: active\n62207/tcp on tailscale0 ALLOW Anywhere\n"
                "62207/tcp ALLOW 10.20.0.0/16\n62207/tcp ALLOW 203.0.113.9\n"
                "62207/tcp ALLOW 2001:db8::9\n62207/tcp DENY Anywhere\n")
        _, _, _, steps = self.mixed([], ufw_active=True, ufw_text=text)
        self.assertTrue(all(s["status"] == "done" for s in steps.values()), steps)

    def test_mixed_source_specific_drop_is_not_default_deny(self):
        rules = self.mixed_rules()[:-1] + [("drop", 62207, ["198.51.100.9/32"], None)]
        _, _, ctx, _ = self.mixed(rules)
        self.assertNotEqual(ctx["allowlist"]["status"], "pass")

    def test_real_nft_prefix_json_is_parsed(self):
        for module in (STAGE0, STAGE2):
            with self.subTest(script=module.SCRIPT):
                for address, length in (("10.20.0.0", 16), ("2001:db8::", 64)):
                    values = module.literal_values({"set": [{"prefix": {"addr": address, "len": length}}]})
                    self.assertEqual(values, [address + "/" + str(length)])

    def test_stage0_also_requires_all_declared_sources(self):
        rules = self.mixed_rules()
        rules[1] = ("accept", 62207, ["10.20.0.0/16"], None)
        system = make_stub(STAGE0, allowlist_rules=rules)
        result = STAGE0.allowlist_assessment(STAGE0.nft_ruleset_summary(system), {}, 62207,
                                            ["10.20.0.0/16", "203.0.113.9/32"], tailnet=True)
        self.assertNotEqual(result["status"], "pass")

    def test_mixed_cloud_and_public_sessions_remain_allowed(self):
        for source in ("10.20.1.8", "203.0.113.9", "2001:db8::9"):
            with self.subTest(source=source):
                _, _, _, steps = self.build(session_source=source, tailnet=True,
                    allow=["10.20.0.0/16", "203.0.113.9/32", "2001:db8::9/128"],
                    session_port=62207, listeners=[62207], backup=True,
                    disk_ports=(62207,), auth=HARDENED_AUTH, hardening_mtime=999999999,
                    allowlist_rules=self.mixed_rules(), extra=["--tailnet"])
                self.assertEqual(steps["1-allowlist"]["status"], "done")
                self.assertEqual(steps["3-confirm"]["status"], "done")

    def test_mixed_ufw_real_ipv6_rows_remain_allowed(self):
        text = ("Status: active\n62207/tcp on tailscale0 ALLOW Anywhere\n"
                "62207/tcp ALLOW 10.20.0.0/16\n62207/tcp ALLOW 203.0.113.9\n"
                "62207/tcp DENY Anywhere\n62207/tcp (v6) on tailscale0 ALLOW Anywhere (v6)\n"
                "62207/tcp (v6) ALLOW 2001:db8::9\n62207/tcp (v6) DENY Anywhere (v6)\n")
        _, _, ctx, steps = self.mixed([], ufw_active=True, ufw_text=text)
        self.assertEqual(ctx["allowlist"]["status"], "pass")
        self.assertEqual(steps["3-confirm"]["status"], "done")

    def test_mixed_ufw_missing_source_cannot_pass(self):
        text = ("Status: active\n62207/tcp on tailscale0 ALLOW Anywhere\n"
                "62207/tcp DENY Anywhere\n")
        _, _, ctx, _ = self.mixed([], ufw_active=True, ufw_text=text)
        self.assertNotEqual(ctx["allowlist"]["status"], "pass")

    def test_tailnet_requires_interface(self):
        _, _, _, steps = self.build(session_source="100.64.1.9", tailnet=False, allow=[],
                                    session_port=62207, listeners=[62207], backup=True,
                                    extra=["--tailnet"])
        self.assertEqual(steps["0-preconditions"]["status"], "blocked")
        self.assertIn("Tailscale 已接入", steps["0-preconditions"]["evidence"])

    def test_tailnet_binding_marks_public_closed(self):
        _, _, _, steps = self.build(session_source="100.64.1.9", tailnet=True, allow=[],
                                    session_port=62207, listeners=[62207], backup=True,
                                    bind_address="100.64.1.5", extra=["--tailnet"])
        self.assertEqual(steps["1b-close-public"]["status"], "done")
        self.assertIn("回环/tailnet", steps["1b-close-public"]["evidence"])


class TestStage0Assessment(unittest.TestCase):
    def run_stage0(self, argv, **kwargs):
        system = make_stub(STAGE0, **kwargs)
        return (*run_main(STAGE0, argv, system), system)

    def test_goal_position_progress(self):
        code, output, _ = self.run_stage0(["--port", "62207", "--user", "fenix", "--allow", "203.0.113.0/24"])
        self.assertIn("stage1", output)
        self.assertIn("下一步", output)

    def test_hardened_not_rebooted(self):
        code, output, _ = self.run_stage0(["--port", "62207", "--user", "fenix", "--allow", "203.0.113.0/24"],
                                          session_port=62207, listeners=[62207], disk_ports=(62207,), backup=True,
                                          auth=HARDENED_AUTH, allowlist_rules=ALLOW_RULES, hardening_mtime=1000000001)
        self.assertIn("待跨重启验证", output)
        self.assertEqual(code, 2)

    def test_verified_after_reboot(self):
        code, output, _ = self.run_stage0(["--port", "62207", "--user", "fenix", "--allow", "203.0.113.0/24"],
                                          session_port=62207, listeners=[62207], disk_ports=(62207,), backup=True,
                                          auth=HARDENED_AUTH, allowlist_rules=ALLOW_RULES, hardening_mtime=999999999)
        self.assertIn("已完成并通过跨重启验证", output)
        self.assertEqual(code, 0)

    def test_tailnet_declared_accepts_interface_rule(self):
        rules = [("accept", None, None, ("established", "related")),
                 ("accept", 62207, None, None, "tailscale0"),
                 ("drop", 62207, None, None)]
        code, output, _ = self.run_stage0(["--port", "62207", "--user", "fenix", "--tailnet"],
                                          session_port=62207, listeners=[62207], disk_ports=(62207,), backup=True,
                                          auth=HARDENED_AUTH, allowlist_rules=rules, tailnet=True,
                                          hardening_mtime=999999999)
        self.assertIn("tailscale0 放行", output)
        self.assertIn("tailscale0：up", output)
        self.assertEqual(code, 0)

    def test_tailnet_declared_without_interface_is_fail(self):
        code, output, _ = self.run_stage0(["--port", "62207", "--user", "fenix", "--tailnet"], tailnet=False)
        self.assertIn("未发现 tailscale0", output)
        self.assertIn("[未达标] Tailscale 接入", output)

    def test_legacy_pending_blocks_with_exit_1(self):
        code, output, _ = self.run_stage0([], legacy_pending=True)
        self.assertEqual(code, 1)
        self.assertIn("旧版", output)

    def test_json_report_shape(self):
        code, output, _ = self.run_stage0(["--port", "62207", "--user", "fenix", "--format", "json"])
        report = json.loads(output)
        self.assertTrue(report["read_only"])
        self.assertEqual(report["script"], "stage0-check.sh")
        self.assertIn(report["position"], {"goals-undeclared", "stage0", "stage1-progress", "stage1-done",
                                           "hardened", "verified", "legacy-blocking"})
        self.assertIn("next_step", report)

    def test_non_root_returns_2(self):
        system = make_stub(STAGE0)
        STAGE0.System = lambda: system
        original = STAGE0.is_root
        STAGE0.is_root = lambda: False
        try:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = STAGE0.main(["--port", "62207", "--user", "fenix"])
        finally:
            STAGE0.is_root = original
        self.assertEqual(code, 2)
        self.assertIn("sudo", buffer.getvalue())


class TestArgumentValidation(unittest.TestCase):
    def test_stage1_rejects_root_and_bad_port(self):
        with self.assertRaises(SystemExit):
            STAGE1.parse_args(["--port", "70000", "--user", "fenix"])
        with self.assertRaises(SystemExit):
            STAGE1.parse_args(["--port", "62207", "--user", "root"])

    def test_stage2_requires_allow(self):
        with self.assertRaises(SystemExit):
            STAGE2.parse_args(["--port", "62207", "--user", "fenix"])

    def test_stage2_requires_strict_cidr(self):
        with self.assertRaises(SystemExit):
            STAGE2.parse_args(["--port", "62207", "--user", "fenix", "--allow", "203.0.113.9/24"])

    def test_stage2_normalizes_ipv6_cidr(self):
        options = STAGE2.parse_args(["--port", "62207", "--user", "fenix", "--allow", "2001:0DB8::/32"])
        self.assertEqual(options.allow, ["2001:db8::/32"])

    def test_stage0_rejects_conflicting_ports(self):
        with self.assertRaises(SystemExit):
            STAGE0.parse_args(["--port", "62207", "--closed-port", "62207"])


class TestJsonReports(unittest.TestCase):
    def test_stage1_json_is_serializable(self):
        system = make_stub(STAGE1, session_port=62207, listeners=[22, 62207], disk_ports=(22, 62207),
                           backup=True)
        code, output = run_main(STAGE1, ["--port", "62207", "--user", "fenix", "--rescue-confirmed",
                                         "--format", "json"], system)
        report = json.loads(output)
        self.assertTrue(report["read_only"])
        self.assertEqual(report["next_step"], "5-close-old")
        self.assertFalse(report["complete"])
        self.assertEqual(code, 2)

    def test_stage2_json_complete(self):
        system = make_stub(STAGE2, session_port=62207, listeners=[62207], disk_ports=(62207,), backup=True,
                           auth=HARDENED_AUTH, allowlist_rules=ALLOW_RULES, hardening_mtime=999999999)
        code, output = run_main(STAGE2, ["--port", "62207", "--user", "fenix", "--allow", "203.0.113.0/24",
                                         "--rescue-confirmed", "--format", "json"], system)
        report = json.loads(output)
        self.assertTrue(report["complete"])
        self.assertIsNone(report["next_step"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)