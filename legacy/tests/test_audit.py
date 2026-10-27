#!/usr/bin/env python3
"""独立审计回归：命令/文件替身覆盖结果语义，另由原有集成入口验证真实 nft JSON。"""
import contextlib
import copy
import fnmatch
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from audit_source import load_audit

audit = load_audit()


def match(left, right):
    return {"match": {"op": "==", "left": left, "right": right}}


def rule(*expressions):
    return {"rule": {"family": "inet", "table": "sshguard", "chain": "guard", "expr": list(expressions)}}


PORT = match({"payload": {"protocol": "tcp", "field": "dport"}}, 2222)
SOURCE = match({"payload": {"protocol": "ip", "field": "saddr"}}, {"prefix": {"addr": "203.0.113.0", "len": 24}})
RUNTIME_TEXT = '''table inet sshguard {
 chain guard {
  type filter hook input priority -100; policy accept;
  iif "lo" tcp dport 2222 accept
  ip saddr 203.0.113.0/24 tcp dport 2222 accept
  tcp dport 2222 ct state established,related accept
  tcp dport 2222 drop
 }
}
'''


def ruleset():
    return {"nftables": [
        {"metainfo": {"json_schema_version": 1}},
        {"table": {"family": "inet", "name": "sshguard"}},
        {"chain": {"family": "inet", "table": "sshguard", "name": "guard", "type": "filter", "hook": "input", "prio": -100, "policy": "accept"}},
        rule(match({"meta": {"key": "iif"}}, "lo"), PORT, {"accept": None}),
        rule(SOURCE, PORT, {"accept": None}),
        rule(PORT, match({"ct": {"key": "state"}}, {"set": ["established", "related"]}), {"accept": None}),
        rule(PORT, {"drop": None}),
    ]}


class FakeSystem:
    def __init__(self):
        self.calls = []
        self.nft = ruleset()
        self.options = {"permitrootlogin": "no", "passwordauthentication": "no", "kbdinteractiveauthentication": "no",
                        "pubkeyauthentication": "yes", "authenticationmethods": "any", "hostbasedauthentication": "no",
                        "gssapiauthentication": "no", "permitemptypasswords": "no"}
        self.files = {
            "/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\nKbdInteractiveAuthentication no\nPasswordAuthentication no\n",
            "/etc/ssh/sshd_config.d/10-old.conf": "PermitRootLogin no\nPasswordAuthentication no\nPort 2222\n",
            "/etc/systemd/system/ssh-firewall.service": "旧服务配置存在\n",
            "/etc/systemd/system/ssh.socket.d/override.conf": "旧 socket 配置存在\n",
            "/usr/local/sbin/old-loader": "#!/bin/sh\nexec /usr/sbin/nft -f /etc/old-ssh.nft\n",
            "/etc/old-ssh.nft": RUNTIME_TEXT,
            "/proc/sys/kernel/random/boot_id": "11111111-1111-1111-1111-111111111111\n",
            "/proc/10/cmdline": "/usr/sbin/sshd\0-D\0",
            "/proc/10/environ": "SSHD_OPTS=\0",
            f"/proc/{os.getpid()}/status": "PPid:\t123\n",
            "/proc/123/status": "PPid:\t10\n",
            "/proc/10/status": "PPid:\t1\n",
            "/proc/sys/net/ipv6/bindv6only": "0\n",
        }
        base = {"LoadState": "loaded", "ActiveState": "active", "NeedDaemonReload": "no"}
        self.units = {
            "ssh.socket": {**base, "Listen": "0.0.0.0:2222 (Stream)", "Requires": "ssh-firewall.service", "After": "ssh-firewall.service", "BindIPv6Only": "ipv6-only"},
            "ssh.service": {**base, "MainPID": "10"},
            "ssh-firewall.service": {**base, "Type": "oneshot", "Before": "ssh.socket", "ExecStart": "{ path=/usr/local/sbin/old-loader ; argv[]=/usr/local/sbin/old-loader ; ignore_errors=no ; }"},
            "reinforce-my-ssh-firewall.service": {"LoadState": "not-found"},
        }
        self.enabled = {}
        self.changed = False
        self.bad_log_pid = False
        self.bad_graph = False
        self.denied = None
        self.ipv6_only = False
        self.login_method = "publickey"

    def read(self, path):
        if path not in self.files:
            raise audit.EvidenceError("缺少测试证据：" + path)
        return self.files[path]

    def exists(self, path):
        return path in self.files

    def expand(self, pattern):
        return sorted(name for name in self.files if fnmatch.fnmatch(name, pattern))

    def mtime(self, path):
        return 200 if self.changed else 90

    def process_start(self, pid):
        return 100 if pid == 10 else 150

    def run(self, *args):
        self.calls.append(args)
        if args[0] == self.denied:
            raise audit.EvidenceError("权限不足")
        if args[0] == "id":
            return "1000\n"
        if args[0] == "sshd":
            return "" if "-t" in args else "".join(f"{key} {value}\n" for key, value in self.options.items())
        if args[:2] == ("systemctl", "show"):
            return "".join(f"{key}={value}\n" for key, value in self.units[args[2]].items())
        if args[:2] == ("systemctl", "is-enabled"):
            return self.enabled.get(args[2], "enabled") + "\n"
        if args[0] == "systemd-analyze":
            if self.bad_graph:
                raise audit.EvidenceError("Found ordering cycle on ssh.socket/start")
            return ""
        if args[0] == "nft":
            return json.dumps(self.nft) if "-j" in args else RUNTIME_TEXT
        if args[0] == "ip":
            return json.dumps([{"addr_info": [{"local": "192.0.2.10"}]}])
        if args[0] == "ss":
            if "established" in args:
                return '0 0 192.0.2.10:2222 203.0.113.7:50000 users:(("sshd",pid=123,fd=4))\n'
            if "-6" in args:
                only = 0 if self.units["ssh.socket"]["BindIPv6Only"] == "both" else 1
                return f'LISTEN 0 128 [::]:2222 [::]:* users:(("systemd",pid=1,fd=4)) v6only:{only}\n' if self.ipv6_only else ""
            if self.ipv6_only and "-4" in args:
                return ""
            return 'LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=10,fd=4))\n'
        if args[0] == "journalctl":
            return json.dumps({"_BOOT_ID": "1" * 32, "_PID": "9999" if self.bad_log_pid else "123", "MESSAGE": f"Accepted {self.login_method} for deploy from 203.0.113.7 port 50000 ssh2"}) + "\n"
        raise AssertionError("非预期命令：" + str(args))


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.system = FakeSystem()
        self.policy = audit.Policy(2222, "deploy", ["203.0.113.0/24"], [22])
        self.environment = patch.dict(os.environ, {"SSH_CONNECTION": "203.0.113.7 50000 192.0.2.10 2222", "SUDO_USER": "deploy", "SUDO_UID": "1000"})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def report(self):
        return audit.Auditor(self.policy, self.system).audit()

    def test_no_arguments_inspect_current_session_without_learning_policy(self):
        _, policy = audit.arguments([])
        before = copy.deepcopy(self.system.files)
        report = audit.Auditor(policy, self.system).audit()
        self.assertEqual(report["security_result"], audit.PASS, report)
        self.assertEqual(report["policy_result"], audit.UNKNOWN)
        self.assertEqual(report["mode"], "inspect")
        self.assertEqual((policy.user, policy.port, policy.allows, policy.closed_ports), ("deploy", 2222, [], []))
        self.assertEqual(report["observed"]["connection"]["source"], "203.0.113.7")
        self.assertEqual(report["observed"]["login_method"], "publickey")
        self.assertEqual(report["target_origin"], {"user": "SUDO_USER", "port": "SSH_CONNECTION"})
        self.assertEqual(before, self.system.files)

    def test_sudo_environment_recovers_connection_from_ancestor(self):
        del os.environ["SSH_CONNECTION"]
        self.system.files[f"/proc/{os.getpid()}/environ"] = "USER=root\0"
        self.system.files["/proc/123/environ"] = "SSH_CONNECTION=203.0.113.7 50000 192.0.2.10 2222\0"
        _, policy = audit.arguments([])
        report = audit.Auditor(policy, self.system).audit()
        self.assertEqual(report["security_result"], audit.PASS, report)
        self.assertEqual(policy.port, 2222)

    def test_port_22_is_not_implicitly_required_closed(self):
        os.environ["SSH_CONNECTION"] = "203.0.113.7 50000 192.0.2.10 22"
        _, policy = audit.arguments([])
        auditor = audit.Auditor(policy, self.system)
        auditor.find_connection()
        auditor.resolve_target()
        self.assertEqual((policy.port, policy.closed_ports), (22, []))

    def test_explicit_target_wins_and_allow_enables_policy_comparison(self):
        _, policy = audit.arguments(["--port", "2200", "--user", "other", "--allow", "203.0.113.0/24"])
        auditor = audit.Auditor(policy, self.system)
        auditor.find_connection()
        auditor.resolve_target()
        self.assertEqual((policy.port, policy.user, policy.mode), (2200, "other", "policy"))
        self.assertEqual(auditor.report["target_origin"], {"user": "explicit", "port": "explicit"})
        _, policy = audit.arguments(["--allow", "203.0.113.0/24", "--closed-port", "22"])
        report = audit.Auditor(policy, self.system).audit()
        self.assertEqual(report["policy_result"], audit.PASS, report)

    def test_unique_listener_fallback_does_not_invent_session_evidence(self):
        del os.environ["SSH_CONNECTION"]
        _, policy = audit.arguments([])
        report = audit.Auditor(policy, self.system).audit()
        self.assertEqual(policy.port, 2222)
        self.assertEqual(report["security_result"], audit.UNKNOWN)
        self.assertNotIn("login_method", report["observed"])
        self.assertEqual(report["target_origin"]["port"], "unique-live-listener")

    def test_ambiguous_listener_on_root_console_does_not_guess_port(self):
        del os.environ["SSH_CONNECTION"]
        os.environ["SUDO_USER"] = "root"
        os.environ["USER"] = "root"
        self.system.units["ssh.socket"]["Listen"] = "0.0.0.0:22 (Stream)"
        _, policy = audit.arguments([])
        report = audit.Auditor(policy, self.system).audit()
        self.assertIsNone(policy.port)
        self.assertEqual(policy.user, "root")
        self.assertEqual(report["security_result"], audit.UNKNOWN)
        self.assertEqual(report["observed"]["port_candidates"], [22, 2222])

    def test_inspect_firewall_collects_facts_without_whitelist_verdict(self):
        self.system.nft["nftables"].insert(3, rule(PORT, {"accept": None}))
        _, policy = audit.arguments([])
        report = audit.Auditor(policy, self.system).audit()
        self.assertEqual(report["policy_result"], audit.UNKNOWN)
        self.assertEqual(report["observed"]["firewall"]["accept_source_literals"], ["203.0.113.0/24"])
        self.assertFalse(any(item["name"] == "来源白名单" for item in report["checks"]))
        self.assertEqual(self.report()["security_result"], audit.FAIL)

    def test_password_login_is_reported_and_unrelated_log_is_not_evidence(self):
        _, policy = audit.arguments([])
        self.system.login_method = "password"
        report = audit.Auditor(policy, self.system).audit()
        self.assertEqual(report["observed"]["login_method"], "password")
        self.assertEqual(report["security_result"], audit.FAIL)
        self.system.bad_log_pid = True
        report = audit.Auditor(policy, self.system).audit()
        self.assertNotIn("login_method", report["observed"])
        self.assertEqual(report["security_result"], audit.UNKNOWN)

    def test_no_arguments_text_json_and_nonroot_have_clear_scope(self):
        for fmt in ("text", "json"):
            stdout = io.StringIO()
            with patch.object(audit.os, "geteuid", return_value=0, create=True), patch.object(audit, "System", return_value=self.system), contextlib.redirect_stdout(stdout):
                self.assertEqual(audit.main(["--format", fmt]), 0)
            if fmt == "text":
                self.assertIn("账户=deploy，端口=2222", stdout.getvalue())
                self.assertIn("来源白名单目标：未指定，未判定合规", stdout.getvalue())
            else:
                self.assertEqual(json.loads(stdout.getvalue())["policy_result"], audit.UNKNOWN)
        with patch.object(audit.os, "geteuid", return_value=1000, create=True), contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(audit.main([]), 2)
        self.assertIn("SSH 只读现状检查", stdout.getvalue())
        self.assertIn("sudo bash stage0-audit.sh", stdout.getvalue())

    def test_auto_detected_port_conflicting_with_closed_port_is_flagged(self):
        _, policy = audit.arguments(["--closed-port", "2222"])
        report = audit.Auditor(policy, self.system).audit()
        self.assertTrue(any(item["name"] == "检查目标冲突" and item["result"] == audit.FAIL for item in report["checks"]))

    def test_discovery_reads_live_listener_when_systemctl_is_unavailable(self):
        del os.environ["SSH_CONNECTION"]
        self.system.denied = "systemctl"
        _, policy = audit.arguments([])
        report = audit.Auditor(policy, self.system).audit()
        self.assertEqual(policy.port, 2222)
        self.assertEqual(report["security_result"], audit.UNKNOWN)

    def test_extra_socket_port_is_observation_only_in_inspect_mode(self):
        self.system.units["ssh.socket"]["Listen"] = "0.0.0.0:22 (Stream)"
        _, policy = audit.arguments([])
        inspected = audit.Auditor(policy, self.system).audit()
        self.assertEqual(inspected["security_result"], audit.PASS, inspected)
        self.assertEqual(self.report()["security_result"], audit.FAIL)

    def test_safe_legacy_is_not_failed_for_missing_new_state(self):
        before = copy.deepcopy(self.system.files)
        report = self.report()
        self.assertEqual(report["security_result"], audit.PASS, report)
        self.assertEqual(report["ownership"]["kind"], "legacy")
        self.assertEqual(report["migration"]["status"], "migration-planned")
        self.assertEqual(report["reboot"]["status"], audit.UNKNOWN)
        self.assertEqual(before, self.system.files)
        self.assertTrue(all("--apply" not in command and "restart" not in command for command in self.system.calls))

    def test_unsafe_auth_fails_even_with_managed_record(self):
        self.system.files[audit.STATE_ROOT + "/state.conf"] = "STAGE=verified\n"
        self.system.options["passwordauthentication"] = "yes"
        report = self.report()
        self.assertEqual(report["security_result"], audit.FAIL)
        self.assertEqual(report["ownership"]["kind"], "managed-record")

    def test_any_auth_requires_all_other_methods_disabled(self):
        self.system.options["hostbasedauthentication"] = "yes"
        self.assertEqual(self.report()["security_result"], audit.FAIL)
        del self.system.options["hostbasedauthentication"]
        self.assertEqual(self.report()["security_result"], audit.UNKNOWN)

    def test_match_is_unknown_not_blanket_security_failure(self):
        self.system.files["/etc/ssh/sshd_config.d/10-old.conf"] += "Match User other\n PasswordAuthentication yes\n"
        self.assertEqual(self.report()["security_result"], audit.UNKNOWN)
        self.system.options["passwordauthentication"] = "yes"
        self.assertEqual(self.report()["security_result"], audit.UNKNOWN)

    def test_permission_failure_is_unknown(self):
        self.system.denied = "nft"
        self.assertEqual(self.report()["security_result"], audit.UNKNOWN)

    def test_unsafe_firewall_and_rule_order(self):
        self.system.nft["nftables"].insert(3, rule(PORT, {"accept": None}))
        self.assertEqual(self.report()["security_result"], audit.FAIL)
        self.system.nft = ruleset()
        # 在最终无条件 drop 后面的 accept 不会扩大入口。
        self.system.nft["nftables"].append(rule(PORT, {"accept": None}))
        self.assertEqual(self.report()["security_result"], audit.PASS)

    def test_unsupported_nft_and_other_chains_are_unknown(self):
        self.system.nft["nftables"].append({"chain": {"family": "ip", "table": "filter", "name": "input", "hook": "input"}})
        self.assertEqual(self.report()["security_result"], audit.UNKNOWN)
        self.system.nft = ruleset()
        self.system.nft["nftables"][4] = rule({"jump": {"target": "other"}})
        self.assertEqual(self.report()["security_result"], audit.UNKNOWN)

    def test_old_loopback_without_interface_is_not_silently_accepted(self):
        self.system.nft["nftables"][3] = rule(match({"payload": {"protocol": "ip", "field": "saddr"}}, "127.0.0.1"), PORT, {"accept": None})
        self.assertEqual(self.report()["security_result"], audit.UNKNOWN)

    def test_disabled_boot_cycle_and_complex_loader(self):
        self.system.enabled["ssh-firewall.service"] = "disabled"
        self.assertEqual(self.report()["security_result"], audit.FAIL)
        self.system.enabled.clear()
        self.system.bad_graph = True
        self.assertEqual(self.report()["security_result"], audit.FAIL)
        self.system.bad_graph = False
        self.system.files["/usr/local/sbin/old-loader"] += "echo extra-command\n"
        self.assertEqual(self.report()["security_result"], audit.UNKNOWN)

    def test_disk_later_than_process_and_wrong_log_pid_are_unknown(self):
        self.system.changed = True
        self.assertEqual(self.report()["security_result"], audit.UNKNOWN)

    def test_unsafe_loader_prerequisite_and_hidden_post_command(self):
        self.system.files["/etc/old-ssh.nft"] = "flush table inet sshguard\n" + RUNTIME_TEXT
        self.assertEqual(self.report()["security_result"], audit.UNKNOWN)
        self.system.files["/etc/old-ssh.nft"] = RUNTIME_TEXT
        self.system.units["ssh-firewall.service"]["ExecStartPost"] = "{ argv[]=/bin/true ; }"
        self.assertEqual(self.report()["security_result"], audit.UNKNOWN)
        self.system.changed = False
        self.system.bad_log_pid = True
        self.assertEqual(self.report()["security_result"], audit.UNKNOWN)

    def test_ipv6_dual_socket_is_equivalent_for_ipv4(self):
        self.system.ipv6_only = True
        self.system.units["ssh.socket"]["Listen"] = "[::]:2222 (Stream)"
        self.system.units["ssh.socket"]["BindIPv6Only"] = "both"
        self.assertEqual(self.report()["security_result"], audit.PASS)
        self.system.units["ssh.socket"]["BindIPv6Only"] = "ipv6-only"
        self.assertEqual(self.report()["security_result"], audit.FAIL)

    def test_corrupt_ownership_does_not_taint_security(self):
        self.system.files[audit.STATE_ROOT + "/state.conf"] = "BROKEN\n"
        report = self.report()
        self.assertEqual(report["security_result"], audit.PASS)
        self.assertEqual(report["ownership"]["kind"], "unknown")

    def test_consistent_managed_reboot_record_and_drift(self):
        self.system.files[audit.STATE_ROOT + "/policy.conf"] = "registered policy\n"
        digest = hashlib.sha256(b"POLICY\nregistered policy\n")
        for path in audit.MANAGED:
            self.system.files[path] = "managed file\n"
            digest.update(f"FILE {path}\nmanaged file\n".encode())
        sha = digest.hexdigest()
        pre, post = audit.STATE_ROOT + "/baselines/pre.test", audit.STATE_ROOT + "/baselines/post.test"
        old, current = "2" * 36, self.system.files["/proc/sys/kernel/random/boot_id"].strip()
        self.system.files[audit.STATE_ROOT + "/state.conf"] = f"STAGE=verified\nTX=test\nCONFIG_SHA={sha}\nPENDING_BOOT={old}\nVERIFIED_BOOT={current}\nPRE_BASELINE={pre}\nPOST_BASELINE={post}\n"
        for path, kind, boot in ((pre, "pre", old), (post, "post", current)):
            self.system.files[path + "/META"] = f"KIND={kind}\nBOOT_ID={boot}\nCONFIG_SHA={sha}\nTX=test\nRESULT=complete\n"
        self.assertEqual(self.report()["reboot"]["status"], "managed-record-consistent")
        self.system.files[audit.MANAGED[0]] += "drift\n"
        self.assertEqual(self.report()["reboot"]["status"], audit.UNKNOWN)

    def test_nonroot_exit_two_and_invalid_apply_rejected(self):
        args = ["--port", "2222", "--user", "deploy", "--allow", "203.0.113.0/24", "--format", "json"]
        with patch.object(audit.os, "geteuid", return_value=1000), contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(audit.main(args), 2)
        self.assertEqual(json.loads(stdout.getvalue())["security_result"], audit.UNKNOWN)
        result = subprocess.run(["bash", str(ROOT / "stage0-audit.sh"), *args, "--apply"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)

    def test_reboot_record_includes_migrated_files_and_detects_their_drift(self):
        policy = audit.STATE_ROOT + "/policy.conf"
        migration = audit.STATE_ROOT + "/migration.json"
        extra = "/etc/ssh/sshd_config.d/legacy-retained.conf"
        self.system.files[policy] = "registered policy\n"
        for path in audit.MANAGED:
            self.system.files[path] = "managed file\n"
        self.system.files[extra] = "# migrated original\n"
        self.system.files[migration] = json.dumps({"schema": 1, "files": [{"path": extra}]})
        digest = hashlib.sha256(b"POLICY\nregistered policy\n")
        for path in [*audit.MANAGED, extra, migration]:
            digest.update(f"FILE {path}\n".encode() + self.system.files[path].encode())
        sha = digest.hexdigest()
        pre, post = audit.STATE_ROOT + "/baselines/pre.migrated", audit.STATE_ROOT + "/baselines/post.migrated"
        old, current = "2" * 36, self.system.files["/proc/sys/kernel/random/boot_id"].strip()
        self.system.files[audit.STATE_ROOT + "/state.conf"] = f"STAGE=verified\nTX=test\nCONFIG_SHA={sha}\nPENDING_BOOT={old}\nVERIFIED_BOOT={current}\nPRE_BASELINE={pre}\nPOST_BASELINE={post}\n"
        for path, kind, boot in ((pre, "pre", old), (post, "post", current)):
            self.system.files[path + "/META"] = f"KIND={kind}\nBOOT_ID={boot}\nCONFIG_SHA={sha}\nTX=test\nRESULT=complete\n"
        self.assertEqual(self.report()["reboot"]["status"], "managed-record-consistent")
        self.system.files[extra] += "# external drift\n"
        self.assertEqual(self.report()["reboot"]["status"], audit.UNKNOWN)

    def test_mutating_commands_cannot_use_collector(self):
        for command in (("systemctl", "restart", "ssh.socket"), ("nft", "flush", "ruleset"), ("bash", "-c", "true")):
            with self.subTest(command=command), self.assertRaises(audit.EvidenceError):
                audit.System().run(*command)

    def test_password_and_open_auth_are_facts_in_default_mode(self):
        self.system.login_method = "password"
        self.system.options.update(permitrootlogin="yes", passwordauthentication="yes")
        with patch.object(audit.os, "geteuid", return_value=0, create=True), patch.object(audit, "System", return_value=self.system):
            for args, expected in (([], 0), (["--check-baseline"], 1), (["--allow", "203.0.113.0/24"], 1)):
                with self.subTest(args=args), contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(audit.main(args), expected)
                if not args:
                    self.assertIn("现状采集：完成", output.getvalue())
                    self.assertIn("[待加固]", output.getvalue())
                    self.assertNotIn("现状基线结果：不符合", output.getvalue())

    def test_incomplete_required_collection_remains_exit_two(self):
        self.system.denied = "nft"
        with patch.object(audit.os, "geteuid", return_value=0, create=True), patch.object(audit, "System", return_value=self.system), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(audit.main(["--format", "json"]), 2)
        report = json.loads(output.getvalue())
        self.assertEqual(report["collection_result"], audit.UNKNOWN)
        self.assertIn("防火墙采集", report["collection_issues"])

    def test_root_is_observed_without_becoming_a_valid_deployment_target(self):
        os.environ.pop("SUDO_USER", None)
        os.environ.pop("SUDO_UID", None)
        os.environ["USER"] = "root"
        original = self.system.run
        def run(*args):
            if args == ("id", "-u", "root"):
                return "0\n"
            if args[0] == "journalctl":
                return original(*args).replace("for deploy", "for root")
            return original(*args)
        self.system.run = run
        with patch.object(audit.os, "geteuid", return_value=0, create=True), patch.object(audit, "System", return_value=self.system), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(audit.main(["--format", "json"]), 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["policy"]["user"], "root")
        self.assertEqual(report["collection_result"], audit.PASS)
        self.assertEqual(report["baseline_result"], audit.FAIL)
        self.assertEqual(report["observed"]["login_method"], "publickey")
        self.assertEqual(len(report["observed"]["authentication"]), 1)

    def test_absent_state_is_new_deployment_not_blocker(self):
        _, policy = audit.arguments([])
        auditor = audit.Auditor(policy, self.system)
        auditor.ownership()
        auditor.migration()
        self.assertEqual(auditor.report["migration"]["blockers"], [])
        self.assertNotEqual(auditor.report["migration"]["status"], "blocked")

    def test_ufw_is_collected_separately_from_project_loader(self):
        self.system.units["ufw.service"] = {"LoadState": "loaded", "ActiveState": "active"}
        original = self.system.run
        def run(*args):
            return "Status: active\n22/tcp ALLOW IN Anywhere\n" if args == ("ufw", "status", "verbose") else original(*args)
        self.system.run = run
        report = self.report()
        self.assertIn("Status: active", report["observed"]["ufw_status"])
        self.assertTrue(any(item.get("unit") == "ufw.service" for item in report["observed"]["firewall_managers"]))

    def test_upload_includes_audit_without_unconditional_stage3(self):
        path = ROOT / "working-scripts" / "upload-ssh-apply-to-aliyun-1.sh"
        if not path.exists():
            self.skipTest("本机上传脚本不入库")
        result = subprocess.run(["bash", str(path), "--dry-run"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("audit.py", result.stdout)
        self.assertNotIn("stage1.sh", result.stdout)
        for name in ("stage0-audit.sh", "stage1-newport.sh", "stage2-harden.sh", "stage3-reboot-check.sh"):
            self.assertIn(name, result.stdout)
        self.assertNotIn("stage3.sh --port", result.stdout)
        self.assertIn("不创建新版 state/policy", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
