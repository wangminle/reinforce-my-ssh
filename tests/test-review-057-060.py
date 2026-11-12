"""BUG-057～060：反例不得变成安全通过，并保留正常规则的正向验收。"""
import copy
import ast
import importlib
import json
import shutil
import subprocess
import sys
import unittest

g = importlib.import_module("test-guides")


def raw_rules():
    return json.loads(g.packet_nft(g.ALLOW_RULES))


def assess(module, raw, allows=None, tailnet=False):
    system = g.make_stub(module)
    system.can("nft -j list ruleset", json.dumps(raw))
    summary = module.nft_ruleset_summary(system)
    return module.allowlist_assessment(summary, {}, 62207,
        ["203.0.113.0/24"] if allows is None else allows, tailnet), summary


class TestFirewallEvidence(unittest.TestCase):
    def test_negated_other_port_accept_is_not_skipped_as_irrelevant(self):
        raw = raw_rules()
        broad = copy.deepcopy(raw["nftables"][-1]["rule"])
        broad["expr"][0]["match"].update(op="!=", right=80)
        broad["expr"][-1] = {"accept": None}
        raw["nftables"].insert(2, {"rule": broad})
        for module in (g.STAGE0, g.STAGE2):
            self.assertNotEqual(assess(module, raw)[0]["status"], "pass")

    def test_invalid_deny_cannot_close_tcp_port(self):
        for case in ("negated-port", "udp", "ipv4-only", "forward", "unhooked",
                     "conditional-state", "conditional-flags"):
            raw = raw_rules()
            drop = raw["nftables"][-1]["rule"]
            if case == "negated-port":
                drop["expr"][0]["match"]["op"] = "!="
            elif case == "udp":
                drop["expr"][0]["match"]["left"]["payload"]["protocol"] = "udp"
            elif case == "ipv4-only":
                drop["expr"].insert(0, {"match": {"op": "==",
                    "left": {"meta": {"key": "nfproto"}}, "right": "ipv4"}})
            elif case in ("forward", "unhooked"):
                chain = raw["nftables"][1]["chain"]
                if case == "forward":
                    chain["hook"] = "forward"
                else:
                    chain.pop("hook")
            elif case == "conditional-state":
                drop["expr"].insert(0, {"match": {"op": "==",
                    "left": {"ct": {"key": "state"}}, "right": "established"}})
            else:
                drop["expr"].insert(0, {"match": {"op": "==",
                    "left": {"payload": {"protocol": "tcp", "field": "flags"}}, "right": "ack"}})
            for module in (g.STAGE0, g.STAGE2):
                with self.subTest(case=case, script=module.SCRIPT):
                    result, summary = assess(module, raw)
                    self.assertNotEqual(result["status"], "pass", result)
                    if module is g.STAGE2:
                        self.assertIsNot(module.nft_public_verdict(summary, 62207), False)

    def test_allow_and_deny_cannot_be_stitched_across_chains(self):
        raw = raw_rules()
        raw["nftables"].insert(2, {"chain": {"family": "inet", "table": "sshguard",
            "name": "other", "hook": "input", "policy": "accept"}})
        raw["nftables"][-1]["rule"]["chain"] = "other"
        for module in (g.STAGE0, g.STAGE2):
            self.assertNotEqual(assess(module, raw)[0]["status"], "pass")

    def test_negated_source_and_named_set_are_not_literal_allow_evidence(self):
        for right, op in (("203.0.113.0/24", "!="), ("@trusted", "==")):
            raw = raw_rules()
            match = raw["nftables"][-2]["rule"]["expr"][-2]["match"]
            match.update(right=right, op=op)
            for module in (g.STAGE0, g.STAGE2):
                self.assertNotEqual(assess(module, raw)[0]["status"], "pass")

    def test_dual_stack_inet_and_input_policy_drop_remain_supported(self):
        for policy in (False, True):
            raw = raw_rules()
            if policy:
                raw["nftables"][1]["chain"]["policy"] = "drop"
                raw["nftables"].pop()
            for module in (g.STAGE0, g.STAGE2):
                self.assertEqual(assess(module, raw)[0]["status"], "pass")

    def test_separate_ip_and_ip6_input_chains_need_their_own_deny(self):
        raw = raw_rules()
        ipv4 = copy.deepcopy(raw["nftables"])
        for entry in ipv4:
            for value in entry.values():
                value["family"] = "ip"
        raw["nftables"] = ipv4
        for module in (g.STAGE0, g.STAGE2):
            self.assertNotEqual(assess(module, raw)[0]["status"], "pass")
        ipv6 = [{"table": {"family": "ip6", "name": "v6"}},
                {"chain": {"family": "ip6", "table": "v6", "name": "input",
                           "hook": "input", "policy": "drop"}}]
        raw["nftables"] += ipv6
        for module in (g.STAGE0, g.STAGE2):
            self.assertEqual(assess(module, raw)[0]["status"], "pass")

    def test_invalid_deny_blocks_complete_stage0_and_stage2(self):
        for module in (g.STAGE0, g.STAGE2):
            raw = raw_rules()
            raw["nftables"][-1]["rule"]["expr"][0]["match"]["op"] = "!="
            system = g.make_stub(module, session_port=62207, listeners=[62207],
                disk_ports=(62207,), backup=True, auth=g.HARDENED_AUTH,
                allowlist_rules=g.ALLOW_RULES, hardening_mtime=999999999)
            system.can("nft -j list ruleset", json.dumps(raw))
            code, output = g.run_main(module, ["--port", "62207", "--user", "fenix",
                "--allow", "203.0.113.0/24", "--rescue-confirmed", "--reboot-confirmed",
                "--format", "json"], system)
            self.assertNotEqual(code, 0)
            if module is g.STAGE2:
                report = json.loads(output)
                self.assertFalse(report["complete"])
                steps = {x["id"]: x for x in report["steps"]}
                self.assertNotEqual(steps["3-confirm"]["status"], "done")
                self.assertNotEqual(steps["4-reboot-verify"]["status"], "done")


class TestAuthenticationMethods(unittest.TestCase):
    def test_multifactor_and_unverified_any_cannot_complete_hardening(self):
        for methods in ("publickey,password", "publickey,keyboard-interactive",
                        "publickey,publickey", "password publickey,password", "any"):
            auth = dict(g.HARDENED_AUTH, authenticationmethods=methods)
            for module in (g.STAGE0, g.STAGE2):
                with self.subTest(methods=methods, script=module.SCRIPT):
                    system = g.make_stub(module, session_port=62207, listeners=[62207],
                        disk_ports=(62207,), backup=True, auth=auth,
                        allowlist_rules=g.ALLOW_RULES, hardening_mtime=999999999)
                    code, output = g.run_main(module, ["--port", "62207", "--user", "fenix",
                        "--allow", "203.0.113.0/24", "--rescue-confirmed", "--reboot-confirmed",
                        "--format", "json"], system)
                    self.assertNotEqual(code, 0, "多因素/未核实认证配置被误报完成：" + methods)


class TestSocketAndAccountPort(unittest.TestCase):
    def test_unrelated_systemd_socket_is_excluded(self):
        system = g.make_stub(g.STAGE2, session_port=62207, listeners=[62207])
        system.canned["ss -tlnpH"].stdout += 'LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("systemd",pid=1,fd=99))\n'
        self.assertEqual(g.STAGE2.ssh_listener_ports(system), [62207])
        self.assertNotIn(8080, [x["port"] for x in g.STAGE2.sshd_bindings(system)])

    def test_ssh_socket_listener_remains_included(self):
        system = g.make_stub(g.STAGE2, session_port=62207, listeners=[62207], listener_process="systemd")
        self.assertEqual(g.STAGE2.ssh_listener_ports(system), [62207])
        self.assertIn(62207, [x["port"] for x in g.STAGE2.sshd_bindings(system)])

    def test_no_old_port_account_and_tailnet_commands_use_current_entry(self):
        _, _, _, steps = g.TestStage1Steps().steps(
            session_port=62207, listeners=[62207], disk_ports=(62207,),
            account=False, backup=True, tailnet=True,
            extra=["--old-port", "none", "--tailnet"])
        for sid in ("2-account", "2b-tailnet"):
            commands = "\n".join(steps[sid]["do"])
            self.assertNotIn("-p 22 ", commands)
            self.assertIn("-p 62207 ", commands)

    def test_known_old_port_is_preserved_for_account_installation(self):
        _, _, _, steps = g.TestStage1Steps().steps(account=False, extra=["--old-port", "22"])
        self.assertIn("-p 22 ", "\n".join(steps["2-account"]["do"]))

    def test_same_port_other_address_is_not_an_ssh_socket_binding(self):
        system = g.make_stub(g.STAGE2, session_port=62207, listeners=[62207], listener_process="systemd")
        system.can("systemctl show ssh.socket", "LoadState=loaded\nActiveState=active\nListen=127.0.0.1:62207 (Stream)\n")
        self.assertEqual(g.STAGE2.sshd_bindings(system), [])

    def test_account_without_session_uses_declared_port_not_22(self):
        _, options, ctx, _ = g.TestStage1Steps().steps(account=False, extra=["--old-port", "none"])
        ctx["connection"] = None
        steps = {x["id"]: x for x in g.STAGE1.build_steps(None, options, ctx)}
        self.assertIn("-p 62207 ", "\n".join(steps["2-account"]["do"]))


class TestNativeAndSharedFirewallCode(unittest.TestCase):
    def test_two_embedded_firewall_implementations_cannot_drift(self):
        functions = []
        for script in ("stage0-check.sh", "stage2-lockdown.sh"):
            tree = ast.parse(g.load_script(script).SOURCE)
            functions.append({node.name: ast.dump(node, include_attributes=False)
                for node in tree.body if isinstance(node, ast.FunctionDef)})
        for name in ("rule_digest", "nft_ruleset_summary", "nft_allowlist_assessment", "allowlist_assessment"):
            self.assertEqual(functions[0][name], functions[1][name], name)

    def test_actual_kernel_json_keeps_protocol_operator_family_and_hook(self):
        if not sys.platform.startswith("linux") or not all(shutil.which(x) for x in ("unshare", "nft")):
            self.skipTest("需要 Linux unshare 与 nft；只在独立用户/网络命名空间执行")
        runner = """import subprocess,sys
subprocess.run(['nft','-f','-'],input=sys.stdin.read(),text=True,check=True)
print(subprocess.check_output(['nft','-j','-n','list','ruleset'],text=True))
"""
        for deny, expected in (("tcp dport 62207 drop", "pass"),
                ("tcp dport != 62207 drop", None), ("udp dport 62207 drop", None),
                ("meta nfproto ipv4 tcp dport 62207 drop", None)):
            rules = ("table inet review { chain input { type filter hook input priority 0; policy accept; "
                     "tcp dport 62207 ip saddr 203.0.113.0/24 accept; " + deny + "; }; }\n")
            result = subprocess.run(["unshare", "-Urn", "--", sys.executable, "-c", runner],
                input=rules, capture_output=True, text=True)
            if result.returncode and "unshare failed: Operation not permitted" in result.stderr:
                self.skipTest("本机禁止隔离用户/网络命名空间")
            self.assertEqual(result.returncode, 0, result.stderr)
            for module in (g.STAGE0, g.STAGE2):
                outcome = assess(module, json.loads(result.stdout))[0]["status"]
                with self.subTest(deny=deny, script=module.SCRIPT):
                    if expected:
                        self.assertEqual(outcome, expected)
                    else:
                        self.assertNotEqual(outcome, "pass")
