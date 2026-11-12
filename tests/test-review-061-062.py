"""BUG-061/062：UFW 端口范围放行不得漏判，拒绝证据须分 IPv4/IPv6 各自成立。"""
import ast
import importlib
import json
import unittest

g = importlib.import_module("test-guides")

HEAD = "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\n"
ALLOW4 = "62207/tcp ALLOW IN 203.0.113.0/24\n"
DENY_BOTH = "62207/tcp DENY IN Anywhere\n62207/tcp (v6) DENY IN Anywhere (v6)\n"
ALLOWS = ["203.0.113.0/24"]


def assess(module, body, head=HEAD, allows=None, tailnet=False):
    ufw = {"available": True, "active": True, "text": (head + body).strip()}
    return module.allowlist_assessment({"rules": [], "input_policy": []}, ufw, 62207,
                                       ALLOWS if allows is None else allows, tailnet)


def run_main(module, body, head=HEAD):
    system = g.make_stub(module, session_port=62207, listeners=[62207], disk_ports=(62207,),
        backup=True, auth=g.HARDENED_AUTH, allowlist_rules=g.ALLOW_RULES, hardening_mtime=999999999,
        ufw_active=True, ufw_text=head + body)
    code, output = g.run_main(module, ["--port", "62207", "--user", "fenix", "--allow", "203.0.113.0/24",
        "--rescue-confirmed", "--reboot-confirmed", "--format", "json"], system)
    return code, json.loads(output)


class TestBug061PortRanges(unittest.TestCase):
    """覆盖目标端口的范围/列表/全端口放行与单端口规则同样按首条匹配语义处理。"""

    def not_pass(self, body, **kwargs):
        for module in (g.STAGE0, g.STAGE2):
            with self.subTest(script=module.SCRIPT, body=body):
                self.assertNotEqual(assess(module, body, **kwargs)["status"], "pass")

    def passes(self, body, **kwargs):
        for module in (g.STAGE0, g.STAGE2):
            with self.subTest(script=module.SCRIPT, body=body):
                result = assess(module, body, **kwargs)
                self.assertEqual(result["status"], "pass", result["detail"])

    def test_range_allow_anywhere_before_allowlist_fails(self):
        self.not_pass("62000:63000/tcp ALLOW IN Anywhere\n" + ALLOW4 + DENY_BOTH)

    def test_range_allow_anywhere_ipv6_row_fails(self):
        self.not_pass(ALLOW4 + "62000:63000/tcp (v6) ALLOW IN Anywhere (v6)\n" + DENY_BOTH)

    def test_port_list_and_range_inside_list_fail(self):
        for spec in ("62207,62208/tcp", "80,62000:63000/tcp", "62207,62208", "62000:63000"):
            self.not_pass(spec + " ALLOW IN Anywhere\n" + ALLOW4 + DENY_BOTH)

    def test_all_ports_and_proto_only_allow_fail(self):
        for spec in ("Anywhere", "Anywhere/tcp"):
            self.not_pass(spec + " ALLOW IN Anywhere\n" + ALLOW4 + DENY_BOTH)

    def test_limit_rule_is_an_accept(self):
        self.not_pass("62000:63000/tcp LIMIT IN Anywhere\n" + ALLOW4 + DENY_BOTH)

    def test_range_allow_from_foreign_source_fails(self):
        self.not_pass("62000:63000/tcp ALLOW IN 198.51.100.0/24\n" + ALLOW4 + DENY_BOTH)

    def test_unresolvable_rules_cannot_prove_allowlist(self):
        for rule in ("OpenSSH ALLOW IN Anywhere",
                     "192.168.1.5 62207/tcp ALLOW IN Anywhere",
                     "62207/tcp ALLOW IN 203.0.113.0/24 1024"):
            self.not_pass(rule + "\n" + ALLOW4 + DENY_BOTH)

    def test_unrelated_rules_do_not_cause_false_positive(self):
        for rule in ("22/tcp ALLOW IN Anywhere", "62000:62100/tcp ALLOW IN Anywhere",
                     "62207/udp ALLOW IN Anywhere", "80,443/tcp ALLOW IN Anywhere",
                     "Anywhere/udp ALLOW IN Anywhere", "62207/tcp ALLOW OUT Anywhere (out)",
                     "62207/tcp ALLOW FWD Anywhere", "192.168.1.5 80/tcp ALLOW IN Anywhere"):
            self.passes(rule + "\n" + ALLOW4 + DENY_BOTH)

    def test_range_allow_from_declared_source_is_valid_evidence(self):
        self.passes("62000:63000/tcp ALLOW IN 203.0.113.0/24\n" + DENY_BOTH)

    def test_range_deny_after_allowlist_closes_both_families(self):
        self.passes(ALLOW4 + "62000:63000/tcp DENY IN Anywhere\n62000:63000/tcp (v6) DENY IN Anywhere (v6)\n")

    def test_comment_does_not_break_parsing(self):
        self.passes("62207/tcp ALLOW IN 203.0.113.0/24 # ssh allowlist\n62207/tcp DENY IN Anywhere # d\n"
                    "62207/tcp (v6) DENY IN Anywhere (v6) # d\n")

    def test_reported_ordering_cannot_complete_stage0_or_stage2(self):
        body = ("62000:63000/tcp ALLOW IN Anywhere\n" + ALLOW4 + DENY_BOTH)
        for module in (g.STAGE0, g.STAGE2):
            with self.subTest(script=module.SCRIPT):
                code, report = run_main(module, body)
                self.assertNotEqual(code, 0)
                if module is g.STAGE2:
                    self.assertFalse(report["complete"])
                    steps = {x["id"]: x for x in report["steps"]}
                    self.assertNotEqual(steps["1-allowlist"]["status"], "done")
                    self.assertNotEqual(steps["3-confirm"]["status"], "done")


class TestBug062AddressFamilies(unittest.TestCase):
    def not_pass(self, body, head=HEAD):
        for module in (g.STAGE0, g.STAGE2):
            with self.subTest(script=module.SCRIPT, body=body):
                self.assertNotEqual(assess(module, body, head)["status"], "pass")

    def test_ipv4_only_deny_does_not_cover_ipv6(self):
        self.not_pass(ALLOW4 + "62207/tcp DENY IN Anywhere\n")
        self.not_pass(ALLOW4 + "62207/tcp DENY IN Anywhere\n",
                      head="Status: active\nDefault: allow (incoming), allow (outgoing)\n")

    def test_ipv6_only_deny_does_not_cover_ipv4(self):
        self.not_pass(ALLOW4 + "62207/tcp (v6) DENY IN Anywhere (v6)\n")

    def test_failure_names_the_missing_family(self):
        for module in (g.STAGE0, g.STAGE2):
            detail = assess(module, ALLOW4 + "62207/tcp DENY IN Anywhere\n")["detail"]
            self.assertIn("IPv6", detail)
            detail = assess(module, ALLOW4 + "62207/tcp (v6) DENY IN Anywhere (v6)\n")["detail"]
            self.assertIn("IPv4", detail)

    def test_source_specific_deny_is_not_a_default_deny(self):
        self.not_pass(ALLOW4 + "62207/tcp DENY IN 198.51.100.0/24\n62207/tcp (v6) DENY IN 2001:db8::/32\n")

    def test_dual_stack_deny_still_passes(self):
        for module in (g.STAGE0, g.STAGE2):
            self.assertEqual(assess(module, ALLOW4 + DENY_BOTH)["status"], "pass")

    def test_dual_stack_allowlist_with_ipv6_source_passes(self):
        body = ("62207/tcp ALLOW IN 203.0.113.0/24\n62207/tcp (v6) ALLOW IN 2001:db8::/32\n" + DENY_BOTH)
        for module in (g.STAGE0, g.STAGE2):
            result = assess(module, body, allows=["203.0.113.0/24", "2001:db8::/32"])
            self.assertEqual(result["status"], "pass", result["detail"])

    def test_tailnet_allow_still_needs_both_families_denied(self):
        body = "62207/tcp on tailscale0 ALLOW IN Anywhere\n62207/tcp DENY IN Anywhere\n"
        for module in (g.STAGE0, g.STAGE2):
            self.assertNotEqual(assess(module, body, allows=[], tailnet=True)["status"], "pass")
            both = "62207/tcp (v6) on tailscale0 ALLOW IN Anywhere (v6)\n" + body + "62207/tcp (v6) DENY IN Anywhere (v6)\n"
            self.assertEqual(assess(module, both, allows=[], tailnet=True)["status"], "pass")

    def test_reported_ipv4_only_deny_cannot_complete_stage0_or_stage2(self):
        head = "Status: active\nDefault: allow (incoming), allow (outgoing), disabled (routed)\n"
        for module in (g.STAGE0, g.STAGE2):
            with self.subTest(script=module.SCRIPT):
                code, report = run_main(module, ALLOW4 + "62207/tcp DENY IN Anywhere\n", head)
                self.assertNotEqual(code, 0)
                if module is g.STAGE2:
                    self.assertFalse(report["complete"])


class TestPublicEntryVerdict(unittest.TestCase):
    """stage2 --tailnet 的公网入口判定：IPv4 拒绝不能代表 IPv6 已关闭。"""

    def verdict(self, body):
        return g.STAGE2.ufw_public_verdict({"active": True, "text": HEAD + body}, 62207)

    def test_single_family_deny_is_not_closed(self):
        self.assertIsNone(self.verdict("62207/tcp on tailscale0 ALLOW IN Anywhere\n62207/tcp DENY IN Anywhere\n"))
        self.assertIsNone(self.verdict("62207/tcp (v6) DENY IN Anywhere (v6)\n"))

    def test_both_families_denied_is_closed(self):
        self.assertIs(self.verdict("62207/tcp on tailscale0 ALLOW IN Anywhere\n" + DENY_BOTH), False)

    def test_range_allow_before_deny_keeps_public_open(self):
        self.assertIs(self.verdict("62000:63000/tcp ALLOW IN Anywhere\n" + DENY_BOTH), True)

    def test_ipv6_range_allow_cannot_be_hidden_by_ipv4_deny(self):
        body = "62207/tcp DENY IN Anywhere\n62000:63000/tcp (v6) ALLOW IN Anywhere (v6)\n62207/tcp (v6) DENY IN Anywhere (v6)\n"
        self.assertIs(self.verdict(body), True)

    def test_unresolvable_rule_prevents_a_closed_verdict(self):
        self.assertIsNone(self.verdict("OpenSSH ALLOW IN Anywhere\n" + DENY_BOTH))

    def test_unrelated_rules_are_ignored(self):
        self.assertIs(self.verdict("22/tcp ALLOW IN Anywhere\n" + DENY_BOTH), False)


class TestFirstMatchModel(unittest.TestCase):
    """固定种子随机规则表：判定为 pass/关闭时，按 UFW 首条匹配模型（最坏情况默认允许）必须真的成立。"""
    PORT = 62207
    TOS = ["62207/tcp", "62207", "62000:63000/tcp", "62207,62208/tcp", "80/tcp", "22/tcp", "62207/udp",
           "Anywhere", "Anywhere/tcp", "62000:62100/tcp", "63000:64000", "80,62000:63000/tcp"]
    SRC4 = ["Anywhere", "203.0.113.0/24", "203.0.113.9", "198.51.100.0/24"]
    SRC6 = ["Anywhere", "2001:db8::/32"]
    VERBS = ["ALLOW", "DENY", "LIMIT", "REJECT"]

    def covers(self, to):
        if to.startswith("Anywhere"):
            return not to.endswith("udp")
        spec, _, proto = to.partition("/")
        if proto == "udp":
            return False
        for item in spec.split(","):
            low, _, high = item.partition(":")
            if int(low) <= self.PORT <= int(high or low):
                return True
        return False

    def reachable(self, rules, family, address):
        import ipaddress
        for to, verb, source, fam in rules:
            if fam == family and self.covers(to) and (
                    source == "Anywhere" or ipaddress.ip_address(address) in ipaddress.ip_network(source)):
                return verb in ("ALLOW", "LIMIT")
        return True

    def test_pass_and_closed_verdicts_are_sound(self):
        import random
        rng = random.Random(1234)
        checked = 0
        for _ in range(4000):
            rules = []
            for _ in range(rng.randint(1, 6)):
                family = rng.choice([4, 6])
                rules.append((rng.choice(self.TOS), rng.choice(self.VERBS),
                              rng.choice(self.SRC4 if family == 4 else self.SRC6), family))
            for family in (4, 6):
                if rng.random() < 0.8:
                    rules.append(("62207/tcp", "DENY", "Anywhere", family))
            body = "\n".join("%s%s %s IN %s" % (to, " (v6)" if fam == 6 else "", verb,
                "Anywhere (v6)" if fam == 6 and src == "Anywhere" else src) for to, verb, src, fam in rules)
            allowed_ok = all(self.reachable(rules, 4, a) for a in ("203.0.113.1", "203.0.113.200"))
            denied_ok = (not self.reachable(rules, 4, "198.51.100.7") and not self.reachable(rules, 4, "192.0.2.77")
                         and not self.reachable(rules, 6, "2001:db8::1") and not self.reachable(rules, 6, "2001:4860::1"))
            for module in (g.STAGE0, g.STAGE2):
                if assess(module, body)["status"] == "pass":
                    checked += 1
                    self.assertTrue(allowed_ok and denied_ok, module.SCRIPT + "\n" + body)
            if g.STAGE2.ufw_public_verdict({"active": True, "text": body}, self.PORT) is False:
                self.assertTrue(denied_ok and not self.reachable(rules, 4, "203.0.113.1"), body)
        self.assertGreater(checked, 100, "随机样本中应包含足够多的合法 pass 以证明不是恒拒绝")


class TestSharedImplementation(unittest.TestCase):
    def test_ufw_parsers_cannot_drift_between_scripts(self):
        functions = []
        for script in ("stage0-check.sh", "stage2-lockdown.sh"):
            tree = ast.parse(g.load_script(script).SOURCE)
            functions.append({node.name: ast.dump(node, include_attributes=False)
                for node in tree.body if isinstance(node, ast.FunctionDef)})
        for name in ("ufw_rules", "allowlist_assessment"):
            self.assertIn(name, functions[0])
            self.assertEqual(functions[0][name], functions[1][name], name)


if __name__ == "__main__":
    unittest.main()
