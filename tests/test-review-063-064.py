"""BUG-063/064：未知拒绝保留遮挡风险，tailnet 完整接口放行按族取证。"""
import importlib
import json
import random
import unittest

g = importlib.import_module("test-guides")
r = importlib.import_module("test-review-061-062")
TN4 = "62207/tcp on tailscale0 ALLOW IN Anywhere\n"
TN6 = "62207/tcp (v6) on tailscale0 ALLOW IN Anywhere (v6)\n"


class TestUnknownDeny(unittest.TestCase):
    def test_unknown_deny_cannot_be_erased_before_allow(self):
        for first in ("10.0.0.5 62207/tcp DENY IN Anywhere\n",
                      "OpenSSH DENY IN Anywhere\n",
                      "62207/tcp REJECT IN 203.0.113.0/24 1024\n"):
            for m in (g.STAGE0, g.STAGE2):
                with self.subTest(first=first, script=m.SCRIPT):
                    body = first + r.ALLOW4 + r.DENY_BOTH
                    self.assertNotEqual(r.assess(m, body)["status"], "pass")
                    code, report = r.run_main(m, body)
                    self.assertEqual(code, 2)
                    if m is g.STAGE2:
                        self.assertFalse(report["complete"])

    def test_unknown_ipv6_deny_cannot_certify_tailnet(self):
        body = "OpenSSH (v6) DENY IN Anywhere (v6)\n" + TN4 + TN6 + r.DENY_BOTH
        for m in (g.STAGE0, g.STAGE2):
            self.assertNotEqual(r.assess(m, body, allows=[], tailnet=True)["status"], "pass")

    def test_known_unrelated_deny_does_not_block(self):
        for first in ("10.0.0.5 22/tcp DENY IN Anywhere\n",
                      "62207/udp DENY IN Anywhere\n",
                      "OpenSSH DENY OUT Anywhere (out)\n"):
            for m in (g.STAGE0, g.STAGE2):
                self.assertEqual(r.assess(m, first + r.ALLOW4 + r.DENY_BOTH)["status"], "pass")


class TestTailnetEvidence(unittest.TestCase):
    def assess(self, body):
        return [r.assess(m, body, allows=[], tailnet=True) for m in (g.STAGE0, g.STAGE2)]

    def test_each_missing_family_is_named(self):
        for allow, missing in ((TN4, "IPv6"), (TN6, "IPv4")):
            for result in self.assess(allow + r.DENY_BOTH):
                self.assertNotEqual(result["status"], "pass")
                self.assertIn(missing, result["detail"])

    def test_restricted_sources_cannot_certify_whole_interface(self):
        for literal in ("100.64.1.9", "100.64.0.0/10"):
            for result in self.assess(TN4.replace("Anywhere", literal) + TN6 + r.DENY_BOTH):
                self.assertNotEqual(result["status"], "pass")
        for result in self.assess(TN4 + TN6.replace("Anywhere (v6)", "fd7a:115c:a1e0::1") + r.DENY_BOTH):
            self.assertNotEqual(result["status"], "pass")

    def test_dual_stack_unrestricted_interface_passes(self):
        for body in (TN4 + TN6, TN4.replace("Anywhere", "0.0.0.0/0") + TN6.replace("Anywhere (v6)", "::/0")):
            for result in self.assess(body + r.DENY_BOTH):
                self.assertEqual(result["status"], "pass", result)

    def test_restricted_rule_then_full_interface_allow_can_pass(self):
        for result in self.assess(TN4.replace("Anywhere", "100.64.1.9") + TN4 + TN6 + r.DENY_BOTH):
            self.assertEqual(result["status"], "pass")

    def test_wrong_interface_or_allow_after_deny_cannot_certify(self):
        for body in (TN4 + TN6.replace("tailscale0", "eth0") + r.DENY_BOTH,
                     TN4 + r.DENY_BOTH + TN6):
            for result in self.assess(body):
                self.assertNotEqual(result["status"], "pass")

    def test_full_entry_rejects_single_family_and_accepts_both(self):
        for allow, expected in ((TN4, 2), (TN6, 2), (TN4 + TN6, 0)):
            for m in (g.STAGE0, g.STAGE2):
                system = g.make_stub(m, session_source="100.64.1.9", session_port=62207,
                    listeners=[62207], disk_ports=(62207,), backup=True, auth=g.HARDENED_AUTH,
                    allowlist_rules=g.ALLOW_RULES, hardening_mtime=999999999, tailnet=True,
                    ufw_active=True, ufw_text=r.HEAD + allow + r.DENY_BOTH)
                code, output = g.run_main(m, ["--port", "62207", "--user", "fenix", "--tailnet",
                    "--tailnet-session-confirmed", "--rescue-confirmed", "--reboot-confirmed",
                    "--format", "json"], system)
                self.assertEqual(code, expected, (m.SCRIPT, output))
                if m is g.STAGE2:
                    self.assertEqual(json.loads(output)["complete"], expected == 0)

    def test_random_interface_rules_against_first_match_model(self):
        """独立模型显式模拟族、接口、来源；每个通过样本必须保留完整 tailnet 并拒绝公网。"""
        import ipaddress
        rng = random.Random(64063)
        sources = {4: ["Anywhere", "100.64.1.9", "100.64.0.0/10"],
                   6: ["Anywhere", "fd7a:115c:a1e0::1", "fd7a:115c:a1e0::/48"]}
        passed = 0
        for _ in range(2000):
            rules = [(rng.choice((4, 6)), rng.choice(("tailscale0", "eth0", None)),
                      rng.choice(("ALLOW", "DENY", "REJECT"))) for _ in range(rng.randint(0, 5))]
            model, lines = [], []
            for fam, iface, verb in rules + [(4, "tailscale0", "ALLOW"), (6, "tailscale0", "ALLOW"),
                                             (4, None, "DENY"), (6, None, "DENY")]:
                src = rng.choice(sources[fam]) if len(model) < len(rules) else "Anywhere"
                model.append((fam, iface, verb, src))
                lines.append("62207/tcp%s%s %s IN %s%s" % (
                    " (v6)" if fam == 6 else "", " on " + iface if iface else "", verb, src,
                    " (v6)" if fam == 6 and src == "Anywhere" else ""))
            body = "\n".join(lines)
            def reachable(fam, iface, address):
                for family, interface, verb, src in model:
                    if family == fam and (interface is None or interface == iface) and (
                            src == "Anywhere" or ipaddress.ip_address(address) in ipaddress.ip_network(src)):
                        return verb == "ALLOW"
                return True
            for result in self.assess(body):
                if result["status"] == "pass":
                    passed += 1
                    for fam, addr in ((4, "100.64.1.9"), (4, "100.64.2.8"),
                                      (6, "fd7a:115c:a1e0::1"), (6, "fd7a:115c:a1e0::2")):
                        self.assertTrue(reachable(fam, "tailscale0", addr), body)
                    for fam, addr in ((4, "198.51.100.1"), (6, "2001:db8::1")):
                        self.assertFalse(reachable(fam, "eth0", addr), body)
        self.assertGreater(passed, 100)
