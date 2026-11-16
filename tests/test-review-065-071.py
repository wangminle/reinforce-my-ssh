"""BUG-065~071：多 input 基链、相邻/重叠来源、UFW 前置插入、纯 UFW 主机、位置判定、回退命令与大小写解析。"""
import importlib
import json
import unittest

g = importlib.import_module("test-guides")

ALLOW = ["203.0.113.0/24"]


def nft_with(extra_items, rules=None, **chain_overrides):
    raw = json.loads(g.packet_nft(rules if rules is not None else g.ALLOW_RULES))
    raw["nftables"].extend(extra_items)
    return raw


def assess_nft(module, raw, allows=None, tailnet=False):
    system = g.make_stub(module)
    system.can("nft -j list ruleset", json.dumps(raw))
    return module.nft_allowlist_assessment(module.nft_ruleset_summary(system), 62207,
                                           ALLOW if allows is None else allows, tailnet)


def chain(name, policy, family="inet", table="filter"):
    return {"chain": {"family": family, "table": table, "name": name, "hook": "input",
                      "type": "filter", "policy": policy}}


def rule(verdict, expr_extra=None, name="input", table="filter", family="inet"):
    expr = list(expr_extra or []) + [{verdict: None}]
    return {"rule": {"family": family, "table": table, "chain": name, "expr": expr}}


def dport_match(port=62207):
    return {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": port}}


class TestBug065MultipleInputChains(unittest.TestCase):
    def test_other_chain_default_drop_blocks_pass(self):
        raw = nft_with([{"table": {"family": "inet", "name": "filter"}}, chain("input", "drop")])
        for m in (g.STAGE0, g.STAGE2):
            with self.subTest(script=m.SCRIPT):
                result = assess_nft(m, raw)
                self.assertEqual(result["status"], "fail", result)
                self.assertIn("全部 input 基链", result["detail"])

    def test_other_chain_explicit_drop_blocks_pass(self):
        raw = nft_with([chain("input", "accept"), rule("drop", [dport_match()])])
        for m in (g.STAGE0, g.STAGE2):
            with self.subTest(script=m.SCRIPT):
                self.assertEqual(assess_nft(m, raw)["status"], "fail")

    def test_unrelated_accept_chain_does_not_block(self):
        raw = nft_with([chain("input", "accept")])
        for m in (g.STAGE0, g.STAGE2):
            with self.subTest(script=m.SCRIPT):
                self.assertEqual(assess_nft(m, raw)["status"], "pass")

    def test_established_only_accept_chain_does_not_block(self):
        est = {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": {"set": ["established", "related"]}}}
        raw = nft_with([chain("input", "accept"), rule("accept", [est])])
        for m in (g.STAGE0, g.STAGE2):
            with self.subTest(script=m.SCRIPT):
                self.assertEqual(assess_nft(m, raw)["status"], "pass")


def saddr_rule(addresses):
    return {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"set": addresses}}}


def allow_raw(addresses):
    raw = json.loads(g.packet_nft([("accept", None, None, ("established", "related")),
                                   ("accept", 62207, ["203.0.113.0/24"], None),
                                   ("drop", 62207, None, None)]))
    for item in raw["nftables"]:
        for expr in item.get("rule", {}).get("expr", []):
            node = expr.get("match", {})
            if node.get("left", {}).get("payload", {}).get("field") == "saddr":
                node["right"] = {"set": addresses}
    return raw


class TestBug066AdjacentOverlappingSources(unittest.TestCase):
    def test_parse_collapses_overlapping_and_adjacent(self):
        for m, extra in ((g.STAGE0, []), (g.STAGE1, ["--port", "62207", "--user", "fenix"]),
                         (g.STAGE2, ["--port", "62207", "--user", "fenix"])):
            with self.subTest(script=m.SCRIPT):
                overlap = m.parse_args(extra + ["--allow", "10.0.0.0/24", "--allow", "10.0.0.128/25"])
                self.assertEqual(overlap.allow, ["10.0.0.0/24"])
                adjacent = m.parse_args(extra + ["--allow", "10.0.0.0/24", "--allow", "10.0.1.0/24",
                                                  "--allow", "2001:db8::/64"])
                self.assertEqual(adjacent.allow, ["10.0.0.0/23", "2001:db8::/64"])

    def test_nft_merged_supernet_is_accepted(self):
        raw = allow_raw([{"prefix": {"addr": "10.0.0.0", "len": 23}}])
        for m in (g.STAGE0, g.STAGE2):
            with self.subTest(script=m.SCRIPT):
                result = assess_nft(m, raw, allows=["10.0.0.0/24", "10.0.1.0/24"])
                self.assertEqual(result["status"], "pass", result)

    def test_nft_range_element_is_parsed(self):
        raw = allow_raw([{"range": ["10.0.1.0", "10.0.2.255"]}])
        for m in (g.STAGE0, g.STAGE2):
            with self.subTest(script=m.SCRIPT):
                self.assertEqual(m.literal_values({"range": ["10.0.1.0", "10.0.2.255"]}, addresses=True),
                                 ["10.0.1.0/24", "10.0.2.0/24"])
                self.assertEqual(m.literal_values({"range": [1000, 2000]}), [])
                result = assess_nft(m, raw, allows=["10.0.1.0/24", "10.0.2.0/24"])
                self.assertEqual(result["status"], "pass", result)

    def test_range_wider_than_declared_is_rejected(self):
        raw = allow_raw([{"range": ["10.0.1.0", "10.0.3.255"]}])
        for m in (g.STAGE0, g.STAGE2):
            with self.subTest(script=m.SCRIPT):
                self.assertEqual(assess_nft(m, raw, allows=["10.0.1.0/24", "10.0.2.0/24"])["status"], "fail")

    def test_port_range_stays_uninterpretable(self):
        for m in (g.STAGE0, g.STAGE2):
            digest = m.rule_digest({"expr": [{"match": {"op": "==", "left": {"payload": {
                "protocol": "tcp", "field": "dport"}}, "right": {"range": [60000, 65000]}}}, {"accept": None}]})
            self.assertFalse(digest["conditions_supported"])

    def test_stage2_generates_collapsed_nft_set(self):
        _, _, _, steps = g.TestStage2Steps().build(
            session_port=62207, listeners=[62207], backup=True, allow=["10.0.0.0/24", "10.0.0.128/25"],
            session_source="10.0.0.9")
        text = "\n".join(steps["1-allowlist"]["do"])
        self.assertIn("ip saddr { 10.0.0.0/24 }", text)
        self.assertNotIn("10.0.0.128/25", text)


class TestBug067UfwPrepend(unittest.TestCase):
    def test_ipv6_and_tailnet_use_prepend(self):
        ufw_text = "Status: active\n62207/tcp ALLOW Anywhere\n"
        _, _, _, steps = g.TestStage2Steps().build(
            session_port=62207, listeners=[62207], backup=True, ufw_active=True, ufw_text=ufw_text, tailnet=True,
            session_source="2001:db8::9", allow=["2001:db8::/32", "203.0.113.0/24"],
            extra=["--tailnet"])
        commands = steps["1-allowlist"]["do"] + steps["1b-close-public"]["do"]
        self.assertFalse([c for c in commands if "ufw insert" in c], commands)
        self.assertTrue([c for c in commands if c.startswith("sudo ufw prepend allow from 2001:db8::/32")])
        self.assertTrue([c for c in commands if c.startswith("sudo ufw prepend allow in on tailscale0")])
        self.assertFalse([c for c in commands if c.startswith("sudo ufw allow in on tailscale0")])


class TestBug068NftUnavailable(unittest.TestCase):
    ARGS = ["--port", "62207", "--user", "fenix", "--allow", "203.0.113.0/24", "--format", "json"]

    def run_stage0(self, **kwargs):
        system = g.make_stub(g.STAGE0, session_port=62207, listeners=[62207], disk_ports=(62207,), backup=True,
                             auth=g.HARDENED_AUTH, hardening_mtime=999999999, **kwargs)
        system.can("nft -j list ruleset", "", returncode=1, stderr="nft: command not found")
        code, output = g.run_main(g.STAGE0, self.ARGS + ["--reboot-confirmed", "--rescue-confirmed"], system)
        return code, json.loads(output)

    def test_ufw_only_host_is_still_assessed(self):
        code, report = self.run_stage0(ufw_active=True)
        statuses = {x["item"]: x["status"] for x in report["assessment"]}
        self.assertEqual(statuses["来源白名单"], "pass", report["facts"].get("allowlist"))
        self.assertEqual(report["facts"]["failed"], [])
        self.assertEqual(code, 0)
        self.assertIn("error", report["facts"]["nft"])

    def test_without_ufw_nft_failure_is_reported(self):
        code, report = self.run_stage0(ufw_active=False)
        self.assertEqual(code, 2)
        self.assertEqual([x["name"] for x in report["facts"]["failed"]], ["防火墙采集"])
        statuses = {x["item"]: x["status"] for x in report["assessment"]}
        self.assertNotEqual(statuses["来源白名单"], "pass")


class TestBug069Position(unittest.TestCase):
    BASE = ["--port", "62207", "--user", "fenix", "--allow", "203.0.113.0/24", "--format", "json"]

    def system(self, **kwargs):
        options = dict(session_port=62207, listeners=[62207], disk_ports=(62207,), backup=True,
                       auth=g.HARDENED_AUTH, allowlist_rules=g.ALLOW_RULES, hardening_mtime=999999999)
        options.update(kwargs)
        return g.make_stub(g.STAGE0, **options)

    def go(self, argv, system):
        code, output = g.run_main(g.STAGE0, argv, system)
        return code, json.loads(output)

    def test_missing_tailnet_interface_is_not_verified(self):
        rules = [("accept", None, None, ("established", "related")),
                 ("accept", 62207, None, None, "tailscale0"),
                 ("accept", 62207, ["203.0.113.0/24"], None),
                 ("drop", 62207, None, None)]
        code, report = self.go(self.BASE + ["--tailnet", "--reboot-confirmed"], self.system(allowlist_rules=rules, tailnet=False))
        self.assertEqual(code, 2)
        self.assertNotIn(report["position"], ("verified", "hardened"))
        # 接入为 stage1 成果：回到 stage1。
        self.assertEqual(report["position"], "stage1-progress")
        self.assertIn("stage1-port-key.sh", report["next_step"]["commands"][0])

    def test_missing_backup_points_back_to_stage1(self):
        code, report = self.go(self.BASE + ["--reboot-confirmed"], self.system(backup=False))
        self.assertEqual(code, 2)
        self.assertEqual(report["position"], "stage1-progress")
        self.assertIn("stage1-port-key.sh", report["next_step"]["commands"][0])
        self.assertNotIn("stage2-lockdown.sh", report["next_step"]["commands"][0])

    def test_match_block_prevents_verified(self):
        system = self.system()
        system.set_read("/etc/ssh/sshd_config", "Port 62207\nMatch User bob\n  PasswordAuthentication yes\n")
        code, report = self.go(self.BASE + ["--reboot-confirmed"], system)
        self.assertEqual(code, 2)
        self.assertEqual(report["position"], "match-review")
        statuses = {x["item"]: x["status"] for x in report["assessment"]}
        self.assertEqual(statuses["Match 块"], "warn")

    def test_no_match_block_still_verifies(self):
        code, report = self.go(self.BASE + ["--reboot-confirmed"], self.system())
        self.assertEqual((code, report["position"]), (0, "verified"))

    def test_stage1_command_keeps_declared_flags(self):
        code, report = self.go(["--port", "62207", "--user", "fenix", "--tailnet", "--tailnet-session-confirmed",
                                 "--rescue-confirmed", "--format", "json"], g.make_stub(g.STAGE0))
        command = report["next_step"]["commands"][0]
        self.assertIn("stage1-port-key.sh", command)
        self.assertIn("--rescue-confirmed", command)
        self.assertIn("--tailnet-session-confirmed", command)

    def test_boot_id_is_collected(self):
        system = self.system()
        system.reads = {"/proc/sys/kernel/random/boot_id": "0a1b2c3d-1111-2222-3333-444455556666\n", **system.reads}
        facts = g.STAGE0.collect(system, g.STAGE0.parse_args([]))
        self.assertEqual(facts["reboot"]["boot_id"], "0a1b2c3d-1111-2222-3333-444455556666")


class TestBug070Stage1Fallback(unittest.TestCase):
    def test_fallback_command_keeps_allow_and_tailnet_confirmation(self):
        _, _, _, steps = g.TestStage2Steps().build(
            allow=["203.0.113.0/24", "198.51.100.0/24"], tailnet=True,
            extra=["--tailnet", "--tailnet-session-confirmed"])
        step = steps["0-preconditions"]
        self.assertEqual(step["status"], "blocked")
        command = next(line for line in step["do"] if "stage1-port-key.sh" in line)
        for flag in ("--allow 198.51.100.0/24", "--allow 203.0.113.0/24", "--tailnet-session-confirmed",
                     "--tailnet", "--rescue-confirmed", "--host h", "--backup-dir"):
            self.assertIn(flag, command)


class TestBug071CaseAndSudo(unittest.TestCase):
    def test_lowercase_port_and_match_are_detected(self):
        for m in (g.STAGE0, g.STAGE1):
            system = g.make_stub(m)
            system.set_read("/etc/ssh/sshd_config", "port 2222\nPORT=2223\nmatch user bob\nMATCH Address 10.0.0.0/8\n")
            system.touch_dir("/etc/ssh/sshd_config.d", [])
            with self.subTest(script=m.SCRIPT):
                self.assertEqual(sorted(m.disk_port_directives(system)), [2222, 2223])
                self.assertEqual(len(m.match_blocks(system)), 2)
        system = g.make_stub(g.STAGE2)
        system.set_read("/etc/ssh/sshd_config", "match user bob\n")
        system.touch_dir("/etc/ssh/sshd_config.d", [])
        self.assertEqual(len(g.STAGE2.match_blocks(system)), 1)

    def test_ss_hint_uses_sudo(self):
        text = (g.ROOT / "stage1-port-key.sh").read_text(encoding="utf-8")
        self.assertNotIn("ss -tlnp | grep sshd", text)
        self.assertIn('"sudo ss -tlnp"', text)


if __name__ == "__main__":
    unittest.main()
