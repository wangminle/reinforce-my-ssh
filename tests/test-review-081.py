"""BUG-081：附加 input 基链默认 drop 且无可解释的目标端口规则时，UNKNOWN 不得掩盖 FAIL 而在 UFW 路径放行。

场景：UFW 文本对目标端口的双族白名单看起来完整，另有一条原生 nft input 基链
`policy drop`，其中没有目标端口的可解释放行/拒绝规则（或只有 established 规则）。
这种链会丢弃所有新的 SSH 连接，白名单必须判 fail，而不是 unknown。
"""
import importlib
import json
import sys
import unittest
from pathlib import Path

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


def native_drop(family="inet", established_only=False, policy="drop"):
    items = [
        {"table": {"family": family, "name": "filter"}},
        {"chain": {"family": family, "table": "filter", "name": "input",
                   "type": "filter", "hook": "input", "policy": policy}},
    ]
    if established_only:
        items.append({"rule": {"family": family, "table": "filter", "chain": "input", "expr": [
            {"match": {"op": "in", "left": {"ct": {"key": "state"}},
                       "right": {"set": ["established", "related"]}}},
            {"accept": None},
        ]}})
    return {"nftables": items}


class TestBug081DropChainWithoutPortRules(unittest.TestCase):
    def summary(self, module, raw):
        system = g.make_stub(module)
        system.can("nft -j list ruleset", json.dumps(raw))
        return module.nft_ruleset_summary(system)

    def test_default_drop_chain_without_target_rules_is_fail(self):
        for module in (g.STAGE0, g.STAGE2):
            for family in ("inet", "ip"):
                with self.subTest(script=module.SCRIPT, family=family):
                    result = module.nft_allowlist_assessment(
                        self.summary(module, native_drop(family)), PORT, ALLOWS)
                    self.assertEqual(result["status"], "fail", result)

    def test_established_only_drop_chain_is_fail(self):
        for module in (g.STAGE0, g.STAGE2):
            with self.subTest(script=module.SCRIPT):
                result = module.nft_allowlist_assessment(
                    self.summary(module, native_drop(established_only=True)), PORT, ALLOWS)
                self.assertEqual(result["status"], "fail", result)

    def test_open_chain_without_target_rules_stays_unknown(self):
        # 回归护栏：默认放行且与目标端口无关的链仍不构成拦截证据。
        for module in (g.STAGE0, g.STAGE2):
            with self.subTest(script=module.SCRIPT):
                result = module.nft_allowlist_assessment(
                    self.summary(module, native_drop(policy="accept")), PORT, ALLOWS)
                self.assertEqual(result["status"], "unknown", result)


class TestBug081UfwPathCannotPass(unittest.TestCase):
    def test_ufw_text_pass_still_fails_on_drop_chain(self):
        for module in (g.STAGE0, g.STAGE2):
            with self.subTest(script=module.SCRIPT):
                summary = module.nft_ruleset_summary(
                    g.make_stub(module).can("nft -j list ruleset", json.dumps(native_drop())))
                result = module.allowlist_assessment(
                    summary, {"available": True, "active": True, "text": UFW_OK}, PORT, ALLOWS)
                self.assertEqual(result["status"], "fail", result)
                self.assertIn("input 基链", result["detail"])

    def test_stage0_does_not_report_verified(self):
        system = g.make_stub(
            g.STAGE0, session_port=PORT, listeners=[PORT], disk_ports=(PORT,), backup=True,
            auth=g.HARDENED_AUTH, allowlist_rules=g.ALLOW_RULES, hardening_mtime=999999999,
            ufw_active=True, ufw_text=UFW_OK)
        system.can("nft -j list ruleset", json.dumps(native_drop(established_only=True)))
        code, output = g.run_main(
            g.STAGE0,
            ["--port", str(PORT), "--user", "fenix", "--allow", ALLOWS[0], "--allow", ALLOWS[1],
             "--reboot-confirmed", "--format", "json"],
            system)
        report = json.loads(output)
        self.assertEqual(code, 2)
        self.assertNotEqual(report["position"], "verified")
        allow = next(item for item in report["assessment"] if item["item"] == "来源白名单")
        self.assertEqual(allow["status"], "fail")

    def test_stage2_allowlist_step_is_not_done(self):
        system = g.make_stub(
            g.STAGE2, session_port=PORT, listeners=[PORT], disk_ports=(PORT,), backup=True,
            auth=g.HARDENED_AUTH, allowlist_rules=g.ALLOW_RULES, hardening_mtime=999999999,
            ufw_active=True, ufw_text=UFW_OK)
        system.can("nft -j list ruleset", json.dumps(native_drop(established_only=True)))
        g.patch_environment(g.STAGE2, system)
        options = g.STAGE2.parse_args(
            ["--port", str(PORT), "--user", "fenix", "--host", "h", "--rescue-confirmed",
             "--allow", ALLOWS[0], "--allow", ALLOWS[1], "--reboot-confirmed"])
        ctx = g.STAGE2.resolve_context(system, options)
        steps = {step["id"]: step for step in g.STAGE2.build_steps(system, options, ctx)}
        self.assertEqual(steps["1-allowlist"]["status"], "todo")
        self.assertFalse(all(step["status"] == "done" for step in steps.values()))


if __name__ == "__main__":
    unittest.main()