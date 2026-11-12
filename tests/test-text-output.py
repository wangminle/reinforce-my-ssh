"""聚焦输出不得丢失当前操作的保护检查、阻断证据或 JSON 恢复信息。"""
import contextlib
import importlib
import io
import json
import unittest

g = importlib.import_module("test-guides")


def render(module, ctx, options, steps):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        module.render_text(ctx, options, list(steps.values()))
    return output.getvalue()


class TestFocusedOutput(unittest.TestCase):
    def test_close_old_port_keeps_entire_guarded_operation_without_recovery_dump(self):
        _, options, ctx, steps = g.TestStage1Steps().steps(
            session_port=62207, listeners=[22, 62207], disk_ports=(22, 62207),
            backup=True, tailnet=True,
            extra=["--old-port", "22", "--tailnet", "--rescue-confirmed",
                   "--tailnet-session-confirmed"])
        brief = render(g.STAGE1, ctx, options, steps)
        self.assertIn("stage1：已完成 6/7 项，剩余 1 项", brief)
        self.assertIn("当前步骤：关闭旧端口", brief)
        self.assertNotIn("步骤清单：", brief)
        self.assertNotIn("SSH_RECOVERY_PY", brief)
        self.assertIn("--verbose", brief)
        self.assertIn("KillMode", brief)
        self.assertIn("ssh_preflight", brief)
        options.verbose = True
        full = render(g.STAGE1, ctx, options, steps)
        self.assertIn("步骤清单：", full)
        self.assertIn("SSH_RECOVERY_PY", full)
        self.assertEqual(brief.split("  执行：", 1)[1].split("\n完整清单", 1)[0],
                         full.split("  执行：", 1)[1].split("  手工撤销", 1)[0].rstrip() + "\n")

    def test_stage2_brief_preserves_blockers_and_full_current_evidence(self):
        _, options, ctx, steps = g.TestStage2Steps().build()
        ctx["sshd_valid"] = False
        ctx["sshd_error"] = "invalid sshd configuration"
        ctx["legacy"] = ["pending legacy transaction"]
        ctx["match_blocks"] = ["Match User fenix"]
        brief = render(g.STAGE2, ctx, options, steps)
        current = next(x for x in steps.values() if x["status"] != "done")
        self.assertIn(current["evidence"], brief)
        self.assertIn("[阻断] sshd -t 失败", brief)
        self.assertIn("pending legacy transaction", brief)
        self.assertIn("Match User fenix", brief)
        self.assertNotIn("步骤清单：", brief)
        self.assertNotIn("SSH_RECOVERY_PY", brief)
        options.verbose = True
        self.assertIn("手工撤销（如需）：", render(g.STAGE2, ctx, options, steps))

    def test_json_retains_all_steps_and_recovery_in_both_display_modes(self):
        for module in (g.STAGE1, g.STAGE2):
            reports = []
            for flags in ([], ["--verbose"]):
                system = g.make_stub(module, session_port=62207, listeners=[22, 62207],
                                     disk_ports=(22, 62207), backup=True)
                code, output = g.run_main(module, ["--port", "62207", "--user", "fenix",
                    "--allow", "203.0.113.0/24", "--rescue-confirmed", "--format", "json"] + flags,
                    system)
                report = json.loads(output)
                self.assertEqual(code, 2)
                self.assertIn("SSH_RECOVERY_PY", json.dumps(report["steps"]))
                reports.append(report)
            for field in ("steps", "next_step", "complete"):
                self.assertEqual(reports[0][field], reports[1][field])
