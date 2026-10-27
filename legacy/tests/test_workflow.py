#!/usr/bin/env python3
"""向导路由、权限、新会话/重启边界与 heredoc 终端输入回归。"""
import contextlib
import copy
import io
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
import test_audit as fixture

audit = fixture.audit
ROOT = Path(__file__).resolve().parents[1]
CURRENT = "11111111-1111-1111-1111-111111111111"
PREVIOUS = "22222222-2222-2222-2222-222222222222"
PROFILE = "PORT=2222\nOLD_PORT=22\nUSER=deploy\nALLOW=203.0.113.0/24\nRECOVERY_SECONDS=900\nRESCUE_CONFIRMED=yes\n"


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.system = fixture.FakeSystem()
        self.system.files["/profile"] = PROFILE
        self.entry = ROOT / "stage0-audit.sh"
        self.options, _ = audit.arguments(["--guide", "--conf", "/profile", "--host", "example-host", "--yes"])
        self.calls = []
        self.env = patch.dict(os.environ, {"SUDO_USER": "deploy", "SUDO_UID": "1000", "SSH_CONNECTION": "203.0.113.7 50000 192.0.2.10 2222"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def state(self, stage, boot=CURRENT):
        self.system.files[audit.STATE_ROOT + "/state.conf"] = f"STAGE={stage}\nTX=test-tx\nCONFIG_SHA={'a' * 64}\nPENDING_BOOT={boot}\nVERIFIED_BOOT={boot}\n"
        self.system.files[audit.STATE_ROOT + "/policy.conf"] = PROFILE

    def plan(self, goals=None, connection=("203.0.113.7", 50000, "192.0.2.10", 2222)):
        return audit.workflow_plan(self.system, self.entry, goals, "example-host", connection, root=True)

    def execute(self, argv):
        self.calls.append(argv)
        name = Path(argv[1]).name
        if name == audit.STAGE_SCRIPTS[1]:
            self.state("candidate-ready" if "--confirm" in argv else "candidate-pending")
        elif name == audit.STAGE_SCRIPTS[2]:
            self.state("hardened" if "--confirm" in argv else "hardening-pending")
        elif "--apply" in argv:
            self.state("reboot-pending")
        elif "--verify" in argv:
            self.state("verified")
        return 0

    def run_guide(self, runner=None, terminal=None):
        with patch.object(audit.os, "geteuid", return_value=0, create=True), contextlib.redirect_stdout(io.StringIO()) as output:
            code = audit.Workflow(self.options, self.system, self.entry, {"policy": {"port": 22, "user": "deploy"}}, terminal, runner or self.execute).run(["--guide"])
        return code, output.getvalue()

    def test_initial_apply_stops_for_new_connection(self):
        os.environ["SSH_CONNECTION"] = "203.0.113.7 50000 192.0.2.10 22"
        code, output = self.run_guide()
        self.assertEqual(code, 2)
        self.assertEqual(len(self.calls), 1)
        self.assertIn("--apply", self.calls[0])
        self.assertIn("PreferredAuthentications=publickey", output)
        self.assertIn("--guide --host example-host", output)
        self.assertNotIn("--confirm", self.calls[0])

    def test_stage1_confirm_then_stage2_apply_and_pause(self):
        self.state("candidate-pending")
        code, _ = self.run_guide()
        self.assertEqual(code, 2)
        self.assertEqual([Path(cmd[1]).name for cmd in self.calls], [audit.STAGE_SCRIPTS[1], audit.STAGE_SCRIPTS[2]])
        self.assertIn("--confirm", self.calls[0])
        self.assertNotIn("--yes", self.calls[0])
        self.assertIn("--apply", self.calls[1])

    def test_stage2_confirm_then_stage3_apply_never_executes_reboot(self):
        self.state("hardening-pending")
        code, output = self.run_guide()
        self.assertEqual(code, 2)
        self.assertEqual([Path(cmd[1]).name for cmd in self.calls], [audit.STAGE_SCRIPTS[2], audit.STAGE_SCRIPTS[3]])
        self.assertIn("sudo reboot", output)
        self.assertFalse(any("reboot" in cmd for cmd in self.calls))
        self.assertFalse(any("--conf" in cmd for cmd in self.calls))

    def test_saved_policy_replaces_partial_initial_config_in_later_stages(self):
        self.system.files["/profile"] = "PORT=2222\nRESCUE_CONFIRMED=no\n"
        self.state("hardening-pending")
        code, _ = self.run_guide()
        self.assertEqual(code, 2)
        self.assertEqual(len(self.calls), 2)
        self.assertNotIn("--conf", self.calls[-1])

    def test_all_phase_guide_entries_delegate_without_running_phase_code(self):
        with tempfile.TemporaryDirectory(prefix="reinforce-guide-entry-") as folder:
            work = Path(folder)
            (work / "stage0-audit.sh").write_text("#!/bin/bash\nprintf '%s\\n' \"$@\"\nexit 42\n")
            for name in audit.STAGE_SCRIPTS.values():
                target = work / name
                target.write_text((ROOT / name).read_text())
                result = subprocess.run(["bash", str(target), "--port", "2222", "--guide", "--host", "example-host"], capture_output=True, text=True)
                self.assertEqual(result.returncode, 42, result.stderr)
                self.assertEqual(result.stdout.splitlines(), ["--guide", "--port", "2222", "--host", "example-host"])

    def test_readonly_next_step_uses_observed_connection(self):
        self.state("candidate-pending")
        report = {"mode": "inspect", "checks": [], "policy": {}, "observed": {"connection": {"source": "203.0.113.7", "source_port": 50000, "local": "192.0.2.10", "port": 2222}}, "collection_result": audit.PASS}
        with patch.object(audit, "System", return_value=self.system), patch.object(audit.os, "geteuid", return_value=0, create=True), patch.object(audit.Auditor, "audit", return_value=report), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(audit.main(["--format", "json"]), 0)
        result = audit.json.loads(output.getvalue())
        self.assertEqual(result["next_step"]["status"], "ready")
        self.assertEqual(result["next_step"]["action"], "confirm")

    def test_same_boot_waits_and_cross_boot_verifies(self):
        self.state("reboot-pending")
        code, output = self.run_guide()
        self.assertEqual(code, 2)
        self.assertEqual(self.calls, [])
        self.assertIn("sudo reboot", output)
        self.state("reboot-pending", PREVIOUS)
        code, output = self.run_guide()
        self.assertEqual(code, 0)
        self.assertEqual(len(self.calls), 1)
        self.assertIn("--verify", self.calls[0])
        self.assertIn("流程完成", output)

    def test_verified_is_rechecked_and_old_boot_requires_new_baseline(self):
        self.state("verified")
        code, _ = self.run_guide()
        self.assertEqual(code, 0)
        self.assertEqual(self.calls[0], ["bash", str(ROOT / audit.STAGE_SCRIPTS[3])])
        self.calls.clear()
        self.state("verified", PREVIOUS)
        code, _ = self.run_guide()
        self.assertEqual(code, 2)
        self.assertIn("--apply", self.calls[0])

    def test_wrong_session_does_not_try_confirm_or_stage2(self):
        self.state("candidate-ready")
        os.environ["SSH_CONNECTION"] = "203.0.113.7 50000 192.0.2.10 22"
        code, _ = self.run_guide()
        self.assertEqual(code, 2)
        self.assertEqual(self.calls, [])

    def test_failure_and_no_progress_do_not_advance_or_loop(self):
        self.state("candidate-ready")
        def failed(argv):
            self.calls.append(argv)
            return 1
        code, output = self.run_guide(failed)
        self.assertEqual(code, 1)
        self.assertEqual(len(self.calls), 1)
        self.assertIn("--rollback", output)
        self.calls.clear()
        code, output = self.run_guide(lambda argv: self.calls.append(argv) or 0)
        self.assertEqual(code, 2)
        self.assertEqual(len(self.calls), 1)
        self.assertIn("未按预期推进", output)

    def test_readonly_plan_never_writes_and_missing_goals_point_to_guide(self):
        before = copy.deepcopy(self.system.files)
        plan = self.plan()
        self.assertEqual(plan["status"], "parameters-required")
        self.assertEqual(plan["commands"], [audit.shlex.join(plan["resume"])])
        self.assertEqual(before, self.system.files)

    def test_changed_policy_after_success_does_not_report_completion(self):
        self.state("verified")
        def changed(argv):
            self.calls.append(argv)
            self.system.files[audit.STATE_ROOT + "/policy.conf"] = "BROKEN\n"
            return 0
        code, output = self.run_guide(changed)
        self.assertEqual(code, 2)
        self.assertEqual(len(self.calls), 1)
        self.assertNotIn("流程完成", output)

    def test_corrupt_state_policy_or_conflicting_goal_never_executes(self):
        self.state("hardened")
        self.assertEqual(self.plan({"PORT": "3333"})["status"], "repair-required")
        self.system.files[audit.STATE_ROOT + "/policy.conf"] = "BROKEN\n"
        self.assertEqual(self.plan()["status"], "repair-required")
        self.system.files[audit.STATE_ROOT + "/state.conf"] = "STAGE=$(touch /tmp/bad)\n"
        self.assertEqual(self.plan()["status"], "repair-required")
        self.assertEqual(self.calls, [])

    def test_sudo_handoff_preserves_arguments_without_reading_private_policy(self):
        original = ["--guide", "--port", "2222", "--allow", "203.0.113.0/24"]
        with patch.object(audit.os, "geteuid", return_value=1000, create=True), patch.object(audit.shutil, "which", return_value="/usr/bin/sudo"), contextlib.redirect_stdout(io.StringIO()):
            workflow = audit.Workflow(self.options, self.system, self.entry, {}, object(), lambda argv: self.calls.append(argv) or 2)
            self.assertEqual(workflow.run(original), 2)
        self.assertEqual(self.calls[0], ["sudo", "--", "bash", str(self.entry), *original])
        self.assertEqual(audit.workflow_plan(self.system, self.entry, root=False)["status"], "sudo-required")

    def test_headless_without_yes_and_yes_without_rescue_never_mutate(self):
        self.options.yes = False
        self.assertEqual(self.run_guide()[0], 2)
        self.assertEqual(self.calls, [])
        self.options.yes = True
        self.system.files["/profile"] = PROFILE.replace("RESCUE_CONFIRMED=yes", "RESCUE_CONFIRMED=no")
        with self.assertRaises(audit.EvidenceError):
            self.run_guide()
        self.assertEqual(self.calls, [])

    def test_config_is_data_and_host_is_not_shell_code(self):
        with self.assertRaises(audit.EvidenceError):
            audit.setup_values(PROFILE + "ALLOW=$(touch /tmp/bad)\n")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            audit.arguments(["--guide", "--host", "server;reboot"])

    def test_real_pty_passes_input_through_heredoc_to_child(self):
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            self.skipTest("真实 PTY/权限入口需要 Linux root")
        import pty
        with tempfile.TemporaryDirectory(prefix="reinforce-guide-") as folder:
            work = Path(folder)
            data = work / "state"
            data.mkdir()
            source = self.entry.read_text().replace('STATE_ROOT = "/var/lib/reinforce-my-ssh"', "STATE_ROOT = " + repr(str(data)))
            for number, managed in enumerate(audit.MANAGED):
                source = source.replace(managed, str(work / ("managed-" + str(number))))
            entry = work / "stage0-audit.sh"
            entry.write_text(source)
            profile = work / "profile"
            profile.write_text(PROFILE.replace("USER=deploy", "USER=nobody"))
            stub = "#!/bin/bash\nset -e\nprintf 'GUIDE_CHILD_PROMPT\\n'\nread -r answer\n[[ $answer == ready ]]\n" + "cat > " + audit.shlex.quote(str(data / "policy.conf")) + " <<'POLICY'\n" + profile.read_text() + "POLICY\n" + "printf 'STAGE=candidate-pending\\nTX=test-tx\\nCONFIG_SHA=\\n' > " + audit.shlex.quote(str(data / "state.conf")) + "\nprintf 'GUIDE_CHILD_INPUT_OK\\n'\n"
            (work / audit.STAGE_SCRIPTS[1]).write_text(stub)
            for number in (2, 3):
                (work / audit.STAGE_SCRIPTS[number]).write_text("#!/bin/bash\necho UNEXPECTED_STAGE\nexit 99\n")
            pid, fd = pty.fork()
            if pid == 0:
                os.environ.update(SUDO_USER="nobody", SUDO_UID="65534", SSH_CONNECTION="203.0.113.7 50000 192.0.2.10 22")
                os.execvp("bash", ["bash", str(entry), "--guide", "--conf", str(profile), "--host", "example-host"])
            output, sent, status = b"", False, None
            try:
                deadline = time.monotonic() + 35
                while time.monotonic() < deadline:
                    ready, _, _ = select.select([fd], [], [], 0.1)
                    if ready:
                        try:
                            chunk = os.read(fd, 65536)
                        except OSError:
                            break
                        if not chunk:
                            break
                        output += chunk
                        if b"GUIDE_CHILD_PROMPT" in output and not sent:
                            os.write(fd, b"ready\n")
                            sent = True
                    child, status = os.waitpid(pid, os.WNOHANG)
                    if child:
                        break
                else:
                    os.kill(pid, 9)
                    self.fail("向导等待终端输入超时")
                if status is None or not child:
                    _, status = os.waitpid(pid, 0)
                self.assertEqual(os.waitstatus_to_exitcode(status), 2, output.decode(errors="replace"))
                self.assertIn(b"GUIDE_CHILD_INPUT_OK", output)
                self.assertNotIn(b"UNEXPECTED_STAGE", output)
            finally:
                os.close(fd)


if __name__ == "__main__":
    unittest.main(verbosity=2)
