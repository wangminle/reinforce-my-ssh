"""BUG-031、035～041：续跑状态、生成文件和真实隔离救援执行。"""
import contextlib
import importlib.util
import io
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

if "test_guides" in sys.modules:
    g = sys.modules["test_guides"]
else:
    spec = importlib.util.spec_from_file_location("test_guides", Path(__file__).with_name("test-guides.py"))
    g = importlib.util.module_from_spec(spec)
    sys.modules["test_guides"] = g
    spec.loader.exec_module(g)


def program(module):
    command = module.recovery_commands("/unused")[1]
    return command.split("<<'SSH_RECOVERY_PY'\n", 1)[1].rsplit("SSH_RECOVERY_PY", 1)[0]


class TestFollowupRegressions(unittest.TestCase):
    def test_endpoint_accepts_bare_ipv4_ipv6_and_rejects_non_tcp(self):
        for module in (g.STAGE0, g.STAGE1, g.STAGE2):
            for value in ("62207", "0.0.0.0:62207", "[::]:62207"):
                self.assertEqual(module.endpoint_port(value), 62207)
            for value in ("", "/run/ssh.socket", "0", "65536", "[::]"):
                with self.assertRaises(ValueError):
                    module.endpoint_port(value)

    def test_stage0_reads_generated_bare_socket_dropin_via_system(self):
        system = g.make_stub(g.STAGE0, listeners=[62207], session_port=62207)
        system.touch_dir(g.STAGE0.SOCKET_DROPIN_DIR, ["10-newport.conf"])
        system.set_read(g.STAGE0.SOCKET_DROPIN_DIR + "/10-newport.conf", "[Socket]\nListenStream=\nListenStream=62207\n")
        facts = g.STAGE0.collect(system, g.STAGE0.parse_args(["--port", "62207", "--user", "fenix"]))
        self.assertEqual(facts["disk_ports"]["62207"], [g.STAGE0.SOCKET_DROPIN_DIR + "/10-newport.conf:3"])
        self.assertNotIn("认证采集", [x["name"] for x in facts["failed"]])

    def test_stage0_goal_failure_returns_2_but_no_goals_returns_0(self):
        system = g.make_stub(g.STAGE0)
        with patch.object(g.STAGE0, "System", return_value=system), patch.object(g.STAGE0, "is_root", return_value=True):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(g.STAGE0.main(["--port", "62207", "--user", "fenix"]), 2)
                self.assertEqual(g.STAGE0.main([]), 0)

    def test_unreadable_keys_are_unknown_not_empty_keys(self):
        for unreadable in (True, False):
            system = g.make_stub(g.STAGE0)
            original = system.read
            def read(path):
                if path.endswith("authorized_keys"):
                    if unreadable:
                        raise g.STAGE0.EvidenceError("permission denied")
                    return "# no keys\n"
                return original(path)
            system.read = read
            options = g.STAGE0.parse_args(["--user", "fenix"])
            facts = g.STAGE0.collect(system, options)
            items, _, _ = g.STAGE0.assess(facts, options)
            result = next(x for x in items if x["item"] == "sudo 账户与公钥")
            self.assertEqual(result["status"], "unknown" if unreadable else "fail")

    def test_dot_paths_cannot_alias_root_backup(self):
        for module in (g.STAGE0, g.STAGE1, g.STAGE2):
            args = [] if module is g.STAGE0 else ["--port", "62207", "--user", "fenix"]
            if module is g.STAGE2:
                args += ["--tailnet"]
            for value in ("/.", "/./", "/./.", "/var/./backup", "/var/../"):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    module.parse_args(args + ["--backup-dir", value])

    def test_unknown_port_resume_never_becomes_none(self):
        system, options, ctx, steps = g.TestStage1Steps().steps(
            session_port=62207, listeners=[22, 2222, 62207], disk_ports=(22, 2222, 62207),
            socket_active=False, backup=True, extra=["--rescue-confirmed"])
        self.assertIsNone(ctx["old_port"])
        command = next(x for x in steps["4-verify-new"]["do"] if "stage1-port-key.sh" in x)
        self.assertNotIn("--old-port", shlex.split(command))
        resumed = g.STAGE1.parse_args(shlex.split(command)[3:])
        again = g.STAGE1.resolve_context(system, resumed)
        steps = {x["id"]: x for x in g.STAGE1.build_steps(system, resumed, again)}
        self.assertIsNone(again["old_port"])
        self.assertEqual(steps["3-new-port"]["status"], "blocked")
        self.assertEqual(steps["5-close-old"]["status"], "blocked")

    def test_explicit_none_cannot_skip_other_listeners_or_new_session(self):
        for listeners, session_port in (([22, 62207], 62207), ([22], 22)):
            _, _, _, steps = g.TestStage1Steps().steps(
                listeners=listeners, session_port=session_port, backup=True,
                extra=["--rescue-confirmed", "--old-port", "none"])
            self.assertNotEqual(steps["5-close-old"]["status"], "done")

    def test_old_port_supplement_preserves_all_options(self):
        _, options, _, steps = g.TestStage1Steps().steps(
            session_port=62207, listeners=[22, 2222, 62207], backup=True,
            extra=["--backup-dir", "/var/backup space's", "--tailnet", "--host", "server.example",
                   "--rescue-confirmed", "--allow", "203.0.113.0/24"], tailnet=True)
        template = next(x[2:] for x in steps["5-close-old"]["do"] if x.startswith("# sudo "))
        restored = g.STAGE1.parse_args(shlex.split(template.replace("REPLACE_WITH_OLD_PORT", "22"))[3:])
        for name in ("backup_dir", "host", "tailnet", "rescue_confirmed", "allow"):
            self.assertEqual(getattr(restored, name), getattr(options, name))
        self.assertEqual(restored.old_port, "22")

    def test_completed_tailnet_handoff_is_parseable_and_keeps_rescue(self):
        _, options, ctx, steps = g.TestStage1Steps().steps(
            session_port=62207, listeners=[62207], disk_ports=(62207,), backup=True, tailnet=True,
            extra=["--old-port", "22", "--tailnet", "--rescue-confirmed"])
        self.assertTrue(all(x["status"] == "done" for x in steps.values()))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            g.STAGE1.render_text(ctx, options, list(steps.values()))
        command = next(x.strip() for x in output.getvalue().splitlines() if x.strip().startswith("sudo bash"))
        stage2_options = g.STAGE2.parse_args(shlex.split(command)[3:])
        self.assertTrue(stage2_options.rescue_confirmed)
        self.assertTrue(stage2_options.tailnet)

    def test_completed_cidr_handoff_and_missing_source_template(self):
        for extra in (["--allow", "203.0.113.0/24"], []):
            _, options, ctx, steps = g.TestStage1Steps().steps(
                session_port=62207, listeners=[62207], disk_ports=(62207,), backup=True,
                extra=["--old-port", "22", "--rescue-confirmed"] + extra)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                g.STAGE1.render_text(ctx, options, list(steps.values()))
            lines = output.getvalue().splitlines()
            commands = [x.strip() for x in lines if x.strip().startswith("sudo bash")]
            if extra:
                result = g.STAGE2.parse_args(shlex.split(commands[0])[3:])
                self.assertEqual(result.allow, ["203.0.113.0/24"])
                self.assertTrue(result.rescue_confirmed)
            else:
                self.assertFalse(commands)
                self.assertIn("REPLACE_WITH_TRUSTED_CIDR", output.getvalue())

    def test_recovery_program_is_selfcontained_and_same_in_both_scripts(self):
        expected = Path(__file__).with_name("recovery-program.txt").read_text()
        for module in (g.STAGE1, g.STAGE2):
            self.assertEqual(program(module), expected)
            compile(program(module), "generated-recovery", "exec")
            self.assertNotIn("flush ruleset", program(module))

    def test_all_undo_paths_use_snapshot_recovery(self):
        _, _, _, stage1 = g.TestStage1Steps().steps(
            session_port=62207, listeners=[22, 62207], backup=True, extra=["--rescue-confirmed"])
        _, _, _, stage2 = g.TestStage2Steps().build(
            session_port=62207, listeners=[62207], backup=True, auth=g.HARDENED_AUTH, tailnet=True, extra=["--tailnet"])
        for steps, ids in ((stage1, ("3-new-port", "5-close-old")),
                           (stage2, ("1-allowlist", "1b-close-public", "2-auth", "4-reboot-verify"))):
            for sid in ids:
                self.assertTrue(any("SSH_RECOVERY_PY" in x for x in steps[sid]["undo"]), sid)

    def test_actual_recovery_restores_files_and_targeted_nft_only(self):
        if os.name == "nt":
            self.skipTest("真实救援执行需要 Linux 用户/网络命名空间")
        # 两种关键场景：原有 sshguard/同名配置，以及原来完全不存在。
        for had_original in (True, False):
            self.run_recovery_sandbox(had_original)

    def run_recovery_sandbox(self, had_original):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup = root / "backup space's"
            backup.mkdir()
            filesystem = root / "system"
            for name in ("sshd_config.d", "ssh.socket.d", "nftables.d", "ufw"):
                (backup / name).mkdir()
            for name, content in {"sshd_config": "Port 22\n", "units.txt": "fixture",
                                  "backup-complete": "complete\n", "ssh.socket.active": "active\n",
                                  "nftables.enabled": "disabled\n", "nftables.conf": "# original\n",
                                  "ufw-status.txt": "Status: active\n"}.items():
                (backup / name).write_text(content)
            (backup / "sshd_config.d/original.conf").write_text("# original file\n")
            if had_original:
                (backup / "sshd_config.d/20-hardening.conf").write_text("# original hardening\n")
                (backup / "nftables.d/ssh-allowlist.nft").write_text("# original allowlist\n")
            for path in ("etc/ssh/sshd_config.d/10-newport.conf", "etc/ssh/sshd_config.d/20-hardening.conf",
                         "etc/systemd/system/ssh.socket.d/10-newport.conf", "etc/nftables.d/ssh-allowlist.nft",
                         "etc/ssh/sshd_config.d/unrelated-new.conf"):
                destination = filesystem / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text("# introduced\n")
            bindir = root / "bin"
            bindir.mkdir()
            log = root / "calls"
            for tool in ("sshd", "systemctl", "ufw"):
                executable = bindir / tool
                executable.write_text("#!/bin/sh\nprintf '%s\\n' \"$0 $*\" >> " + shlex.quote(str(log)) + "\n")
                executable.chmod(0o755)
            # 仅替换测试文件系统根；实际 nft 命令在独立命名空间执行。
            body = program(g.STAGE2).replace('ROOT = Path("/")', "ROOT = Path(" + repr(str(filesystem)) + ")")
            setup = '''import subprocess,json,sys
from pathlib import Path
b=Path(sys.argv[1]); had=sys.argv[2]=='True'
def nft(text): subprocess.run(['nft','-f','-'],input=text.replace('} }', '}; }')+'\\n',text=True,check=True)
nft('table inet unrelated { chain keep { counter comment "keep-me"; } }')
nft('table inet transit { chain input { type filter hook input priority 0; policy accept; } }')
if had: nft('table inet sshguard { chain old { counter comment "original-table"; } }')
(b/'nft-ruleset.nft').write_text(subprocess.check_output(['nft','list','ruleset'],text=True))
(b/'nft-ruleset.json').write_text(subprocess.check_output(['nft','-j','list','ruleset'],text=True))
if had:
    (b/'sshguard.nft').write_text(subprocess.check_output(['nft','list','table','inet','sshguard'],text=True))
    nft('delete table inet sshguard')
else: (b/'sshguard.nft.absent').touch()
nft('table inet sshguard { chain new { counter comment "introduced-table"; } }')
nft('add rule inet transit input tcp dport 62207 ct state new accept comment "stage1 new-port bridge"')
'''
            verify = '''
rules=run('nft','list','ruleset',capture_output=True).stdout
require('keep-me' in rules, 'unrelated table lost')
require('stage1 new-port bridge' not in rules, 'bridge remains')
require('introduced-table' not in rules, 'new table remains')
require(('original-table' in rules) == had, 'original table restoration failed')
'''
            result = subprocess.run(["unshare", "-Urn", "--", sys.executable, "-c", setup + body + verify,
                                     str(backup), str(had_original)],
                                    env=dict(os.environ, PATH=str(bindir) + ":" + os.environ["PATH"]),
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((filesystem / "etc/ssh/sshd_config").read_text(), "Port 22\n")
            self.assertFalse((filesystem / "etc/ssh/sshd_config.d/10-newport.conf").exists())
            self.assertFalse((filesystem / "etc/systemd/system/ssh.socket.d/10-newport.conf").exists())
            self.assertTrue((filesystem / "etc/ssh/sshd_config.d/unrelated-new.conf").exists())
            for path in ("etc/ssh/sshd_config.d/20-hardening.conf", "etc/nftables.d/ssh-allowlist.nft"):
                if had_original:
                    self.assertIn("original", (filesystem / path).read_text())
                else:
                    self.assertFalse((filesystem / path).exists())
            calls = log.read_text()
            self.assertIn("ufw reload", calls)
            self.assertIn("systemctl restart ssh.socket", calls)
            self.assertIn("systemctl reload-or-restart ssh.service", calls)
            self.assertNotIn("systemctl stop", calls)

    def test_incomplete_recovery_stops_before_deleting_anything(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup = root / "backup"
            backup.mkdir()
            destination = root / "etc/ssh/sshd_config.d/20-hardening.conf"
            destination.parent.mkdir(parents=True)
            destination.write_text("must remain")
            body = program(g.STAGE1).replace('ROOT = Path("/")', "ROOT = Path(" + repr(str(root)) + ")")
            result = subprocess.run([sys.executable, "-c", body, str(backup)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(destination.read_text(), "must remain")


if __name__ == "__main__":
    unittest.main()
