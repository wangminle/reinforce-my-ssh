"""BUG-037/047/055/056：安全服务切换、缺失单元与加载器启用状态恢复。"""
import contextlib
import importlib.util
import io
import json
import os
import shutil
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


class TestServiceRecovery(unittest.TestCase):
    def helper(self, module=g.STAGE1):
        ns = {}
        exec(module.ssh_service_program(), ns)
        return ns

    def controller(self, unsafe=None, failure=None, current_socket="active"):
        calls = []
        failed = False
        def run(args, **kwargs):
            nonlocal failed
            calls.append(tuple(args))
            if args[:3] == ["systemctl", "show", "ssh.service"]:
                props = dict(KillMode="process", SendSIGHUP="no", ExecStop="", ExecStopPost="")
                props.update(unsafe or {})
                output = "\n".join(k + "=" + v for k, v in props.items())
            elif args[0] == "busctl":
                output = json.dumps({"type": "a(sasbttttuii)", "data": [{}] if (unsafe or {}).get(args[-1]) else []})
            elif args[:3] == ["systemctl", "show", "ssh.socket"]:
                output = "LoadState=loaded\nActiveState=" + current_socket
            else:
                output = ""
            if failure and tuple(args) == failure and not failed:
                failed = True
                raise subprocess.CalledProcessError(1, args)
            return subprocess.CompletedProcess(args, 0, output, "")
        return calls, run

    def test_socket_switch_coordinates_stop_and_start(self):
        for module in (g.STAGE1, g.STAGE2):
            ns = self.helper(module)
            calls, run = self.controller()
            with patch.object(subprocess, "run", side_effect=run):
                ns["switch_ssh"](True)
            stop = ("systemctl", "stop", "ssh.socket", "ssh.service")
            start = ("systemctl", "start", "ssh.socket", "ssh.service")
            self.assertLess(calls.index(stop), calls.index(start))
            self.assertNotIn(("systemctl", "restart", "ssh.socket"), calls)
            self.assertLess(calls.index(("sshd", "-t")), calls.index(stop))

    def test_unsafe_kill_settings_and_stop_hooks_never_stop_service(self):
        for unsafe in ({"KillMode": "control-group"}, {"KillMode": "mixed"},
                       {"SendSIGHUP": "yes"}, {"ExecStop": "kill something"},
                       {"ExecStopPost": "kill something"}, {"KillMode": ""}):
            ns = self.helper()
            calls, run = self.controller(unsafe=unsafe)
            with patch.object(subprocess, "run", side_effect=run), self.assertRaises(SystemExit):
                ns["switch_ssh"](True)
            self.assertFalse(any(x[:2] == ("systemctl", "stop") for x in calls))

    def test_failure_stops_at_failed_command_and_prints_manual_suggestions(self):
        for module in (g.STAGE1, g.STAGE2):
            for socket_active, failure in (
                (True, ("sshd", "-t")),
                (True, ("systemctl", "daemon-reload")),
                (True, ("systemctl", "start", "ssh.socket", "ssh.service")),
                (True, ("systemctl", "is-active", "--quiet", "ssh.service")),
                (True, ("systemctl", "is-active", "--quiet", "ssh.socket")),
                (False, ("systemctl", "reload-or-restart", "ssh.service")),
            ):
                calls, run = self.controller(failure=failure, current_socket="active" if socket_active else "inactive")
                with patch.object(subprocess, "run", side_effect=run), self.assertRaises(SystemExit) as error:
                    self.helper(module)["switch_ssh"](socket_active)
                self.assertEqual(calls[-1], failure)
                self.assertEqual(calls.count(failure), 1)
                self.assertIn("仅供手工执行", str(error.exception))
                self.assertIn("sudo systemctl status", str(error.exception))
                self.assertIn("sudo journalctl", str(error.exception))
                self.assertIn("sudo systemctl start", str(error.exception))

    def test_stop_failure_never_starts_entry(self):
        for module in (g.STAGE1, g.STAGE2):
            stop = ("systemctl", "stop", "ssh.socket", "ssh.service")
            calls, run = self.controller(failure=stop)
            with patch.object(subprocess, "run", side_effect=run), self.assertRaises(SystemExit):
                self.helper(module)["switch_ssh"](True)
            self.assertEqual(calls[-1], stop)
            self.assertNotIn(("systemctl", "start", "ssh.socket", "ssh.service"), calls)

    def test_unreadable_stop_hooks_never_stop_service(self):
        calls, run = self.controller(failure=("busctl", "--json=short", "get-property", "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1/unit/ssh_2eservice", "org.freedesktop.systemd1.Service", "ExecStop"))
        with patch.object(subprocess, "run", side_effect=run), self.assertRaises(SystemExit):
            self.helper()["switch_ssh"](True)
        self.assertFalse(any(x[:2] == ("systemctl", "stop") for x in calls))

    def test_query_or_syntax_failure_never_stops_service(self):
        for failure in (("sshd", "-t"),
                        ("systemctl", "show", "ssh.service", "--all", "-p", "KillMode", "-p", "SendSIGHUP")):
            calls, run = self.controller(failure=failure)
            with patch.object(subprocess, "run", side_effect=run), self.assertRaises((SystemExit, subprocess.CalledProcessError)):
                self.helper()["switch_ssh"](True)
            self.assertFalse(any(x[:2] == ("systemctl", "stop") for x in calls))

    def test_restoring_traditional_mode_stops_current_socket_but_plain_reload_does_not(self):
        for active in ("active", "inactive"):
            ns = self.helper()
            calls, run = self.controller(current_socket=active)
            with patch.object(subprocess, "run", side_effect=run):
                ns["switch_ssh"](False)
            if active == "active":
                self.assertIn(("systemctl", "stop", "ssh.socket", "ssh.service"), calls)
                self.assertIn(("systemctl", "start", "ssh.service"), calls)
            else:
                self.assertIn(("systemctl", "reload-or-restart", "ssh.service"), calls)

    def test_stage1_both_socket_paths_generate_guarded_switch(self):
        _, _, _, steps = g.TestStage1Steps().steps(
            session_port=62207, listeners=[22, 62207], backup=True,
            disk_ports=(22, 62207), extra=["--rescue-confirmed"])
        for sid in ("3-new-port", "5-close-old"):
            commands = "\n".join(steps[sid]["do"])
            self.assertIn("switch_ssh(True)", commands)
            self.assertNotIn("restart ssh.socket", commands)

    def test_recovery_unsafe_service_refuses_before_changing_files(self):
        for module in (g.STAGE1, g.STAGE2):
            with tempfile.TemporaryDirectory() as tmp:
                backup = Path(tmp) / "backup"
                backup.mkdir()
                for name, text in {"sshd_config": "Port 22\n", "backup-complete": "complete\n",
                                   "units.txt": "fixture", "ssh.socket.active": "active\n",
                                   "nftables.enabled": "not-found\n", "ssh-allowlist.active": "not-found\n",
                                   "ssh-allowlist.enabled": "not-found\n"}.items():
                    (backup / name).write_text(text)
                for name in ("sshd_config.d.absent", "ssh.socket.d.absent", "nftables.d.absent",
                             "ufw.absent", "nftables.conf.absent", "nft-ruleset.nft.unavailable",
                             "ufw-status.txt.unavailable", "ssh-allowlist.service.absent",
                             "ssh-allowlist.service.d.absent"):
                    (backup / name).touch()
                body = module.recovery_commands(str(backup))[1].split("<<'SSH_RECOVERY_PY'\n", 1)[1].rsplit("SSH_RECOVERY_PY", 1)[0]
                body = body.replace('ROOT = Path("/")', "ROOT = Path(" + repr(str(Path(tmp) / "system")) + ")")
                calls, run = self.controller(unsafe={"KillMode": "control-group"})
                with patch.object(sys, "argv", ["recovery", str(backup)]), \
                     patch.object(shutil, "which", return_value=None), \
                     patch.object(subprocess, "run", side_effect=run), self.assertRaises(SystemExit):
                    exec(body, {})
                self.assertFalse(any(x[0] == "cp" or x[:2] == ("systemctl", "stop") for x in calls))

    def test_backup_missing_unit_and_query_failures_in_real_shell(self):
        if os.name == "nt":
            self.skipTest("生成备份的真实 shell 执行需要 Linux/WSL")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bindir = root / "bin"
            bindir.mkdir()
            tools = {
                "sudo": '#!/bin/sh\nexec "$@"\n',
                "cp": '#!/bin/sh\ncase "$3" in *.d|*/ufw) mkdir -p "$4";; *) touch "$4";; esac\n',
                "nft": '#!/bin/sh\nprintf "{}\\n"\n',
                "ufw": '#!/bin/sh\nprintf "Status: inactive\\n"\n',
                "systemctl": '''#!/bin/sh
if [ "$MODE" = real-missing ] && [ "$2" = codex-ssh-guide-absent-fixture.service ]; then exec "$REAL_SYSTEMCTL" "$@"; fi
if [ "$1" = show ] && [ "$3" = -p ]; then
  case "$MODE" in
    bus-failure) echo 'Failed to connect to bus' >&2; exit 1;;
    missing) echo not-found;;
    bad-load) echo error;;
    *) echo loaded;;
  esac
elif [ "$1" = is-enabled ]; then
  case "$MODE" in
    missing) echo 'No such file or directory' >&2; exit 1;;
    empty) exit 1;;
    invalid) echo nonsense;;
    *) echo disabled; exit 1;;
  esac
elif [ "$1" = is-active ]; then echo inactive; exit 3
else echo ActiveState=active
fi
''',
            }
            for name, content in tools.items():
                p = bindir / name
                p.write_text(content)
                p.chmod(0o755)
            for mode in ("missing", "real-missing", "loaded", "bus-failure", "bad-load", "empty", "invalid"):
                if mode == "real-missing":
                    binary = shutil.which("systemctl")
                    probe = (subprocess.run([binary, "show", "codex-ssh-guide-absent-fixture.service", "-p", "LoadState", "--value"],
                                            capture_output=True, text=True) if binary else None)
                    if probe is None or probe.returncode != 0 or probe.stdout.strip() != "not-found":
                        with self.subTest(mode=mode):
                            self.skipTest("无可查询的真实 systemd 总线，仅跳过该原生子项，其余模拟故障仍验证")
                        continue
                dest = root / mode
                command = g.STAGE1.backup_commands(str(dest))[0]
                if mode == "real-missing":
                    command = command.replace("nftables.service", "codex-ssh-guide-absent-fixture.service")
                result = subprocess.run(["sh", "-c", command],
                    env=dict(os.environ, PATH=str(bindir) + ":" + os.environ["PATH"], MODE=mode,
                             REAL_SYSTEMCTL=shutil.which("systemctl") or ""),
                    capture_output=True, text=True)
                markers = list(dest.glob("*/backup-complete"))
                self.assertEqual(result.returncode == 0, mode in ("missing", "real-missing", "loaded"), result.stderr)
                self.assertEqual(bool(markers), mode in ("missing", "real-missing", "loaded"), mode)
                if mode in ("missing", "real-missing"):
                    self.assertEqual((markers[0].parent / "nftables.enabled").read_text().strip(), "not-found")


    def test_enabled_runtime_recovery_removes_only_persistent_loader_links(self):
        for module in (g.STAGE1, g.STAGE2):
            with self.subTest(module=module.SCRIPT), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                backup = root / "backup"
                backup.mkdir()
                for name, text in {"sshd_config": "Port 22\n", "backup-complete": "complete\n",
                                   "units.txt": "fixture", "ssh.socket.active": "active\n",
                                   "nftables.enabled": "not-found\n", "ssh-allowlist.active": "inactive\n",
                                   "ssh-allowlist.enabled": "enabled-runtime\n",
                                   "ssh-allowlist.service": "[Unit]\n[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=sysinit.target\n"}.items():
                    (backup / name).write_text(text)
                for name in ("sshd_config.d.absent", "ssh.socket.d.absent", "nftables.d.absent",
                             "ufw.absent", "nftables.conf.absent", "nft-ruleset.nft.unavailable",
                             "ufw-status.txt.unavailable", "ssh-allowlist.service.d.absent"):
                    (backup / name).touch()
                persistent = [root / "system/etc/systemd/system" / (target + ".wants/ssh-allowlist.service")
                              for target in ("multi-user.target", "sysinit.target")]
                runtime = root / "system/run/systemd/system/sysinit.target.wants/ssh-allowlist.service"
                unrelated = root / "system/etc/systemd/system/sysinit.target.wants/unrelated.service"
                for path in (*persistent, runtime, unrelated):
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("fixture")
                body = module.recovery_commands(str(backup))[1].split("<<'SSH_RECOVERY_PY'\n", 1)[1].rsplit("SSH_RECOVERY_PY", 1)[0]
                body = body.replace('ROOT = Path("/")', "ROOT = Path(" + repr(str(root / "system")) + ")")
                calls, run = self.controller()
                with patch.object(sys, "argv", ["recovery", str(backup)]), \
                     patch.object(shutil, "which", return_value=None), \
                     patch.object(subprocess, "run", side_effect=run):
                    exec(body, {})
                self.assertIn(("systemctl", "enable", "--runtime", "ssh-allowlist.service"), calls)
                self.assertTrue(all(not path.exists() for path in persistent))
                self.assertTrue(runtime.exists())
                self.assertTrue(unrelated.exists())

    def test_loader_states_restore_links_with_offline_systemctl(self):
        if os.name == "nt" or not shutil.which("systemctl"):
            self.skipTest("真实离线启用链接验证需要 Linux systemctl --root")
        real_run = subprocess.run
        for module in (g.STAGE1, g.STAGE2):
            for state in ("enabled", "enabled-runtime", "static"):
                for install_target in ("multi-user.target", "sysinit.target", "custom.target"):
                    with self.subTest(module=module.SCRIPT, state=state, target=install_target), tempfile.TemporaryDirectory() as tmp:
                        root = Path(tmp) / "system"
                        backup = Path(tmp) / "backup"
                        backup.mkdir()
                        unit = "[Service]\nExecStart=/bin/true\n"
                        if state != "static":
                            unit += "[Install]\nWantedBy=" + install_target + "\n"
                        for name, text in {"sshd_config": "Port 22\n", "backup-complete": "complete\n",
                            "units.txt": "fixture", "ssh.socket.active": "active\n", "nftables.enabled": "not-found\n",
                            "ssh-allowlist.active": "inactive\n", "ssh-allowlist.enabled": state + "\n",
                            "ssh-allowlist.service": unit}.items():
                            (backup / name).write_text(text)
                        for name in ("sshd_config.d.absent", "ssh.socket.d.absent", "nftables.d.absent", "ufw.absent",
                            "nftables.conf.absent", "nft-ruleset.nft.unavailable", "ufw-status.txt.unavailable", "ssh-allowlist.service.d.absent"):
                            (backup / name).touch()
                        system = root / "etc/systemd/system"
                        system.mkdir(parents=True)
                        loader = system / "ssh-allowlist.service"
                        loader.write_text("[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=sysinit.target\n")
                        for target in ("multi-user.target", "sysinit.target", "custom.target"):
                            (system / target).write_text("[Unit]\n")
                        # 本工具可能留下的新旧持久链接；enabled 的原目标也保留在初始夹具中。
                        for target in {"multi-user.target", "sysinit.target"} | ({install_target} if state == "enabled" else set()):
                            link = system / (target + ".wants/ssh-allowlist.service")
                            link.parent.mkdir(exist_ok=True)
                            link.symlink_to("../ssh-allowlist.service")
                        runtime = root / ("run/systemd/system/" + install_target + ".wants/ssh-allowlist.service")
                        if state == "enabled-runtime":
                            runtime.parent.mkdir(parents=True)
                            runtime.symlink_to(loader)
                        unrelated = system / "sysinit.target.wants/unrelated.service"
                        unrelated.symlink_to("/unrelated-intentionally-dangling.service")
                        calls, fake_run = self.controller()
                        def run(args, **kwargs):
                            if args[0] == "cp":
                                Path(args[-1]).parent.mkdir(parents=True, exist_ok=True)
                                shutil.copy2(args[-2], args[-1])
                                return subprocess.CompletedProcess(args, 0, "", "")
                            if tuple(args[:2]) in (("systemctl", "enable"), ("systemctl", "disable")):
                                return real_run(["systemctl", "--root", str(root), *args[1:]], **kwargs)
                            return fake_run(args, **kwargs)
                        body = module.recovery_commands(str(backup))[1].split("<<'SSH_RECOVERY_PY'\n", 1)[1].rsplit("SSH_RECOVERY_PY", 1)[0]
                        body = body.replace('ROOT = Path("/")', "ROOT = Path(" + repr(str(root)) + ")")
                        with patch.object(sys, "argv", ["recovery", str(backup)]), patch.object(shutil, "which", return_value=None), \
                             patch.object(subprocess, "run", side_effect=run), contextlib.redirect_stdout(io.StringIO()):
                            exec(body, {})
                        persistent = {p.parent.name.removesuffix(".wants") for p in system.glob("*.wants/ssh-allowlist.service") if p.is_symlink()}
                        self.assertEqual(persistent, {install_target} if state == "enabled" else set())
                        self.assertTrue(unrelated.is_symlink())
                        if state == "enabled-runtime":
                            self.assertTrue(runtime.is_symlink())
                        result = real_run(["systemctl", "--root", str(root), "is-enabled", "ssh-allowlist.service"], capture_output=True, text=True)
                        self.assertEqual(result.stdout.strip(), state, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
