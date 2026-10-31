#!/usr/bin/env python3
"""显式运行：sudo python3 tests/verify-systemd-switch.py。

只创建 codex-ssh-test-* 回环临时单元，不操作真实 ssh.service/socket。
服务持有 systemd 传入的监听 fd，fork 的已连接会话用于验证 KillMode=process。
sshd -t 在此夹具中替换为成功；这不属于真实 OpenSSH 登录验收。
"""
import importlib.util
import os
import socket
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from unittest.mock import patch


def main():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise SystemExit("需在有 systemd 的 Linux 中以 root 显式运行")
    spec = importlib.util.spec_from_file_location("support", Path(__file__).with_name("guide-support.py"))
    support = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(support)
    ns = {}
    exec(support.load_script("stage1-port-key.sh").ssh_service_program(), ns)
    base = "codex-ssh-test-" + uuid.uuid4().hex[:12]
    service, sockunit = base + ".service", base + ".socket"
    ns.update(SSH_SERVICE=service, SSH_SOCKET=sockunit)
    files = [Path("/run/systemd/system") / name for name in (service, sockunit)]
    clients = []
    child_pids = []
    real_run = subprocess.run
    switch_calls = []
    def run(args, **kwargs):
        return real_run(args, **kwargs)
    def fixture_run(args, **kwargs):
        switch_calls.append(tuple(args))
        if args == ["sshd", "-t"]:
            return subprocess.CompletedProcess(args, 0)
        return real_run(args, **kwargs)
    def connect(port):
        client = socket.create_connection(("127.0.0.1", port), timeout=3)
        client.settimeout(3)
        clients.append(client)
        child_pids.append(int(client.recv(64)))
        return client
    def echo(client):
        client.sendall(b"still-alive\n")
        assert client.recv(64) == b"still-alive\n"
    with tempfile.TemporaryDirectory(prefix=base) as tmp:
        server = Path(tmp) / "server.py"
        server.write_text('''import socket,os
listener=socket.socket(fileno=3)
while True:
    conn,_=listener.accept()
    if os.fork()==0:
        listener.close()
        conn.sendall(str(os.getpid()).encode())
        while True:
            data=conn.recv(4096)
            if not data: break
            conn.sendall(data)
        os._exit(0)
    conn.close()
''')
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        files[0].write_text("[Unit]\nStartLimitIntervalSec=0\n[Service]\nType=exec\nKillMode=process\nSendSIGHUP=no\nExecStart="
                            + sys.executable + " " + str(server) + "\n")
        files[1].write_text("[Socket]\nListenStream=127.0.0.1:" + str(port) + "\n")
        try:
            run(["systemctl", "daemon-reload"], check=True)
            run(["systemctl", "start", sockunit], check=True)
            old = connect(port)
            echo(old)
            # 证明夹具确实复现旧实现：活跃主进程持有继承的监听 fd。
            rejected = run(["systemctl", "restart", sockunit], capture_output=True, text=True)
            assert rejected.returncode != 0, "夹具没有复现旧 socket 重启错误"
            print("旧实现复现：active 服务下单独重启 socket 被拒绝", flush=True)
            with patch.object(subprocess, "run", side_effect=fixture_run):
                ns["switch_ssh"](True)
            echo(old)
            echo(connect(port))
            print("正常切换：旧连接保留，新连接可建立", flush=True)
            original_unit = files[0].read_text()
            files[0].write_text(original_unit.replace("KillMode=process", "KillMode=control-group"))
            with patch.object(subprocess, "run", side_effect=fixture_run):
                try:
                    ns["switch_ssh"](True)
                except SystemExit:
                    pass
                else:
                    raise AssertionError("危险 KillMode 未被拒绝")
            echo(old)
            echo(connect(port))
            print("危险 KillMode 被拒绝：旧服务与连接仍可用", flush=True)
            # 主进程启动失败：程序立即停止，只输出建议，不执行任何自动重试。
            files[0].write_text(original_unit.replace(sys.executable + " " + str(server), "/nonexistent-codex-ssh-fixture"))
            before_failure = len(switch_calls)
            with patch.object(subprocess, "run", side_effect=fixture_run):
                try:
                    ns["switch_ssh"](True)
                except SystemExit as error:
                    print("启动失败明确报错：" + str(error), flush=True)
                else:
                    raise AssertionError("故意破坏启动后却报告成功")
            failed_calls = switch_calls[before_failure:]
            start = ("systemctl", "start", sockunit, service)
            assert failed_calls.count(start) == 1, failed_calls
            assert failed_calls[-1] == start, failed_calls
            echo(old)
            print("启动失败后立即停止：无自动重试，旧连接仍保留", flush=True)
            # 模拟操作员另行决定修正配置，再手工运行切换；不属于失败程序的后续动作。
            files[0].write_text(original_unit)
            with patch.object(subprocess, "run", side_effect=fixture_run):
                ns["switch_ssh"](True)
            echo(old)
            echo(connect(port))
            print("另行手工执行：修正后旧连接仍保留，新连接恢复", flush=True)
        finally:
            for client in clients:
                client.close()
            run(["systemctl", "stop", sockunit, service], check=False)
            # 子进程由夹具记录，仅清理这些临时服务的会话。
            for pid in child_pids:
                try:
                    os.kill(pid, 15)
                except ProcessLookupError:
                    pass
            for path in files:
                path.unlink(missing_ok=True)
            run(["systemctl", "daemon-reload"], check=True)
            run(["systemctl", "reset-failed", service, sockunit], capture_output=True)
            result = run(["systemctl", "show", service, sockunit, "-p", "LoadState", "-p", "ActiveState"],
                         check=True, capture_output=True, text=True)
            assert result.stdout.count("LoadState=not-found") == 2, result.stdout
            assert result.stdout.count("ActiveState=inactive") == 2, result.stdout
            print("临时单元已清理：" + base, flush=True)


if __name__ == "__main__":
    main()
