#!/usr/bin/env python3
"""三阶段回归：默认仅临时文件/替身；--integration 增加真实 nft 和 systemd 隔离检查。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
INTEGRATION = False


def function(stage, name):
    text = (ROOT / f"stage{stage}.sh").read_text(encoding="utf-8")
    start = text.index(name + "() {")
    # 函数以顶格 } 结尾；Python heredoc 内没有单独的顶格 }。
    return text[start:start + re.search(r"^}\n", text[start:], re.M).end()]


def library(stage):
    text = (ROOT / f"stage{stage}.sh").read_text(encoding="utf-8")
    return text[:text.index("\nneed_val()")] + text[text.index("\nnormalize_port()"):text.index("\nrequire_root\n")]


class Regression(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="reinforce-ssh-test-")
        self.work = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def bash(self, stage, body, *, integration=False, ok=True, env=None):
        script = self.work / f"case-{stage}.sh"
        script.write_text(library(stage) + '\nset -uo pipefail\nWORK=$1\n' + body, encoding="utf-8")
        command = ["bash", str(script), str(self.work)]
        if integration:
            command = ["unshare", "-n", *command]
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=35, env={**os.environ, **(env or {})})
        if ok:
            self.assertEqual(result.returncode, 0, result.stdout)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        return result.stdout

    def test_static(self):
        for stage in (1, 2, 3):
            path = ROOT / f"stage{stage}.sh"
            for command in (["bash", "-n"], ["shellcheck", "-S", "warning"]):
                with self.subTest(stage=stage, command=command):
                    result = subprocess.run([*command, str(path)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_normalizers_identical(self):
        self.assertEqual(function(1, "normalize_nft"), function(2, "normalize_nft"))
        self.assertEqual(function(1, "normalize_nft"), function(3, "normalize_nft"))

    def test_socket_output_and_bind_configuration(self):
        for stage in (1, 2):
            self.bash(stage, r'''
PORT=2222; OLD_PORT=none
systemctl() { printf '0.0.0.0:2222 (Stream)\n[::]:2222 (Stream)\n/run/example (Datagram)\n'; }
[[ $(socket_addrs) == $'0.0.0.0:2222\n[::]:2222' ]] || exit 1
gen_socket_override "$WORK/socket" || exit 2
grep -qx 'BindIPv6Only=ipv6-only' "$WORK/socket" || exit 3
gen_fw_unit "$WORK/fw" || exit 4
grep -qx "ExecReload=$NFT_LOADER" "$WORK/fw"
''')
        stage3 = (ROOT / "stage3.sh").read_text()
        self.assertIn('awk \'$2 == "(Stream)" {print $1}\'', stage3)

    def test_nft_equivalence_and_extra_rule_rejection(self):
        expected = '''table inet sshguard { chain input {
type filter hook input priority -100; policy accept;
ip saddr 203.0.113.7/32 tcp dport { 2222 } counter accept
ip6 saddr 2001:0db8::1/128 tcp dport { 2222 } counter drop
} }\n'''
        actual = expected.replace("{ 2222 }", "2222").replace("203.0.113.7/32", "203.0.113.7").replace("2001:0db8::1/128", "2001:db8::1").replace("counter", "counter packets 12 bytes 789")
        (self.work / "expected").write_text("add table inet sshguard\ndelete table inet sshguard\n" + expected)
        (self.work / "actual").write_text(actual)
        (self.work / "extra").write_text(actual.replace("} }", "tcp dport 2222 accept\n} }"))
        (self.work / "flush").write_text("flush ruleset\n" + actual)
        for stage in (1, 2):
            self.bash(stage, r'''
normalize_nft "$WORK/expected" "$WORK/a" && normalize_nft "$WORK/actual" "$WORK/b" || exit 1
cmp -s "$WORK/a" "$WORK/b" || exit 2
normalize_nft "$WORK/extra" "$WORK/c" && normalize_nft "$WORK/flush" "$WORK/d" || exit 3
! cmp -s "$WORK/a" "$WORK/c" && ! cmp -s "$WORK/a" "$WORK/d"
''')

    def test_ssh_switch_order_and_failed_socket(self):
        for stage in (1, 2):
            output = self.bash(stage, r'''
systemctl() {
  if [[ $1 == show ]]; then printf 'process\n'; return 0; fi
  printf '%s\n' "$*"
}
sshd() { return 0; }
start_ssh_entry
''')
            self.assertEqual(output.strip().splitlines(), ["stop ssh.service ssh.socket", "start ssh.socket", "start ssh.service"])
            output = self.bash(stage, r'''
systemctl() {
  if [[ $1 == show ]]; then printf 'process\n'; return 0; fi
  printf '%s\n' "$*"
  [[ $* != 'start ssh.socket' ]]
}
sshd() { return 0; }
start_ssh_entry
''', ok=False)
            self.assertNotIn("start ssh.service", output)
            self.bash(stage, r'''
systemctl() { [[ $1 == show ]] && { printf 'control-group\n'; return 0; }; exit 9; }
stop_ssh_entry
''', ok=False)

    def test_restore_absent_unit_does_not_stop_missing_unit(self):
        for stage in (1, 2):
            self.bash(stage, r'''
TX_DIR=$WORK
printf 'absent.service|not-found|inactive\n' > "$TX_DIR/units.conf"
systemctl() {
  case $1 in show) printf 'not-found\n';; is-active) printf 'inactive\n'; return 3;; *) exit 9;; esac
}
restore_unit_state absent.service
''')

    def test_allow_equivalent_cidr_and_leading_zero_window(self):
        for stage in (1, 2):
            self.bash(stage, r'''
STATE_STAGE=candidate-ready; POLICY_FILE=$WORK/policy
printf 'PORT=2222\nOLD_PORT=22\nUSER=deploy\nALLOW=2001:db8::/32\nRECOVERY_SECONDS=0900\nRESCUE_CONFIRMED=yes\n' > "$POLICY_FILE"
ALLOWS=(2001:0DB8::/32); ALLOW_SET=1
load_policy || exit 1
id() { [[ $1 == -u ]] && printf '1000\n'; return 0; }
normalize_params || exit 2
[[ ${ALLOWS[0]} == 2001:db8::/32 ]]
''')

    def test_late_recovery_cleans_only_its_own_units(self):
        for stage in (1, 2):
            self.bash(stage, rf'''
SELF=stage{stage}.sh; TX_ROOT=$WORK; STATE_TX=newer; STATE_STAGE=verified
mkdir "$WORK/old"
printf '{{"files":[]}}\n' > "$WORK/old/manifest.json"
: > "$WORK/old/units.conf"; printf 'stage{stage}\n' > "$WORK/old/stage"
cancel_recovery() {{ [[ $TX_ID == old ]] && touch "$WORK/cleaned"; }}
stop_ssh_entry() {{ exit 9; }}
tx_restore old 1 && test -f "$WORK/cleaned"
''')

    def test_partial_recovery_install_cleanup_and_retry(self):
        for stage in (1, 2):
            self.bash(stage, r'''
TX_ID=demo
recovery_paths() { RECOVERY_UNIT=$WORK/recovery.service; RECOVERY_TIMER=$WORK/recovery.timer; }
touch "$WORK/recovery.service"
systemctl() { [[ $1 == show ]] && printf 'not-found\n'; return 0; }
cancel_recovery || exit 1
test ! -e "$WORK/recovery.service" || exit 2
touch "$WORK/recovery.service" "$WORK/recovery.timer"
systemctl() { [[ $1 != disable ]]; }
if cancel_recovery; then exit 3; fi
test -e "$WORK/recovery.service" && test -e "$WORK/recovery.timer"
''')

    def boundary(self):
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
        (self.work / "confirmation.json").write_text(json.dumps({"cursor": "after-switch", "boot": boot}))
        return boot

    def test_journal_boundary_current_boot_and_capture_failure(self):
        boot = self.boundary()
        (self.work / "event").write_text(json.dumps({"__CURSOR": "after-switch", "_BOOT_ID": boot}) + "\n")
        for stage in (1, 2):
            self.bash(stage, r'''
TX_DIR=$WORK
journalctl() { cat "$WORK/event"; }
record_confirmation_boundary || exit 1
python3 - "$WORK/confirmation.json" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))['cursor']=='after-switch'
PY
journalctl() { return 8; }
! record_confirmation_boundary
''')

    def session_case(self, stage, bad=None):
        self.boundary()
        env = {"BAD_CASE": bad or "none"}
        return self.bash(stage, r'''
USERNAME=deploy; SUDO_USER=deploy; SUDO_UID=1000
PORT=2222; SSH_CONNECTION='203.0.113.7 50000 192.0.2.10 2222'; ALLOWS=(203.0.113.0/24)
id() { printf '1000\n'; }; ip_is_local() { return 1; }
ss() {
  local socket_pid=$$
  [[ $BAD_CASE != socket ]] || socket_pid=99999999
  printf '0 0 192.0.2.10:2222 203.0.113.7:50000 users:(("sshd",pid=%s,fd=4))\n' "$socket_pid"
}
journalctl() {
  [[ $* == *'--after-cursor after-switch'* && $* == *'-o json'* ]] || return 9
  [[ $BAD_CASE != before-boundary ]] || return 0
  python3 - "$$" "$BAD_CASE" <<'PY'
import json,sys
pid,case=sys.argv[1:]
boot=open('/proc/sys/kernel/random/boot_id').read().strip().replace('-','')
method='password' if case=='password' else 'publickey'
event={'_PID':'99999999' if case=='pid' else pid,'_BOOT_ID':boot,'MESSAGE':f'Accepted {method} for deploy from 203.0.113.7 port 50000 ssh2'}
if case=='boot': event['_BOOT_ID']='other-boot'
print(json.dumps(event))
PY
}
session_evidence "$WORK/confirmation.json"
''', ok=bad is None, env=env)

    def test_session_evidence_positive_and_unrelated_or_old_log_rejected(self):
        for stage in (1, 2):
            for bad in (None, "pid", "socket", "password", "before-boundary", "boot"):
                with self.subTest(stage=stage, bad=bad):
                    self.session_case(stage, bad)

    def test_stage2_rejects_parent_digest_before_system_changes(self):
        self.bash(2, r'''
STATE_STAGE=candidate-ready; STATE_CONFIG_SHA=old
config_digest() { printf 'changed\n'; }
preflight() { echo WRONG; exit 9; }
do_apply
''', ok=False)

    def test_initial_arm_failure_rolls_back_to_unconfigured(self):
        self.bash(1, r'''
SELF=stage1.sh; STATE_ROOT=$WORK/state; POLICY_FILE=$STATE_ROOT/policy.conf
STATE_FILE=$STATE_ROOT/state.conf; TX_ROOT=$STATE_ROOT/transactions
PORT=2222; OLD_PORT=22; USERNAME=deploy; ALLOWS=(203.0.113.0/24)
SSHD_DROPIN=$WORK/sshd; NFT_RULES=$WORK/nft; NFT_LOADER=$WORK/loader
FW_UNIT=$WORK/fw; SOCKET_OVERRIDE=$WORK/socket
MANAGED_FILES=("$SSHD_DROPIN" "$NFT_RULES" "$NFT_LOADER" "$FW_UNIT" "$SOCKET_OVERRIDE")
preflight() { return 0; }; confirm_rescue() { RESCUE_CONFIRMED=yes; }
arm_recovery() { return 1; }; cancel_recovery() { return 0; }
systemctl() {
  case $1 in
    is-enabled) [[ $2 == "$FW_NAME" ]] && { echo not-found; return 1; }; [[ $2 == ssh.socket ]] && echo enabled || echo disabled;;
    is-active) [[ $2 == "$FW_NAME" ]] && { echo inactive; return 3; }; echo active;;
    show) [[ $* == *KillMode* ]] && echo process || { [[ $2 == "$FW_NAME" ]] && echo not-found || echo loaded; };;
    stop) [[ $2 != "$FW_NAME" ]];;
    *) return 0;;
  esac
}
nft() { [[ $1 != list ]]; }; sshd() { return 0; }; ss() { return 0; }
(do_apply) && exit 1
grep -qx 'STAGE=unconfigured' "$STATE_FILE" || exit 2
test ! -e "$POLICY_FILE" || exit 3
for file in "${MANAGED_FILES[@]}"; do test ! -e "$file" || exit 4; done
''')

    def test_stage3_boot_gate(self):
        script = self.work / "stage3-boot.sh"
        script.write_text('''#!/bin/bash
set -uo pipefail
die() { echo "$*"; exit 1; }
ok() { return 0; }
declare -A STATE=([PENDING_BOOT]=11111111-1111-1111-1111-111111111111)
STAGE=reboot-pending
CURRENT_BOOT=11111111-1111-1111-1111-111111111111
run_checks() { echo UNEXPECTED; exit 9; }
''' + function(3, "do_verify") + '\ndo_verify\n')
        result = subprocess.run(["bash", str(script)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("UNEXPECTED", result.stdout)
        self.assertIn("boot_id 未变化", result.stdout)

    def test_stage2_order_reload_firewall_and_boundary_after_checks(self):
        for old_open in (False, True):
            output = self.bash(2, r'''
STATE_STAGE=candidate-ready; STATE_CONFIG_SHA=valid; STATE_TX=parent
TX_ROOT=$WORK; PORT=2222; OLD_PORT=22
config_digest() { printf 'valid\n'; }; preflight() { return 0; }
verify_runtime() { printf 'verify %s\n' "$1"; }
session_evidence() { return 0; }; confirm_rescue() { return 0; }
tx_begin() { TX_ID=child; TX_DIR=$WORK/child; mkdir "$TX_DIR"; }
arm_recovery() { return 0; }; put_file() { printf 'put %s\n' "${1##*/}"; }
sshd() { return 0; }; nft() { return 0; }; verify_nft_semantics() { return 0; }
systemctl() { printf 'systemctl %s\n' "$*"; }
start_ssh_entry() { printf 'switch ssh\n'; }
port_any_listening() { [[ $OLD_OPEN == yes ]]; }
record_confirmation_boundary() { printf 'boundary\n'; }
abort_tx() { printf 'aborted %s\n' "$1"; exit 1; }
do_apply
''', ok=not old_open, env={"OLD_OPEN": "yes" if old_open else "no"})
            if old_open:
                self.assertNotIn("put nft", output)
            else:
                self.assertLess(output.index("switch ssh"), output.index("put nft"))
                self.assertIn("systemctl reload reinforce-my-ssh-firewall.service", output)
                self.assertLess(output.index("verify hardened"), output.index("boundary"))

    def restore_fixture(self, parent="candidate-ready"):
        tx = self.work / "transactions" / "demo"
        (tx / "files").mkdir(parents=True)
        file = self.work / "managed"
        data = b"parent config\n"
        (tx / "files" / "0").write_bytes(data)
        file.write_bytes(b"child config\n")
        entry = {"path": str(file), "exists": True, "name": "0", "sha256": hashlib.sha256(data).hexdigest(),
                 "uid": os.getuid(), "gid": os.getgid(), "mode": 0o600}
        (tx / "manifest.json").write_text(json.dumps({"files": [entry]}))
        (tx / "stage").write_text("stage2\n")
        (tx / "units.conf").write_text("ssh.socket|enabled|active\nssh.service|disabled|active\nreinforce-my-ssh-firewall.service|enabled|active\n")
        (tx / "policy.before").write_text("parent policy\n")
        (self.work / "policy.conf").write_text("child policy\n")
        digest = hashlib.sha256(b"POLICY\nparent policy\n" + f"FILE {file}\n".encode() + data).hexdigest()
        (tx / "parent").write_text(f"{parent}\nparent\n{digest}\n")
        (tx / "listeners.before").write_text("")
        (tx / "runtime.nft").write_text("table inet sshguard {\n chain original {\n type filter hook input priority 0; policy accept;\n }\n}\n")
        return tx, digest

    def test_restore_policy_digest_and_failed_nft_never_commits(self):
        tx, digest = self.restore_fixture()
        for failure in (False, True):
            if failure:
                (self.work / "state.conf").unlink()
                (tx / "ROLLED_BACK").unlink()
            self.bash(2, r'''
SELF=stage2.sh; STATE_ROOT=$WORK; STATE_FILE=$WORK/state.conf; POLICY_FILE=$WORK/policy.conf
TX_ROOT=$WORK/transactions; STATE_TX=demo; STATE_STAGE=hardening-pending
PORT=2222; OLD_PORT=22; MANAGED_FILES=("$WORK/managed")
cancel_recovery() { return 0; }; stop_ssh_entry() { echo stop >> "$WORK/stops"; }
systemctl() { [[ $1 != show ]] || printf 'loaded\n'; return 0; }
restore_unit_state() { return 0; }; sshd() { return 0; }; ss() { return 0; }
nft() { [[ $NFT_FAIL != yes ]]; }; verify_nft_semantics() { [[ $NFT_FAIL != yes ]]; }
tx_restore demo 0
''', ok=not failure, env={"NFT_FAIL": "yes" if failure else "no"})
            self.assertEqual((self.work / "policy.conf").read_text(), "parent policy\n")
            self.assertEqual((tx / "ROLLED_BACK").exists(), not failure)
            if not failure:
                self.assertIn(f"CONFIG_SHA={digest}", (self.work / "state.conf").read_text())

    def test_native_nft_all_stages_and_atomic_failure(self):
        if not INTEGRATION:
            self.skipTest("需要 --integration：真实 nft 命名空间")
        (self.work / "stage3-functions").write_text(function(3, "normalize_nft") + '\n' + function(3, "gen_expected_nft"))
        (self.work / "stage1-functions").write_text(library(1))
        self.bash(2, r'''
PORT=2222; OLD_PORT=22; ALLOWS=(203.0.113.7/32 2001:db8::1/128)
for target in candidate hardened; do
  TARGET_STAGE=$target
  gen_nft_rules "$WORK/$target.nft" && nft -f "$WORK/$target.nft" || exit 1
  verify_nft_semantics "$WORK/$target.nft" "$WORK/actual" || { diff -u "$WORK/$target.nft.norm" "$WORK/actual.norm"; exit 2; }
done
POLICY_ALLOWS=("${ALLOWS[@]}")
source "$WORK/stage3-functions"
gen_expected_nft && normalize_nft "$WORK/nft-expected-raw.txt" "$WORK/expected3" || exit 5
nft -s -y list table inet sshguard > "$WORK/actual3"
normalize_nft "$WORK/actual3" "$WORK/normalized3" && cmp -s "$WORK/expected3" "$WORK/normalized3" || exit 6
source "$WORK/stage1-functions"
PORT=2222; OLD_PORT=none; ALLOWS=(203.0.113.7/32 2001:db8::1/128)
gen_nft_rules "$WORK/none.nft" && nft -f "$WORK/none.nft" || exit 7
verify_nft_semantics "$WORK/none.nft" "$WORK/none-actual" || exit 8
nft -s -n -y list table inet sshguard > "$WORK/before"
cp "$WORK/hardened.nft" "$WORK/bad"
printf '\nnot a valid nft command\n' >> "$WORK/bad"
if nft -f "$WORK/bad" 2>/dev/null; then exit 3; fi
nft -s -n -y list table inet sshguard > "$WORK/after"
cmp -s "$WORK/before" "$WORK/after" || exit 4
''', integration=True)

    def test_native_restore_removes_extra_chain(self):
        if not INTEGRATION:
            self.skipTest("需要 --integration：真实 nft 恢复")
        tx, _ = self.restore_fixture()
        self.bash(2, r'''
SELF=stage2.sh; STATE_ROOT=$WORK; STATE_FILE=$WORK/state.conf; POLICY_FILE=$WORK/policy.conf
TX_ROOT=$WORK/transactions; STATE_TX=demo; STATE_STAGE=hardening-pending
PORT=2222; OLD_PORT=22; MANAGED_FILES=("$WORK/managed")
nft -f "$TX_ROOT/demo/runtime.nft" || exit 1
ALLOWS=(203.0.113.0/24); TARGET_STAGE=hardened
gen_nft_rules "$WORK/new.nft" && nft -f "$WORK/new.nft" || exit 2
cancel_recovery() { return 0; }; stop_ssh_entry() { return 0; }
systemctl() { [[ $1 != show ]] || printf 'loaded\n'; return 0; }
restore_unit_state() { return 0; }; sshd() { return 0; }
tx_restore demo 0 || exit 3
nft -s -n -y list table inet sshguard > "$WORK/restored"
grep -q 'chain original' "$WORK/restored" && ! grep -q 'chain input' "$WORK/restored"
''', integration=True)
        self.assertTrue((tx / "ROLLED_BACK").exists())

    def test_native_systemd_dual_stack_and_service_switch(self):
        if not INTEGRATION:
            self.skipTest("需要 --integration：真实 systemd 临时单元")
        # 临时 socket 使用 PrivateNetwork；service 只持有传入 fd，不绑定主机网络。
        self.bash(2, r'''
name=reinforce-test-$$
cleanup() {
  command systemctl stop "$name.service" "$name.socket" >/dev/null 2>&1 || :
  rm -f "/run/systemd/system/$name.service" "/run/systemd/system/$name.socket"
  command systemctl daemon-reload
  command systemctl reset-failed "$name.service" "$name.socket" >/dev/null 2>&1 || :
}
trap cleanup EXIT
printf '[Service]\nExecStart=/bin/sleep 60\nKillMode=process\n' > "/run/systemd/system/$name.service"
printf '[Socket]\nPrivateNetwork=yes\nBindIPv6Only=ipv6-only\nListenStream=0.0.0.0:42222\nListenStream=[::]:42222\n' > "/run/systemd/system/$name.socket"
command systemctl daemon-reload && command systemctl start "$name.socket" || exit 1
command systemctl start "$name.service" || exit 2
before=$(command systemctl show "$name.service" -p MainPID --value)
systemctl() {
  local -a args=(); local arg
  for arg in "$@"; do
    case $arg in ssh.service) arg=$name.service;; ssh.socket) arg=$name.socket;; esac
    args+=("$arg")
  done
  command systemctl "${args[@]}"
}
sshd() { return 0; }
start_ssh_entry || exit 3
after=$(command systemctl show "$name.service" -p MainPID --value)
[[ $before != "$after" && $after != 0 ]] || exit 4
[[ $(socket_addrs) == $'0.0.0.0:42222\n[::]:42222' ]]
''')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--integration", action="store_true", help="运行真实 nft/临时 systemd 隔离检查，需要 Linux root")
    options, remaining = parser.parse_known_args()
    INTEGRATION = options.integration
    if options.integration:
        if os.geteuid() != 0:
            parser.error("--integration 需要 root；不操作真实 SSH 单元或主机 nft 表")
        probe = subprocess.run(["unshare", "-n", "true"], capture_output=True)
        if probe.returncode:
            parser.error("无法创建独立网络命名空间")
    unittest.main(argv=[__file__, *remaining], verbosity=2)
