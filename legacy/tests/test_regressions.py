#!/usr/bin/env python3
"""三阶段回归：默认仅临时文件/替身；--integration 增加真实 nft 和 systemd 隔离检查。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
from audit_source import audit_source

ROOT = Path(__file__).resolve().parents[1]
INTEGRATION = False
STAGE_FILES = {1: "stage1-newport.sh", 2: "stage2-harden.sh", 3: "stage3-reboot-check.sh"}


def function(stage, name):
    text = (ROOT / STAGE_FILES[stage]).read_text(encoding="utf-8")
    start = text.index(name + "() {")
    # 函数以顶格 } 结尾；Python heredoc 内没有单独的顶格 }。
    return text[start:start + re.search(r"^}\n", text[start:], re.M).end()]


def library(stage):
    text = (ROOT / STAGE_FILES[stage]).read_text(encoding="utf-8")
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
        for name in (*STAGE_FILES.values(), "stage0-audit.sh", "stage1.sh", "stage2.sh", "stage3.sh"):
            path = ROOT / name
            for command in (["bash", "-n"], ["shellcheck", "-S", "warning"]):
                with self.subTest(script=name, command=command):
                    result = subprocess.run([*command, str(path)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def migration_case(self, body, *, ok=True):
        if os.geteuid() != 0:
            self.skipTest("迁移文件权限检查需要 root 测试用户")
        ssh = self.work / "ssh"
        (ssh / "sshd_config.d").mkdir(parents=True)
        socket = self.work / "socket"
        socket.mkdir()
        ufw = self.work / "ufw"
        ufw.mkdir()
        (ssh / "sshd_config").write_text(f"Include {ssh}/sshd_config.d/*.conf\nPort 22\nListenAddress 127.0.0.1\n")
        (ssh / "sshd_config.d" / "99-old.conf").write_text("PermitRootLogin yes\nPasswordAuthentication yes\nKbdInteractiveAuthentication no\n")
        (socket / "override.conf").write_text("[Unit]\nRequires=ssh-firewall.service other.service\n[Socket]\nListenStream=22\nBindIPv6Only=both\n")
        (ufw / "user.rules").write_text("# original business rules\n")
        (ufw / "user6.rules").write_text("# original IPv6 business rules\n")
        (ufw / "ufw.conf").write_text("ENABLED=yes\n")
        (self.work / "default-ufw").write_text("MANAGE_BUILTINS=no\n")
        (self.work / "compute-stage3").write_text(function(3, "compute_config_sha"))
        (self.work / "stage2-transactions").write_text("\n".join(function(2, name) for name in ("tx_begin", "tx_restore", "gen_sshd_dropin", "gen_fw_unit", "all_ports")))
        return self.bash(1, r'''
SSHD_CONFIG=$WORK/ssh/sshd_config; SSHD_DROPIN=$WORK/ssh/sshd_config.d/00-reinforce-my-ssh.conf
SOCKET_DIR=$WORK/socket; SOCKET_OVERRIDE=$WORK/socket/00-reinforce-my-ssh.conf
UFW_DIR=$WORK/ufw; UFW_DEFAULT=$WORK/default-ufw
STATE_ROOT=$WORK/state; TX_ROOT=$STATE_ROOT/transactions
STATE_FILE=$STATE_ROOT/state.conf; POLICY_FILE=$STATE_ROOT/policy.conf
NFT_RULES=$WORK/nft; NFT_LOADER=$WORK/loader; FW_UNIT=$WORK/unit
MANAGED_FILES=("$SSHD_DROPIN" "$NFT_RULES" "$NFT_LOADER" "$FW_UNIT" "$SOCKET_OVERRIDE")
CORE_MANAGED_FILES=("${MANAGED_FILES[@]}")
PORT=62207; OLD_PORT=22; USERNAME=deploy; ALLOWS=(203.0.113.7/32 2001:db8::1/128)
sshd() {
  if [[ $1 == -T ]]; then
    printf 'permitrootlogin yes\npubkeyauthentication yes\npasswordauthentication yes\nkbdinteractiveauthentication no\nauthenticationmethods any\n'
  fi
  return 0
}
systemctl() {
  printf '%s\n' "$*" >> "$WORK/systemctl-calls"
  case $1 in
    show)
      case $4 in
        LoadState) printf 'loaded\n';;
        Type) printf 'oneshot\n';;
      esac;;
    is-enabled) printf 'enabled\n';;
    is-active) [[ $2 != firewalld.service ]] || { printf 'inactive\n'; return 3; }; printf 'active\n';;
  esac
  return 0
}
ufw() {
  printf '%s\n' "$*" >> "$WORK/ufw-calls"
  case $1 in
    status) printf 'Status: active\n';;
    prepend) printf '# added candidate\n' >> "$UFW_DIR/user.rules";;
    reload) grep -q 'original business rules' "$UFW_DIR/user.rules" || return 1;;
    *) return 1;;
  esac
}
nft() { [[ $* == 'list tables' || $1 != list ]]; }
ss() { return 0; }
''' + body, ok=ok, env={"TMPDIR": str(self.work)})

    def test_migration_plan_apply_and_full_rollback(self):
        self.migration_case(r'''
cp "$SSHD_CONFIG" "$WORK/main.before"; cp "$SOCKET_DIR/override.conf" "$WORK/socket.before"
prepare_migration || exit 1
cmp -s "$SSHD_CONFIG" "$WORK/main.before" || exit 2
gen_sshd_dropin "$WORK/candidate" candidate || exit 3
grep -qx 'passwordauthentication yes' "$WORK/candidate" || exit 4
tx_begin stage1 candidate-pending || exit 5
test -f "$TX_DIR/migration-plan.json" || exit 6
apply_migration && coordinate_firewall || exit 7
cp "$WORK/candidate" "$SSHD_DROPIN"
for f in "$NFT_RULES" "$NFT_LOADER" "$FW_UNIT" "$SOCKET_OVERRIDE"; do printf 'Managed by reinforce-my-ssh\n' > "$f"; done
grep -q '^# reinforce-my-ssh migrated: PermitRootLogin yes' "$WORK/ssh/sshd_config.d/99-old.conf" || exit 8
grep -qx 'Requires=other.service' "$SOCKET_DIR/override.conf" || exit 9
grep -qx 'disable ssh-firewall.service' "$WORK/systemctl-calls" || exit 10
! grep -q -- '--now' "$WORK/systemctl-calls" || exit 11
grep -q 'prepend allow proto tcp from 203.0.113.7/32 to any port 62207' "$WORK/ufw-calls" || exit 12
digest=$(config_digest) || exit 13
source "$WORK/compute-stage3"
test "$(compute_config_sha)" = "$digest" || exit 14
cancel_recovery() { return 0; }; stop_ssh_entry() { return 0; }; restore_unit_state() { return 0; }
tx_restore "$TX_ID" 0 || exit 15
cmp -s "$SSHD_CONFIG" "$WORK/main.before" && cmp -s "$SOCKET_DIR/override.conf" "$WORK/socket.before" || exit 16
test ! -e "$STATE_ROOT/migration.json" && test ! -e "$SSHD_DROPIN" || exit 17
grep -qx '# original business rules' "$UFW_DIR/user.rules" || exit 18
grep -qx 'STAGE=unconfigured' "$STATE_FILE" || exit 19
''')

    def test_migration_input_drift_fails_before_any_file_is_changed(self):
        self.migration_case(r'''
cp "$SSHD_CONFIG" "$WORK/main.before"
prepare_migration || exit 1
tx_begin stage1 candidate-pending || exit 2
printf '# concurrent edit\n' >> "$WORK/ssh/sshd_config.d/99-old.conf"
if apply_migration; then exit 3; fi
cmp -s "$SSHD_CONFIG" "$WORK/main.before" || exit 4
test ! -e "$STATE_ROOT/migration.json" || exit 5
''')

    def test_compat_firewall_restore_failure_can_be_retried(self):
        self.migration_case(r'''
prepare_migration && tx_begin stage1 candidate-pending && apply_migration && coordinate_firewall || exit 1
# 正常路径拒绝损坏记录；回滚可使用事务中保存的清单恢复。
printf 'corrupt metadata\n' > "$STATE_ROOT/migration.json"
if (load_state); then exit 6; fi
MANAGED_FILES=("${CORE_MANAGED_FILES[@]}")
DO_ROLLBACK=1
load_state || exit 7
cancel_recovery() { return 0; }; restore_unit_state() { return 0; }
stop_ssh_entry() { printf 'stop\n' >> "$WORK/stops"; }
ufw() { [[ $RESTORE_FAIL == no ]]; }
RESTORE_FAIL=yes
if tx_restore "$TX_ID" 0; then exit 2; fi
test ! -e "$TX_DIR/ROLLED_BACK" && test -s "$WORK/stops" || exit 3
RESTORE_FAIL=no
tx_restore "$TX_ID" 0 || exit 4
test -f "$TX_DIR/ROLLED_BACK" && grep -qx 'STAGE=unconfigured' "$STATE_FILE" || exit 5
''')

    def test_migrated_stage2_then_stage1_reverse_rollback(self):
        self.migration_case(r'''
prepare_migration && tx_begin stage1 candidate-pending && apply_migration && coordinate_firewall || exit 1
gen_sshd_dropin "$SSHD_DROPIN" candidate || exit 2
for f in "$NFT_RULES" "$NFT_LOADER" "$FW_UNIT" "$SOCKET_OVERRIDE"; do printf 'Managed by reinforce-my-ssh\n' > "$f"; done
parent=$TX_ID; parent_sha=$(config_digest) || exit 3
write_state candidate-ready "$parent" "$parent_sha" || exit 4
source "$WORK/stage2-transactions"
STAGE_ID=stage2; MIGRATION_PLAN=''
tx_begin stage2 hardening-pending || exit 5
gen_sshd_dropin "$SSHD_DROPIN" hardened || exit 6
cancel_recovery() { return 0; }; stop_ssh_entry() { return 0; }; restore_unit_state() { return 0; }
tx_restore "$TX_ID" 0 || exit 7
test "$STATE_TX" = "$parent" && test "$(config_digest)" = "$parent_sha" || exit 8
grep -qx 'passwordauthentication yes' "$SSHD_DROPIN" || exit 9
STAGE_ID=stage1
tx_restore "$parent" 0 || exit 10
test ! -e "$SSHD_DROPIN" && test ! -e "$STATE_ROOT/migration.json" || exit 11
grep -qx '# original business rules' "$UFW_DIR/user.rules" || exit 12
''')

    def test_candidate_regeneration_survives_new_process_and_stage2(self):
        self.migration_case(r'''
prepare_migration && generate_files "$WORK/expected" candidate || exit 1
tx_begin stage1 candidate-pending && apply_migration || exit 2
# 新会话没有预检时的临时计划变量，只能读取持久迁移记录。
MIGRATION_PLAN=''
generate_files "$WORK/reopened" candidate || exit 3
source "$WORK/stage2-transactions"
TARGET_STAGE=candidate
generate_files "$WORK/stage2" candidate || exit 4
for file in sshd socket loader unit nft; do
  cmp -s "$WORK/expected/$file" "$WORK/reopened/$file" || exit 5
  cmp -s "$WORK/expected/$file" "$WORK/stage2/$file" || exit 6
done
''')

    def test_current_user_and_old_port_are_inferred_without_overriding_explicit_policy(self):
        self.bash(1, r'''
id() { printf '1000\n'; }
find_ssh_connection() { printf '203.0.113.7 5000 192.0.2.10 62207\n'; }
PORT=2222; USERNAME=''; SUDO_USER=deploy; OLD_PORT_SET=0; ALLOWS=(203.0.113.7/32)
normalize_params
test "$USERNAME" = deploy && test "$OLD_PORT" = 62207 || exit 1
OLD_PORT_SET=1; OLD_PORT=none
normalize_params
test "$OLD_PORT" = none || exit 2
OLD_PORT_SET=0; PORT=62207
normalize_params
test "$OLD_PORT" = none || exit 3
''')

    def test_migration_paths_reject_escape_and_core_file_collision(self):
        self.migration_case(r'''
prepare_migration || exit 1
cp "$MIGRATION_PLAN" "$WORK/plan.original"
python3 - "$MIGRATION_PLAN" <<'PY'
import json,sys
p=json.load(open(sys.argv[1])); p['files'][0]['path']='/etc/passwd'; json.dump(p,open(sys.argv[1],'w'))
PY
if load_migration "$MIGRATION_PLAN"; then exit 2; fi
cp "$WORK/plan.original" "$MIGRATION_PLAN"
python3 - "$MIGRATION_PLAN" "$SSHD_DROPIN" <<'PY'
import json,sys
p=json.load(open(sys.argv[1])); p['files'][0]['path']=sys.argv[2]; json.dump(p,open(sys.argv[1],'w'))
PY
if load_migration "$MIGRATION_PLAN"; then exit 3; fi
test ! -e "$STATE_FILE" || exit 4
''')

    def test_migration_rejects_unsafe_ufw_and_match_without_modification(self):
        self.migration_case(r'''
cp "$SSHD_CONFIG" "$WORK/main.before"
printf 'MANAGE_BUILTINS=yes\n' > "$UFW_DEFAULT"
if prepare_migration; then exit 1; fi
printf 'MANAGE_BUILTINS=no\n' > "$UFW_DEFAULT"
printf 'Match User other\n PasswordAuthentication yes\n' >> "$WORK/ssh/sshd_config.d/99-old.conf"
if prepare_migration; then exit 2; fi
cmp -s "$SSHD_CONFIG" "$WORK/main.before" && test ! -e "$STATE_FILE" || exit 3
''')

    def test_migration_enables_keys_without_closing_passwords_or_relaxing_mfa(self):
        self.migration_case(r'''
sshd() { printf 'permitrootlogin yes\npubkeyauthentication no\npasswordauthentication yes\nkbdinteractiveauthentication no\nauthenticationmethods %s\n' "$METHODS"; }
METHODS=any
prepare_migration && gen_sshd_dropin "$WORK/candidate" candidate || exit 1
grep -qx 'pubkeyauthentication yes' "$WORK/candidate" || exit 2
grep -qx 'passwordauthentication yes' "$WORK/candidate" || exit 3
METHODS=publickey,password
if prepare_migration; then exit 4; fi
test ! -e "$STATE_FILE" || exit 5
''')

    def test_hardened_auth_generation_uses_stage_argument(self):
        for stage in (1, 2):
            self.bash(stage, r'''
PORT=2222; OLD_PORT=none
gen_sshd_dropin "$WORK/config" hardened || exit 1
grep -qx 'PermitRootLogin no' "$WORK/config" || exit 2
grep -qx 'PasswordAuthentication no' "$WORK/config" || exit 3
grep -qx 'AuthenticationMethods publickey' "$WORK/config" || exit 4
''')

    def test_stage3_state_only_rollback_does_not_need_valid_migration_metadata(self):
        if os.geteuid() != 0:
            self.skipTest("stage3 完整入口权限检查需要 root")
        state = self.work / "stage3-state"
        state.mkdir()
        (state / "policy.conf").write_text("PORT=2222\nOLD_PORT=22\nUSER=nobody\nALLOW=203.0.113.0/24\nRECOVERY_SECONDS=900\nRESCUE_CONFIRMED=yes\n")
        (state / "state.conf").write_text("STAGE=verified\nTX=parent\nCONFIG_SHA=" + "a" * 64 + "\nPENDING_BOOT=\nVERIFIED_BOOT=\n")
        (state / "migration.json").write_text("corrupt metadata\n")
        source = (ROOT / STAGE_FILES[3]).read_text().replace("STATE_DIR=/var/lib/reinforce-my-ssh", "STATE_DIR=" + str(state))
        source = source.replace("/run/lock/reinforce-my-ssh.lock", str(self.work / "lock"))
        script = self.work / "stage3.sh"
        script.write_text(source)
        result = subprocess.run(["bash", str(script), "--rollback"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("STAGE=hardened", (state / "state.conf").read_text())
        self.assertEqual((state / "migration.json").read_text(), "corrupt metadata\n")
        result = subprocess.run(["bash", str(script)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("迁移路径记录无效", result.stdout + result.stderr)

    def test_normalizers_identical(self):
        self.assertEqual(function(1, "normalize_nft"), function(2, "normalize_nft"))
        self.assertEqual(function(1, "normalize_nft"), function(3, "normalize_nft"))
        for name in ("migration_paths", "load_migration"):
            self.assertEqual(function(1, name), function(2, name))
            self.assertEqual(function(1, name), function(3, name))

    def test_old_entry_names_delegate_and_stage0_preserves_arguments(self):
        for stage, canonical in STAGE_FILES.items():
            with self.subTest(stage=stage):
                old = subprocess.run(["bash", str(ROOT / f"stage{stage}.sh"), "--help"], capture_output=True, text=True)
                new = subprocess.run(["bash", str(ROOT / canonical), "--help"], capture_output=True, text=True)
                self.assertEqual(old.returncode, 0, old.stderr)
                self.assertEqual(new.returncode, 0, new.stderr)
                self.assertEqual(old.stdout, new.stdout)
                self.assertIn(canonical, new.stdout)
        for arguments in (["--help"], ["--port", "2222", "--user", "deploy", "--allow", "203.0.113.0/24", "--apply"]):
            reference = self.work / "audit-reference.py"
            reference.write_text(audit_source(), encoding="utf-8")
            wrapper = subprocess.run(["bash", str(ROOT / "stage0-audit.sh"), *arguments], capture_output=True, text=True)
            backend = subprocess.run([sys.executable, str(reference), *arguments], capture_output=True, text=True)
            self.assertEqual(wrapper.returncode, backend.returncode)
            self.assertEqual(wrapper.stdout, backend.stdout)
            self.assertEqual(wrapper.stderr, backend.stderr)

    def test_four_runtime_files_are_self_contained(self):
        names = ("stage0-audit.sh", *STAGE_FILES.values())
        runtime = self.work / "runtime"
        runtime.mkdir()
        for name in names:
            (runtime / name).write_bytes((ROOT / name).read_bytes())
        self.assertEqual(sorted(path.name for path in runtime.iterdir()), sorted(names))
        for name in names:
            result = subprocess.run(["bash", str(runtime / name), "--help"], cwd=runtime,
                                    capture_output=True, text=True, env={**os.environ, "PYTHONPATH": ""})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(name, result.stdout)

    def test_recovery_uses_stable_stage_id_after_rename(self):
        for stage in (1, 2):
            for name in (f"stage{stage}.sh", STAGE_FILES[stage]):
                with self.subTest(stage=stage, name=name):
                    self.bash(stage, rf'''
SELF={name}; TX_ROOT=$WORK; STATE_TX=newer; STATE_STAGE=verified
mkdir -p "$WORK/old"
printf '{{"files":[]}}\n' > "$WORK/old/manifest.json"
: > "$WORK/old/units.conf"; printf 'stage{stage}\n' > "$WORK/old/stage"
cancel_recovery() {{ return 0; }}
tx_restore old 1 || exit 1
printf 'stage9\n' > "$WORK/old/stage"
(tx_restore old 1) && exit 2
exit 0
''')

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
        stage3 = (ROOT / STAGE_FILES[3]).read_text()
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

    def tx_begin_failure(self, stage, mode):
        return self.bash(stage, r'''
SELF=stage-test.sh; STATE_ROOT=$WORK/state; POLICY_FILE=$STATE_ROOT/policy.conf
STATE_FILE=$STATE_ROOT/state.conf; TX_ROOT=$STATE_ROOT/transactions
STATE_STAGE=candidate-ready; STATE_TX=parent; STATE_CONFIG_SHA=parentsha
PORT=2222; OLD_PORT=22; USERNAME=deploy; ALLOWS=(203.0.113.0/24)
MANAGED_FILES=()
rm -rf "$STATE_ROOT"; mkdir -p "$STATE_ROOT"; printf 'PORT=2222\n' > "$POLICY_FILE"
nft() {
  [[ $MODE != inventory ]] || return 1
  if [[ $* == 'list tables' ]]; then
    [[ $MODE != backup ]] || printf 'table inet sshguard\n'
    return 0
  fi
  return 1
}
ss() { return 0; }
systemctl() {
  if [[ $1 == is-enabled ]]; then
    [[ $MODE != enabled ]] || { printf 'linked\n'; return 0; }
    printf 'enabled\n'; return 0
  fi
  if [[ $1 == is-active ]]; then
    [[ $MODE != active ]] || return 1
    printf 'active\n'; return 0
  fi
  return 0
}
tx_begin test-stage pending
''', ok=False, env={"MODE": mode})

    def test_tx_begin_rejects_nft_inventory_failures(self):
        messages = {"inventory": "无法枚举 nft 表", "backup": "内核 nft 备份失败"}
        for stage in (1, 2):
            for mode, message in messages.items():
                with self.subTest(stage=stage, mode=mode):
                    output = self.tx_begin_failure(stage, mode)
                    self.assertIn(message, output)
                    self.assertFalse((self.work / "state" / "state.conf").exists())

    def test_tx_begin_rejects_unsupported_unit_states(self):
        for stage in (1, 2):
            for mode in ("active", "enabled"):
                with self.subTest(stage=stage, mode=mode):
                    output = self.tx_begin_failure(stage, mode)
                    self.assertIn(f"ssh.socket 的 {mode} 状态", output)
                    self.assertFalse((self.work / "state" / "state.conf").exists())

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
nft() { [[ $* == 'list tables' ]] || [[ $1 != list ]]; }; sshd() { return 0; }; ss() { return 0; }
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

    def test_unmanaged_diagnostics_do_not_report_security_failure(self):
        for stage, variable in ((2, "STATE_ROOT"), (3, "STATE_DIR")):
            with self.subTest(stage=stage):
                text = (ROOT / STAGE_FILES[stage]).read_text(encoding="utf-8")
                text = text.replace(f"{variable}=/var/lib/reinforce-my-ssh", f"{variable}={self.work}/absent")
                # 所有受管路径也映射到临时目录，避免读取本机已有配置。
                for name, path in (
                    ("SSHD_DROPIN", "/etc/ssh/sshd_config.d/00-reinforce-my-ssh.conf"),
                    ("NFT_RULES", "/etc/nftables.d/reinforce-my-ssh.nft"),
                    ("NFT_LOADER", "/usr/local/sbin/reinforce-my-ssh-firewall"),
                    ("FW_UNIT", "/etc/systemd/system/reinforce-my-ssh-firewall.service"),
                    ("SOCKET_OVERRIDE" if stage == 2 else "SOCKET_DROPIN", "/etc/systemd/system/ssh.socket.d/00-reinforce-my-ssh.conf"),
                ):
                    text = text.replace(f"{name}={path}", f"{name}={self.work}/{name}")
                # 该测试只验证只读入口语义，普通用户运行测试也不要求 root。
                if stage == 2:
                    text = text.replace("\nrequire_root\n", "\n:\n")
                else:
                    text = text.replace("if (( EUID != 0 )); then", "if false; then")
                script = self.work / f"diagnostic-{stage}.sh"
                script.write_text(text)
                before = sorted(self.work.iterdir())
                result = subprocess.run(["bash", str(script)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("未执行", result.stdout + result.stderr)
                self.assertIn("stage0-audit.sh", result.stdout + result.stderr)
                self.assertEqual(before, sorted(self.work.iterdir()))

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

    def test_initial_rollback_failure_keeps_policy_and_retry_entry(self):
        tx, _ = self.restore_fixture()
        (tx / "stage").write_text("stage1\n")
        (tx / "parent").write_text("unconfigured\n\n\n")
        (tx / "policy.before").unlink()
        profile = "PORT=2222\nOLD_PORT=22\nUSER=deploy\nALLOW=203.0.113.0/24\nRECOVERY_SECONDS=900\nRESCUE_CONFIRMED=yes\n"
        (self.work / "policy.conf").write_text(profile)
        self.bash(1, r'''
SELF=stage1.sh; STATE_ROOT=$WORK; STATE_FILE=$WORK/state.conf; POLICY_FILE=$WORK/policy.conf
TX_ROOT=$WORK/transactions; STATE_TX=demo; STATE_STAGE=candidate-pending; DO_ROLLBACK=1
PORT=2222; OLD_PORT=22; MANAGED_FILES=("$WORK/managed"); CORE_MANAGED_FILES=("${MANAGED_FILES[@]}")
cancel_recovery() { return 0; }; stop_ssh_entry() { echo stop >> "$WORK/stops"; }
systemctl() { [[ $1 != show ]] || printf 'loaded\n'; return 0; }
restore_unit_state() { return 0; }; sshd() { return 0; }; ss() { return 0; }
nft() { return 1; }; verify_nft_semantics() { return 1; }
if tx_restore demo 0; then exit 5; fi
[[ -r $POLICY_FILE ]] || exit 6
load_policy || exit 7
[[ $PORT == 2222 && $USERNAME == deploy ]] || exit 8
test ! -e "$TX_DIR/ROLLED_BACK" || exit 9
nft() { return 0; }; verify_nft_semantics() { return 0; }
tx_restore demo 0 || exit 10
grep -qx 'STAGE=unconfigured' "$STATE_FILE" || exit 11
test ! -e "$POLICY_FILE" && test -r "$TX_DIR/policy.target"
''')

    def test_rollback_loads_transaction_policy_after_global_policy_is_lost(self):
        tx, _ = self.restore_fixture()
        profile = "PORT=2222\nOLD_PORT=22\nUSER=deploy\nALLOW=203.0.113.0/24\nRECOVERY_SECONDS=900\nRESCUE_CONFIRMED=yes\n"
        (tx / "policy.target").write_text(profile)
        (self.work / "policy.conf").unlink()
        for stage in (1, 2):
            self.bash(stage, r'''
STATE_STAGE=candidate-pending; STATE_TX=demo; TX_ROOT=$WORK/transactions
POLICY_FILE=$WORK/policy.conf; DO_ROLLBACK=1
load_policy || exit 1
[[ $PORT == 2222 && $OLD_PORT == 22 && $USERNAME == deploy && ${ALLOWS[*]} == 203.0.113.0/24 ]] || exit 2
''')

    def test_confirm_never_stops_ssh_on_success_or_rejected_evidence(self):
        for stage, pending, ready in ((1, "candidate-pending", "candidate-ready"), (2, "hardening-pending", "hardened")):
            for failure in (False, True):
                output = self.bash(stage, rf'''
STATE_STAGE={pending}; STATE_TX=demo; TX_ROOT=$WORK
STATE_ROOT=$WORK; STATE_FILE=$WORK/state.conf
mkdir -p "$WORK/demo"
rm -f "$STATE_FILE"
date +%s > "$WORK/demo/started"
PORT=62207; USERNAME=deploy
recovery_paths() {{ RECOVERY_UNIT=$WORK/recovery.service; RECOVERY_TIMER=$WORK/recovery.timer; }}
touch "$WORK/recovery.service" "$WORK/recovery.timer"
verify_runtime() {{ return 0; }}
session_evidence() {{ [[ $EVIDENCE_FAIL != yes ]]; }}
config_digest() {{ printf '%064d\n' 1; }}
stop_ssh_entry() {{ echo FORBIDDEN_STOP; exit 90; }}
tx_restore() {{ echo FORBIDDEN_ROLLBACK; exit 91; }}
systemctl() {{
  case "$*" in
    "disable --now reinforce-my-ssh-demo.timer"|"disable reinforce-my-ssh-demo.service"|daemon-reload) return 0;;
    *) echo FORBIDDEN_SYSTEMCTL; exit 92;;
  esac
}}
do_confirm
grep -qx 'STAGE={ready}' "$STATE_FILE"
''', ok=not failure, env={"EVIDENCE_FAIL": "yes" if failure else "no"})
                self.assertNotIn("FORBIDDEN", output)
                if failure:
                    self.assertIn("原自动恢复计时", output)

    def test_native_tx_begin_distinguishes_existing_and_absent_table(self):
        if not INTEGRATION:
            self.skipTest("需要 --integration：真实 nft 事务备份")
        for stage in (1, 2):
            with self.subTest(stage=stage):
                self.bash(stage, r'''
SELF=stage-test.sh; STATE_ROOT=$WORK/native-$CASE_STAGE
POLICY_FILE=$STATE_ROOT/policy.conf; STATE_FILE=$STATE_ROOT/state.conf
TX_ROOT=$STATE_ROOT/transactions; MANAGED_FILES=()
STATE_STAGE=candidate-ready; STATE_TX=parent; STATE_CONFIG_SHA=parentsha
PORT=2222; OLD_PORT=22; USERNAME=deploy; ALLOWS=(203.0.113.0/24)
systemctl() {
  case $1 in
    is-enabled) printf 'disabled\n';;
    is-active) printf 'inactive\n';;
    *) return 1;;
  esac
}
# 同名不同 family 和前缀相同的表都不能误认成目标表。
nft add table ip sshguard || exit 1
nft add table inet sshguard-other || exit 2
tx_begin test-stage pending || exit 3
test -f "$TX_DIR/NFT_ABSENT" && test ! -e "$TX_DIR/runtime.nft" || exit 4
nft add table inet sshguard || exit 5
nft add chain inet sshguard sentinel || exit 6
tx_begin test-stage pending || exit 7
test ! -e "$TX_DIR/NFT_ABSENT" && test -s "$TX_DIR/runtime.nft" || exit 8
nft -s -y list table inet sshguard > "$WORK/expected-$CASE_STAGE.nft" || exit 9
cmp -s "$TX_DIR/runtime.nft" "$WORK/expected-$CASE_STAGE.nft" || exit 10
''', integration=True, env={"CASE_STAGE": str(stage)})

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

    def test_native_audit_nft_json(self):
        if not INTEGRATION:
            self.skipTest("需要 --integration：真实 nft JSON 独立审计")
        (self.work / "audit-check.py").write_text('''import sys
sys.dont_write_bytecode = True
sys.path.insert(0, ''' + repr(str(ROOT / "tests")) + ''')
from audit_source import load_audit
import json
audit=load_audit()
policy=audit.Policy(2222,'deploy',['203.0.113.7/32','2001:db8::1/128'],[22])
data=json.loads(audit.System().run('nft','-j','-s','list','ruleset'))
check=audit.firewall_policy(data,policy)
print(check)
assert check.result==sys.argv[1], check
''')
        self.bash(2, r'''
PORT=2222; OLD_PORT=22; ALLOWS=(203.0.113.7/32 2001:db8::1/128); TARGET_STAGE=hardened
gen_nft_rules "$WORK/new.nft" && nft -f "$WORK/new.nft" || exit 1
python3 "$WORK/audit-check.py" pass || exit 2
nft insert rule inet sshguard input tcp dport 2222 accept || exit 3
python3 "$WORK/audit-check.py" fail || exit 4
''', integration=True)

    def test_native_audit_dual_stack_socket_option(self):
        if not INTEGRATION:
            self.skipTest("需要 --integration：真实 socket 的 v6only 属性")
        (self.work / "socket-audit.py").write_text('''import socket, sys
sys.dont_write_bytecode=True
sys.path.insert(0, ''' + repr(str(ROOT / "tests")) + ''')
from audit_source import load_audit
audit=load_audit()
for only, expected in ((0,audit.PASS),(1,audit.FAIL)):
 s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
 s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,only)
 s.bind(('::',42222)); s.listen()
 auditor=audit.Auditor(audit.Policy(42222,'deploy',['203.0.113.0/24']))
 auditor.unit=lambda name: {'Listen':'[::]:42222 (Stream)'}
 auditor.listeners()
 check=next(x for x in auditor.checks if x.name=='来源地址族监听')
 assert check.result==expected, check
 s.close()
''')
        self.bash(2, 'python3 "$WORK/socket-audit.py"\n', integration=True)

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
