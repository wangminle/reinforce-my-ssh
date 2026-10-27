#!/usr/bin/env python3
"""可选原生验收：使用解包的 ufw/openssh-server，不安装或启动主机服务。"""
import argparse
import hashlib
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

import test_regressions as regression


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", required=True, type=Path, help="dpkg-deb -x 解包得到的运行目录")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("需要 root，仅在独立网络和挂载命名空间操作")
    runtime = args.runtime.resolve()
    for name in ("usr/sbin/ufw", "usr/sbin/sshd", "usr/lib/python3/dist-packages/ufw"):
        if not (runtime / name).exists():
            parser.error("缺少运行依赖: " + name)
    with tempfile.TemporaryDirectory(prefix="reinforce-native-migration-") as folder:
        work = Path(folder)
        data = work / "root"
        for source, target in (("usr/lib/ufw", "lib/ufw"), ("usr/share/ufw", "usr/share/ufw"), ("etc/ufw", "etc/ufw")):
            shutil.copytree(runtime / source, data / target)
        (data / "etc/default").mkdir(parents=True)
        shutil.copy2(runtime / "etc/default/ufw", data / "etc/default/ufw")
        shutil.copy2(runtime / "usr/share/ufw/ufw.conf", data / "etc/ufw/ufw.conf")
        for rules in (runtime / "usr/share/ufw/iptables").glob("*.rules"):
            shutil.copy2(rules, data / "etc/ufw" / rules.name)
        for name in ("before.init", "after.init"):
            shutil.copy2(runtime / "usr/share/ufw" / name, data / "etc/ufw" / name)
            (data / "etc/ufw" / name).chmod(0o640)
        (data / "usr/sbin").mkdir(parents=True)
        for name in ("iptables", "ip6tables", "iptables-restore", "ip6tables-restore", "iptables-save", "ip6tables-save"):
            (data / "usr/sbin" / name).symlink_to(shutil.which(name))
        ssh = work / "ssh"
        (ssh / "sshd_config.d").mkdir(parents=True)
        socket = work / "socket"
        socket.mkdir()
        (work / "run/sshd").mkdir(parents=True)
        units = work / "units"
        units.mkdir()
        ufw_unit = (runtime / "usr/lib/systemd/system/ufw.service").read_text()
        ufw_unit = "\n".join(line.split("=", 1)[0] + "=/bin/true" if line.startswith(("ExecStart=", "ExecStop=")) else line for line in ufw_unit.splitlines())
        (units / "ufw.service").write_text(ufw_unit + "\n")
        (units / "ssh.service").write_text("[Service]\nExecStart=/bin/true\nKillMode=process\n")
        (units / "ssh.socket").write_text("[Unit]\nRequires=reinforce-my-ssh-firewall.service\nAfter=reinforce-my-ssh-firewall.service\n[Socket]\nListenStream=62207\n")
        (ssh / "sshd_config").write_text(f"Include {ssh}/sshd_config.d/*.conf\nPort 22\nPermitRootLogin yes\nPasswordAuthentication yes\nKbdInteractiveAuthentication no\n")
        (socket / "override.conf").write_text("[Socket]\nListenStream=22\n")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(work / "hostkey")], check=True)
        body = r'''
set -e
mount --make-rprivate /
mkdir -p "$WORK/etc-upper" "$WORK/etc-work"
mount -t overlay overlay -o "lowerdir=/etc,upperdir=$WORK/etc-upper,workdir=$WORK/etc-work" /etc
getent passwd sshd >/dev/null || printf 'sshd:x:65534:65534:isolated test:/nonexistent:/usr/sbin/nologin\n' >> /etc/passwd
getent passwd deploy >/dev/null || printf 'deploy:x:65533:65534:isolated target:/nonexistent:/usr/sbin/nologin\n' >> /etc/passwd
mount --bind "$WORK/run" /run
SSHD_CONFIG=$WORK/ssh/sshd_config; SSHD_DROPIN=$WORK/ssh/sshd_config.d/00-reinforce-my-ssh.conf
SOCKET_DIR=$WORK/socket; SOCKET_OVERRIDE=$SOCKET_DIR/00-reinforce-my-ssh.conf
UFW_DIR=$SANDBOX/etc/ufw; UFW_DEFAULT=$SANDBOX/etc/default/ufw
STATE_ROOT=$WORK/state; TX_ROOT=$STATE_ROOT/transactions
POLICY_FILE=$STATE_ROOT/policy.conf; STATE_FILE=$STATE_ROOT/state.conf
NFT_RULES=$WORK/managed.nft; NFT_LOADER=$WORK/loader; FW_UNIT=$WORK/unit
MANAGED_FILES=("$SSHD_DROPIN" "$NFT_RULES" "$NFT_LOADER" "$FW_UNIT" "$SOCKET_OVERRIDE")
CORE_MANAGED_FILES=("${MANAGED_FILES[@]}")
PORT=62207; OLD_PORT=22; USERNAME=deploy; ALLOWS=(203.0.113.7/32 2001:db8::1/128)
systemctl() {
  case $1 in
    show) if [[ $2 == ufw.service ]]; then printf 'loaded\n'; else printf 'not-found\n'; fi;;
    is-enabled) printf 'disabled\n';;
    is-active) printf 'inactive\n'; return 3;;
  esac
  return 0
}
ufw() { PYTHONPATH="$PKG/usr/lib/python3/dist-packages" "$PKG/usr/sbin/ufw" --rootdir="$SANDBOX" --datadir="$SANDBOX" "$@"; }
sshd() { "$PKG/usr/sbin/sshd" -h "$WORK/hostkey" -f "$SSHD_CONFIG" "$@"; }
ufw allow 443/tcp comment business-https
ufw allow 22/tcp
ufw --force enable
# 非 UFW 管理链也必须保留。
iptables -N reinforce-business
iptables -A reinforce-business -p tcp --dport 8443 -j ACCEPT
iptables -I INPUT 1 -j reinforce-business
iptables -S reinforce-business > "$WORK/business.before"
prepare_migration
tx_begin stage1 candidate-pending
apply_migration
coordinate_firewall
gen_sshd_dropin "$SSHD_DROPIN" candidate
gen_socket_override "$SOCKET_OVERRIDE"
gen_nft_rules "$NFT_RULES"
nft -f "$NFT_RULES"
gen_loader "$NFT_LOADER"
chmod 0755 "$NFT_LOADER"
gen_fw_unit "$FW_UNIT"
cp "$FW_UNIT" "$WORK/units/$FW_NAME"
SYSTEMD_UNIT_PATH="$WORK/units:/usr/lib/systemd/system" systemd-analyze --man=no --generators=no verify ssh.socket "$FW_NAME" ufw.service
sshd -t -f "$SSHD_CONFIG"
sshd -T -f "$SSHD_CONFIG" > "$WORK/candidate.auth"
grep -qx 'passwordauthentication yes' "$WORK/candidate.auth"
grep -qx 'permitrootlogin yes' "$WORK/candidate.auth"
test "$(grep -c '^port 22$' "$WORK/candidate.auth")" = 1
test "$(grep -c '^port 62207$' "$WORK/candidate.auth")" = 1
iptables -S ufw-user-input | grep -- '--dport 62207'
ip6tables -S ufw6-user-input | grep -- '--dport 62207'
ufw status | grep '443/tcp'
gen_sshd_dropin "$SSHD_DROPIN" hardened
sshd -t -f "$SSHD_CONFIG"
sshd -T -f "$SSHD_CONFIG" > "$WORK/hardened.auth"
grep -qx 'permitrootlogin no' "$WORK/hardened.auth"
grep -qx 'passwordauthentication no' "$WORK/hardened.auth"
grep -qx 'authenticationmethods publickey' "$WORK/hardened.auth"
cancel_recovery() { return 0; }; stop_ssh_entry() { return 0; }; restore_unit_state() { return 0; }
tx_restore "$TX_ID" 0
sshd -T -f "$SSHD_CONFIG" > "$WORK/restored.auth"
grep -qx 'passwordauthentication yes' "$WORK/restored.auth"
! iptables -S ufw-user-input | grep -- '--dport 62207' >/dev/null
! ip6tables -S ufw6-user-input | grep -- '--dport 62207' >/dev/null
ufw status | grep '443/tcp'
iptables -S reinforce-business > "$WORK/business.after"
cmp -s "$WORK/business.before" "$WORK/business.after"
iptables -S INPUT | grep -- '-j reinforce-business'
test ! -e "$STATE_ROOT/migration.json"
printf 'NATIVE_MIGRATION_PASS\n'
'''
        script = work / "case.sh"
        script.write_text(regression.library(1) + "\nWORK=" + shlex.quote(str(work)) + "\nPKG=" + shlex.quote(str(runtime)) + "\nSANDBOX=" + shlex.quote(str(data)) + "\n" + body)
        identity_before = hashlib.sha256(Path("/etc/passwd").read_bytes()).hexdigest()
        firewall_before = subprocess.check_output(["nft", "-s", "list", "ruleset"])
        result = subprocess.run(["unshare", "-n", "-m", "--fork", "bash", str(script)], env={**os.environ, "TMPDIR": str(work), "LC_ALL": "C"}, timeout=120)
        assert hashlib.sha256(Path("/etc/passwd").read_bytes()).hexdigest() == identity_before, "挂载命名空间外账户文件发生变化"
        assert subprocess.check_output(["nft", "-s", "list", "ruleset"]) == firewall_before, "网络命名空间外规则发生变化"
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
