#!/usr/bin/env bash
# stage1-newport.sh — 建立候选 SSH 通道；外部公钥登录和 sudo 验证后才提交。
# 支持 Ubuntu/Debian + systemd + ssh.socket。默认只读部署预检，不是通用安全审计。
# 用法见 --help；设计与限制见 plans/DESIGN.md。
set -uo pipefail

SELF=${0##*/}
STAGE_ID=stage1
SRC=$(cd "$(dirname "$0")" && pwd)
STATE_ROOT=/var/lib/reinforce-my-ssh
POLICY_FILE=$STATE_ROOT/policy.conf
STATE_FILE=$STATE_ROOT/state.conf
TX_ROOT=$STATE_ROOT/transactions
LOCK_FILE=/run/lock/reinforce-my-ssh.lock
SSHD_DROPIN=/etc/ssh/sshd_config.d/00-reinforce-my-ssh.conf
NFT_RULES=/etc/nftables.d/reinforce-my-ssh.nft
NFT_LOADER=/usr/local/sbin/reinforce-my-ssh-firewall
FW_UNIT=/etc/systemd/system/reinforce-my-ssh-firewall.service
FW_NAME=reinforce-my-ssh-firewall.service
SOCKET_OVERRIDE=/etc/systemd/system/ssh.socket.d/00-reinforce-my-ssh.conf
NFT_TABLE=sshguard
MANAGED_FILES=("$SSHD_DROPIN" "$NFT_RULES" "$NFT_LOADER" "$FW_UNIT" "$SOCKET_OVERRIDE")

PORT=""; OLD_PORT=22; USERNAME=""; CONF=""; RECOVERY_SECONDS=900; RESCUE_CONFIRMED=no
ALLOWS=(); APPLY=0; CONFIRM=0; DO_ROLLBACK=0; ASSUME_YES=0; AUTO_RECOVERY=0; REQUEST_TX=""
PORT_SET=0; OLD_PORT_SET=0; USER_SET=0; ALLOW_SET=0; RECOVERY_SET=0
STATE_STAGE=unconfigured; STATE_TX=""; STATE_CONFIG_SHA=""; STATE_PENDING_BOOT=""; STATE_VERIFIED_BOOT=""
TX_ID=""; TX_DIR=""; TX_STARTED=""; PARENT_STAGE=unconfigured; PARENT_TX=""

log()  { printf '[%s] %s\n' "$1" "$2"; }
ok()   { log OK "$1"; }
warn() { log WARN "$1"; }
fail() { log FAIL "$1" >&2; }
die()  { fail "$1"; exit 1; }

usage() {
  cat <<'USAGE'
用法:
  stage1-newport.sh --port <n> --user <name> --allow <cidr> [选项]       # 只读预检
  stage1-newport.sh --port <n> --user <name> --allow <cidr> --apply      # 部署候选通道
  stage1-newport.sh --confirm                                            # 从新外部会话中 sudo 执行
  stage1-newport.sh --rollback [--transaction <id>]                       # 逆序回滚

选项:
  --old-port <n|none>       保留的旧 SSH 端口，默认 22
  --allow <cidr>            来源白名单，可重复
  --conf <file>             严格 KEY=VALUE 配置文件
  --recovery-seconds <n>    未确认前自动恢复时限，默认 900
  --apply / --confirm       部署 / 外部验证后提交
  --yes                     跳过交互；仍需 RESCUE_CONFIRMED=yes
  --rollback                回滚当前阶段事务
  --transaction <id>        精确指定事务（自动恢复内部使用）
  -h, --help                显示帮助

配置文件键: PORT, OLD_PORT, USER, ALLOW（可重复）, RECOVERY_SECONDS,
            RESCUE_CONFIRMED=yes（表示已实际演练独立于 sshd 的救援通道）。
默认检查只判断部署前提/受管配置；已有旧方案请用独立 stage0-audit.sh。
普通用户 SSH 登录后 sudo 执行即可，不需要开放 root SSH 登录。
USAGE
}

need_val() { (($2 >= 2)) || { fail "$1 缺少取值"; usage >&2; exit 2; }; }
while (($#)); do
  case "$1" in
    --port) need_val "$1" $#; PORT=$2; PORT_SET=1; shift 2 ;;
    --old-port) need_val "$1" $#; OLD_PORT=$2; OLD_PORT_SET=1; shift 2 ;;
    --user) need_val "$1" $#; USERNAME=$2; USER_SET=1; shift 2 ;;
    --allow) need_val "$1" $#; ALLOWS+=("$2"); ALLOW_SET=1; shift 2 ;;
    --conf) need_val "$1" $#; CONF=$2; shift 2 ;;
    --recovery-seconds) need_val "$1" $#; RECOVERY_SECONDS=$2; RECOVERY_SET=1; shift 2 ;;
    --apply) APPLY=1; shift ;;
    --confirm) CONFIRM=1; shift ;;
    --rollback) DO_ROLLBACK=1; shift ;;
    --transaction) need_val "$1" $#; REQUEST_TX=$2; shift 2 ;;
    --auto-recovery) AUTO_RECOVERY=1; shift ;;
    --yes) ASSUME_YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "未知参数: $1"; usage >&2; exit 2 ;;
  esac
done
(( APPLY + CONFIRM + DO_ROLLBACK <= 1 )) || die "--apply、--confirm、--rollback 互斥"
(( AUTO_RECOVERY == 0 || DO_ROLLBACK == 1 )) || die "--auto-recovery 只能与 --rollback 连用"

if [[ -n $CONF ]]; then
  [[ -r $CONF ]] || die "配置文件不可读: $CONF"
  [[ ! -s $CONF || -z $(tail -c 1 "$CONF") ]] || die "配置文件最后一行必须以 LF 结束"
  declare -A CONF_SEEN=()
  while IFS= read -r line; do
    [[ $line =~ ^[[:space:]]*$ || $line =~ ^[[:space:]]*# ]] && continue
    [[ $line =~ ^([A-Z_]+)=(.*)$ ]] || die "配置文件存在非法行: $line"
    key=${BASH_REMATCH[1]}; value=${BASH_REMATCH[2]}
    [[ $value != *$'\r'* ]] || die "配置文件含 CR，请转换为 LF"
    case $key in
      PORT|OLD_PORT|USER|RECOVERY_SECONDS|RESCUE_CONFIRMED)
        [[ -z ${CONF_SEEN[$key]:-} ]] || die "配置键重复: $key"; CONF_SEEN[$key]=1 ;;
      ALLOW) ;;
      *) die "未知配置键: $key" ;;
    esac
    case $key in
      PORT) ((PORT_SET)) || PORT=$value ;;
      OLD_PORT) ((OLD_PORT_SET)) || OLD_PORT=$value ;;
      USER) ((USER_SET)) || USERNAME=$value ;;
      ALLOW) ((ALLOW_SET)) || ALLOWS+=("$value") ;;
      RECOVERY_SECONDS) ((RECOVERY_SET)) || RECOVERY_SECONDS=$value ;;
      RESCUE_CONFIRMED) RESCUE_CONFIRMED=$value ;;
    esac
  done < "$CONF"
fi

normalize_port() {
  [[ $1 =~ ^[0-9]{1,5}$ ]] || return 1
  local n=$((10#$1)); ((n >= 1 && n <= 65535)) || return 1
  printf '%d' "$n"
}
normalize_params() {
  PORT=$(normalize_port "$PORT") || die "非法 --port: $PORT"
  if [[ $OLD_PORT != none ]]; then OLD_PORT=$(normalize_port "$OLD_PORT") || die "非法 --old-port"; fi
  [[ $OLD_PORT == none || $OLD_PORT != "$PORT" ]] || die "新旧端口数值相同"
  [[ $USERNAME =~ ^[a-z_][a-z0-9_-]*\$?$ ]] || die "非法账户名"
  [[ $USERNAME != root ]] || die "--user 必须是非 root 账户"
  id "$USERNAME" >/dev/null 2>&1 || die "账户不存在: $USERNAME"
  [[ $(id -u "$USERNAME") != 0 ]] || die "禁止使用 UID 0 管理账户"
  [[ $RECOVERY_SECONDS =~ ^[0-9]+$ ]] && ((10#$RECOVERY_SECONDS >= 60 && 10#$RECOVERY_SECONDS <= 86400)) \
    || die "RECOVERY_SECONDS 应为 60–86400"
  [[ $RESCUE_CONFIRMED == yes || $RESCUE_CONFIRMED == no ]] || die "RESCUE_CONFIRMED 只能是 yes/no"
  ((${#ALLOWS[@]} > 0)) || die "至少提供一个 --allow"
  local a n; local normalized=()
  for a in "${ALLOWS[@]}"; do
    n=$(python3 -c 'import ipaddress,sys; print(ipaddress.ip_network(sys.argv[1], strict=True))' "$a" 2>/dev/null) \
      || die "非法或带主机位的 CIDR: $a"
    normalized+=("$n")
  done
  mapfile -t ALLOWS < <(printf '%s\n' "${normalized[@]}" | sort -u)
}
load_state() {
  local f k v seen_stage=0 seen_tx=0 seen_sha=0
  if [[ ! -e $STATE_FILE ]]; then
    for f in "${MANAGED_FILES[@]}"; do
      [[ ! -e $f ]] || die "发现受管配置但状态文件缺失，拒绝当作 unconfigured: $f"
    done
    return 0
  fi
  [[ -r $STATE_FILE ]] || die "状态文件存在但不可读: $STATE_FILE"
  while IFS='=' read -r k v; do
    case $k in
      STAGE) STATE_STAGE=$v; seen_stage=1 ;;
      TX) STATE_TX=$v; seen_tx=1 ;;
      CONFIG_SHA) STATE_CONFIG_SHA=$v; seen_sha=1 ;;
      PENDING_BOOT) STATE_PENDING_BOOT=$v ;; VERIFIED_BOOT) STATE_VERIFIED_BOOT=$v ;;
    esac
  done < "$STATE_FILE"
  ((seen_stage && seen_tx && seen_sha)) || die "状态文件缺少 STAGE/TX/CONFIG_SHA，拒绝继续"
  case $STATE_STAGE in unconfigured|candidate-pending|candidate-ready|hardening-pending|hardened|reboot-pending|verified) ;; *) die "未知阶段状态: $STATE_STAGE" ;; esac
  if [[ $STATE_STAGE == unconfigured ]]; then
    [[ -z $STATE_TX && -z $STATE_CONFIG_SHA ]] || die "unconfigured 状态包含事务或摘要，拒绝继续"
    for f in "${MANAGED_FILES[@]}"; do [[ ! -e $f ]] || die "unconfigured 与受管文件矛盾: $f"; done
  else
    [[ -n $STATE_TX ]] || die "非 unconfigured 状态缺少当前事务"
    [[ $STATE_STAGE == candidate-pending || $STATE_STAGE == hardening-pending || $STATE_CONFIG_SHA =~ ^[0-9a-f]{64}$ ]] \
      || die "已提交状态缺少有效配置摘要"
  fi
}
load_policy() {
  [[ $STATE_STAGE != unconfigured ]] || return 0
  [[ -r $POLICY_FILE ]] || die "已有阶段状态但策略文件不可读: $POLICY_FILE"
  local k v; local saved=("${ALLOWS[@]}"); local policy_allows=()
  while IFS='=' read -r k v; do
    case $k in
      PORT) ((PORT_SET)) && [[ $PORT != "$v" ]] && die "PORT 与已存策略冲突"; PORT=$v ;;
      OLD_PORT) ((OLD_PORT_SET)) && [[ $OLD_PORT != "$v" ]] && die "OLD_PORT 与已存策略冲突"; OLD_PORT=$v ;;
      USER) ((USER_SET)) && [[ $USERNAME != "$v" ]] && die "USER 与已存策略冲突"; USERNAME=$v ;;
      ALLOW) policy_allows+=("$v") ;;
      RECOVERY_SECONDS) ((RECOVERY_SET)) && [[ $RECOVERY_SECONDS != "$v" ]] && die "RECOVERY_SECONDS 与已存策略冲突"; RECOVERY_SECONDS=$v ;;
      RESCUE_CONFIRMED) RESCUE_CONFIRMED=$v ;;
    esac
  done < "$POLICY_FILE"
  if ((ALLOW_SET)); then
    local saved_normal policy_normal
    saved_normal=$(python3 -c 'import ipaddress,sys; print("\n".join(sorted({str(ipaddress.ip_network(x,strict=True)) for x in sys.argv[1:]})))' "${saved[@]}") || die "ALLOW 非法"
    policy_normal=$(python3 -c 'import ipaddress,sys; print("\n".join(sorted({str(ipaddress.ip_network(x,strict=True)) for x in sys.argv[1:]})))' "${policy_allows[@]}") || die "已存 ALLOW 非法"
    [[ $saved_normal == "$policy_normal" ]] || die "ALLOW 与已存策略冲突；如需改策略请先回滚 stage1"
  else
    ALLOWS=("${policy_allows[@]}")
  fi
}
require_root() {
  ((EUID == 0)) && return 0
  fail "权限不足，未完成检查；请以目标普通用户登录后 sudo bash 执行，不必开放 root SSH 登录"
  exit 2
}
ensure_state_root() {
  mkdir -p "$STATE_ROOT" && mkdir -p "$TX_ROOT" || die "无法创建 $STATE_ROOT"
  chmod 0700 "$STATE_ROOT" "$TX_ROOT" || die "无法保护状态目录"
}
lock_all() { exec 9>"$LOCK_FILE" || die "无法打开锁"; flock -x 9 || die "无法取得事务锁"; }
write_policy() {
  local t; t=$(mktemp "$STATE_ROOT/.policy.XXXXXX") || return 1
  { printf 'PORT=%s\nOLD_PORT=%s\nUSER=%s\nRECOVERY_SECONDS=%s\nRESCUE_CONFIRMED=%s\n' \
      "$PORT" "$OLD_PORT" "$USERNAME" "$RECOVERY_SECONDS" "$RESCUE_CONFIRMED"
    printf 'ALLOW=%s\n' "${ALLOWS[@]}"
  } > "$t" || { rm -f "$t"; return 1; }
  chmod 0600 "$t" && mv -f "$t" "$POLICY_FILE"
}
write_state() {
  local stage=$1 tx=$2 config_sha=${3-$STATE_CONFIG_SHA}; local t
  t=$(mktemp "$STATE_ROOT/.state.XXXXXX") || return 1
  printf 'STAGE=%s\nTX=%s\nCONFIG_SHA=%s\nPENDING_BOOT=%s\nVERIFIED_BOOT=%s\n' \
    "$stage" "$tx" "$config_sha" "$STATE_PENDING_BOOT" "$STATE_VERIFIED_BOOT" > "$t" \
    || { rm -f "$t"; return 1; }
  chmod 0600 "$t" && mv -f "$t" "$STATE_FILE" || { rm -f "$t"; return 1; }
  STATE_STAGE=$stage; STATE_TX=$tx; STATE_CONFIG_SHA=$config_sha
}
config_digest() {
  { printf 'POLICY\n'; cat "$POLICY_FILE" 2>/dev/null || return 1
    local f; for f in "${MANAGED_FILES[@]}"; do
      if [[ -f $f ]]; then printf 'FILE %s\n' "$f"; cat "$f" || return 1; else printf 'ABSENT %s\n' "$f"; fi
    done
  } | sha256sum | awk '{print $1}'
}
all_ports() { if [[ $OLD_PORT == none ]]; then printf '%s\n' "$PORT"; else printf '%s\n%s\n' "$OLD_PORT" "$PORT"; fi; }
port_set() { local p out=""; while IFS= read -r p; do out+="${out:+, }$p"; done < <(all_ports | sort -n -u); printf '{ %s }' "$out"; }
ip_in_cidrs() { python3 - "$@" <<'PY'
import ipaddress,sys
try:
 a=ipaddress.ip_address(sys.argv[1]); nets=[ipaddress.ip_network(x) for x in sys.argv[2:]]
except ValueError: sys.exit(2)
sys.exit(0 if any(a in n for n in nets) else 1)
PY
}
ip_is_local() {
  ip -j address show 2>/dev/null | python3 -c '
import ipaddress,json,sys
target=ipaddress.ip_address(sys.argv[1])
try: data=json.load(sys.stdin)
except Exception: sys.exit(2)
for link in data:
 for item in link.get("addr_info",[]):
  try:
   if ipaddress.ip_address(item["local"])==target: sys.exit(0)
  except (KeyError,ValueError): pass
sys.exit(1)' "$1"
}

find_ssh_connection() {
  local p v
  if [[ -n ${SSH_CONNECTION:-} ]]; then printf '%s\n' "$SSH_CONNECTION"; return 0; fi
  p=$PPID
  while [[ $p =~ ^[0-9]+$ ]] && ((p > 1)); do
    if [[ -r /proc/$p/environ ]]; then
      v=$(tr '\0' '\n' < "/proc/$p/environ" 2>/dev/null | sed -n 's/^SSH_CONNECTION=//p' | head -1)
      [[ -z $v ]] || { printf '%s\n' "$v"; return 0; }
    fi
    p=$(awk '/^PPid:/{print $2}' "/proc/$p/status" 2>/dev/null) || return 1
  done
  return 1
}
require_source_allowed() {
  local conn c cp s sp
  conn=$(find_ssh_connection) || { fail "无法确定当前 SSH_CONNECTION；远程 apply 已拒绝"; return 1; }
  read -r c cp s sp extra <<< "$conn"
  [[ -n ${sp:-} && -z ${extra:-} ]] || { fail "SSH_CONNECTION 格式异常"; return 1; }
  ip_in_cidrs "$c" "${ALLOWS[@]}" || { fail "当前来源 $c 不在白名单内"; return 1; }
  ok "当前来源 $c 在白名单内"
}
record_confirmation_boundary() {
  local raw tmp
  raw=$(mktemp "$TX_DIR/.journal.XXXXXX") || return 1
  tmp=$(mktemp "$TX_DIR/.confirmation.XXXXXX") || { rm -f "$raw"; return 1; }
  journalctl -b -n 1 --no-pager -o json > "$raw" \
    && python3 - "$raw" "$tmp" <<'PY'
import json,sys
events=[json.loads(x) for x in open(sys.argv[1]) if x.strip()]
if not events or not events[-1].get('__CURSOR'): raise SystemExit('缺少 journal cursor')
boot=open('/proc/sys/kernel/random/boot_id').read().strip().replace('-','')
if events[-1].get('_BOOT_ID')!=boot: raise SystemExit('journal boot 不匹配')
json.dump({'cursor':events[-1]['__CURSOR'],'boot':boot},open(sys.argv[2],'w'))
PY
  local rc=$?
  rm -f "$raw"
  if ((rc == 0)); then chmod 0600 "$tmp" && mv -f "$tmp" "$TX_DIR/confirmation.json" || rc=1; fi
  rm -f "$tmp"
  return "$rc"
}
session_evidence() {
  local boundary=$1 conn c cp s sp uid extra d rc=0
  [[ ${SUDO_USER:-} == "$USERNAME" ]] || { fail "必须由 $USERNAME 通过 sudo 执行"; return 1; }
  uid=$(id -u "$USERNAME") || return 1
  [[ ${SUDO_UID:-} == "$uid" ]] || { fail "SUDO_UID 与目标账户不匹配"; return 1; }
  conn=$(find_ssh_connection) || { fail "找不到当前外部 SSH 会话四元组"; return 1; }
  read -r c cp s sp extra <<< "$conn"
  [[ -n ${sp:-} && -z ${extra:-} && $sp == "$PORT" && $cp =~ ^[0-9]+$ ]] \
    || { fail "当前会话不是新端口 $PORT 的有效连接"; return 1; }
  python3 -c 'import ipaddress,sys; a=ipaddress.ip_address(sys.argv[1]); sys.exit(1 if a.is_loopback else 0)' "$c" \
    || { fail "回环连接不能作为外部登录证据"; return 1; }
  local local_rc; ip_is_local "$c"; local_rc=$?
  ((local_rc == 1)) || { fail "来源为本机或无法核实来源地址"; return 1; }
  ip_in_cidrs "$c" "${ALLOWS[@]}" || { fail "会话来源 $c 不在白名单内"; return 1; }
  [[ -f $boundary ]] || { fail "确认事件边界缺失；请回滚后重新部署"; return 1; }
  d=$(mktemp -d) || return 1
  local cursor
  cursor=$(python3 - "$boundary" <<'PY'
import json,sys
b=json.load(open(sys.argv[1])); boot=open('/proc/sys/kernel/random/boot_id').read().strip().replace('-','')
if b.get('boot')!=boot or not isinstance(b.get('cursor'),str) or not b['cursor']: raise SystemExit(1)
print(b['cursor'])
PY
  ) || { rm -rf "$d"; fail "确认边界不属于本次启动"; return 1; }
  ss -tnpH state established "( sport = :$PORT )" > "$d/ss" 2>/dev/null \
    && journalctl -b -u ssh -u sshd -u 'ssh@*' --after-cursor "$cursor" --no-pager -o json > "$d/journal" 2>/dev/null \
    && python3 - "$d" "$USERNAME" "$c" "$cp" "$s" "$sp" "$$" <<'PY'
import ipaddress,json,re,sys
root,u,c,cp,s,sp,pid=sys.argv[1:]
def split(endpoint):
 host,port=endpoint.rsplit(':',1)
 return ipaddress.ip_address(host.strip('[]')),int(port)
ancestors=set()
while pid.isdigit() and int(pid)>1 and pid not in ancestors:
 ancestors.add(pid)
 try:
  status=open('/proc/'+pid+'/status').read()
  pid=re.search(r'^PPid:\s+(\d+)',status,re.M).group(1)
 except (OSError,AttributeError): break
live=set()
for line in open(root+'/ss'):
 fields=line.split()
 if len(fields)<5: continue
 try:
  if split(fields[2])!=(ipaddress.ip_address(s),int(sp)) or split(fields[3])!=(ipaddress.ip_address(c),int(cp)): continue
 except ValueError: continue
 live.update(re.findall(r'"sshd(?:-session|-auth)?",pid=(\d+)',line))
if not live.intersection(ancestors): raise SystemExit('连接不属于当前 sudo 会话的 sshd 进程链')
boot=open('/proc/sys/kernel/random/boot_id').read().strip().replace('-','')
pat=re.compile(r'^Accepted publickey for (\S+) from (\S+) port ([0-9]+)(?:\s|$)')
matched=False
for line in open(root+'/journal'):
 event=json.loads(line)
 if event.get('_BOOT_ID')!=boot or str(event.get('_PID','')) not in ancestors: continue
 message=event.get('MESSAGE','')
 if not isinstance(message,str): continue
 match=pat.search(message)
 if match and match[1]==u and match[3]==cp:
  try: matched |= ipaddress.ip_address(match[2])==ipaddress.ip_address(c)
  except ValueError: pass
if not matched: raise SystemExit('缺少边界之后、属于当前 sshd 进程链的公钥日志')
PY
  rc=$?
  rm -rf "$d"
  ((rc == 0)) || { fail "当前连接、公钥日志与 sudo 进程链关联失败"; return 1; }
  ok "已证明目标用户经新端口公钥登录、会话仍存活，并完成真实 sudo"
}

scan_sshd_config() {
  python3 - "$SSHD_DROPIN" <<'PY'
import glob,os,re,sys
managed=os.path.realpath(sys.argv[1]); seen=set(); errors=[]; controlled={
 'port','listenaddress','permitrootlogin','pubkeyauthentication','passwordauthentication',
 'kbdinteractiveauthentication','authenticationmethods'}
def visit(path,depth=0):
 if depth>16: errors.append(path+': Include 递归过深'); return
 path=os.path.realpath(path)
 if path in seen: return
 seen.add(path)
 try: lines=open(path,encoding='utf-8').read().splitlines()
 except OSError as e: errors.append(f'{path}: {e}'); return
 for no,line in enumerate(lines,1):
  s=line.strip()
  if not s or s.startswith('#'): continue
  m=re.match(r'(\S+)\s+(.*)',s)
  if not m: errors.append(f'{path}:{no}: 无法解析'); continue
  key,args=m.group(1).lower(),m.group(2).strip()
  if key=='match': errors.append(f'{path}:{no}: 不支持活动 Match，请先人工整理')
  elif key=='include':
   if not os.path.isabs(args) or len(args.split())!=1:
    errors.append(f'{path}:{no}: 仅支持单个绝对 Include pattern，拒绝无法完整解析的配置'); continue
   for pat in glob.glob(args): visit(pat,depth+1)
  elif key in controlled and path!=managed:
   errors.append(f'{path}:{no}: 接管阻断：非受管指令 {m.group(1)}；这不是安全不合格结论，请先独立审计')
visit('/etc/ssh/sshd_config')
print('\n'.join(errors))
sys.exit(bool(errors))
PY
}
assert_manageable() {
  local f
  for f in "${MANAGED_FILES[@]}"; do
    [[ ! -e $f ]] && continue
    [[ -f $f ]] || { fail "受管路径不是普通文件: $f"; return 1; }
    grep -q 'Managed by reinforce-my-ssh' "$f" 2>/dev/null \
      || { fail "拒绝接管非本工具文件: $f"; return 1; }
  done
}
preflight() {
  local bad=0 cmd
  for cmd in python3 nft sshd systemctl ssh ss ip flock sha256sum install journalctl timeout; do
    command -v "$cmd" >/dev/null 2>&1 || { fail "缺少命令: $cmd"; bad=1; }
  done
  id -nG "$USERNAME" 2>/dev/null | tr ' ' '\n' | grep -qx sudo \
    || { fail "$USERNAME 不在 sudo 组"; bad=1; }
  systemctl cat ssh.socket >/dev/null 2>&1 || { fail "仅支持 ssh.socket 激活布局"; bad=1; }
  scan_sshd_config || bad=1
  assert_manageable || bad=1
  require_source_allowed || bad=1
  [[ $(systemctl show ssh.service -p KillMode --value) == process ]] || { fail "仅支持 KillMode=process 的 ssh.service"; bad=1; }
  [[ $(systemctl show ssh.socket -p Accept --value) == no ]] || { fail "仅支持 Accept=no 的 ssh.socket"; bad=1; }
  sshd -t || bad=1
  return "$bad"
}
confirm_rescue() {
  [[ $RESCUE_CONFIRMED == yes ]] && return 0
  ((ASSUME_YES == 0)) || die "--yes 不能替代 RESCUE_CONFIRMED=yes"
  local answer
  printf '请确认已实际登录过独立于 sshd 的 VNC/串口/Agent 救援通道。输入 yes: '
  read -r answer; [[ $answer == yes ]] || die "未确认独立救援通道"
  RESCUE_CONFIRMED=yes
}

gen_nft_rules() {
  local out=$1 a fam
  {
    printf '# Managed by reinforce-my-ssh; do not edit\nadd table inet %s\ndelete table inet %s\n' "$NFT_TABLE" "$NFT_TABLE"
    printf 'table inet %s {\n\tchain input {\n' "$NFT_TABLE"
    printf '\t\ttype filter hook input priority -100; policy accept;\n'
    printf '\t\tiif "lo" ip saddr 127.0.0.1 tcp dport %s counter accept\n' "$(port_set)"
    printf '\t\tiif "lo" ip6 saddr ::1 tcp dport %s counter accept\n' "$(port_set)"
    for a in "${ALLOWS[@]}"; do [[ $a == *:* ]] && fam=ip6 || fam=ip; printf '\t\t%s saddr %s tcp dport %s counter accept\n' "$fam" "$a" "$(port_set)"; done
    printf '\t\ttcp dport %s ct state established,related counter accept\n' "$(port_set)"
    printf '\t\ttcp dport %s counter drop\n\t}\n}\n' "$(port_set)"
  } > "$out"
}
gen_loader() { printf '#!/bin/sh\n# Managed by reinforce-my-ssh; do not edit\nexec /usr/sbin/nft -f %s\n' "$NFT_RULES" > "$1"; }
gen_fw_unit() {
  cat > "$1" <<UNIT
# Managed by reinforce-my-ssh; do not edit
[Unit]
Description=Reinforce My SSH firewall
DefaultDependencies=no
After=local-fs.target network-pre.target
Wants=network-pre.target
Before=ssh.socket shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$NFT_LOADER
ExecReload=$NFT_LOADER

[Install]
WantedBy=sysinit.target
UNIT
}
gen_sshd_dropin() {
  local stage=$1 p
  {
    printf '# Managed by reinforce-my-ssh; do not edit\n'
    if [[ $stage == hardened ]]; then
      printf 'PermitRootLogin no\nPubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nAuthenticationMethods publickey\n'
    fi
    while IFS= read -r p; do printf 'Port %s\n' "$p"; done < <(all_ports | sort -n -u)
  } > "$1"
}
gen_socket_override() {
  local p
  {
    printf '# Managed by reinforce-my-ssh; do not edit\n[Unit]\nRequires=%s\nAfter=%s\n\n[Socket]\nBindIPv6Only=ipv6-only\nListenStream=\n' "$FW_NAME" "$FW_NAME"
    while IFS= read -r p; do printf 'ListenStream=0.0.0.0:%s\nListenStream=[::]:%s\n' "$p" "$p"; done < <(all_ports | sort -n -u)
  } > "$1"
}
generate_files() {
  local d=$1 stage=$2
  mkdir -p "$d" || return 1
  gen_nft_rules "$d/nft" && gen_loader "$d/loader" && gen_fw_unit "$d/unit" \
    && gen_sshd_dropin "$d/sshd" "$stage" && gen_socket_override "$d/socket"
}
put_file() { install -m "$3" -o root -g root "$1" "$2"; }

normalize_nft() {
  python3 - "$1" "${2:--}" "$NFT_TABLE" <<'PY'
import ipaddress,re,sys
src,dst,table=sys.argv[1:]
text=open(src,encoding='utf-8').read()
# 仅忽略本表的事务前导；其他命令必须保留，不能掩盖额外操作。
lines=[]
for raw in text.splitlines():
 line=raw.strip()
 if not line or line.startswith('#'): continue
 if line in {f'add table inet {table}',f'delete table inet {table}',f'flush table inet {table}'}: continue
 line=re.sub(r'\bcounter(?:\s+packets\s+\d+\s+bytes\s+\d+)?\b','',line)
 lines.append(line)
tokens=re.findall(r'"(?:\\.|[^"\\])*"|[^\s{};,]+|[{};,]', '\n'.join(lines))
out=[]; i=0
while i<len(tokens):
 token=tokens[i]
 if token in {'saddr','daddr'} and i+1<len(tokens):
  out.append(token); i+=1
  try:
   net=ipaddress.ip_network(tokens[i],strict=False)
   token=str(net.network_address) if net.prefixlen==net.max_prefixlen else str(net)
  except ValueError: token=tokens[i]
 elif token=='{' and out and out[-1]=='dport' and i+2<len(tokens) and tokens[i+1].isdigit() and tokens[i+2]=='}':
  token=tokens[i+1]; i+=2
 out.append(token); i+=1
normalized='\n'.join(out)+'\n'
if dst=='-': sys.stdout.write(normalized)
else:
 with open(dst,'w',encoding='utf-8') as f: f.write(normalized)
PY
}
verify_nft_semantics() {
  local expected=$1 actual=$2
  nft -s -y list table inet "$NFT_TABLE" > "$actual.raw" 2>/dev/null || return 1
  normalize_nft "$expected" > "$expected.norm" && normalize_nft "$actual.raw" > "$actual.norm" && cmp -s "$expected.norm" "$actual.norm"
}
socket_addrs() { systemctl show ssh.socket -p Listen --value 2>/dev/null | awk '$2=="(Stream)"{print $1}' | sort; }
check_listener() {
  local port=$1
  ss -tlnpH 2>/dev/null | python3 -c '
import sys
p=int(sys.argv[1]); found=set()
for line in sys.stdin:
 f=line.split()
 if len(f)<5 or not ("systemd" in line or "sshd" in line): continue
 try:
  h,port=f[3].rsplit(":",1)
  if int(port)==p: found.add(h.strip("[]"))
 except ValueError: pass
sys.exit(0 if {"0.0.0.0","::"}<=found else 1)' "$port"
}
port_any_listening() {
  ss -tlnH 2>/dev/null | python3 -c '
import sys
p=int(sys.argv[1])
for line in sys.stdin:
 f=line.split()
 if len(f)<4: continue
 try:
  if int(f[3].rsplit(":",1)[1])==p: sys.exit(0)
 except (ValueError,IndexError): pass
sys.exit(1)' "$1"
}
verify_auth_context() {
  local conn c cp s sp key value u
  conn=$(find_ssh_connection 2>/dev/null) || conn="127.0.0.1 1 127.0.0.1 $PORT"
  read -r c cp s sp <<< "$conn"
  for u in "$USERNAME" root; do
    local output
    output=$(sshd -T -C "user=$u,host=localhost,addr=$c,laddr=$s,lport=$PORT" 2>/dev/null) || { fail "sshd 上下文解析失败: $u"; return 1; }
    for key in permitrootlogin pubkeyauthentication passwordauthentication kbdinteractiveauthentication authenticationmethods; do
      value=$(awk -v k="$key" '$1==k{print $2;exit}' <<< "$output")
      case $u:$key in
        root:permitrootlogin|*:passwordauthentication|*:kbdinteractiveauthentication) [[ $value == no ]] || { fail "$u $key=$value"; return 1; } ;;
        *:pubkeyauthentication) [[ $value == yes ]] || { fail "$u $key=$value"; return 1; } ;;
        *:authenticationmethods) [[ $value == publickey ]] || { fail "$u $key=$value"; return 1; } ;;
        *) ;;
      esac
    done
  done
}
verify_runtime() {
  local stage=$1 d bad=0 p expected actual
  scan_sshd_config || bad=1
  d=$(mktemp -d) || return 1
  generate_files "$d" "$stage" || { rm -rf "$d"; return 1; }
  for pair in "$d/nft:$NFT_RULES" "$d/loader:$NFT_LOADER" "$d/unit:$FW_UNIT" "$d/sshd:$SSHD_DROPIN" "$d/socket:$SOCKET_OVERRIDE"; do
    [[ -f ${pair#*:} ]] && cmp -s "${pair%%:*}" "${pair#*:}" || { fail "受管文件漂移: ${pair#*:}"; bad=1; }
  done
  sshd -t || bad=1
  expected=$(all_ports | sort -n -u | tr '\n' ' ' | sed 's/ $//')
  actual=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -n -u | tr '\n' ' ' | sed 's/ $//')
  [[ $actual == "$expected" ]] || { fail "sshd 端口 [$actual]，期望 [$expected]"; bad=1; }
  [[ $(systemctl show ssh.socket -p BindIPv6Only --value) == ipv6-only ]] || { fail "socket 未明确隔离 IPv6/IPv4 绑定"; bad=1; }
  local expected_addrs
  expected_addrs=$(while IFS= read -r p; do printf '0.0.0.0:%s\n[::]:%s\n' "$p" "$p"; done < <(all_ports | sort -n -u) | sort | tr '\n' ' ' | sed 's/ $//')
  actual=$(socket_addrs | tr '\n' ' ' | sed 's/ $//')
  [[ $actual == "$expected_addrs" ]] || { fail "socket 监听 [$actual]，期望 [$expected_addrs]"; bad=1; }
  while IFS= read -r p; do
    check_listener "$p" || { fail "端口 $p 缺少 IPv4/IPv6 通配监听"; bad=1; }
    timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/$p" 2>/dev/null || { fail "IPv4 回环不可连: $p"; bad=1; }
    timeout 5 bash -c "exec 3<>/dev/tcp/::1/$p" 2>/dev/null || { fail "IPv6 回环不可连: $p"; bad=1; }
  done < <(all_ports | sort -n -u)
  if [[ $stage == hardened && $OLD_PORT != none ]] && port_any_listening "$OLD_PORT"; then
    fail "旧端口 $OLD_PORT 仍有监听"; bad=1
  fi
  verify_nft_semantics "$d/nft" "$d/actual" || { fail "nft 规则语义与目标不一致"; bad=1; }
  systemctl is-active --quiet ssh.service && systemctl is-active --quiet ssh.socket && systemctl is-active --quiet "$FW_NAME" || { fail "SSH/firewall 单元未全部 active"; bad=1; }
  [[ $(systemctl is-enabled ssh.socket) == enabled && $(systemctl is-enabled "$FW_NAME") == enabled ]] || { fail "SSH/firewall 单元未全部 enabled"; bad=1; }
  systemctl show ssh.socket -p Requires --value | grep -qw "$FW_NAME" || { fail "socket 缺少防火墙 Requires"; bad=1; }
  systemctl show ssh.socket -p After --value | grep -qw "$FW_NAME" || { fail "socket 缺少防火墙 After"; bad=1; }
  [[ $stage != hardened ]] || verify_auth_context || bad=1
  rm -rf "$d"
  ((bad == 0))
}

tx_begin() {
  local stage=$1 pending=$2
  ensure_state_root
  TX_ID="$(date +%Y%m%d-%H%M%S-%N)-$$"; TX_DIR=$TX_ROOT/$TX_ID
  mkdir -m 0700 "$TX_DIR" || die "无法创建事务目录"
  python3 - "$TX_DIR" "${MANAGED_FILES[@]}" <<'PY' || die "文件备份失败"
import hashlib,json,os,shutil,stat,sys
out=sys.argv[1]; paths=sys.argv[2:]; entries=[]; os.mkdir(out+'/files',0o700)
for i,p in enumerate(paths):
 e={'path':p,'exists':os.path.exists(p)}
 if e['exists']:
  if not os.path.isfile(p): raise SystemExit('not a regular file: '+p)
  st=os.stat(p); data=open(p,'rb').read(); name=str(i); shutil.copy2(p,out+'/files/'+name)
  if hashlib.sha256(open(out+'/files/'+name,'rb').read()).digest()!=hashlib.sha256(data).digest(): raise SystemExit('backup digest mismatch')
  e.update(name=name,mode=stat.S_IMODE(st.st_mode),uid=st.st_uid,gid=st.st_gid,sha256=hashlib.sha256(data).hexdigest())
 entries.append(e)
tmp=out+'/manifest.tmp'; json.dump({'files':entries},open(tmp,'w'),indent=2); os.replace(tmp,out+'/manifest.json')
PY
  : > "$TX_DIR/units.conf" || die "无法记录单元状态"
  local u en ac
  for u in ssh.socket ssh.service "$FW_NAME"; do
    en=$(systemctl is-enabled "$u" 2>/dev/null || true); ac=$(systemctl is-active "$u" 2>/dev/null || true)
    printf '%s|%s|%s\n' "$u" "${en:-unknown}" "${ac:-unknown}" >> "$TX_DIR/units.conf" || die "单元状态写入失败"
  done
  if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
    nft -s -y list table inet "$NFT_TABLE" > "$TX_DIR/runtime.nft" || die "内核 nft 备份失败"
  else
    : > "$TX_DIR/NFT_ABSENT" || die "nft 状态记录失败"
  fi
  ss -tlnH > "$TX_DIR/listeners.before" || die "监听状态备份失败"
  cp -- "$0" "$TX_DIR/$SELF" || die "恢复脚本备份失败"
  chmod 0700 "$TX_DIR/$SELF" || die "恢复脚本权限设置失败"
  TX_STARTED=$(date +%s); printf '%s\n' "$TX_STARTED" > "$TX_DIR/started" || die "事务时间写入失败"
  printf '%s\n' "$stage" > "$TX_DIR/stage" || die "事务阶段写入失败"
  printf '%s\n%s\n%s\n' "$STATE_STAGE" "$STATE_TX" "$STATE_CONFIG_SHA" > "$TX_DIR/parent" || die "父状态写入失败"
  cp "$POLICY_FILE" "$TX_DIR/policy.before" 2>/dev/null || [[ ! -e $POLICY_FILE ]] || die "策略备份失败"
  write_policy || die "目标策略写入失败"
  write_state "$pending" "$TX_ID" "" || die "pending 状态写入失败"
  ok "事务 $TX_ID 已备份；尚未修改 SSH 配置"
}
recovery_paths() { RECOVERY_UNIT=/etc/systemd/system/reinforce-my-ssh-$TX_ID.service; RECOVERY_TIMER=/etc/systemd/system/reinforce-my-ssh-$TX_ID.timer; }
arm_recovery() {
  recovery_paths
  cat > "$RECOVERY_UNIT" <<UNIT || return 1
[Unit]
Description=Automatic rollback for reinforce-my-ssh $TX_ID
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/bin/bash $TX_DIR/$SELF --rollback --transaction $TX_ID --auto-recovery --yes

[Install]
WantedBy=multi-user.target
UNIT
  cat > "$RECOVERY_TIMER" <<UNIT || return 1
[Unit]
Description=Deadline for reinforce-my-ssh $TX_ID

[Timer]
OnActiveSec=$RECOVERY_SECONDS

[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload \
    && systemctl enable "reinforce-my-ssh-$TX_ID.service" \
    && systemctl enable --now "reinforce-my-ssh-$TX_ID.timer"
}
cancel_recovery() {
  recovery_paths; local bad=0
  if [[ -e $RECOVERY_TIMER || -e $RECOVERY_UNIT ]]; then
    if [[ -e $RECOVERY_TIMER ]] || [[ $(systemctl show "reinforce-my-ssh-$TX_ID.timer" -p LoadState --value) != not-found ]]; then
      systemctl disable --now "reinforce-my-ssh-$TX_ID.timer" >/dev/null 2>&1 || bad=1
    fi
    if [[ -e $RECOVERY_UNIT ]]; then
      systemctl disable "reinforce-my-ssh-$TX_ID.service" >/dev/null 2>&1 || bad=1
    fi
    # 清理失败时保留文件，迟到任务仍能找到并重试清理。
    ((bad == 0)) || return 1
    rm -f "$RECOVERY_TIMER" "$RECOVERY_UNIT" || return 1
    systemctl daemon-reload || return 1
  fi
}
stop_ssh_entry() {
  [[ $(systemctl show ssh.service -p KillMode --value) == process ]] \
    || { fail "ssh.service KillMode 必须是 process，拒绝可能终止现存会话的操作"; return 1; }
  systemctl stop ssh.service ssh.socket
}
start_ssh_entry() {
  sshd -t && stop_ssh_entry && systemctl start ssh.socket && systemctl start ssh.service
}
restore_unit_state() {
  local wanted=$1 u en ac current load
  while IFS='|' read -r u en ac; do
    [[ $u == "$wanted" ]] || continue
    load=$(systemctl show "$u" -p LoadState --value 2>/dev/null) || return 1
    if [[ $en == not-found && $ac == inactive && $load == not-found ]]; then
      current=$(systemctl is-active "$u" 2>/dev/null || true)
      [[ $current == inactive || $current == unknown ]] && return 0
    fi
    if [[ $ac == active ]]; then systemctl restart "$u" >/dev/null 2>&1 || return 1
    elif [[ $ac == inactive || $ac == failed ]]; then systemctl stop "$u" >/dev/null 2>&1 || return 1
    else fail "拒绝恢复未知 active 状态: $u=$ac"; return 1; fi
    current=$(systemctl is-enabled "$u" 2>/dev/null || true)
    [[ $current == "$en" ]] && return 0
    case $en in
      enabled) systemctl enable "$u" >/dev/null 2>&1 ;;
      enabled-runtime) systemctl disable "$u" >/dev/null 2>&1 && systemctl enable --runtime "$u" >/dev/null 2>&1 ;;
      disabled) systemctl disable "$u" >/dev/null 2>&1 ;;
      masked) systemctl mask "$u" >/dev/null 2>&1 ;;
      not-found) [[ $load == not-found ]] ;;
      static|indirect|generated|transient) return 0 ;;
      *) fail "拒绝恢复未知 enabled 状态: $u=$en"; return 1 ;;
    esac
    return $?
  done < "$TX_DIR/units.conf"
  return 1
}
policy_listeners() {
  python3 - "$1" "$PORT" "$OLD_PORT" <<'PY'
import sys
wanted={sys.argv[2]} | ({sys.argv[3]} if sys.argv[3]!='none' else set())
for line in open(sys.argv[1],encoding='utf-8'):
 f=line.split()
 if len(f)<4: continue
 try:
  if f[3].rsplit(':',1)[1] in wanted: print(f[3])
 except IndexError: pass
PY
}
tx_restore() {
  local requested=$1 auto=$2 expected_stage=$STAGE_ID
  [[ -n $requested ]] || die "没有可回滚事务"
  TX_ID=$requested; TX_DIR=$TX_ROOT/$TX_ID
  [[ -f $TX_DIR/manifest.json && -f $TX_DIR/units.conf && -f $TX_DIR/stage ]] || die "事务备份不完整"
  [[ $(cat "$TX_DIR/stage") == "$expected_stage" ]] || die "$SELF 不能回滚其他阶段的事务"
  if ((auto)) && { [[ $STATE_TX != "$requested" ]] || [[ $STATE_STAGE != candidate-pending && $STATE_STAGE != hardening-pending ]]; }; then
    cancel_recovery || return 1
    ok "事务已提交或已结束，残留恢复单元已清理"; return 0
  fi
  [[ $STATE_TX == "$requested" ]] || die "事务不是当前事务；请按阶段逆序回滚"
  case $STATE_STAGE in
    candidate-pending|candidate-ready|hardening-pending|hardened) ;;
    *) die "请先撤销后续阶段，再回滚配置" ;;
  esac
  local parent_lines=() parent_sha
  mapfile -t parent_lines < "$TX_DIR/parent"
  ((${#parent_lines[@]} == 3)) || { fail "父事务记录不完整"; return 1; }
  PARENT_STAGE=${parent_lines[0]}; PARENT_TX=${parent_lines[1]}; parent_sha=${parent_lines[2]}
  cancel_recovery || warn "恢复定时器清理失败，将继续恢复配置"
  stop_ssh_entry || { fail "无法安全停止 SSH 监听，拒绝继续恢复"; return 1; }
  local bad=0 fw_bad=0
  # 在删除本次创建的单元文件前撤销 enable，避免留下悬空链接。
  if grep -Fqx "$FW_NAME|not-found|inactive" "$TX_DIR/units.conf" \
     && [[ $(systemctl show "$FW_NAME" -p LoadState --value) != not-found ]]; then
    systemctl disable --now "$FW_NAME" || { bad=1; fw_bad=1; }
  fi
  python3 - "$TX_DIR" "${MANAGED_FILES[@]}" <<'PY' || { bad=1; fw_bad=1; }
import hashlib,json,os,shutil,sys
root=sys.argv[1]; allowed=set(sys.argv[2:]); entries=json.load(open(root+'/manifest.json'))['files']
if len(entries)!=len(allowed) or {e['path'] for e in entries}!=allowed: raise SystemExit('manifest path set mismatch')
# 修改任何文件前检查所有备份，避免恢复到一半才发现损坏。
for e in entries:
 if e['exists'] and hashlib.sha256(open(root+'/files/'+e['name'],'rb').read()).hexdigest()!=e['sha256']:
  raise SystemExit('backup digest mismatch: '+e['path'])
for e in entries:
 p=e['path']
 if e['exists']:
  src=root+'/files/'+e['name']; tmp=p+'.reinforce-restore'
  shutil.copyfile(src,tmp); os.chown(tmp,e['uid'],e['gid']); os.chmod(tmp,e['mode']); os.replace(tmp,p)
 else:
  try: os.unlink(p)
  except FileNotFoundError: pass
PY
  if [[ -f $TX_DIR/policy.before ]]; then
    local policy_tmp
    policy_tmp=$(mktemp "$STATE_ROOT/.policy-restore.XXXXXX") \
      && cp -- "$TX_DIR/policy.before" "$policy_tmp" && chmod 0600 "$policy_tmp" && mv -f "$policy_tmp" "$POLICY_FILE" \
      || { bad=1; fw_bad=1; }
  elif [[ $PARENT_STAGE == unconfigured ]]; then
    rm -f "$POLICY_FILE" || { bad=1; fw_bad=1; }
  else
    fail "父阶段策略备份缺失"; bad=1; fw_bad=1
  fi
  systemctl daemon-reload || { bad=1; fw_bad=1; }
  restore_unit_state "$FW_NAME" || { fail "防火墙单元状态恢复失败"; bad=1; fw_bad=1; }
  local restore
  restore=$(mktemp) || { bad=1; fw_bad=1; }
  if [[ -n ${restore:-} ]]; then
    { printf 'add table inet %s\ndelete table inet %s\n' "$NFT_TABLE" "$NFT_TABLE"
      [[ -f $TX_DIR/NFT_ABSENT ]] || cat "$TX_DIR/runtime.nft"
    } > "$restore" && nft -f "$restore" || { bad=1; fw_bad=1; }
    rm -f "$restore"
  fi
  if [[ -f $TX_DIR/NFT_ABSENT ]]; then
    if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then fail "nft 表未撤销"; bad=1; fw_bad=1; fi
  else
    verify_nft_semantics "$TX_DIR/runtime.nft" "$TX_DIR/restored" \
      || { fail "恢复后的 nft 与备份语义不同"; bad=1; fw_bad=1; }
  fi
  sshd -t || { fail "恢复后的 sshd 配置无效"; bad=1; fw_bad=1; }
  if ((fw_bad == 0)); then
    restore_unit_state ssh.socket && restore_unit_state ssh.service || { fail "SSH 单元状态恢复失败"; bad=1; }
  fi
  if ((bad == 0)); then
    local before after
    ss -tlnH > "$TX_DIR/listeners.after" || bad=1
    before=$(policy_listeners "$TX_DIR/listeners.before" | sort -u) || bad=1
    after=$(policy_listeners "$TX_DIR/listeners.after" | sort -u) || bad=1
    [[ $before == "$after" ]] || { fail "恢复后的监听集合与备份不同"; bad=1; }
    if [[ $PARENT_STAGE != unconfigured ]]; then
      [[ $(config_digest) == "$parent_sha" ]] || { fail "恢复后的父摘要不匹配"; bad=1; }
    fi
  fi
  if ((bad)); then
    stop_ssh_entry || fail "停止新 SSH 接入失败，请立即使用独立救援通道"
    fail "回滚未完成；事务保留，可修复原因后重试: $TX_ID"; return 1
  fi
  : > "$TX_DIR/ROLLED_BACK" || { fail "无法写回滚标记"; return 1; }
  if ! write_state "$PARENT_STAGE" "$PARENT_TX" "$parent_sha"; then
    rm -f "$TX_DIR/ROLLED_BACK"
    fail "配置已恢复但父状态写失败；事务仍可重试"; return 1
  fi
  ok "事务 $TX_ID 已完整回滚"
}
tx_commit() {
  local stage=$1 digest
  digest=$(config_digest) || { fail "无法计算配置摘要"; return 1; }
  write_state "$stage" "$TX_ID" "$digest" || { fail "提交状态写失败"; return 1; }
  : > "$TX_DIR/COMMITTED" || { fail "事务提交标记写失败"; return 1; }
  cancel_recovery || { warn "已提交，但恢复定时器清理失败；迟到任务将空操作"; return 1; }
  STATE_CONFIG_SHA=$digest; ok "阶段已提交: $stage"
}
abort_tx() { fail "$1；开始自动回滚"; tx_restore "$TX_ID" 0 || die "自动回滚失败，请使用控制台并指定事务 $TX_ID"; die "变更已撤回"; }

do_apply() {
  [[ $STATE_STAGE == unconfigured ]] || die "stage1 只能从 unconfigured 部署；当前 $STATE_STAGE"
  preflight || die "预检失败，未修改系统"
  confirm_rescue
  local d; d=$(mktemp -d) || die "无法创建临时目录"
  generate_files "$d" candidate || { rm -rf "$d"; die "配置生成失败"; }
  nft -c -f "$d/nft" || { rm -rf "$d"; die "nft 候选语法无效"; }
  tx_begin stage1 candidate-pending
  arm_recovery || abort_tx "自动恢复定时器安装失败"
  mkdir -p /etc/ssh/sshd_config.d /etc/nftables.d /etc/systemd/system/ssh.socket.d || abort_tx "配置目录创建失败"
  put_file "$d/nft" "$NFT_RULES" 0644 && put_file "$d/loader" "$NFT_LOADER" 0755 && put_file "$d/unit" "$FW_UNIT" 0644 \
    || { rm -rf "$d"; abort_tx "防火墙文件安装失败"; }
  systemctl daemon-reload && systemctl restart "$FW_NAME" && verify_nft_semantics "$d/nft" "$d/check" \
    || { rm -rf "$d"; abort_tx "防火墙加载或语义验证失败"; }
  put_file "$d/sshd" "$SSHD_DROPIN" 0644 && put_file "$d/socket" "$SOCKET_OVERRIDE" 0644 \
    || { rm -rf "$d"; abort_tx "SSH 文件安装失败"; }
  sshd -t && systemctl daemon-reload && systemctl enable ssh.socket "$FW_NAME" && start_ssh_entry \
    || { rm -rf "$d"; abort_tx "SSH/socket 生效失败"; }
  verify_runtime candidate || { rm -rf "$d"; abort_tx "候选通道验证失败"; }
  record_confirmation_boundary || { rm -rf "$d"; abort_tx "确认日志边界记录失败"; }
  rm -rf "$d"
  cat <<DONE

候选通道已部署，但阶段尚未完成，自动恢复时限为 ${RECOVERY_SECONDS} 秒。
请保留当前旧会话，从另一台机器执行：
  ssh -p $PORT $USERNAME@<服务器地址>
然后在新会话中执行：
  sudo bash $SRC/$SELF --confirm
事务: $TX_ID
DONE
}
do_confirm() {
  if [[ $STATE_STAGE == candidate-ready ]]; then
    verify_runtime candidate && [[ $(config_digest) == "$STATE_CONFIG_SHA" ]] \
      && { ok "第一阶段已经确认且复验通过"; return 0; }
    die "第一阶段配置已漂移"
  fi
  [[ $STATE_STAGE == candidate-pending ]] || die "只有 candidate-pending 可以确认；当前 $STATE_STAGE"
  TX_ID=$STATE_TX; TX_DIR=$TX_ROOT/$TX_ID
  verify_runtime candidate || die "候选配置或运行时验证失败"
  session_evidence "$TX_DIR/confirmation.json" || die "外部登录/sudo 证据不足"
  tx_commit candidate-ready || die "提交失败；以实际 state 和恢复定时器状态为准"
  printf '\n第一阶段完成。现在可执行 stage2-harden.sh --apply。\n'
}

require_root
load_state
if ((DO_ROLLBACK)); then
  load_policy
  lock_all
  load_state
  load_policy
  ((AUTO_RECOVERY)) || { [[ $STATE_STAGE != verified && $STATE_STAGE != reboot-pending ]] || die "请先执行 stage3-reboot-check.sh --rollback"; }
  tx_restore "${REQUEST_TX:-$STATE_TX}" "$AUTO_RECOVERY"
  exit $?
fi
load_policy
normalize_params
if ((APPLY || CONFIRM)); then lock_all; load_state; load_policy; normalize_params; fi
case $STATE_STAGE in unconfigured|candidate-pending|candidate-ready) ;; *) die "当前阶段 $STATE_STAGE 不允许运行 stage1" ;; esac
if ((CONFIRM)); then do_confirm; exit $?; fi
if [[ $STATE_STAGE == candidate-pending ]]; then
  ((APPLY)) || die "候选通道待外部确认；请在新会话执行 --confirm"
  TX_ID=$STATE_TX; TX_DIR=$TX_ROOT/$TX_ID
  verify_runtime candidate && ok "候选配置已部署，无需重复修改；请执行 --confirm"
  exit $?
fi
if [[ $STATE_STAGE == candidate-ready ]]; then
  verify_runtime candidate || die "第一阶段配置已漂移"
  [[ $(config_digest) == "$STATE_CONFIG_SHA" ]] || die "第一阶段配置摘要已变化"
  ok "第一阶段已经完成且复验通过"; exit 0
fi
if ((APPLY)); then
  do_apply
else
  warn "当前为部署预检，不是已有服务器的安全审计；未纳管不等于未加固。独立审计：sudo bash $SRC/stage0-audit.sh --help"
  preflight || { fail "部署前提检查未通过；安全效果未由本命令判定，未修改系统"; exit 2; }
  ok "部署前提检查通过；尚未部署、未证明整机安全；使用 --apply 部署候选通道"
fi
