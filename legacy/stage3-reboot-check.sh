#!/usr/bin/env bash
# stage3-reboot-check.sh —— 纯重启验证与基线记录
#
# 默认执行受管状态的完整只读复验；已有旧方案由 stage0-audit.sh 独立审计。
# --apply 只记录重启前状态，不重启系统；
# --verify 只在跨过重启且配置未漂移时记录验证结果；--rollback 只回退验证状态。
# 本脚本绝不 enable/disable 单元，也不修改 SSH、nft 或 socket 配置。

set -uo pipefail
umask 077

STATE_DIR=/var/lib/reinforce-my-ssh
POLICY_FILE=$STATE_DIR/policy.conf
STATE_FILE=$STATE_DIR/state.conf
BASELINE_ROOT=$STATE_DIR/baselines
SSHD_DROPIN=/etc/ssh/sshd_config.d/00-reinforce-my-ssh.conf
NFT_RULES=/etc/nftables.d/reinforce-my-ssh.nft
NFT_LOADER=/usr/local/sbin/reinforce-my-ssh-firewall
FW_UNIT=/etc/systemd/system/reinforce-my-ssh-firewall.service
SOCKET_DROPIN=/etc/systemd/system/ssh.socket.d/00-reinforce-my-ssh.conf
FW_UNIT_NAME=reinforce-my-ssh-firewall.service
NFT_TABLE=sshguard
MANAGED_FILES=("$SSHD_DROPIN" "$NFT_RULES" "$NFT_LOADER" "$FW_UNIT" "$SOCKET_DROPIN")
CORE_MANAGED_FILES=("${MANAGED_FILES[@]}")
SSHD_CONFIG=/etc/ssh/sshd_config
SOCKET_DIR=/etc/systemd/system/ssh.socket.d
UFW_DIR=/etc/ufw
UFW_DEFAULT=/etc/default/ufw
STATE_ROOT=$STATE_DIR
migration_paths() {
  python3 - "$1" "$SSHD_CONFIG" "$SOCKET_DIR" "$UFW_DIR" "$UFW_DEFAULT" "${CORE_MANAGED_FILES[@]}" <<'PY'
import json,os,sys
plan=json.load(open(sys.argv[1])); main,socket,ufw,default=sys.argv[2:6]; core=set(sys.argv[6:])
roots=[os.path.dirname(main),socket,ufw]
if plan.get('schema')!=1 or not isinstance(plan.get('files'),list) or len(plan['files'])>128: raise SystemExit('迁移清单格式错误')
paths=[]
for item in plan['files']:
 p=item['path']
 if not isinstance(p,str) or '\n' in p or os.path.normpath(p)!=p or not os.path.isabs(p): raise SystemExit('非法迁移路径')
 if p not in {default,os.path.join(os.path.dirname(socket),'ssh.socket')} and not any(p.startswith(root.rstrip('/')+'/') for root in roots): raise SystemExit('迁移路径超出 SSH/socket/UFW 范围: '+p)
 if p in paths or p in core: raise SystemExit('迁移路径重复或与核心文件重叠')
 paths.append(p)
print('\n'.join(sorted(paths)))
PY
}
load_migration() {
  local plan=${1:-$STATE_ROOT/migration.json} paths
  [[ -e $plan || -L $plan ]] || return 0
  [[ -f $plan && ! -L $plan ]] || return 1
  paths=$(migration_paths "$plan") || return 1
  local extras=(); [[ -z $paths ]] || mapfile -t extras <<< "$paths"
  MANAGED_FILES=("${CORE_MANAGED_FILES[@]}" "${extras[@]}" "$STATE_ROOT/migration.json")
}

if [[ -t 1 ]]; then
  C_RST=$'\033[0m'; C_B=$'\033[1m'; C_DIM=$'\033[2m'
  C_OK=$'\033[32m'; C_FAIL=$'\033[31m'; C_WARN=$'\033[33m'
else
  C_RST=; C_B=; C_DIM=; C_OK=; C_FAIL=; C_WARN=
fi
hdr()  { printf '\n%s══ %s ══%s\n' "$C_B" "$*" "$C_RST"; }
sub()  { printf '\n%s── %s ──%s\n' "$C_DIM" "$*" "$C_RST"; }
ok()   { printf '   %s[ OK ]%s %s\n' "$C_OK" "$C_RST" "$*"; }
fail() { printf '   %s[FAIL]%s %s\n' "$C_FAIL" "$C_RST" "$*"; }
inf()  { printf '          %s%s%s\n' "$C_DIM" "$*" "$C_RST"; }
die()  { printf '\n%sfatal:%s %s\n' "$C_FAIL" "$C_RST" "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
用法: stage3-reboot-check.sh [--port <n>] [--user <name>] [--old-port <n>|none] [--conf <file>] [模式]

模式（互斥）:
  默认          完整只读检查，不写状态或基线
  --apply       在 hardened 或 verified 状态启动一次重启验证
  --verify      在 reboot-pending 状态验证一次真实重启
  --rollback    仅将 reboot-pending/verified 回退为 hardened，保留基线

其他选项:
  --guide       按当前状态继续整个流程，缺项时给出操作指令
  --yes         跳过 --apply 的交互确认
  -h, --help    显示本帮助

参数只用于核对权威策略，不会覆盖 /var/lib/reinforce-my-ssh/policy.conf。
脚本不会重启、enable/disable 单元或修改任何 SSH/nft/socket 配置。
默认检查需要新版策略和状态；未纳管不等于未加固，请用 stage0-audit.sh。
普通用户 SSH 登录后 sudo 执行即可，不需要开放 root SSH 登录。
USAGE
}

REPLAY_ARGS=("$@")
GUIDE_ARGS=(); GUIDE_REQUESTED=0
for guide_arg in "$@"; do
  if [[ $guide_arg == --guide ]]; then GUIDE_REQUESTED=1; else GUIDE_ARGS+=("$guide_arg"); fi
done
if ((GUIDE_REQUESTED)); then
  guide_dir=$(cd "$(dirname "$0")" && pwd)
  [[ -f $guide_dir/stage0-audit.sh ]] || die "缺少同目录 stage0-audit.sh，请同步四个脚本"
  exec bash "$guide_dir/stage0-audit.sh" --guide "${GUIDE_ARGS[@]}"
fi

CLI_PORT=""; CLI_USERNAME=""; CLI_OLD_PORT=""; CONF=""
PORT_SET=0; USER_SET=0; OLD_PORT_SET=0
APPLY=0; VERIFY_MODE=0; DO_ROLLBACK=0; ASSUME_YES=0
need_val() {
  (( $2 >= 2 )) && return 0
  printf '参数 %s 缺少取值\n' "$1" >&2
  exit 2
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)     need_val "$1" $#; CLI_PORT="$2"; PORT_SET=1; shift 2 ;;
    --user)     need_val "$1" $#; CLI_USERNAME="$2"; USER_SET=1; shift 2 ;;
    --old-port) need_val "$1" $#; CLI_OLD_PORT="$2"; OLD_PORT_SET=1; shift 2 ;;
    --conf)     need_val "$1" $#; CONF="$2"; shift 2 ;;
    --apply)    APPLY=1; shift ;;
    --verify)   VERIFY_MODE=1; shift ;;
    --rollback) DO_ROLLBACK=1; shift ;;
    --yes)      ASSUME_YES=1; shift ;;
    -h|--help)  usage; exit 0 ;;
    *)          printf '未知参数: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done
(( APPLY + VERIFY_MODE + DO_ROLLBACK <= 1 )) || die "--apply、--verify、--rollback 互斥"
(( ! ASSUME_YES || APPLY )) || die "--yes 只能与 --apply 一起使用"
if (( EUID != 0 )); then
  fail "权限不足，未完成复验；普通用户 SSH 登录后 sudo bash 执行即可"
  printf '请执行：'; printf '%q ' sudo bash "$0" "${REPLAY_ARGS[@]}"; printf '\n'
  exit 2
fi
if [[ ! -f $POLICY_FILE || ! -r $POLICY_FILE || ! -f $STATE_FILE || ! -r $STATE_FILE ]]; then
  fail "新版策略/状态缺失或不可读，stage3 未执行重启复验；这不是服务器安全不合格结论"
  printf '从现状进入部署向导：sudo bash %q --guide\n' "$(dirname "$0")/stage0-audit.sh"
  exit 2
fi
if (( APPLY || VERIFY_MODE || DO_ROLLBACK )); then
  exec 9>/run/lock/reinforce-my-ssh.lock || die "无法打开事务锁"
  flock -x 9 || die "无法取得事务锁"
fi

declare -A POLICY=() CONF_POLICY=() STATE=()
POLICY_ALLOWS=() CONF_ALLOWS=() STATE_ORDER=()

load_policy() {  # load_policy <文件> <关联数组名> <ALLOW 数组名>
  local file="$1" line key value
  local -n out="$2"
  local -n allows="$3"
  [[ -r "$file" && -f "$file" ]] || die "策略文件不可读: $file"
  [[ ! -s "$file" || -z $(tail -c 1 "$file") ]] || die "策略最后一行必须以 LF 结束: $file"
  while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*$ || "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" =~ ^([A-Z][A-Z0-9_]*)=(.*)$ ]] || die "策略格式错误: $file: $line"
    key=${BASH_REMATCH[1]}; value=${BASH_REMATCH[2]}
    case "$key" in
      ALLOW)
        [[ -n "$value" ]] || die "ALLOW 不能为空: $file"
        allows+=("$value")
        ;;
      PORT|USER|OLD_PORT|RECOVERY_SECONDS|RESCUE_CONFIRMED)
        [[ -z "${out[$key]+x}" ]] || die "策略键重复: $file: $key"
        [[ -n "$value" ]] || die "$key 不能为空: $file"
        out[$key]="$value"
        ;;
      *) die "未知策略键: $file: $key" ;;
    esac
  done < "$file"
  local k
  for k in PORT USER OLD_PORT RECOVERY_SECONDS RESCUE_CONFIRMED; do
    [[ -n "${out[$k]:-}" ]] || die "策略缺少 $k: $file"
  done
  (( ${#allows[@]} > 0 )) || die "策略至少需要一个 ALLOW: $file"
}

is_port() {
  [[ "$1" =~ ^[0-9]{1,5}$ ]] || return 1
  local n=$((10#$1))
  (( n >= 1 && n <= 65535 ))
}
validate_policy() {  # validate_policy <关联数组名> <ALLOW 数组名>
  local -n p="$1"
  local -n a="$2"
  is_port "${p[PORT]}" || die "PORT 非法: ${p[PORT]}"
  [[ "${p[OLD_PORT]}" == none ]] || is_port "${p[OLD_PORT]}" \
    || die "OLD_PORT 非法: ${p[OLD_PORT]}"
  [[ "${p[OLD_PORT]}" == none || "${p[OLD_PORT]}" != "${p[PORT]}" ]] \
    || die "OLD_PORT 不能与 PORT 相同"
  [[ "${p[USER]}" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]] \
    || die "USER 非法: ${p[USER]}"
  [[ "${p[USER]}" != root ]] || die "USER 必须是非 root 管理账户"
  id "${p[USER]}" >/dev/null 2>&1 || die "管理账户不存在: ${p[USER]}"
  [[ $(id -u "${p[USER]}") != 0 ]] || die "禁止使用 UID 0 管理账户"
  [[ "${p[RECOVERY_SECONDS]}" =~ ^[0-9]+$ ]] \
    && ((10#${p[RECOVERY_SECONDS]} >= 60 && 10#${p[RECOVERY_SECONDS]} <= 86400)) \
    || die "RECOVERY_SECONDS 应为 60–86400"
  [[ "${p[RESCUE_CONFIRMED]}" == yes || "${p[RESCUE_CONFIRMED]}" == no ]] \
    || die "RESCUE_CONFIRMED 只能是 yes/no"
  local seen=$'\n' item
  for item in "${a[@]}"; do
    python3 -c 'import ipaddress,sys; n=ipaddress.ip_network(sys.argv[1],strict=True); print(n)' "$item" >/dev/null 2>&1 \
      || die "ALLOW 非法或带主机位: $item"
    [[ "$seen" != *$'\n'"$item"$'\n'* ]] || die "ALLOW 重复: $item"
    seen+="$item"$'\n'
  done
}

if (( ! DO_ROLLBACK )); then
  load_migration "$STATE_ROOT/migration.json" || die "迁移路径记录无效"
fi
load_policy "$POLICY_FILE" POLICY POLICY_ALLOWS
validate_policy POLICY POLICY_ALLOWS
if (( PORT_SET )) && [[ "$CLI_PORT" != "${POLICY[PORT]}" ]]; then
  die "--port 与权威策略不一致"
fi
if (( USER_SET )) && [[ "$CLI_USERNAME" != "${POLICY[USER]}" ]]; then
  die "--user 与权威策略不一致"
fi
if (( OLD_PORT_SET )) && [[ "$CLI_OLD_PORT" != "${POLICY[OLD_PORT]}" ]]; then
  die "--old-port 与权威策略不一致"
fi
PORT=${POLICY[PORT]}; USERNAME=${POLICY[USER]}; OLD_PORT=${POLICY[OLD_PORT]}
if [[ -n "$CONF" ]]; then
  load_policy "$CONF" CONF_POLICY CONF_ALLOWS
  validate_policy CONF_POLICY CONF_ALLOWS
  policy_key=""
  for policy_key in PORT USER OLD_PORT RECOVERY_SECONDS RESCUE_CONFIRMED; do
    [[ "${CONF_POLICY[$policy_key]}" == "${POLICY[$policy_key]}" ]] \
      || die "--conf 的 $policy_key 与权威策略不一致"
  done
  [[ "${CONF_ALLOWS[*]}" == "${POLICY_ALLOWS[*]}" ]] \
    || die "--conf 的 ALLOW 列表与权威策略不一致"
fi

load_state() {
  [[ -f "$STATE_FILE" && -r "$STATE_FILE" ]] || die "状态文件不可读: $STATE_FILE"
  local line key value
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*$ || "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" =~ ^([A-Z][A-Z0-9_]*)=(.*)$ ]] || die "状态格式错误: $line"
    key=${BASH_REMATCH[1]}; value=${BASH_REMATCH[2]}
    [[ -z "${STATE[$key]+x}" ]] || die "状态键重复: $key"
    STATE[$key]="$value"; STATE_ORDER+=("$key")
  done < "$STATE_FILE"
  for key in STAGE TX CONFIG_SHA PENDING_BOOT VERIFIED_BOOT; do
    [[ -n "${STATE[$key]+x}" ]] || die "状态缺少 $key"
  done
  [[ -n "${STATE[TX]}" ]] || die "TX 不能为空"
  [[ "${STATE[CONFIG_SHA]}" =~ ^[0-9a-f]{64}$ ]] || die "CONFIG_SHA 格式错误"
}
set_state() {
  local key="$1" value="$2"
  [[ -n "${STATE[$key]+x}" ]] || STATE_ORDER+=("$key")
  STATE[$key]="$value"
}
write_state() {
  local tmp key
  tmp=$(mktemp "$STATE_DIR/.state.conf.XXXXXX") || die "无法创建状态临时文件"
  if ! {
    for key in "${STATE_ORDER[@]}"; do
      printf '%s=%s\n' "$key" "${STATE[$key]}"
    done
  } > "$tmp"; then
    rm -f -- "$tmp"
    die "写状态失败: $STATE_FILE"
  fi
  if ! mv -f -- "$tmp" "$STATE_FILE"; then
    rm -f -- "$tmp"
    die "无法原子更新状态: $STATE_FILE"
  fi
}

load_state
STAGE=${STATE[STAGE]}
case "$STAGE" in
  candidate-pending|candidate-ready|hardening-pending)
    die "当前 STAGE=$STAGE，尚未进入第三阶段"
    ;;
  hardened|reboot-pending|verified) ;;
  *) die "未知 STAGE: $STAGE" ;;
esac

current_boot_id() {
  local id
  [[ -r /proc/sys/kernel/random/boot_id ]] || return 1
  IFS= read -r id < /proc/sys/kernel/random/boot_id || return 1
  [[ "$id" =~ ^[0-9A-Fa-f-]{36}$ ]] || return 1
  printf '%s\n' "$id"
}
compute_config_sha() {
  { printf 'POLICY\n'; cat "$POLICY_FILE" || return 1
    local f
    for f in "${MANAGED_FILES[@]}"; do
      [[ -f "$f" && -r "$f" ]] || return 1
      printf 'FILE %s\n' "$f"; cat "$f" || return 1
    done
  } | sha256sum | awk '{print $1}'
}

if (( ! DO_ROLLBACK )); then
  CURRENT_SHA=$(compute_config_sha) || die "无法采集受管与迁移文件的配置摘要"
  [[ "$CURRENT_SHA" == "${STATE[CONFIG_SHA]}" ]] \
    || die "配置摘要已变化（state=${STATE[CONFIG_SHA]} current=$CURRENT_SHA）；verified/pending 已失效，请先由前序阶段重新登记配置"
fi
CURRENT_BOOT=$(current_boot_id) || die "无法读取有效 boot_id"

WORK=$(mktemp -d) || die "无法创建临时采集目录"
trap 'rm -rf -- "$WORK"' EXIT
CHECK_FAILED=0
c_ok()   { ok "$1"; }
c_fail() { fail "$1"; CHECK_FAILED=$((CHECK_FAILED + 1)); }
record_failure() { c_fail "$1"; }

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

gen_expected_nft() {
  local a fam
  {
    printf 'table inet %s {\n' "$NFT_TABLE"
    printf ' chain input {\n'
    printf '  type filter hook input priority -100; policy accept;\n'
    printf '  iif "lo" ip saddr 127.0.0.1 tcp dport { %s } counter accept\n' "$PORT"
    printf '  iif "lo" ip6 saddr ::1 tcp dport { %s } counter accept\n' "$PORT"
    for a in "${POLICY_ALLOWS[@]}"; do
      if [[ "$a" == *:* ]]; then fam=ip6; else fam=ip; fi
      printf '  %s saddr %s tcp dport { %s } counter accept\n' "$fam" "$a" "$PORT"
    done
    printf '  tcp dport { %s } ct state established,related counter accept\n' "$PORT"
    printf '  tcp dport { %s } counter drop\n' "$PORT"
    printf ' }\n}\n'
  } > "$WORK/nft-expected-raw.txt"
}

unit_list_has() {  # unit_list_has <文件> <属性> <单元>
  awk -v prop="$2" -v unit="$3" '
    index($0, prop "=") == 1 {
      line = substr($0, length(prop) + 2)
      n = split(line, items, /[[:space:]]+/)
      for (i = 1; i <= n; i++) if (items[i] == unit) found = 1
    }
    END { exit(found ? 0 : 1) }
  ' "$1"
}

sshd_value() {
  awk -v key="$2" '$1 == key {print substr($0, length(key) + 2); exit}' "$1"
}

find_ssh_client() {
  local value pid parent
  if [[ -n "${SSH_CLIENT:-}" ]]; then
    value=${SSH_CLIENT%% *}
    [[ "$value" =~ ^[0-9A-Fa-f:.]+$ ]] || return 1
    printf '%s\n' "$value"
    return 0
  fi
  pid=$PPID
  while [[ "$pid" =~ ^[0-9]+$ ]] && (( pid > 1 )); do
    if [[ -r "/proc/$pid/environ" ]]; then
      value=$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | awk -F= '$1 == "SSH_CLIENT" {print $2; exit}')
      if [[ "$value" =~ ^[0-9A-Fa-f:.]+$ ]]; then printf '%s\n' "$value"; return 0; fi
    fi
    [[ -r "/proc/$pid/stat" ]] || return 1
    parent=$(awk '/^PPid:/{print $2}' "/proc/$pid/status") || return 1
    [[ "$parent" =~ ^[0-9]+$ ]] || return 1
    pid=$parent
  done
  return 1
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
    errors.append(f'{path}:{no}: 仅支持单个绝对 Include pattern'); continue
   for pat in glob.glob(args): visit(pat,depth+1)
  elif key in controlled and path!=managed:
   errors.append(f'{path}:{no}: 非受管指令 {m.group(1)} 会影响目标策略')
visit('/etc/ssh/sshd_config')
print('\n'.join(errors))
sys.exit(bool(errors))
PY
}
run_checks() {
  sub "完整只读验证"
  scan_sshd_config || c_fail "sshd 配置含非受管 Match/端口/认证漂移"
  local output file key value idx addr laddr user
  local -a addrs=() ports=()

  if sshd -T > "$WORK/sshd-T.txt" 2> "$WORK/sshd-T.err"; then
    mapfile -t ports < <(awk '$1 == "port" {print $2}' "$WORK/sshd-T.txt")
    if (( ${#ports[@]} == 1 )) && [[ "${ports[0]}" == "$PORT" ]]; then
      c_ok "sshd -T 端口集合精确等于 {$PORT}"
    else
      c_fail "sshd -T 端口集合为 {${ports[*]:-空}}，期望 {$PORT}"
    fi
  else
    record_failure "sshd -T 采集失败；不以默认值替代"
  fi

  if systemctl show ssh.socket -p Listen --value > "$WORK/socket-listen.txt" 2> "$WORK/socket-listen.err"; then
    mapfile -t addrs < <(awk '$2 == "(Stream)" {print $1}' "$WORK/socket-listen.txt" | sort)
    if (( ${#addrs[@]} == 2 )) \
       && [[ "${addrs[0]}" == "0.0.0.0:$PORT" && "${addrs[1]}" == "[::]:$PORT" ]]; then
      c_ok "ssh.socket 有效 ListenStream 精确等于 IPv4/IPv6 的 {$PORT}"
    else
      c_fail "ssh.socket ListenStream 不匹配：${addrs[*]:-空}"
    fi
  else
    record_failure "无法读取 ssh.socket 有效 ListenStream"
  fi

  if ss -tlnH > "$WORK/ss-listen.txt" 2> "$WORK/ss-listen.err"; then
    mapfile -t addrs < <(awk -v port=":$PORT" 'substr($4, length($4)-length(port)+1) == port {print $4}' "$WORK/ss-listen.txt" | sort)
    if (( ${#addrs[@]} == 2 )) \
       && [[ "${addrs[0]}" == "0.0.0.0:$PORT" && "${addrs[1]}" == "[::]:$PORT" ]]; then
      c_ok "ss 实际监听精确等于 IPv4/IPv6 的 {$PORT}"
    else
      c_fail "ss 在端口 $PORT 上的监听地址不匹配：${addrs[*]:-空}"
    fi
    if [[ "$OLD_PORT" != none ]] \
       && awk -v port=":$OLD_PORT" 'substr($4, length($4)-length(port)+1) == port {found=1} END{exit !found}' "$WORK/ss-listen.txt"; then
      c_fail "旧端口 $OLD_PORT 仍有实际监听"
    elif [[ "$OLD_PORT" != none ]]; then
      c_ok "旧端口 $OLD_PORT 无实际监听"
    fi
  else
    record_failure "ss 实际监听采集失败"
  fi

  if [[ $(systemctl show ssh.socket -p BindIPv6Only --value) == ipv6-only ]]; then
    c_ok "ssh.socket 明确使用 IPv6-only 绑定"
  else
    c_fail "ssh.socket 缺少 BindIPv6Only=ipv6-only"
  fi
  local unit prop
  : > "$WORK/units.txt" || record_failure "无法记录单元状态"
  for unit in ssh.service ssh.socket "$FW_UNIT_NAME"; do
    if output=$(systemctl is-active "$unit" 2>&1) && [[ "$output" == active ]]; then
      c_ok "$unit active"
    else
      c_fail "$unit 非 active：${output:-无输出}"
    fi
    printf '%s is-active=%s\n' "$unit" "${output:-采集失败}" >> "$WORK/units.txt" \
      || record_failure "单元基线写入失败"
    [[ $unit != ssh.service ]] || continue
    if output=$(systemctl is-enabled "$unit" 2>&1) && [[ "$output" == enabled ]]; then
      c_ok "$unit enabled"
    else
      c_fail "$unit 非持久 enabled：${output:-无输出}"
    fi
    printf '%s is-enabled=%s\n' "$unit" "${output:-采集失败}" >> "$WORK/units.txt" \
      || record_failure "单元基线写入失败"
  done
  for prop in Requires After; do
    file="$WORK/socket-$prop.txt"
    if systemctl show ssh.socket -p "$prop" > "$file" 2> "$file.err"; then
      if unit_list_has "$file" "$prop" "$FW_UNIT_NAME"; then
        c_ok "ssh.socket 有效 $prop 包含 $FW_UNIT_NAME"
      else
        c_fail "ssh.socket 有效 $prop 缺少 $FW_UNIT_NAME"
      fi
    else
      record_failure "无法读取 ssh.socket 有效 $prop"
    fi
  done

  if timeout 5 bash -c 'exec 3<>/dev/tcp/$1/$2' _ 127.0.0.1 "$PORT" 2> "$WORK/loopback-v4.err"; then
    c_ok "IPv4 回环 127.0.0.1:$PORT 可连接"
  else
    c_fail "IPv4 回环 127.0.0.1:$PORT 连接失败"
  fi
  if timeout 5 bash -c 'exec 3<>/dev/tcp/$1/$2' _ ::1 "$PORT" 2> "$WORK/loopback-v6.err"; then
    c_ok "IPv6 回环 [::1]:$PORT 可连接"
  else
    c_fail "IPv6 回环 [::1]:$PORT 连接失败"
  fi

  : > "$WORK/sshd-contexts.txt" || record_failure "无法记录上下文清单"
  idx=0
  local context_bad
  for user in root "$USERNAME"; do
    for addr in 127.0.0.1 ::1; do
      idx=$((idx + 1)); laddr=$addr; context_bad=0
      file="$WORK/sshd-C-$idx.txt"
      printf 'user=%s host=reinforce-my-ssh.invalid addr=%s laddr=%s lport=%s file=%s\n' \
        "$user" "$addr" "$laddr" "$PORT" "$file" >> "$WORK/sshd-contexts.txt" \
        || record_failure "上下文基线写入失败"
      if ! sshd -T -C "user=$user,host=reinforce-my-ssh.invalid,addr=$addr,laddr=$laddr,lport=$PORT" \
           > "$file" 2> "$file.err"; then
        c_fail "sshd 完整上下文解析失败：user=$user addr=$addr；禁止回退"
        continue
      fi
      for key in permitrootlogin passwordauthentication kbdinteractiveauthentication authenticationmethods pubkeyauthentication; do
        value=$(sshd_value "$file" "$key")
        case "$key:$value" in
          permitrootlogin:no|passwordauthentication:no|kbdinteractiveauthentication:no|authenticationmethods:publickey|pubkeyauthentication:yes) ;;
          *) c_fail "上下文 user=$user addr=$addr 的 $key=${value:-缺失} 不符合目标"; context_bad=1 ;;
        esac
      done
      (( context_bad )) || c_ok "sshd 完整上下文已验证：user=$user addr=$addr laddr=$laddr lport=$PORT"
    done
  done
  if addr=$(find_ssh_client); then
    if [[ "$addr" != 127.0.0.1 && "$addr" != ::1 ]]; then
      for user in root "$USERNAME"; do
        idx=$((idx + 1)); laddr=0.0.0.0; context_bad=0
        [[ "$addr" == *:* ]] && laddr=::
        file="$WORK/sshd-C-$idx.txt"
        printf 'user=%s host=reinforce-my-ssh.invalid addr=%s laddr=%s lport=%s file=%s\n' \
          "$user" "$addr" "$laddr" "$PORT" "$file" >> "$WORK/sshd-contexts.txt" \
          || record_failure "远程上下文基线写入失败"
        if ! sshd -T -C "user=$user,host=reinforce-my-ssh.invalid,addr=$addr,laddr=$laddr,lport=$PORT" \
             > "$file" 2> "$file.err"; then
          c_fail "sshd 当前来源完整上下文解析失败：user=$user addr=$addr；禁止回退"
          continue
        fi
        for key in permitrootlogin passwordauthentication kbdinteractiveauthentication authenticationmethods pubkeyauthentication; do
          value=$(sshd_value "$file" "$key")
          case "$key:$value" in
            permitrootlogin:no|passwordauthentication:no|kbdinteractiveauthentication:no|authenticationmethods:publickey|pubkeyauthentication:yes) ;;
            *) c_fail "当前来源 user=$user addr=$addr 的 $key=${value:-缺失} 不符合目标"; context_bad=1 ;;
          esac
        done
        (( context_bad )) || c_ok "sshd 当前来源完整上下文已验证：user=$user addr=$addr"
      done
    fi
  else
    inf "未发现当前 SSH_CLIENT；已强制验证 IPv4/IPv6 回环完整上下文"
  fi

  if [[ -r "$NFT_RULES" ]]; then
    if ! cp -- "$NFT_RULES" "$WORK/nft-disk-raw.txt"; then
      record_failure "无法采集磁盘 nft 规则"
    fi
  else
    record_failure "磁盘 nft 规则不可读: $NFT_RULES"
  fi
  if ! nft -s -y list table inet "$NFT_TABLE" > "$WORK/nft-runtime-raw.txt" 2> "$WORK/nft-runtime.err"; then
    record_failure "nft -s -n -y list table inet $NFT_TABLE 采集失败"
  fi
  gen_expected_nft || record_failure "无法生成期望 nft 规则"
  local kind
  for kind in expected disk runtime; do
    if [[ -f "$WORK/nft-$kind-raw.txt" ]]; then
      normalize_nft "$WORK/nft-$kind-raw.txt" "$WORK/nft-$kind-normalized.txt" \
        || record_failure "nft $kind 规范化失败"
    fi
  done
  if [[ -f "$WORK/nft-disk-normalized.txt" && -f "$WORK/nft-runtime-normalized.txt" ]]; then
    if cmp -s "$WORK/nft-disk-normalized.txt" "$WORK/nft-runtime-normalized.txt"; then
      c_ok "nft 内核规则与磁盘受管规则语义精确一致（无额外规则）"
    else
      c_fail "nft 内核规则与磁盘受管规则不一致"
    fi
  fi
  if [[ -f "$WORK/nft-expected-normalized.txt" && -f "$WORK/nft-disk-normalized.txt" ]]; then
    if cmp -s "$WORK/nft-expected-normalized.txt" "$WORK/nft-disk-normalized.txt"; then
      c_ok "nft 规则精确符合 ALLOW 策略、端口 {$PORT}、回环与末尾 drop；无额外规则"
    else
      c_fail "nft 规则偏离策略期望（含额外/缺失/乱序规则）"
    fi
  fi

  printf 'CONFIG_SHA=%s\nBOOT_ID=%s\nTX=%s\n' "$CURRENT_SHA" "$CURRENT_BOOT" "${STATE[TX]}" \
    > "$WORK/facts.txt" || record_failure "关键事实基线写入失败"
  cp -- "$POLICY_FILE" "$WORK/policy.conf" || record_failure "策略基线采集失败"
  cp -- "$STATE_FILE" "$WORK/state.conf" || record_failure "状态基线采集失败"
  printf '%s\n' "${MANAGED_FILES[@]}" > "$WORK/managed-files.txt" \
    || record_failure "受管文件清单写入失败"
  for file in "${MANAGED_FILES[@]}"; do
    sha256sum -- "$file" >> "$WORK/managed-sha256.txt" \
      || record_failure "受管文件摘要采集失败: $file"
  done
  return "$CHECK_FAILED"
}

save_baseline() {  # save_baseline <pre|post>
  local kind="$1" destination
  destination=$(mktemp -d "$BASELINE_ROOT/$kind.XXXXXXXX") \
    || die "无法创建 $kind 基线目录；请先确保 $BASELINE_ROOT 存在"
  if ! cp -a -- "$WORK/." "$destination/"; then
    die "$kind 基线复制失败: $destination"
  fi
  if ! {
    printf 'KIND=%s\n' "$kind"
    printf 'CREATED_AT=%s\n' "$(date -Is)"
    printf 'BOOT_ID=%s\n' "$CURRENT_BOOT"
    printf 'CONFIG_SHA=%s\n' "$CURRENT_SHA"
    printf 'TX=%s\n' "${STATE[TX]}"
    printf 'RESULT=complete\n'
  } > "$destination/META"; then
    die "$kind 基线元数据写入失败: $destination"
  fi
  printf '%s\n' "$destination"
}

do_apply() {
  [[ "$STAGE" == hardened || "$STAGE" == verified ]] \
    || die "--apply 仅允许 hardened 或 verified，当前为 $STAGE"
  run_checks || die "完整检查未通过；未启动重启验证，也未写状态"
  if (( ! ASSUME_YES )); then
    printf '\n%s将只写入重启前基线和 reboot-pending 状态，不重启、不改配置。输入 yes 继续：%s ' "$C_WARN" "$C_RST"
    read -r answer
    [[ "$answer" == yes ]] || die "已取消"
  fi
  mkdir -p -- "$BASELINE_ROOT" || die "无法创建基线目录: $BASELINE_ROOT"
  local baseline
  baseline=$(save_baseline pre) || die "重启前基线失败"
  [[ -n "$baseline" && -f "$baseline/META" ]] || die "重启前基线不完整"
  set_state STAGE reboot-pending
  set_state PENDING_BOOT "$CURRENT_BOOT"
  set_state VERIFIED_BOOT ""
  set_state PRE_BASELINE "$baseline"
  set_state POST_BASELINE ""
  write_state
  ok "重启前基线: $baseline"
  ok "PENDING_BOOT=$CURRENT_BOOT，STAGE=reboot-pending"
  inf "请确认独立于 sshd 的 VNC/串口或 Agent 救援通道后自行重启；回来后运行 $0 --verify"
}

do_verify() {
  [[ "$STAGE" == reboot-pending ]] || die "--verify 要求 reboot-pending，当前为 $STAGE"
  [[ "${STATE[PENDING_BOOT]}" =~ ^[0-9A-Fa-f-]{36}$ ]] || die "PENDING_BOOT 缺失或格式无效"
  [[ "${STATE[PENDING_BOOT]}" != "$CURRENT_BOOT" ]] \
    || die "boot_id 未变化；同一次开机不能作为重启验证"
  ok "boot_id 已从 ${STATE[PENDING_BOOT]} 变为 $CURRENT_BOOT"
  run_checks || die "重启后完整验证未通过；保留 reboot-pending，不写 post 基线或 verified"
  mkdir -p -- "$BASELINE_ROOT" || die "无法创建基线目录: $BASELINE_ROOT"
  local baseline
  baseline=$(save_baseline post) || die "重启后基线失败"
  [[ -n "$baseline" && -f "$baseline/META" ]] || die "重启后基线不完整"
  set_state STAGE verified
  set_state VERIFIED_BOOT "$CURRENT_BOOT"
  set_state POST_BASELINE "$baseline"
  write_state
  ok "重启后基线: $baseline"
  ok "VERIFIED_BOOT=$CURRENT_BOOT，STAGE=verified"
}

do_rollback() {
  [[ "$STAGE" == reboot-pending || "$STAGE" == verified ]] \
    || die "--rollback 仅允许 reboot-pending 或 verified，当前为 $STAGE"
  set_state STAGE hardened
  set_state PENDING_BOOT ""
  set_state VERIFIED_BOOT ""
  write_state
  ok "仅验证状态已回退为 hardened；PRE_BASELINE/POST_BASELINE 引用及全部基线文件均保留"
  inf "未 enable/disable 单元，未修改 SSH、nft 或 socket 配置"
}

hdr "stage3 · 纯重启验证与基线记录（STAGE=$STAGE）"
if (( DO_ROLLBACK )); then
  do_rollback
elif (( APPLY )); then
  do_apply
elif (( VERIFY_MODE )); then
  do_verify
else
  run_checks || die "默认只读检查未通过"
  if [[ "$STAGE" == verified && "${STATE[VERIFIED_BOOT]}" != "$CURRENT_BOOT" ]]; then
    die "verified 已随 boot 变化失效；请用 --apply 启动新一轮重启验证"
  fi
  if [[ "$STAGE" == verified ]]; then
    ok "verified 与当前 boot_id、CONFIG_SHA 一致"
  elif [[ "$STAGE" == reboot-pending ]]; then
    inf "重启验证待完成；必须由 --verify 在 boot_id 变化后写入 verified"
  else
    ok "完整只读检查通过；可用 --apply 记录重启前基线"
  fi
fi
