#!/usr/bin/env bash
# stage1-newport.sh — 建立候选 SSH 通道；外部公钥登录和 sudo 验证后才提交。
# 支持 Ubuntu/Debian + systemd + ssh.socket。默认只读生成部署与迁移计划。
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
CORE_MANAGED_FILES=("${MANAGED_FILES[@]}")
SSHD_CONFIG=/etc/ssh/sshd_config
SOCKET_DIR=/etc/systemd/system/ssh.socket.d
UFW_DIR=/etc/ufw
UFW_DEFAULT=/etc/default/ufw
MIGRATION_PLAN=""

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
  stage1-newport.sh --port <n> --allow <cidr> [--user <name>] [选项]       # 只读预检
  stage1-newport.sh --port <n> --user <name> --allow <cidr> --apply      # 部署候选通道
  stage1-newport.sh --confirm                                            # 从新外部会话中 sudo 执行
  stage1-newport.sh --rollback [--transaction <id>]                       # 逆序回滚

选项:
  --user <name>             默认使用当前 SUDO_USER
  --old-port <n|none>       默认识别当前 SSH 端口；目标相同则为 none，无会话时为 22
  --allow <cidr>            来源白名单，可重复
  --conf <file>             严格 KEY=VALUE 配置文件
  --recovery-seconds <n>    未确认前自动恢复时限，默认 900
  --apply / --confirm       部署 / 外部验证后提交
  --yes                     跳过交互；仍需 RESCUE_CONFIRMED=yes
  --rollback                回滚当前阶段事务
  --transaction <id>        精确指定事务（自动恢复内部使用）
  --guide                   从当前实际状态继续，自动执行可执行阶段并提供缺项指引
  -h, --help                显示帮助

配置文件键: PORT, OLD_PORT, USER, ALLOW（可重复）, RECOVERY_SECONDS,
            RESCUE_CONFIRMED=yes（表示已实际演练独立于 sshd 的救援通道）。
默认生成只读迁移计划；--apply 自动备份并迁移普通全局 SSH/socket 配置、协调常规 UFW。
候选阶段启用公钥并保留原 root/密码策略；禁 root/密码由 stage2 完成。密码会话可以启动 stage1。
活动 Match、自定义停止钩子及不能安全恢复的布局仍给出具体原因，不会盲目接管。
普通用户 SSH 登录后 sudo 执行即可，不需要开放 root SSH 登录。
USAGE
}

REPLAY_ARGS=("$@")
GUIDE_ARGS=(); GUIDE_REQUESTED=0
for guide_arg in "$@"; do
  if [[ $guide_arg == --guide ]]; then GUIDE_REQUESTED=1; else GUIDE_ARGS+=("$guide_arg"); fi
done
if ((GUIDE_REQUESTED)); then
  [[ -f $SRC/stage0-audit.sh ]] || die "缺少同目录 stage0-audit.sh，请同步四个脚本"
  exec bash "$SRC/stage0-audit.sh" --guide "${GUIDE_ARGS[@]}"
fi

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
      OLD_PORT) if ((OLD_PORT_SET == 0)); then OLD_PORT=$value; OLD_PORT_SET=1; fi ;;
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
prepare_migration() {
  local auth legacy hooks dependencies ufw_status='' ufw_active=no
  auth=$(sshd -T -f "$SSHD_CONFIG") || return 1
  legacy=$(systemctl show ssh-firewall.service -p LoadState --value) || return 1
  if [[ $legacy == loaded ]]; then
    [[ $(systemctl show ssh-firewall.service -p Type --value) == oneshot ]] || { fail "旧 ssh-firewall 不是一次性加载器，无法自动接管其运行进程"; return 1; }
    hooks=$(systemctl show ssh-firewall.service -p ExecStop -p ExecStopPost -p PartOf -p BindsTo -p TriggeredBy --value) || return 1
    [[ -z $hooks ]] || { fail "旧防火墙包含停止钩子、定时/路径触发或反向生命周期依赖，无法保证保留其他业务"; return 1; }
    dependencies=$(systemctl show ssh-firewall.service -p Requires --value) || return 1
    if grep -Eq '(^|[[:space:]])ssh\.(socket|service)($|[[:space:]])' <<< "$dependencies"; then
      fail "旧防火墙依赖 SSH 生命周期，无法保证切换时不被重新执行"; return 1
    fi
  fi
  if command -v ufw >/dev/null 2>&1; then
    ufw_status=$(LC_ALL=C ufw status) || return 1
    case $ufw_status in
      'Status: active'*)
        [[ $(systemctl show ufw.service -p LoadState --value) == loaded ]] || { fail "UFW 已启用但无可用的 ufw.service，无法建立持久启动依赖"; return 1; }
        ufw_active=yes ;;
      'Status: inactive'*) ;;
      *) fail "无法解释 UFW 状态，未修改系统: $ufw_status"; return 1 ;;
    esac
  fi
  if [[ $(systemctl is-active firewalld.service 2>/dev/null || true) == active ]]; then
    fail "发现 firewalld 动态管理器；当前支持原生 nft 和 UFW，未修改它的规则"; return 1
  fi
  [[ -z $MIGRATION_PLAN ]] || rm -f -- "$MIGRATION_PLAN"
  MIGRATION_PLAN=$(mktemp "${TMPDIR:-/tmp}/reinforce-migration.XXXXXX") || return 1
  python3 - "$MIGRATION_PLAN" "$SSHD_CONFIG" "$SSHD_DROPIN" "$SOCKET_DIR" "$SOCKET_OVERRIDE" "$UFW_DIR" "$UFW_DEFAULT" "$ufw_active" "$legacy" "$auth" <<'PY'
import fnmatch,glob,hashlib,json,os,re,sys
out,main,managed,socket,override,ufw,default,active,legacy,auth=sys.argv[1:]
files={}; seen=set(); managed_refs=0; controlled={'port','listenaddress','permitrootlogin','pubkeyauthentication','passwordauthentication','kbdinteractiveauthentication','authenticationmethods'}
def read(path):
 if not os.path.isabs(path) or os.path.normpath(path)!=path: raise ValueError('迁移路径须为规范绝对路径: '+path)
 if os.path.islink(path) or not os.path.isfile(path): raise ValueError('迁移只支持普通文件: '+path)
 st=os.stat(path)
 roots=[os.path.dirname(main),socket,ufw,os.path.dirname(default),os.path.dirname(socket)]
 stop=next((r for r in roots if path.startswith(r.rstrip('/')+'/')),None)
 if stop is None: raise ValueError('迁移输入超出配置目录: '+path)
 parent=os.path.dirname(path)
 while True:
  pst=os.stat(parent)
  if os.path.islink(parent) or pst.st_uid!=0 or pst.st_mode & 0o022: raise ValueError('配置目录可被普通用户替换: '+parent)
  if parent==stop: break
  parent=os.path.dirname(parent)
 if st.st_uid!=0 or st.st_mode & 0o022: raise ValueError('迁移配置须由 root 管理且不可被普通用户写入: '+path)
 data=open(path,encoding='utf-8').read()
 files[path]={'path':path,'sha256':hashlib.sha256(open(path,'rb').read()).hexdigest(),'text':data,'rewrite':False}
 return data
def visit(path,depth=0):
 global managed_refs
 if depth>16: raise ValueError('Include 递归过深: '+path)
 if path in seen: return
 seen.add(path)
 if path==managed: return
 if not path.startswith(os.path.dirname(main).rstrip('/')+'/'): raise ValueError('Include 超出支持的 SSH 配置目录: '+path)
 lines=read(path).splitlines(keepends=True); result=[]
 for number,line in enumerate(lines,1):
  stripped=line.strip()
  if not stripped or stripped.startswith('#'): result.append(line); continue
  # 同时处理制表符分隔，保留原文用于恢复。
  fields=stripped.split(None,1)
  if len(fields)!=2: raise ValueError(f'{path}:{number}: 无法解析')
  key,args=fields[0].lower(),fields[1].split('#',1)[0].strip()
  if key=='match': raise ValueError(f'{path}:{number}: 活动 Match 无法保证跨用户迁移等价，未作修改')
  if key=='include':
   if len(args.split())!=1 or not os.path.isabs(args): raise ValueError(f'{path}:{number}: Include 需要单个绝对路径')
   target_parts=managed.split('/'); pattern_parts=args.split('/')
   if len(target_parts)==len(pattern_parts) and all(fnmatch.fnmatchcase(part,pat) for part,pat in zip(target_parts,pattern_parts)): managed_refs+=1
   for child in sorted(glob.glob(args)): visit(child,depth+1)
  if key in controlled:
   result.append('# reinforce-my-ssh migrated: '+line)
  else: result.append(line)
 text=''.join(result)
 if path==main:
  if managed_refs>1: raise ValueError('多个 Include 重叠加载受管路径，无法保证端口等价')
  if not managed_refs: text='Include '+managed+'\n'+text
 files[path].update(text=text,rewrite=text!=files[path]['text'])
try:
 visit(main)
 socket_paths=glob.glob(socket+'/*.conf')
 socket_main=os.path.join(os.path.dirname(socket),'ssh.socket')
 if os.path.lexists(socket_main): socket_paths.append(socket_main)
 for path in sorted(socket_paths):
  if path==override: continue
  section=''; lines=[]; original=read(path)
  for line in original.splitlines(keepends=True):
   s=line.strip()
   if s.startswith('[') and s.endswith(']'): section=s[1:-1]
   key,sep,value=s.partition('=')
   if section=='Socket' and sep and key in {'ListenStream','BindIPv6Only'}:
    line='# reinforce-my-ssh migrated: '+line
   elif section=='Unit' and sep and key in {'Requires','Wants','BindsTo','After','Before'} and 'ssh-firewall.service' in value.split():
    keep=[x for x in value.split() if x!='ssh-firewall.service']
    line=(key+'='+' '.join(keep)+'\n') if keep else '# reinforce-my-ssh migrated: '+line
   lines.append(line)
  text=''.join(lines); files[path].update(text=text,rewrite=text!=original)
 if active=='yes':
  settings=read(default)
  if re.search(r'^\s*MANAGE_BUILTINS\s*=\s*["\x27]?yes\b',settings,re.M|re.I): raise ValueError('UFW MANAGE_BUILTINS=yes 会清理外部链，无法安全保留其他业务规则')
  for path in sorted(set(glob.glob(ufw+'/*.rules')+[ufw+'/ufw.conf'])):
   read(path)
  for hook in ('before.init','after.init'):
   if os.path.lexists(ufw+'/'+hook):
    read(ufw+'/'+hook)
    if os.access(ufw+'/'+hook,os.X_OK): raise ValueError('UFW 自定义可执行钩子需单独核验: '+hook)
 values=dict(line.split(None,1) for line in auth.splitlines() if len(line.split(None,1))==2)
 keys=['permitrootlogin','pubkeyauthentication','passwordauthentication','kbdinteractiveauthentication','authenticationmethods']
 if not all(k in values for k in keys): raise ValueError('无法读取候选阶段原认证策略')
 methods=values['authenticationmethods']
 if methods!='any' and not (methods and all(all(part=='publickey' for part in route.split(',')) for route in methods.split())):
  raise ValueError('原 AuthenticationMethods 包含多因素或其他必需方法，无法在保留原策略时自动建立纯公钥候选通道')
 values['pubkeyauthentication']='yes'
 plan={'schema':1,'files':list(files.values()),'auth':{k:values[k] for k in keys},'ufw':active=='yes','legacy_unit':legacy=='loaded'}
 with open(out,'w',encoding='utf-8') as f: json.dump(plan,f,ensure_ascii=False,indent=2)
 print('迁移计划：备份 '+str(len(files))+' 个原配置；启用公钥，保留原 root/密码策略，接管端口/socket'+('；协调 UFW 来源放行' if active=='yes' else ''))
 print('  候选认证按磁盘解析：root='+values['permitrootlogin']+'，密码='+values['passwordauthentication']+'，公钥=yes；stage2 再收紧')
 for item in files.values():
  print(('  将调整 ' if item['rewrite'] else '  将备份 ')+item['path'])
except (OSError,ValueError,KeyError) as exc:
 print('无法生成可恢复的迁移计划: '+str(exc),file=sys.stderr); sys.exit(1)
PY
}
apply_migration() {
  [[ -f $TX_DIR/migration-plan.json ]] || return 0
  python3 - "$TX_DIR/migration-plan.json" "$STATE_ROOT/migration.json" <<'PY'
import hashlib,json,os,shutil,sys,tempfile
plan=json.load(open(sys.argv[1]))
# 先核对全部输入，再修改任一文件；备份与计划之间有漂移则交给事务恢复。
for item in plan['files']:
 if hashlib.sha256(open(item['path'],'rb').read()).hexdigest()!=item['sha256']: raise SystemExit('迁移输入已变化: '+item['path'])
for item in plan['files']:
 if not item['rewrite']: continue
 path=item['path']; st=os.stat(path); fd,tmp=tempfile.mkstemp(prefix='.reinforce-',dir=os.path.dirname(path))
 try:
  with os.fdopen(fd,'w',encoding='utf-8') as f: f.write(item['text'])
  os.chown(tmp,st.st_uid,st.st_gid); os.chmod(tmp,st.st_mode & 0o777); os.replace(tmp,path)
 finally:
  if os.path.exists(tmp): os.unlink(tmp)
fd,tmp=tempfile.mkstemp(prefix='.migration-',dir=os.path.dirname(sys.argv[2]))
os.close(fd); shutil.copyfile(sys.argv[1],tmp); os.chmod(tmp,0o600); os.replace(tmp,sys.argv[2])
PY
}
coordinate_firewall() {
  [[ -f $TX_DIR/migration-plan.json ]] || return 0
  local flag a
  flag=$(python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); print("yes" if p["legacy_unit"] else "no")' "$TX_DIR/migration-plan.json") || return 1
  # 已完成的 oneshot 无需停止；只撤销开机重放，避免执行旧停止逻辑。
  if [[ $flag == yes ]]; then systemctl disable ssh-firewall.service || return 1; fi
  flag=$(python3 -c 'import json,sys; print("yes" if json.load(open(sys.argv[1]))["ufw"] else "no")' "$TX_DIR/migration-plan.json") || return 1
  if [[ $flag == yes ]]; then
    for a in "${ALLOWS[@]}"; do
      LC_ALL=C ufw prepend allow proto tcp from "$a" to any port "$PORT" comment "reinforce-my-ssh-$TX_ID" || return 1
    done
  fi
}
normalize_params() {
  PORT=$(normalize_port "$PORT") || die "非法 --port: $PORT"
  if [[ -z $USERNAME ]]; then USERNAME=${SUDO_USER:-}; fi
  if ((OLD_PORT_SET == 0)) && [[ $STATE_STAGE == unconfigured ]]; then
    local connection _client _client_port _server sp extra
    connection=$(find_ssh_connection) || connection=''
    read -r _client _client_port _server sp extra <<< "$connection"
    if [[ -n ${sp:-} && -z ${extra:-} ]]; then
      if [[ $sp == "$PORT" ]]; then OLD_PORT=none; else OLD_PORT=$sp; fi
    fi
  fi
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
  # 回滚以事务中的已验证清单为准，不能被损坏的当前记录挡住。
  if ((DO_ROLLBACK == 0)); then load_migration || die "迁移路径记录无效"; fi
  local f k v seen_stage=0 seen_tx=0 seen_sha=0
  if [[ ! -e $STATE_FILE ]]; then
    for f in "${CORE_MANAGED_FILES[@]}"; do
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
    for f in "${CORE_MANAGED_FILES[@]}"; do [[ ! -e $f ]] || die "unconfigured 与受管文件矛盾: $f"; done
  else
    [[ -n $STATE_TX ]] || die "非 unconfigured 状态缺少当前事务"
    [[ $STATE_STAGE == candidate-pending || $STATE_STAGE == hardening-pending || $STATE_CONFIG_SHA =~ ^[0-9a-f]{64}$ ]] \
      || die "已提交状态缺少有效配置摘要"
  fi
}
load_policy() {
  [[ $STATE_STAGE != unconfigured ]] || return 0
  local source=$POLICY_FILE requested
  if ((DO_ROLLBACK)); then
    requested=${REQUEST_TX:-$STATE_TX}
    [[ $requested =~ ^[A-Za-z0-9_-]+$ ]] || die "回滚事务 ID 无效"
    if [[ -f $TX_ROOT/$requested/policy.target && -r $TX_ROOT/$requested/policy.target ]]; then
      source=$TX_ROOT/$requested/policy.target
    fi
  fi
  [[ -r $source ]] || die "已有阶段状态但策略不可读；可能恢复尚未完成，停止 confirm。请从控制台核对事务日志及 policy.target: $source"
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
  done < "$source"
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
  local command
  printf -v command '%q ' sudo bash "$SRC/$SELF" "${REPLAY_ARGS[@]}"
  fail "请在自己的终端执行：$command"
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
  for f in "${CORE_MANAGED_FILES[@]}"; do
    [[ ! -e $f ]] && continue
    [[ -f $f ]] || { fail "受管路径不是普通文件: $f"; return 1; }
    grep -q 'Managed by reinforce-my-ssh' "$f" 2>/dev/null \
      || { fail "拒绝接管非本工具文件: $f"; return 1; }
  done
}
preflight() {
  local bad=0 cmd
  ok "部署目标：账户=$USERNAME，端口=$PORT，保留旧入口=$OLD_PORT，允许来源=${ALLOWS[*]}"
  for cmd in python3 nft sshd systemctl ssh ss ip flock sha256sum install journalctl timeout; do
    command -v "$cmd" >/dev/null 2>&1 || { fail "缺少命令: $cmd"; bad=1; }
  done
  id -nG "$USERNAME" 2>/dev/null | tr ' ' '\n' | grep -qx sudo \
    || { fail "$USERNAME 不在 sudo 组"; bad=1; }
  systemctl cat ssh.socket >/dev/null 2>&1 || { fail "仅支持 ssh.socket 激活布局"; bad=1; }
  if [[ $STATE_STAGE == unconfigured ]]; then
    prepare_migration || bad=1
  else
    scan_sshd_config || bad=1
  fi
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
  local plan=${MIGRATION_PLAN:-$STATE_ROOT/migration.json}
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
  if [[ -f $plan ]] && python3 -c 'import json,sys; sys.exit(not json.load(open(sys.argv[1]))["ufw"])' "$plan"; then
    printf '\n[Unit]\nRequires=ufw.service\nAfter=ufw.service\n' >> "$1"
  fi
}
gen_sshd_dropin() {
  local stage=$2 p auth_plan=${MIGRATION_PLAN:-$STATE_ROOT/migration.json}
  {
    printf '# Managed by reinforce-my-ssh; do not edit\n'
    if [[ $stage == hardened ]]; then
      printf 'PermitRootLogin no\nPubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nAuthenticationMethods publickey\n'
    elif [[ -f $auth_plan ]]; then
      python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); print("\n".join(k+" "+v for k,v in p["auth"].items()))' "$auth_plan" || return 1
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
  local backup_plan=${MIGRATION_PLAN:-$STATE_ROOT/migration.json}
  if [[ -f $backup_plan ]]; then
    load_migration "$backup_plan" || die "迁移备份路径无效"
    cp -- "$backup_plan" "$TX_DIR/migration-plan.json" || die "迁移计划备份失败"
  fi
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
  local u en ac tables
  local snapshot_units=(ssh.socket ssh.service "$FW_NAME")
  if [[ -f $TX_DIR/migration-plan.json ]] && python3 -c 'import json,sys; sys.exit(not json.load(open(sys.argv[1]))["legacy_unit"])' "$TX_DIR/migration-plan.json"; then
    snapshot_units+=(ssh-firewall.service)
  fi
  for u in "${snapshot_units[@]}"; do
    en=$(systemctl is-enabled "$u" 2>/dev/null || true); ac=$(systemctl is-active "$u" 2>/dev/null || true)
    case $en in
      enabled|enabled-runtime|disabled|masked|not-found|static|indirect|generated|transient) ;;
      *) die "无法记录 $u 的 enabled 状态: ${en:-空}" ;;
    esac
    case $ac in
      active|inactive|failed) ;;
      *) die "无法记录 $u 的 active 状态: ${ac:-空}" ;;
    esac
    printf '%s|%s|%s\n' "$u" "$en" "$ac" >> "$TX_DIR/units.conf" || die "单元状态写入失败"
  done
  tables=$(nft list tables 2>/dev/null) || die "无法枚举 nft 表，拒绝推断原表不存在"
  if grep -Fqx "table inet $NFT_TABLE" <<< "$tables"; then
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
  install -m 0600 -- "$POLICY_FILE" "$TX_DIR/policy.target" || die "事务目标策略备份失败"
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
  local wanted=$1 keep_active=${2:-0} u en ac current load
  while IFS='|' read -r u en ac; do
    [[ $u == "$wanted" ]] || continue
    load=$(systemctl show "$u" -p LoadState --value 2>/dev/null) || return 1
    if [[ $en == not-found && $ac == inactive && $load == not-found ]]; then
      current=$(systemctl is-active "$u" 2>/dev/null || true)
      [[ $current == inactive || $current == unknown ]] && return 0
    fi
    if [[ $ac == active ]]; then
      if ((keep_active)) && systemctl is-active --quiet "$u"; then :
      else systemctl restart "$u" >/dev/null 2>&1 || return 1; fi
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
restore_compat_firewall() {
  [[ -f $TX_DIR/migration-plan.json ]] || return 0
  local flags
  flags=$(python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); print(int(p["legacy_unit"]),int(p["ufw"]))' "$TX_DIR/migration-plan.json") || return 1
  if [[ $flags == 1\ * ]]; then restore_unit_state ssh-firewall.service 1 || return 1; fi
  if [[ $flags == *\ 1 ]]; then LC_ALL=C ufw reload || return 1; fi
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
  load_migration "$TX_DIR/migration-plan.json" || die "事务迁移路径无效"
  local parent_lines=() parent_sha
  mapfile -t parent_lines < "$TX_DIR/parent"
  ((${#parent_lines[@]} == 3)) || { fail "父事务记录不完整"; return 1; }
  PARENT_STAGE=${parent_lines[0]}; PARENT_TX=${parent_lines[1]}; parent_sha=${parent_lines[2]}
  # 旧事务首次由新版恢复时补留目标策略；失败重试不能依赖已恢复/删除的全局策略。
  if [[ ! -e $TX_DIR/policy.target ]]; then
    [[ -f $POLICY_FILE && -r $POLICY_FILE ]] \
      && install -m 0600 -- "$POLICY_FILE" "$TX_DIR/policy.target" \
      || { fail "缺少可重试的目标策略备份，尚未停止 SSH"; return 1; }
  fi
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
    # 保留到恢复复验完成；中途失败仍可正常进入 --rollback 重试。
    :
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
  if ((fw_bad == 0)); then
    restore_compat_firewall || { fail "原防火墙兼容配置恢复失败"; bad=1; fw_bad=1; }
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
  if [[ $PARENT_STAGE == unconfigured ]]; then
    rm -f "$POLICY_FILE" || { fail "初始策略清理失败；目标策略备份保留，可重试"; return 1; }
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
  apply_migration || abort_tx "旧配置迁移失败"
  stop_ssh_entry || abort_tx "迁移前停止新 SSH 接入失败"
  coordinate_firewall || abort_tx "已有防火墙协调失败"
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
confirmation_pending_hint() {
  warn "本次拒绝确认未请求停止 SSH；事务仍待确认，原自动恢复计时不会因此取消。"
  printf '请在客户端新开公钥连接（SERVER 换为地址或已配置私钥的 SSH 别名）：\n  '
  printf '%q ' ssh -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -p "$PORT" "$USERNAME@SERVER"
  printf '\n然后在该新会话 sudo 执行 --confirm；sudo 密码不等于 SSH 密码认证。\n'
  local started remaining
  if [[ -r $TX_DIR/started ]]; then
    started=$(cat "$TX_DIR/started")
    if [[ $started =~ ^[0-9]{1,12}$ ]]; then
      remaining=$((10#$started + 10#$RECOVERY_SECONDS - $(date +%s)))
      if ((remaining > 0)); then warn "自动恢复剩余约 $remaining 秒；不要在原密码会话反复确认。"
      else warn "原恢复期限已到，恢复任务可能已排队；请核对事务日志和实际状态。"; fi
    fi
  fi
}
do_confirm() {
  if [[ $STATE_STAGE == candidate-ready ]]; then
    verify_runtime candidate && [[ $(config_digest) == "$STATE_CONFIG_SHA" ]] \
      && { ok "第一阶段已经确认且复验通过"; return 0; }
    die "第一阶段配置已漂移"
  fi
  [[ $STATE_STAGE == candidate-pending ]] || die "只有 candidate-pending 可以确认；当前 $STATE_STAGE"
  TX_ID=$STATE_TX; TX_DIR=$TX_ROOT/$TX_ID
  verify_runtime candidate || { confirmation_pending_hint; die "候选配置或运行时验证失败"; }
  session_evidence "$TX_DIR/confirmation.json" || { confirmation_pending_hint; die "外部登录/sudo 证据不足"; }
  tx_commit candidate-ready || die "提交失败；以实际 state 和恢复定时器状态为准"
  printf '\n第一阶段完成。继续向导：sudo bash %q --guide\n' "$SRC/stage0-audit.sh"
}

trap '[[ -z $MIGRATION_PLAN ]] || rm -f -- "$MIGRATION_PLAN"' EXIT
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
  ok "生成部署与迁移计划；--apply 才会执行变更"
  preflight || { fail "部署前提检查未通过；安全效果未由本命令判定，未修改系统"; exit 2; }
  ok "迁移计划检查通过；核对上述清单后使用 --apply 部署候选通道"
fi
