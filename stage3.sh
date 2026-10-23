#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  stage3.sh —— 远程 SSH 加固 · 第三步：固化与验证
# ═══════════════════════════════════════════════════════════════════════════
#
#  【这一步做什么】
#    前两步已经把配置改对了。本步回答两个前两步回答不了的问题：
#      1) 开机之后还对不对？（配置生效 ≠ 重启后仍生效）
#      2) 万一出事，回不回得来？（兜底通道是否存在且验证过）
#    具体做四件事：固化开机自启、产出重启验证清单、生成基线快照、列收尾清单。
#
#  【为什么脚本不自己重启】
#    重启一台远程服务器是有风险的动作，脚本不该擅自替你做决定。
#    本脚本只**产出清单**并说明每一步的验证点；重启由你在确认控制台可用后自己执行。
#    重启完成后跑 `stage3.sh --verify`，脚本会检查重启后的状态并写下验证记录。
#
#  【为什么「重启验证」不能用别的方式替代】
#    白名单是在开机时由 systemd 单元加载的，而开机时网卡/覆盖网络可能尚未就绪 ——
#    加载器为此写了 30 次重试。那段重试逻辑、以及「加载失败时 SSH 干脆不启动」这个
#    失败方向，**只有真的重启一次才能验证**。看配置文件是验证不了这两件事的。
#
#  【参数的含义】（脚本里的注释就是手册）
#    --port <n>       必填。当前 SSH 端口。
#    --user <name>    必填。日常管理用的非 root 账户（用于兜底演练提示）。
#    --old-port <n>   可选，默认 22。第二步关掉的那个旧端口；none 表示没有。
#                     本步用它来复核「旧端口重启后也没有偷偷回来」。
#    --conf <file>    可选。从文件读默认值（每行 KEY=VALUE，# 开头为注释）。
#    --apply          执行固化（enable 开机自启 + 生成快照 + 打印收尾清单）。
#    --verify         重启后验证模式：检查重启后状态，并把结果记进 .stage3-verified。
#                     记录里存的是当前 boot_id —— 下次重启后这份记录会自动失效，
#                     于是「重启验证」必须重做。这是刻意的。
#    --yes            跳过交互确认。
#    --rollback       撤销本步的固化，不碰前两步的配置。依据 --apply 时记下的
#                     「固化前 enable 状态」逐单元恢复：原本就 enabled 的保持原样，
#                     只有本脚本新 enable 的才 disable。记录丢失时不做任何 disable
#                     （盲关 ssh.socket 会让机器下次开机连 SSH 都没有）。
#
#  【典型用法】
#    ./stage3.sh --port 2222 --user deploy              # 只检查
#    ./stage3.sh --port 2222 --user deploy --apply      # 固化，然后按输出清单重启
#    ./stage3.sh --port 2222 --user deploy --verify     # 重启回来后验证并记录
#
# ═══════════════════════════════════════════════════════════════════════════
#  ⚠ 维护提示：下面的「共享框架」段（参数解析 / 输出 / 阶段探测 / 备份回滚）
#    在 stage1.sh、stage2.sh、stage3.sh 中**各自完整存在一份**（刻意不拆 lib.sh）。
#    改动其中一份时请同步另外两份。
# ═══════════════════════════════════════════════════════════════════════════

set -uo pipefail

# ─────────────────────── 共享框架 · 1. 常量与输出 ───────────────────────

SELF="$(basename "$0")"
SRC="$(cd "$(dirname "$0")" && pwd)"
SNAP_ROOT="$SRC/snapshots"
VERIFY_REC="$SRC/.stage3-verified"        # 验证通过记录（存 boot_id，换一次开机自动失效）
PENDING_REC="$SRC/.stage3-pending"        # --apply 时记下的「重启前 boot_id」—— 验证的对照物
FIXATION_PRE="$SRC/.stage3-fixation-pre"  # --apply 前的 enable 状态 —— 回滚的依据
SSH_SOCKET_OVERRIDE=/etc/systemd/system/ssh.socket.d/override.conf
FW_UNIT=/etc/systemd/system/ssh-firewall.service
F2B_JAIL=/etc/fail2ban/jail.d/sshd.local
NFT_TABLE="sshguard"

if [[ -t 1 ]]; then
  C_RST=$'\033[0m'; C_B=$'\033[1m'; C_DIM=$'\033[2m'
  C_OK=$'\033[32m';  C_FAIL=$'\033[31m'; C_WARN=$'\033[33m'; C_ACT=$'\033[36m'
else
  C_RST=; C_B=; C_DIM=; C_OK=; C_FAIL=; C_WARN=; C_ACT=
fi

hdr()  { printf '\n%s══ %s ══%s\n'      "$C_B"   "$*" "$C_RST"; }
sub()  { printf '\n%s── %s ──%s\n'      "$C_DIM" "$*" "$C_RST"; }
ok()   { printf '   %s[ OK ]%s %s\n'    "$C_OK"   "$C_RST" "$*"; }
fail() { printf '   %s[FAIL]%s %s\n'    "$C_FAIL" "$C_RST" "$*"; }
warn() { printf '   %s[WARN]%s %s\n'    "$C_WARN" "$C_RST" "$*"; }
skip() { printf '   %s[SKIP]%s %s\n'    "$C_DIM"  "$C_RST" "$*"; }
act()  { printf '   %s[ →  ]%s %s\n'    "$C_ACT"  "$C_RST" "$*"; }
note() { printf '          %s↳ %s%s\n'  "$C_DIM"  "$*" "$C_RST"; }
inf()  { printf '          %s%s%s\n'    "$C_DIM"  "$*" "$C_RST"; }
tick() { printf '   %s[  ✓ ]%s %s\n'    "$C_OK"   "$C_RST" "$*"; }

die() { printf '\n%sfatal:%s %s\n' "$C_FAIL" "$C_RST" "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
用法: stage3.sh --port <n> --user <name> [--old-port <n>] [选项]

必填:
  --port <n>        当前 SSH 端口
  --user <name>     日常管理用的非 root 账户

选项:
  --old-port <n>    第二步关掉的旧端口，默认 22；none 表示没有
  --conf <file>     从文件读默认值（KEY=VALUE 每行一个）
  --apply           执行固化（enable 开机自启 + 生成快照 + 打印收尾清单）
  --verify          重启后验证模式（检查并记录，记录随下次重启失效）
  --yes             跳过交互确认
  --rollback        按固化前状态撤销本步固化
  -h, --help        显示本帮助

完整说明见本脚本头部注释。
USAGE
}

# ─────────────────────── 共享框架 · 2. 参数解析 ───────────────────────

PORT=""; OLD_PORT="22"; USERNAME=""; CONF=""
APPLY=0; VERIFY_MODE=0; ASSUME_YES=0; DO_ROLLBACK=0
# 「命令行是否显式给过这个键」。配置文件只补没给过的键 ——
# 否则 `--old-port 22` 会被配置里的 OLD_PORT 悄悄覆盖。
PORT_SET=0; OLD_PORT_SET=0; USER_SET=0

# 选项缺值守卫：在**当前 shell**里退出。
# 旧写法 `PORT="${2:-}"; shift 2` 在只写 `--port` 时 shift 失败、参数不变，
# 循环永远退不出去（死循环）。这里遇到缺值立即报错。
need_val() {  # need_val <选项名> <当前剩余参数个数>
  (( $2 >= 2 )) && return 0
  printf '参数 %s 缺少取值\n\n' "$1" >&2
  usage >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)     need_val "$1" $#; PORT="$2";     PORT_SET=1;     shift 2 ;;
    --old-port) need_val "$1" $#; OLD_PORT="$2"; OLD_PORT_SET=1; shift 2 ;;
    --user)     need_val "$1" $#; USERNAME="$2"; USER_SET=1;     shift 2 ;;
    --conf)     need_val "$1" $#; CONF="$2";                     shift 2 ;;
    --apply)    APPLY=1;       shift ;;
    --verify)   VERIFY_MODE=1; shift ;;
    --yes)      ASSUME_YES=1;  shift ;;
    --rollback) DO_ROLLBACK=1; shift ;;
    -h|--help)  usage; exit 0 ;;
    *) printf '未知参数: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

# 配置文件补默认值（命令行 > 配置文件 > 报错）
if [[ -n "$CONF" ]]; then
  [[ -r "$CONF" ]] || die "配置文件不可读: $CONF"
  while IFS='=' read -r k v; do
    k="${k%%#*}"; k="$(printf '%s' "$k" | tr -d '[:space:]')"
    v="$(printf '%s' "$v" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "$k" || -z "$v" ]] && continue
    case "$k" in
      PORT)     (( PORT_SET ))     || PORT="$v" ;;
      OLD_PORT) (( OLD_PORT_SET )) || OLD_PORT="$v" ;;
      USER)     (( USER_SET ))     || USERNAME="$v" ;;
    esac
  done < "$CONF"
fi

# 端口合法性：只接受十进制 1–65535。
# 注意 10# 强制十进制：不写它的话 "08" 会让 Bash 按八进制解析并直接报错退出。
is_port() {
  [[ "$1" =~ ^[0-9]{1,5}$ ]] || return 1
  local n=$((10#$1))
  (( n >= 1 && n <= 65535 ))
}

require_params() {
  local miss=0
  [[ -z "$PORT" ]]     && { fail "--port 未提供"; miss=1; }
  [[ -z "$USERNAME" ]] && { fail "--user 未提供"; miss=1; }
  if [[ -n "$PORT" ]] && ! is_port "$PORT"; then
    fail "--port 非法: $PORT（应为 1–65535 的端口号）"; miss=1
  fi
  if [[ "$OLD_PORT" != "none" ]] && ! is_port "$OLD_PORT"; then
    fail "--old-port 非法: $OLD_PORT（应为 1–65535 的端口号，或 none）"; miss=1
  fi
  if (( miss )); then
    printf '\n'
    die "参数不完整。用 -h 看用法，完整说明见脚本头部注释。"
  fi
}

# ─────────────────────── 共享框架 · 3. 状态探测 ───────────────────────
#
# 注：另外两个脚本在这一段之前还有「备份与回滚」框架（backup_begin / backup_file）。
# 本步**刻意没有**那一块 —— 第三步不修改任何配置文件，只做 enable 开机自启 +
# 采集只读快照，撤销方式就是 systemctl disable（见 do_rollback_fixation）。
# 所以三份脚本在这里长得不一样是**设计如此**，不是漏同步。

# 本步的固化清单：这些单元必须 enable（开机自启）
ENABLE_UNITS=(ssh.socket ssh-firewall.service)

# 权限闸门：必须在使用 detect_stage 之前调用。
#
# 为什么需要它：detect_stage 依赖 `nft list` 与 `sshd -T`，这两个命令**都需要 root**。
# 非 root 执行时它们返回的是权限错误（nft: "Operation not permitted"、
# sshd: "no hostkeys available"），而脚本会把「读不到」误判成「不存在」——
# 于是一台已加固的机器被报成 S0「未加固」，还会拒绝执行。
#
# 低权限输出 ≠ 事实。宁可明确拒绝，也不要给出一个错误的状态判断。
require_root() {
  [[ $EUID -eq 0 ]] && return 0
  fail "需要在 root 下运行：脚本内部直接调用 nft / sshd / systemctl，不会自己 sudo"
  note "非 root 时这两个命令返回的是权限错误，不是真实状态 ——"
  note "  nft  → Operation not permitted (you must be root)"
  note "  sshd → no hostkeys available -- exiting."
  note "把「读不到」当成「没有」，会把已加固的机器误报成「未加固」"
  die "请用 sudo 运行，例如： sudo bash $0 ..."
}

# 取当前会话的来源 IP；sudo 的 env_reset 会清掉 SSH_CLIENT，故沿父进程链找。
# （第三步也要它：Match Address 的生效值只有在给定来源地址时才读得准。）
find_ssh_client() {
  local v p
  if [[ -n "${SSH_CLIENT:-}" ]]; then printf '%s' "${SSH_CLIENT%% *}"; return 0; fi
  p=$PPID
  while [[ "$p" -gt 1 ]]; do
    if [[ -r "/proc/$p/environ" ]]; then
      v="$(tr '\0' '\n' < "/proc/$p/environ" 2>/dev/null | sed -n 's/^SSH_CLIENT=//p' | head -1)"
      if [[ -n "$v" ]]; then printf '%s' "${v%% *}"; return 0; fi
    fi
    p="$(awk '{print $4}' "/proc/$p/stat" 2>/dev/null)" || return 1
    [[ -z "$p" || "$p" -le 1 ]] && return 1
  done
  return 1
}

# 当前会话来源；取不到时返回一个可行的默认上下文地址
client_addr() { find_ssh_client 2>/dev/null || printf '0.0.0.0'; }

# 读 sshd 的「生效值」—— 带连接上下文。
# 不带 -C 的 `sshd -T` 只给出默认上下文；主配置里后来若出现
# `Match Address <远程网段>` / `Match User` 之类的分支，password / root 的放行
# 会藏在那里，而普通的 `sshd -T` 看不到。这里用真实来源 IP 构造上下文去读。
# 取不到时退回不带 -C 的读法。
sshd_eff() {  # sshd_eff <key> <user> [addr]
  local key="$1" u="$2" addr="${3:-0.0.0.0}" v=""
  v="$(sshd -T -C "user=$u,host=localhost,addr=$addr" 2>/dev/null \
       | awk -v k="$key" '$1==k{print $2; exit}')" || true
  if [[ -z "$v" ]]; then
    v="$(sshd -T 2>/dev/null | awk -v k="$key" '$1==k{print $2; exit}')" || true
  fi
  printf '%s' "$v"
}

detect_stage() {
  local fw_ok=0 nft_ok=0 auth_ok=0 legacy=0 ip
  systemctl is-active --quiet ssh-firewall.service 2>/dev/null && fw_ok=1
  nft list table inet "$NFT_TABLE" >/dev/null 2>&1 && nft_ok=1
  ip="$(find_ssh_client 2>/dev/null || true)"; [[ -n "$ip" ]] || ip="0.0.0.0"
  if [[ "$(sshd_eff permitrootlogin root "$ip")" == "no" ]] \
     && [[ "$(sshd_eff passwordauthentication "${USERNAME:-root}" "$ip")" == "no" ]]; then auth_ok=1; fi
  # 旧端口不能写死 22：自定义旧端口仍开放时会误判 S2；
  # 新端口恰好是 22 时又会永远判成 S1（见 --old-port 的语义）。
  if [[ -n "${OLD_PORT:-}" && "$OLD_PORT" != "none" && "$OLD_PORT" != "${PORT:-}" ]]; then
    port_listening "$OLD_PORT" && legacy=1
  fi

  if (( !fw_ok || !nft_ok )); then printf 'S0'; return; fi
  if (( !auth_ok || legacy ));    then printf 'S1'; return; fi
  if [[ -f "$VERIFY_REC" ]] \
     && [[ "$(cat "$VERIFY_REC" 2>/dev/null)" == "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)" ]]; then
    printf 'S3'; return
  fi
  printf 'S2'
}

port_listening() { ss -tlnH 2>/dev/null | grep -qE "[:.]$1\b"; }
boot_id() { cat /proc/sys/kernel/random/boot_id 2>/dev/null; }

# ─────────────────────────────────────────────────────────────────────────
#                              第三步：固化与验证
# ─────────────────────────────────────────────────────────────────────────

CHECK_FAILED=0
CHECKS=()

rec()    { CHECKS+=("$1|$2|${3:-}"); }
c_ok()   { ok "$1";   rec "OK"   "$1"; }
c_fail() { fail "$1"; CHECK_FAILED=$((CHECK_FAILED+1)); rec "FAIL" "$1" "${2:-}"; }
c_warn() { warn "$1"; rec "WARN" "$1" "${2:-}"; }

run_checks() {
  sub "前置检查（只读）"

  if [[ $EUID -eq 0 ]]; then
    c_ok "以 root 运行"
  else
    c_fail "不是以 root 运行" "脚本内部直接调 nft/sshd/systemctl，不会自己 sudo；请用 sudo 运行"
  fi

  # 失败方向开关：ssh.socket 必须 Require 防火墙单元
  if [[ -f "$SSH_SOCKET_OVERRIDE" ]] \
     && grep -qE '^Requires=ssh-firewall\.service' "$SSH_SOCKET_OVERRIDE"; then
    c_ok "socket 已 Require 防火墙单元（失败方向 = 防火墙挂了 SSH 不开）"
  else
    c_fail "socket 未 Require 防火墙单元 —— 失败方向是「敞开」" \
           "白名单加载失败时 SSH 仍会启动。请重跑 stage2.sh 或手工补上"
  fi

  if [[ -f "$FW_UNIT" ]] && grep -qE '^Before=ssh\.socket' "$FW_UNIT"; then
    c_ok "防火墙单元 Before=ssh.socket（加载顺序正确）"
  else
    c_warn "防火墙单元缺少 Before=ssh.socket" "开机时可能出现顺序竞争"
  fi

  local u missing=0
  for u in "${ENABLE_UNITS[@]}"; do
    systemctl is-enabled --quiet "$u" 2>/dev/null || missing=1
  done
  if (( missing == 0 )); then
    c_ok "固化单元均已开机自启（${ENABLE_UNITS[*]}）"
  else
    c_warn "有单元尚未设开机自启 —— 本步的 --apply 会补上" "重启后可能回到未加固状态"
  fi

  local a_root a_pass a_kbd addr
  addr="$(client_addr)"
  a_root="$(sshd_eff permitrootlogin root "$addr")"
  a_pass="$(sshd_eff passwordauthentication "$USERNAME" "$addr")"
  a_kbd="$(sshd_eff kbdinteractiveauthentication "$USERNAME" "$addr")"
  if [[ "$a_root" == "no" && "$a_pass" == "no" && "$a_kbd" == "no" ]]; then
    c_ok "认证策略仍收口（root 直连关 / 密码关 / KbdInteractive 关）"
  else
    c_fail "认证策略有回退（root=${a_root:-?} password=${a_pass:-?} kbd=${a_kbd:-?}）" \
           "请重跑 stage2.sh。注意 kbd=yes 时密码可经 PAM 绕过 passwordauthentication no"
  fi

  # ── 运行时事实（现在在听什么）与配置层事实（重启后还会不会听）是两件事。
  #    前者用 ss 看，后者用 sshd -T 看。跨过重启的只有后者 —— 这正是本步的重点。
  if port_listening "$PORT"; then
    c_ok "端口 $PORT 正在监听"
  else
    c_fail "端口 $PORT 未监听" "先确认 SSH 可用"
  fi

  local cfg_ports
  cfg_ports="$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -u | tr '\n' ' ')"
  inf "sshd 配置声明的端口：${cfg_ports:-（读不到）}"
  if [[ " $cfg_ports " == *" $PORT "* ]]; then
    c_ok "配置里含 $PORT —— 重启后 SSH 仍会监听它"
  else
    c_fail "配置里没有 $PORT —— 重启后你会失去 SSH" "请检查 99-hardening.conf 的 Port"
  fi

  if [[ "$OLD_PORT" != "none" ]]; then
    if port_listening "$OLD_PORT"; then
      c_fail "旧端口 $OLD_PORT 又在监听了" "前两步成果被回退了，请检查"
    else
      c_ok "旧端口 $OLD_PORT 仍未监听"
    fi
    if [[ " $cfg_ports " == *" $OLD_PORT "* ]]; then
      c_fail "配置里仍有 $OLD_PORT —— 重启后旧端口会回来" \
             "多值指令的陷阱：只要任何一处还写着 Port $OLD_PORT，它就会累积生效"
    else
      c_ok "配置里已无 $OLD_PORT —— 重启也不会回来"
    fi
  fi

  # ── fail2ban：不属本步创建，所以只提醒不判定失败
  if systemctl is-active --quiet fail2ban 2>/dev/null; then
    c_ok "fail2ban 在运行"
    if [[ -f "$F2B_JAIL" ]]; then
      # 先把 port= 右侧的值整段取出来再拆成列表，比用正则去凑边界可靠
      # （正则那版在 `port=2222` 无空格时会漏判、在被注释的 `# port = …` 上会误判）
      local f2b_ports
      f2b_ports="$(grep -E '^[[:space:]]*port[[:space:]]*=' "$F2B_JAIL" 2>/dev/null \
                   | sed 's/^[^=]*=//' | tr ',:\n' '   ')"
      if [[ " $f2b_ports " == *" $PORT "* ]]; then
        c_ok "fail2ban jail 端口与 $PORT 对齐"
      else
        c_warn "fail2ban jail 端口未与 $PORT 对齐" \
               "封禁会记到错误端口（属第二步遗留项，不影响 SSH 可用性）"
      fi
    fi
  else
    c_warn "fail2ban 未运行" "若第一步启用了它请检查；未启用则忽略此项"
  fi

  if [[ -w "$SRC" || $EUID -eq 0 ]]; then
    c_ok "工作目录可写（快照将写入 $SNAP_ROOT）"
  else
    c_fail "工作目录不可写: $SRC" "无法生成快照与验证记录"
  fi

  # 控制台救援 —— 只能提醒，宿主机验证不了
  if grep -q 'AuthorizedKeysCommand.*instance_connect\|AuthorizedKeysCommand.*ecs_config' /etc/ssh/sshd_config 2>/dev/null; then
    c_ok "云厂商控制台通道在位"
  else
    c_warn "未发现云厂商控制台通道" "请确认 VNC / 控制台救援可用，且其登录名不是 root"
  fi
}

print_dry_run_table() {
  sub "预期状态 vs 当前状态"
  printf '   %-6s %-56s %s\n' "" "检查项" "结论 / 建议"
  printf '   %s\n' "────────────────────────────────────────────────────────────────────────"
  local e s d adv
  for e in "${CHECKS[@]}"; do
    IFS='|' read -r s d adv <<< "$e"
    printf '   %-6s %-56s %s\n' "[$s]" "$d" "${adv:-—}"
  done
}

print_plan() {
  sub "本步将做的项"
  cat <<PLAN
   A. 固化
      systemctl enable ${ENABLE_UNITS[*]}
      复核 socket 的 Requires / 单元顺序（缺失则报错，不静默改）

   B. 基线快照（只读采集，写入 snapshots/<时间戳>/）
      sshd -T / nft list / ss -tln / systemctl show / drop-in 清单
      用途：将来出问题时与基线 diff，一眼看出哪里变了

   C. 输出「重启验证清单」（脚本**不自动重启**）
      见执行后打印的清单

PLAN
}

conclude() {
  printf '\n%s── 结论 ──%s\n' "$C_DIM" "$C_RST"
  if (( CHECK_FAILED > 0 )); then
    printf '   %s✗ %d 项检查未通过，脚本中止，未做任何修改。%s\n' "$C_FAIL" "$CHECK_FAILED" "$C_RST"
    return 1
  fi
  printf '   %s✅ 检查全过。%s\n' "$C_OK" "$C_RST"
  return 0
}

# ─────────────────────── 执行 ───────────────────────

snapshot() {
  local d="$SNAP_ROOT/$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$d" || die "无法创建快照目录 $d"
  sshd -T                             > "$d/sshd-T.txt"        2>&1
  nft list table inet "$NFT_TABLE"    > "$d/nft-sshguard.txt"   2>&1
  ss -tln                             > "$d/listen.txt"         2>&1
  systemctl show ssh.socket -p Listen > "$d/socket-listen.txt"  2>&1
  for u in "${ENABLE_UNITS[@]}" ssh.service fail2ban.service; do
    printf '%-24s active=%-8s enabled=%s\n' "$u" \
      "$(systemctl is-active "$u" 2>/dev/null)" "$(systemctl is-enabled "$u" 2>/dev/null)"
  done > "$d/services.txt"
  ls -la /etc/ssh/sshd_config.d/      > "$d/dropins.txt"        2>&1
  {
    printf '采集时间: %s\n' "$(date -Is)"
    printf 'boot_id : %s\n' "$(boot_id)"
    printf '内核    : %s\n' "$(uname -r)"
  } > "$d/META.txt"
  printf '%s' "$d"
}

do_apply() {
  sub "A · 固化开机自启"
  local u bad=0 st
  # 先记下「改动前每个单元本来是不是自启」——回滚要靠它。
  # 否则 --rollback 会把原本就 enable 的 ssh.socket 一起 disable，
  # 机器下次重启就再也没有 SSH；即使本步其实没新增任何设置也会中招。
  # 已有记录时**不覆盖**：重复 --apply 时若覆盖，会把第一次固化前的真实
  # 状态冲成「已 enabled」，之后回滚就再也撤不掉第一次的新增自启了。
  if [[ -f "$FIXATION_PRE" ]]; then
    skip "沿用已有固化前状态记录（不覆盖） -> $FIXATION_PRE"
  else
    : > "$FIXATION_PRE" || die "无法写入 $FIXATION_PRE —— 没有它就无法安全回滚，中止"
    for u in "${ENABLE_UNITS[@]}"; do
      st="$(systemctl is-enabled "$u" 2>/dev/null || true)"
      printf '%s=%s\n' "$u" "${st:-unknown}" >> "$FIXATION_PRE"
    done
    act "已记录固化前状态 -> $FIXATION_PRE"
  fi
  inf "固化前：$(tr '\n' ' ' < "$FIXATION_PRE")"

  for u in "${ENABLE_UNITS[@]}"; do
    if systemctl enable "$u" >/dev/null 2>&1; then
      ok "enable $u"
    else
      fail "enable $u 失败"; bad=1
    fi
  done
  (( bad == 0 )) || die "有单元 enable 失败 —— 开机自启没建立起来，本步不算完成（未生成快照）"

  # 记下固化时是哪一次开机。--verify 必须看到 boot_id 变了才算「重启验证」——
  # 否则在同一次开机里跑一遍 --verify 就会标成 S3，而它什么都没证明。
  if printf '%s' "$(boot_id)" > "$PENDING_REC" 2>/dev/null; then
    ok "已记录重启前基线 -> $PENDING_REC"
  else
    die "无法写入 $PENDING_REC —— 没有对照物就无法证明重启，中止"
  fi

  sub "B · 基线快照"
  local d
  d="$(snapshot)" || die "快照生成失败"
  ok "已写入 $d"
  inf "文件：$(ls -1 "$d" | tr '\n' ' ')"

  sub "C · 重启验证清单"
  cat <<'CHECKLIST'

   本脚本不替你重启。请按顺序做：

   ┌─ 1. 先确认兜底通道可用（这一步不能跳）
   │     · 打开云控制台的 VNC / 远程连接页面，确认能进到登录提示
   │     · 或确认 Workbench / 控制台会话管理可用
   │     理由：重启后若白名单加载失败，SSH 会**故意不启动**（那是设计），
   │           此时唯一能进去的就是控制台。
   │
   ├─ 2. 重启
   │     sudo systemctl reboot
   │
   ├─ 3. 等待约 60 秒，然后重新登录
   │     ssh -p <端口> <账户>@<地址>
   │     （已建立的会话会断开，这是预期的）
   │
   └─ 4. 回来验证并记录
         ./stage3.sh --port <端口> --user <账户> --verify

   验证会先核对 boot_id 确实变过（同一次开机内不算重启验证），再检查：
     · nft 白名单是否**自动加载**（开机加载器 + 30 次重试是否奏效）
     · nft 是否含末尾兜底 drop（只有 counter accept 不算）
     · ssh.socket 是否正常启动、端口是否可连
     · 旧端口是否仍然关闭
     · 认证策略是否仍然收口（root / password / KbdInteractive 三项）
   通过后写入 .stage3-verified（存当前 boot_id，下次重启后自动失效）。

CHECKLIST
}

do_verify() {
  sub "重启后验证"
  local bad=0 pending=""

  # ── 先证明「确实重启过」。没有这一步，--apply 之后原地跑一次 --verify
  #    就能把状态标成 S3，「重启验证」四个字就名不副实。
  if [[ -f "$PENDING_REC" ]]; then
    pending="$(cat "$PENDING_REC" 2>/dev/null)"
  fi
  if [[ -z "$pending" ]]; then
    fail "找不到 --apply 留下的重启基线（$PENDING_REC）"
    note "没有对照物就无法证明本次开机跨过了一次重启。"
    note "请先执行 --apply，再重启，最后回来 --verify"
    return 1
  fi
  if [[ "$pending" == "$(boot_id)" ]]; then
    fail "仍是同一次开机（boot_id 未变）—— 这次不算重启验证"
    note "请先重启：sudo systemctl reboot；回来后重跑 --verify"
    return 1
  fi
  ok "检测到新的开机（boot_id 已变化）—— 本次是真实的重启验证"

  # 1) 白名单是否自动加载 —— 这是重启验证的核心
  if systemctl is-active --quiet ssh-firewall.service; then
    ok "ssh-firewall 已自动启动"
  else
    fail "ssh-firewall 未启动 —— 开机加载失败"; bad=1
  fi
  if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
    # 只匹配 'counter' 的话，一张只有 `counter accept` 的表也能过 ——
    # 那意味着没有任何兜底拒绝，白名单形同虚设。
    if nft list table inet "$NFT_TABLE" 2>/dev/null | grep -qE 'counter.*[[:space:]]drop'; then
      ok "nft 表已自动加载且含兜底 drop"
    else
      fail "nft 表在，但缺兜底 drop（只有 counter accept 不算）"; bad=1
    fi
  else
    fail "nft 表未加载 —— 此时 ssh.socket 本应不启动，请检查失败方向是否被破坏"; bad=1
  fi
  systemctl is-enabled --quiet ssh-firewall.service 2>/dev/null \
    && ok "ssh-firewall 已设开机自启" || { fail "ssh-firewall 未设开机自启"; bad=1; }

  # 2) SSH 可用性
  if systemctl is-active --quiet ssh.socket; then
    ok "ssh.socket active"
  else
    fail "ssh.socket 未运行 —— 这就是设计中的失败方向，请从控制台介入"; bad=1
  fi
  port_listening "$PORT" && ok "端口 $PORT 在监听" || { fail "端口 $PORT 未监听"; bad=1; }

  if timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT" 2>/dev/null; then
    ok "本机回环可连 $PORT"
  else
    fail "本机回环连不上 $PORT"; bad=1
  fi

  # 3) 旧端口没有偷偷回来
  if [[ "$OLD_PORT" != "none" ]]; then
    port_listening "$OLD_PORT" && { fail "旧端口 $OLD_PORT 又回来了"; bad=1; } \
                               || ok "旧端口 $OLD_PORT 仍然关闭"
  fi

  # 4) 认证策略没有回退（带连接上下文读，Match 分支里的放行也逃不掉）
  local addr v_root v_pass v_kbd
  addr="$(client_addr)"
  v_root="$(sshd_eff permitrootlogin root "$addr")"
  v_pass="$(sshd_eff passwordauthentication "$USERNAME" "$addr")"
  v_kbd="$(sshd_eff kbdinteractiveauthentication "$USERNAME" "$addr")"
  [[ "$v_root" == "no" ]] && ok "permitrootlogin no 保持" || { fail "permitrootlogin=${v_root:-读不到} 已回退"; bad=1; }
  [[ "$v_pass" == "no" ]] && ok "passwordauthentication no 保持" || { fail "passwordauthentication=${v_pass:-读不到} 已回退"; bad=1; }
  [[ "$v_kbd"  == "no" ]] && ok "kbdinteractiveauthentication no 保持" || { fail "kbdinteractiveauthentication=${v_kbd:-读不到} —— 密码可经 PAM 绕过"; bad=1; }

  if (( bad == 0 )); then
    local d="$SNAP_ROOT/verify-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$d" 2>/dev/null
    {
      printf '验证时间: %s\n' "$(date -Is)"
      printf 'boot_id : %s\n' "$(boot_id)"
      printf '结果    : 通过\n'
    } > "$d/verify.txt" 2>/dev/null
    if printf '%s' "$(boot_id)" > "$VERIFY_REC" 2>/dev/null; then
      ok "已记录验证状态 -> $VERIFY_REC"
    else
      warn "无法写入验证记录 $VERIFY_REC（不影响结论，但下次会重复要求验证）"
    fi
    return 0
  fi
  return 1
}

do_rollback_fixation() {
  hdr "回滚 · 撤销本步固化"
  local u st state
  if [[ ! -f "$FIXATION_PRE" ]]; then
    warn "找不到固化前的状态记录: $FIXATION_PRE"
    note "没有它就无法区分「本步新开的自启」和「原本就有的自启」。"
    note "为避免把原本就有的开机自启误关掉（那会让机器下次重启就没有 SSH），"
    note "本次**不做任何 disable**。"
    rm -f "$VERIFY_REC" "$PENDING_REC" 2>/dev/null || true
    return 0
  fi

  while IFS='=' read -r u st; do
    [[ -z "$u" ]] && continue
    state="$(systemctl is-enabled "$u" 2>/dev/null || true)"
    if [[ "$st" == "enabled" ]]; then
      # 改动前就是开机自启 —— 保持不变或恢复回去，绝不 disable
      if [[ "$state" == "enabled" ]]; then
        skip "$u 改动前就是 enabled —— 保持不变"
      elif systemctl enable "$u" >/dev/null 2>&1; then
        act "恢复 $u 为 enabled（改动前就是自启）"
      else
        fail "恢复 $u 失败"
      fi
    else
      if systemctl disable "$u" >/dev/null 2>&1; then
        act "disable $u（改动前是 ${st:-unknown}）"
      else
        skip "$u 未能 disable（当前 ${state:-unknown}）"
      fi
    fi
  done < "$FIXATION_PRE"

  rm -f "$VERIFY_REC" "$PENDING_REC" 2>/dev/null || true
  act "已删除验证记录与重启基线"
  printf '\n'
  ok "固化已撤销。注意：只是取消**本步新增**的开机自启，没有回退前两步的配置。"
  inf "若要把配置本身也退回去，请依次执行 stage2.sh --rollback、stage1.sh --rollback"
}

print_final_checklist() {
  cat <<'FINAL'

── 收尾清单（脚本不代做，请你逐项确认）──────────────────────────────

  □ 云安全组对齐
      宿主机侧的 nft 白名单只是**内层**。外层云安全组的放行清单必须等于
      「你有意开放的端口」，一条不多。特别注意旧端口是否还留在放行列表里 ——
      主机侧关了、安全组还开着，属于「看起来安全、实际是冷备漏洞」：
      哪天有人把旧端口重新监听，它就立刻裸露在公网。

  □ 兜底演练
      从云控制台（VNC / 会话管理）真登一次，确认能进去。
      没演练过的兜底通道不算兜底通道。

  □ 凭据清理
      · 原 root 账户的 authorized_keys（已失效但通常还躺在那里）
      · 废弃的旧密钥、临时密钥
      · 确认现役公钥的数量与指纹，做好登记

  □ 可观测性
      · nft 各规则的 counter（能看出「挡了多少、放了多少」）
      · fail2ban 的封禁统计是否有人定期看
      · 是否开启云厂商的 VPC 流日志 —— 安全组丢弃的流量主机侧完全看不见，
        只有流日志能回答「到底谁在扫我们」

  □ 其他暴露面
      本次改端口会牵动同机的其他服务。逐个确认它们的绑定地址与认证：
      绑在 0.0.0.0 且无认证的 agent 类服务尤其危险（只靠安全组一层挡着）。

  □ 文档化
      把本次的阶段状态、生效值快照、回滚步骤记下来。
      基线在 snapshots/ 里，回滚入口是三个脚本的 --rollback。

──────────────────────────────────────────────────────────────────────
FINAL
}

# ─────────────────────── 主流程 ───────────────────────

hdr "$SELF · 第三步：固化与验证"

require_root

if (( DO_ROLLBACK )); then
  do_rollback_fixation
  exit 0
fi

require_params

STAGE="$(detect_stage)"
sub "阶段检测"
inf "当前阶段：$STAGE"
case "$STAGE" in
  S0) inf "未加固 —— 前两步还没做 ❌"
      die "拒绝执行。请先依次跑 stage1.sh、stage2.sh。" ;;
  S1) inf "通道已建但认证未收口 —— 前两步还没做完 ❌"
      die "拒绝执行。请先跑 stage2.sh。" ;;
  S2) inf "认证已收口 —— 本步适用 ✅" ;;
  S3) inf "已固化且已验证过本次开机 —— 本步为复验 ✅" ;;
  *)  die "无法识别阶段：$STAGE" ;;
esac

if (( VERIFY_MODE )); then
  if do_verify; then
    printf '\n   %s✅ 重启验证通过，第三步完成。%s\n' "$C_OK" "$C_RST"
    print_final_checklist
    printf '\n'
  else
    printf '\n   %s✗ 重启验证未通过。%s\n' "$C_FAIL" "$C_RST"
    printf '   最多的情况是白名单加载失败 —— 请从控制台介入，\n'
    printf '   查看 systemctl status ssh-firewall.service 与 /run/ssh-allowlist.err。\n\n'
    exit 1
  fi
  exit 0
fi

run_checks
print_dry_run_table

if (( ! APPLY )); then
  print_plan
  # 只读检查的退出码要反映检查结论：有 FAIL 就不能返回 0。
  if conclude; then
    printf '\n   %s这是只读检查（默认行为）。加 --apply 才会真正执行。%s\n' "$C_B" "$C_RST"
    printf '   %s执行完 --apply 后，按输出的「重启验证清单」操作，再跑 --verify。%s\n\n' "$C_DIM" "$C_RST"
    exit 0
  fi
  printf '\n   %s只读检查未全过 —— 先修好上面标 ✗ 的项。%s\n\n' "$C_FAIL" "$C_RST"
  exit 1
fi

conclude || { printf '\n   未做任何修改。\n\n'; exit 1; }

if (( ! ASSUME_YES )); then
  printf '\n   %s本步会设置开机自启，并生成基线快照。%s\n' "$C_WARN" "$C_RST"
  printf '   %s确认后输入 yes 继续：%s ' "$C_WARN" "$C_RST"
  read -r a
  [[ "$a" == "yes" ]] || { printf '   已取消。\n\n'; exit 1; }
fi

do_apply
print_final_checklist
printf '\n   %s✅ 第三步的固化部分完成。%s\n' "$C_OK" "$C_RST"
printf '   重启验证尚未进行 —— 请按上面的清单操作，回来跑：\n'
printf '     %s --port %s --user %s --verify\n' "$SRC/$SELF" "$PORT" "$USERNAME"
printf '   %s--verify 会比对 boot_id：本次开机内跑不算数，必须真的重启过。%s\n\n' "$C_DIM" "$C_RST"