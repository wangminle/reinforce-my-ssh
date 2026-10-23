#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  stage1.sh —— 远程 SSH 加固 · 第一步：建立安全通道
# ═══════════════════════════════════════════════════════════════════════════
#
#  【这一步做什么】
#    把 SSH 从「旧端口 + 可能对公网敞开」迁移到「新端口 + 来源白名单」。
#    本步结束时旧端口**可能仍在监听**（那是第二步的事），但新端口已就位，
#    且来源已被 nftables 白名单收窄。
#
#  【什么时候能跑】
#    当前处于 S0（未加固）或 S1（本步已完成，幂等重跑）。
#    处于 S2 / S3 时本脚本会**拒绝执行** —— 那会把已收口的认证策略倒退回去。
#
#  【参数的含义】（脚本里的注释就是手册）
#    --port <n>       必填。SSH 要迁移到的新端口。
#                     为什么必须显式给：脚本不猜端口，猜错就是失联。
#    --user <name>    必填。日常管理用的非 root 账户。
#                     必须已存在、在 sudo 组、且装了可解析的公钥。
#                     本脚本**只检查不代建** —— 建账户涉及密码策略，不该脚本擅自决定。
#    --allow <cidr>   必填，可重复。允许访问 SSH 的来源网段。
#                     至少要包含你自己的来源，否则改完当场失联。
#                     典型值：覆盖网络 100.64.0.0/10、云 VPC 内网、控制台私网段。
#    --old-port <n>   可选，默认 22。迁移期间**保留**监听的旧端口；none 表示不保留。
#                     为什么默认保留：本步只负责「建立新通道」，关旧端口是第二步的事。
#                     保留期间旧端口**同样受白名单约束** —— 不是「暂时敞开」。
#                     若机器本就没有旧端口，用 --old-port none。
#    --conf <file>    可选。从文件读默认值（每行 KEY=VALUE，# 开头为注释）。
#                     优先级：命令行 > 配置文件 > 报错。缺参数不猜、不给默认值。
#    --apply          实际执行。**不加这个参数时脚本只读不改**（默认行为）。
#    --yes            跳过交互确认（用于无人值守）。
#    --rollback       按最近一次备份还原。
#
#  【执行顺序为什么是这样】（不可调换）
#    1. 先装防火墙并让它生效
#    2. 再切换 sshd 的监听
#    理由：若先切监听而防火墙没生效，中间会出现「已通配、无白名单」的敞开窗口。
#    这是整个方案里最容易被忽略、后果最严重的一处顺序要求。
#
#  【失败方向】
#    ssh.socket 依赖 ssh-firewall.service。白名单加载失败 ⇒ SSH 干脆不启动，
#    而不是「防火墙挂了所以 SSH 敞开」。这个方向是刻意的，不要改。
#
#  【典型用法】
#    ./stage1.sh --port 2222 --user deploy --allow 100.64.0.0/10                 # 只检查
#    ./stage1.sh --port 2222 --user deploy --allow 100.64.0.0/10 --apply         # 执行
#    ./stage1.sh --rollback                                                      # 回滚
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
BACKUP_ROOT="$SRC/backups"
SSH_SOCKET_OVERRIDE=/etc/systemd/system/ssh.socket.d/override.conf
SSHD_DROPIN=/etc/ssh/sshd_config.d/99-hardening.conf
NFT_RULES=/etc/nftables.d/ssh-allowlist.nft
NFT_LOADER=/usr/local/sbin/ssh-allowlist-apply.sh
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

die() { printf '\n%sfatal:%s %s\n' "$C_FAIL" "$C_RST" "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
用法: stage1.sh --port <n> --user <name> --allow <cidr> [--allow <cidr>...] [选项]

必填:
  --port <n>        SSH 新端口
  --user <name>     日常管理用的非 root 账户（须已存在、在 sudo 组、有公钥）
  --allow <cidr>    允许访问的源网段，可重复；至少一个，且须包含你自己的来源

选项:
  --old-port <n>    迁移期间保留监听的旧端口，默认 22；none 表示不保留
  --conf <file>     从文件读默认值（KEY=VALUE 每行一个）
  --apply           实际执行（不加则只检查，脚本只读不改）
  --yes             跳过交互确认
  --rollback        按最近一次备份还原
  -h, --help        显示本帮助

完整说明见本脚本头部注释。
USAGE
}

# ─────────────────────── 共享框架 · 2. 参数解析 ───────────────────────

PORT=""; OLD_PORT="22"; USERNAME=""; CONF=""; ALLOWS=()
APPLY=0; ASSUME_YES=0; DO_ROLLBACK=0

ARGV=("$@")
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)     PORT="${2:-}";      shift 2 ;;
    --old-port) OLD_PORT="${2:-}";  shift 2 ;;
    --user)     USERNAME="${2:-}";  shift 2 ;;
    --allow)    ALLOWS+=("${2:-}"); shift 2 ;;
    --conf)     CONF="${2:-}";      shift 2 ;;
    --apply)    APPLY=1;      shift ;;
    --yes)      ASSUME_YES=1; shift ;;
    --rollback) DO_ROLLBACK=1; shift ;;
    -h|--help)  usage; exit 0 ;;
    *) printf '未知参数: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

# 配置文件补默认值（命令行优先）
if [[ -n "$CONF" ]]; then
  [[ -r "$CONF" ]] || die "配置文件不可读: $CONF"
  while IFS='=' read -r k v; do
    k="${k%%#*}"; k="$(printf '%s' "$k" | tr -d '[:space:]')"
    v="$(printf '%s' "$v" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "$k" || -z "$v" ]] && continue
    case "$k" in
      PORT)  [[ -z "$PORT" ]]     && PORT="$v" ;;
      OLD_PORT) [[ "$OLD_PORT" == "22" ]] && OLD_PORT="$v" ;;
      USER)  [[ -z "$USERNAME" ]] && USERNAME="$v" ;;
      ALLOW) ALLOWS+=("$v") ;;
    esac
  done < "$CONF"
fi

require_params() {
  local miss=0
  [[ -z "$PORT" ]]     && { fail "--port 未提供"; miss=1; }
  [[ -z "$USERNAME" ]] && { fail "--user 未提供"; miss=1; }
  [[ ${#ALLOWS[@]} -eq 0 ]] && { fail "--allow 未提供（至少一个）"; miss=1; }
  if [[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT < 1 || PORT > 65535 )); then
    fail "--port 非法: $PORT"; miss=1
  fi
  if [[ "$OLD_PORT" != "none" ]] && ! [[ "$OLD_PORT" =~ ^[0-9]+$ ]]; then
    fail "--old-port 非法: $OLD_PORT（应为端口号或 none）"; miss=1
  fi
  if [[ "$OLD_PORT" != "none" && "$OLD_PORT" == "$PORT" ]]; then
    fail "--old-port 与 --port 相同（$PORT）—— 那这一步什么也没改"; miss=1
  fi
  if (( miss )); then
    printf '\n'
    die "参数不完整。脚本不猜参数 —— 猜错端口就是失联。用 -h 看用法。"
  fi
}

# 本步实际要监听的端口集合（旧端口在前）
all_ports() {
  if [[ "$OLD_PORT" == "none" ]]; then printf '%s' "$PORT"
  else printf '%s %s' "$OLD_PORT" "$PORT"; fi
}
# nft 的集合写法 {a, b}
port_set() {
  local p out=""
  for p in $(all_ports); do out+="${out:+, }$p"; done
  printf '{%s}' "$out"
}

# ─────────────────────── 共享框架 · 3. 备份与回滚 ───────────────────────

TS=""
MANIFEST=""

backup_begin() {
  TS="$(date +%Y%m%d-%H%M%S)"
  MANIFEST="$BACKUP_ROOT/$TS"
  if ! mkdir -p "$MANIFEST" 2>/dev/null; then
    die "无法创建备份目录 $MANIFEST —— 备份失败必须中止，不能「没备成也接着改」"
  fi
  if [[ ! -w "$MANIFEST" ]]; then
    die "备份目录不可写 $MANIFEST —— 同上，中止"
  fi
  : > "$MANIFEST/MANIFEST"
  ok "备份目录 $MANIFEST"
}

# backup_file <绝对路径>  —— 备份失败立即中止整个脚本
backup_file() {
  local f="$1" base
  base="$(printf '%s' "$f" | tr '/' '_')"
  if [[ -e "$f" ]]; then
    if ! cp -p "$f" "$MANIFEST/$base" 2>/dev/null; then
      die "备份失败: $f —— 中止（不留半个改动）"
    fi
    printf 'EXIST %s %s\n' "$f" "$base" >> "$MANIFEST/MANIFEST"
    act "备份 $f"
  else
    printf 'ABSENT %s %s\n' "$f" "$base" >> "$MANIFEST/MANIFEST"
    act "备份 $f（不存在，标记为「原本没有」）"
  fi
}

newest_manifest_dir() {
  local d
  d="$(ls -1dt "$BACKUP_ROOT"/*/ 2>/dev/null | head -1)"
  [[ -n "$d" ]] || return 1
  printf '%s' "${d%/}"
}

do_rollback() {
  local d="$1" line orig base
  [[ -f "$d/MANIFEST" ]] || die "备份目录里没有 MANIFEST: $d"
  hdr "回滚 · 依据 $d/MANIFEST"
  while read -r kind orig base; do
    [[ -z "${orig:-}" ]] && continue
    if [[ "$kind" == "EXIST" ]]; then
      if cp -f "$d/$base" "$orig" 2>/dev/null; then
        act "还原 $orig"
      else
        fail "还原失败 $orig"
      fi
    else
      if [[ -e "$orig" ]]; then
        rm -f "$orig" && act "删除 $orig（原本不存在）"
      else
        skip "$orig 本就不存在"
      fi
    fi
  done < "$d/MANIFEST"
  # nft 表不在 MANIFEST 里，单独处理
  if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
    nft delete table inet "$NFT_TABLE" 2>/dev/null && act "已删除 nft 表 inet $NFT_TABLE"
  fi
  systemctl daemon-reload 2>/dev/null || true
  systemctl restart ssh.socket 2>/dev/null || true
  systemctl disable --now ssh-firewall.service >/dev/null 2>&1 || true
  printf '\n'
  ok "回滚完成"
  inf "当前监听："
  ss -tlnH 2>/dev/null | awk '{print "        " $4}' | grep -E ':(22|[0-9]+)$' | sort -u
}

# ─────────────────────── 共享框架 · 4. 状态探测 ───────────────────────

# 探测"当前实际处于哪个阶段"，与目标端口无关。
#   S0 未加固 / S1 通道已建 / S2 认证已收口 / S3 已固化验证
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

detect_stage() {
  local fw_ok=0 nft_ok=0 auth_ok=0 legacy=0
  systemctl is-active  --quiet ssh-firewall.service 2>/dev/null && fw_ok=1
  nft list table inet "$NFT_TABLE" >/dev/null 2>&1 && nft_ok=1
  if sshd -T 2>/dev/null | grep -qi '^permitrootlogin no' \
     && sshd -T 2>/dev/null | grep -qi '^passwordauthentication no'; then auth_ok=1; fi
  ss -tlnH 2>/dev/null | grep -qE ':22\b' && legacy=1

  if (( !fw_ok || !nft_ok )); then printf 'S0'; return; fi
  if (( !auth_ok || legacy ));    then printf 'S1'; return; fi
  if [[ -f "$SRC/.stage3-verified" ]] \
     && [[ "$(cat "$SRC/.stage3-verified" 2>/dev/null)" == "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)" ]]; then
    printf 'S3'; return
  fi
  printf 'S2'
}

# 判断某端口是否在监听（只看监听，不看是否可连）
port_listening() { ss -tlnH 2>/dev/null | grep -qE "[:.]$1\b"; }

# 取当前会话的来源 IP；sudo 的 env_reset 会清掉 SSH_CLIENT，故沿父进程链找
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

# ip_in_cidrs <ip> <cidr...>
ip_in_cidrs() {
  local ip="$1"; shift
  python3 - "$ip" "$@" <<'PY' 2>/dev/null
import ipaddress, sys
try:
    a = ipaddress.ip_address(sys.argv[1])
except ValueError:
    sys.exit(2)
for c in sys.argv[2:]:
    try:
        if a in ipaddress.ip_network(c, strict=False):
            sys.exit(0)
    except ValueError:
        pass
sys.exit(1)
PY
}

# ─────────────────────────────────────────────────────────────────────────
#                              第一步：建立安全通道
# ─────────────────────────────────────────────────────────────────────────

CHECK_FAILED=0
CHECKS=()          # "状态|描述|建议" —— 用于最后汇总成表

rec()    { CHECKS+=("$1|$2|${3:-}"); }
c_ok()   { ok "$1";   rec "OK"   "$1"; }
c_fail() { fail "$1"; CHECK_FAILED=$((CHECK_FAILED+1)); rec "FAIL" "$1" "${2:-}"; }
c_warn() { warn "$1"; rec "WARN" "$1" "${2:-}"; }

run_checks() {
  sub "前置检查（只读，不做任何修改）"

  # 1. 权限
  if [[ $EUID -eq 0 ]]; then
    c_ok "以 root 运行"
  else
    c_fail "不是以 root 运行" "脚本内部直接调 nft/sshd/systemctl，不会自己 sudo；请用 sudo 运行"
  fi

  # 2. 管理账户存在且在 sudo 组
  if id "$USERNAME" >/dev/null 2>&1; then
    if id -nG "$USERNAME" 2>/dev/null | tr ' ' '\n' | grep -qx sudo; then
      c_ok "账户 $USERNAME 存在且在 sudo 组"
    else
      c_fail "账户 $USERNAME 不在 sudo 组" "本脚本只检查不代建：请先把它加入 sudo 组"
    fi
  else
    c_fail "账户 $USERNAME 不存在" "本脚本只检查不代建：请先创建该账户并加入 sudo 组"
  fi

  # 3. 该账户有可解析的公钥（用 ssh-keygen 解析，不是数行数 —— 空行/注释/CR 都会骗过 grep -c）
  local home k
  home="$(getent passwd "$USERNAME" 2>/dev/null | cut -d: -f6)"
  if [[ -n "$home" && -r "$home/.ssh/authorized_keys" ]]; then
    k="$(ssh-keygen -lf "$home/.ssh/authorized_keys" 2>/dev/null | wc -l)"
    if (( k > 0 )); then
      c_ok "账户 $USERNAME 有 $k 条可解析公钥"
    else
      c_fail "账户 $USERNAME 的 authorized_keys 里没有可解析的公钥" \
               "本脚本只检查不代建：请先为该账户安装公钥"
    fi
  else
    c_fail "读不到 $USERNAME 的 authorized_keys" "本脚本只检查不代建：请先为该账户安装公钥"
  fi

  # 4. 来源自检 —— 本步的命门。来源若不在白名单内，改完当场失联。
  local src_ip
  if src_ip="$(find_ssh_client)"; then
    if ip_in_cidrs "$src_ip" "${ALLOWS[@]}"; then
      c_ok "当前会话来源 $src_ip 在白名单内"
    else
      c_fail "当前会话来源 $src_ip 不在白名单内" \
               "这会把自己关在门外：请把该来源加入 --allow，或换一条在白名单内的通道"
    fi
  else
    c_warn "无法确定会话来源（非 SSH 登录，或 sudo 清空了环境）" \
             "无法预检「会不会把自己关在门外」；请自行确认本机来源在白名单内"
  fi

  # 5. 兜底通道 —— 出事时还能不能回来
  if grep -q 'AuthorizedKeysCommand.*instance_connect\|AuthorizedKeysCommand.*ecs_config' /etc/ssh/sshd_config 2>/dev/null; then
    c_ok "云厂商控制台通道在位（AuthorizedKeysCommand 已配置）"
  else
    c_warn "未发现云厂商控制台通道" "请确认 VNC / 控制台救援可用，且其登录名不是 root"
  fi

  # 6. 备份可写
  if mkdir -p "$BACKUP_ROOT" 2>/dev/null && [[ -w "$BACKUP_ROOT" ]]; then
    c_ok "备份目录可写: $BACKUP_ROOT"
  else
    c_fail "备份目录不可写: $BACKUP_ROOT" "备份失败必须中止，不能「没备成也接着改」"
  fi

  # 7. 语法预校验
  if command -v nft >/dev/null 2>&1; then
    c_ok "nft 可用: $(nft --version 2>/dev/null | head -1)"
  else
    c_fail "找不到 nft" "本方案依赖 nftables"
  fi
  if sshd -t 2>/dev/null; then
    c_ok "当前 sshd 配置语法正确"
  else
    c_fail "当前 sshd 配置语法有错" "先修好现有配置，本脚本不做抢救"
  fi
  if command -v fail2ban-client >/dev/null 2>&1; then
    c_ok "fail2ban 可用"
  else
    c_warn "找不到 fail2ban-client" "fail2ban 端口对齐步骤会被跳过"
  fi

  # 8. 目标端口可用性
  if port_listening "$PORT"; then
    local who
    who="$(ss -tlnpH 2>/dev/null | grep -E "[:.]$PORT\b" | head -1)"
    if printf '%s' "$who" | grep -qi sshd; then
      c_ok "目标端口 $PORT 已在监听（sshd，本步将是幂等重跑）"
    else
      c_fail "目标端口 $PORT 已被其他服务占用" "换一个端口，或先腾出 $PORT"
    fi
  else
    c_ok "目标端口 $PORT 空闲"
  fi
}

print_dry_run_table() {
  sub "预期状态 vs 当前状态"
  printf '   %-4s %-44s %s\n' "" "检查项" "结论 / 建议"
  printf '   %s\n' "────────────────────────────────────────────────────────────────"
  local e d adv
  for e in "${CHECKS[@]}"; do
    IFS='|' read -r s d adv <<< "$e"
    printf '   %-4s %-44s %s\n' "[$s]" "$d" "${adv:-—}"
  done
}

print_plan() {
  sub "本步将改动的项"
  cat <<PLAN
   文件                                    动作
   ────────────────────────────────────── ──────────────────────────────
   /etc/nftables.d/ssh-allowlist.nft      新建/重写（来源白名单）
   /usr/local/sbin/ssh-allowlist-apply.sh 新建/重写（加载器）
   /etc/systemd/system/ssh-firewall.service 新建/重写（开机加载单元）
   /etc/ssh/sshd_config.d/99-hardening.conf 写入 Port $(all_ports)
   /etc/systemd/system/ssh.socket.d/override.conf 各端口绑 v4+v6
   /etc/fail2ban/jail.d/sshd.local        端口对齐（按 sshd -T 实际值）

   执行顺序（不可调换）：
     1) 写防火墙三件套 → enable --now → 确认表已加载
     2) 再改 sshd 端口与 socket 绑定
     先切监听而防火墙未生效 = 敞开的窗口。
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

gen_nft_rules() {
  local f="$1" a
  {
    printf '#!/usr/sbin/nft -f\n'
    printf '# SSH 来源白名单 —— 由 stage1.sh 生成于 %s\n' "$(date -Is)"
    printf '# 只匹配本机 SSH 端口，不影响其他服务与出向流量。\n'
    printf '# policy accept：本表未匹配的流量一律放行，失败方向是「不拦」而非「断网」。\n'
    printf '# 末尾 counter drop：对本端口而言本表是默认拒绝，白名单是唯一入口。\n'
    printf '\n'
    printf 'table inet %s {\n' "$NFT_TABLE"
    printf '\tchain input {\n'
    printf '\t\ttype filter hook input priority -100; policy accept;\n'
    printf '\t\t# 回环隐式放行（fail2ban、本机自检、脚本自身验证都依赖它）\n'
    printf '\t\t# 每条规则都带 counter：既能看见「挡了多少」，也能看见「放了多少、被谁放的」\n'
    printf '\t\tip  saddr 127.0.0.1          tcp dport %s counter accept\n' "$(port_set)"
    printf '\t\tip6 saddr ::1                tcp dport %s counter accept\n' "$(port_set)"
    for a in "${ALLOWS[@]}"; do
      local fam
      if [[ "$a" == *:* ]]; then fam="ip6"; else fam="ip"; fi
      printf '\t\t%s saddr %-22s tcp dport %s counter accept\n' "$fam" "$a" "$(port_set)"
    done
    printf '\t\ttcp dport %s ct state established,related counter accept\n' "$(port_set)"
    printf '\t\ttcp dport %s counter drop\n' "$(port_set)"
    printf '\t}\n}\n'
  } > "$f"
}

gen_loader() {
  cat > "$1" <<LOADER
#!/usr/bin/env bash
# 加载 SSH 来源白名单（幂等，可重复执行）
# 开机时网卡/覆盖网络可能尚未就绪，故带重试；失败则返回非 0，
# ssh.socket 因 Requires= 而不会启动 —— 失败方向是「不开 SSH」而非「放开 SSH」。
#
# 幂等实现：nft 1.0.9 不支持 \`if exists\` / \`destroy\`，故用 list + delete
# 两个基础命令：先删旧表，确认删干净，再加载新表。
set -u
RULES=$NFT_RULES
ERR=/run/ssh-allowlist.err
NFT=/usr/sbin/nft
TABLENAME="inet $NFT_TABLE"
: >"\$ERR"

for i in \$(seq 1 30); do
	if "\$NFT" list table \$TABLENAME >/dev/null 2>&1; then
		if ! "\$NFT" delete table \$TABLENAME >>"\$ERR" 2>&1; then
			echo "ssh-allowlist: 旧表删除失败，见 \$ERR" >&2; exit 1
		fi
		if "\$NFT" list table \$TABLENAME >/dev/null 2>&1; then
			echo "ssh-allowlist: 旧表删除后仍存在，拒绝加载（避免规则重复）" >&2; exit 1
		fi
	fi
	if "\$NFT" -f "\$RULES" >>"\$ERR" 2>&1; then
		echo "ssh-allowlist 加载成功（第 \$i 次尝试）"; exit 0
	fi
	sleep 1
done
echo "ssh-allowlist 加载失败：\$(tail -3 "\$ERR" 2>/dev/null)" >&2
exit 1
LOADER
}

gen_fw_unit() {
  cat > "$1" <<UNIT
[Unit]
Description=SSH 来源白名单 (nftables inet $NFT_TABLE)
Documentation=file:$NFT_RULES
Before=ssh.socket
After=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$NFT_LOADER

[Install]
WantedBy=sockets.target
UNIT
}

gen_sshd_dropin() {
  {
    printf '# SSH 加固配置 —— 由 stage1.sh 生成于 %s\n' "$(date -Is)"
    printf '# 监听端口：%s\n' "$(all_ports)"
    printf '# 监听地址：通配，不绑定具体 IP —— 若绑具体 IP，换网络环境后可能整体失联\n'
    printf '# 来源限制：由 nftables 表 inet %s 按网段白名单控制\n' "$NFT_TABLE"
    printf '# 注意：Port 是「多值」指令，所有取值会累加；一条都不写时 sshd 会补上默认的 22。\n'
    printf '#       所以要监听的端口必须在这里显式列全。\n'
    for p in $(all_ports); do printf 'Port %s\n' "$p"; done
  } > "$1"
}

gen_socket_override() {
  {
    printf '[Unit]\n'
    printf '# 失败方向：Require 白名单防火墙。加载失败 => ssh.socket 不启动 => SSH 不对外提供。\n'
    printf 'Requires=ssh-firewall.service\n'
    printf 'After=ssh-firewall.service\n'
    printf '\n'
    printf '[Socket]\n'
    printf '# 清空继承自 /usr/lib/systemd/system/ssh.socket 的默认监听\n'
    printf 'ListenStream=\n'
    printf '# 必须与 sshd_config 的 Port 集合保持一致：\n'
    printf '# sshd-socket-generator 会从 sshd_config 的 Port 反推 ListenStream，\n'
    printf '# 两边不一致时最终监听集合难以预测，所以这里始终成对写入。\n'
    for p in $(all_ports); do
      printf 'ListenStream=0.0.0.0:%s\n' "$p"
      printf 'ListenStream=[::]:%s\n' "$p"
    done
  } > "$1"
}

do_apply() {
  local tmp
  tmp="$(mktemp -d)" || die "无法创建临时目录"
  trap 'rm -rf "$tmp"' EXIT

  sub "阶段 A · 防火墙（必须先于端口切换）"
  gen_nft_rules    "$tmp/ssh-allowlist.nft"
  gen_loader       "$tmp/ssh-allowlist-apply.sh"
  gen_fw_unit      "$tmp/ssh-firewall.service"

  if ! nft -c -f "$tmp/ssh-allowlist.nft" 2>"$tmp/nft.err"; then
    fail "nft 语法校验未通过：$(cat "$tmp/nft.err")"
    die "中止（未做任何修改）"
  fi
  ok "nft 语法校验通过"

  backup_begin
  backup_file "$NFT_RULES"; backup_file "$NFT_LOADER"; backup_file "$FW_UNIT"
  backup_file "$SSHD_DROPIN"; backup_file "$SSH_SOCKET_OVERRIDE"; backup_file "$F2B_JAIL"

  mkdir -p /etc/nftables.d
  install -m 0644 -o root -g root "$tmp/ssh-allowlist.nft"    "$NFT_RULES"
  install -m 0755 -o root -g root "$tmp/ssh-allowlist-apply.sh" "$NFT_LOADER"
  install -m 0644 -o root -g root "$tmp/ssh-firewall.service" "$FW_UNIT"
  act "已安装 nft 规则 / 加载器 / systemd 单元"

  systemctl daemon-reload
  systemctl enable ssh-firewall.service >/dev/null 2>&1
  if ! systemctl restart ssh-firewall.service; then
    fail "防火墙加载失败"
    die "中止（此时 sshd 尚未改动，SSH 仍按原样，安全。可执行 --rollback）"
  fi
  if ! nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
    fail "表 inet $NFT_TABLE 未生效"
    die "中止（sshd 尚未改动）"
  fi
  if ! nft list table inet "$NFT_TABLE" 2>/dev/null | grep -q 'counter'; then
    fail "白名单缺少兜底 drop —— 此时若切通配监听就没有防线"
    die "中止（sshd 尚未改动）"
  fi
  ok "inet $NFT_TABLE 已加载，含兜底 drop"

  sub "阶段 B · sshd 端口与 socket 绑定"
  gen_sshd_dropin     "$tmp/99-hardening.conf"
  gen_socket_override "$tmp/override.conf"
  install -m 0644 -o root -g root "$tmp/99-hardening.conf" "$SSHD_DROPIN"
  install -m 0644 -o root -g root "$tmp/override.conf"     "$SSH_SOCKET_OVERRIDE"

  if ! sshd -t -f /etc/ssh/sshd_config; then
    fail "sshd -t 未通过，回滚"
    do_rollback "$MANIFEST"; exit 1
  fi
  ok "sshd 配置语法正确"

  # socket 单元有缓存：不 daemon-reload 就 restart 会沿用旧 ListenStream
  systemctl daemon-reload
  if ! systemctl restart ssh.socket; then
    fail "ssh.socket 重启失败，回滚"
    do_rollback "$MANIFEST"; exit 1
  fi
  sleep 1
  systemctl is-failed --quiet ssh.socket && { fail "ssh.socket 处于 failed，回滚"; do_rollback "$MANIFEST"; exit 1; }

  # 比对 systemd 实际 Listen 条数与文件是否一致（缓存没刷新会在这里暴露）
  local want got
  want="$(grep -cE '^ListenStream=(0\.0\.0\.0|\[::\]):' "$SSH_SOCKET_OVERRIDE")"
  got="$(systemctl show ssh.socket -p Listen --value 2>/dev/null | grep -c Stream)"
  if [[ "$want" -ne "$got" ]]; then
    fail "单元文件写了 $want 条监听，systemd 实际 $got 条 —— 缓存未刷新，回滚"
    do_rollback "$MANIFEST"; exit 1
  fi
  ok "systemd 实际监听 $got 条，与配置文件一致"

  sub "阶段 C · fail2ban 端口对齐"
  if command -v fail2ban-client >/dev/null 2>&1 && [[ -f "$F2B_JAIL" ]]; then
    local ports
    ports="$(sshd -T 2>/dev/null | awk '$1=="port"{printf "%s%s",sep,$2; sep=","}')"
    if [[ -n "$ports" ]]; then
      if grep -qE '^\s*port\s*=' "$F2B_JAIL"; then
        sed -i -E "s/^[[:space:]]*port[[:space:]]*=.*/port     = $ports/" "$F2B_JAIL"
      else
        sed -i -E "s/^\[sshd\]/[sshd]\nport    = $ports/" "$F2B_JAIL"
      fi
      fail2ban-client reload >/dev/null 2>&1 && ok "fail2ban port = $ports" || warn "fail2ban reload 失败（不影响 SSH 可用性）"
    fi
  else
    skip "无 fail2ban，跳过端口对齐"
  fi
}

# ─────────────────────── 验证 ───────────────────────

do_verify() {
  sub "验证"
  local bad=0

  local p
  for p in $(all_ports); do
    if port_listening "$p"; then
      if ss -tlnH 2>/dev/null | grep -qE '0\.0\.0\.0:'"$p"'\b|\*:'"$p"'\b'; then
        ok "端口 $p 正在通配监听"
      else
        warn "端口 $p 在监听但不是通配 —— 确认是否符合预期"
      fi
    else
      fail "端口 $p 未监听"; bad=1
    fi
  done

  nft list table inet "$NFT_TABLE" >/dev/null 2>&1 \
    && ok "nft 表 inet $NFT_TABLE 在位" || { fail "nft 表丢失"; bad=1; }

  systemctl is-active --quiet ssh-firewall.service \
    && ok "ssh-firewall 运行中" || { fail "ssh-firewall 未运行"; bad=1; }
  systemctl is-enabled --quiet ssh-firewall.service 2>/dev/null \
    && ok "ssh-firewall 已设开机自启" || warn "ssh-firewall 未设开机自启（第三步会固化）"

  local eff want
  eff="$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -n | tr '\n' ' ' | sed 's/ $//')"
  want="$(all_ports | tr ' ' '\n' | sort -n | tr '\n' ' ' | sed 's/ $//')"
  if [[ "$eff" == "$want" ]]; then
    ok "sshd 生效端口 = $eff"
  else
    fail "sshd 生效端口 =「$eff」，期望「$want」"; bad=1
  fi

  # 本机回环真实连一次（走 127.0.0.1，白名单里显式放行）
  for p in $(all_ports); do
    if timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/$p" 2>/dev/null; then
      ok "本机回环可连 $p"
    else
      fail "本机回环连不上 $p —— 白名单可能把回环也拦了"; bad=1
    fi
  done

  note "下面这一步必须由你从**另一台机器**验证，脚本无法代劳："
  note "    ssh -p $PORT $USERNAME@<本机地址>"
  note "  并确认你自己指定的白名单来源确实能连上。"

  (( bad == 0 ))
}

# ─────────────────────── 主流程 ───────────────────────

hdr "$SELF · 第一步：建立安全通道"

require_root

if (( DO_ROLLBACK )); then
  prev="$(newest_manifest_dir)" || die "找不到任何备份目录: $BACKUP_ROOT"
  do_rollback "$prev"
  exit 0
fi

require_params

STAGE="$(detect_stage)"
sub "阶段检测"
inf "当前阶段：$STAGE"
case "$STAGE" in
  S0) inf "未加固 —— 本步适用 ✅" ;;
  S1) inf "通道已建 —— 本步为幂等重跑 ✅" ;;
  S2) inf "认证已收口 —— 本步会把认证策略倒退回去 ❌"
      die "拒绝执行。若确需重做通道，请先执行 stage2.sh --rollback" ;;
  S3) inf "已固化验证 —— 本步会把状态倒退回去 ❌"
      die "拒绝执行。若确需重做，请依次回滚 stage3 / stage2 后再来" ;;
  *)  die "无法识别阶段：$STAGE" ;;
esac

run_checks
print_dry_run_table

if (( ! APPLY )); then
  print_plan
  conclude || true
  printf '\n   %s这是只读检查（默认行为）。加 --apply 才会真正执行。%s\n\n' "$C_B" "$C_RST"
  exit 0
fi

conclude || { printf '\n   未做任何修改。\n\n'; exit 1; }

if (( ! ASSUME_YES )); then
  printf '\n   %s即将执行变更。当前会话来源：%s%s\n' "$C_WARN" "$(find_ssh_client 2>/dev/null || echo '未知')" "$C_RST"
  printf '   %s请确认你另有一条可用通道，然后输入 yes 继续：%s ' "$C_WARN" "$C_RST"
  read -r a
  [[ "$a" == "yes" ]] || { printf '   已取消。\n\n'; exit 1; }
fi

do_apply

if do_verify; then
  printf '\n   %s✅ 第一步完成。%s\n' "$C_OK" "$C_RST"
  printf '   备份：%s\n' "$MANIFEST"
  printf '   回滚：%s --rollback\n' "$SRC/$SELF"
  printf '   下一步：用 --user 指定的账户、从**另一台机器**登录新端口成功后，\n'
  printf '           再执行 stage2.sh（认证收口）。\n\n'
else
  printf '\n   %s✗ 验证未通过。%s\n' "$C_FAIL" "$C_RST"
  printf '   可执行 %s --rollback 回滚。备份：%s\n\n' "$SRC/$SELF" "$MANIFEST"
  exit 1
fi