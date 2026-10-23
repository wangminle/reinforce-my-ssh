#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  stage2.sh —— 远程 SSH 加固 · 第二步：认证收口
# ═══════════════════════════════════════════════════════════════════════════
#
#  【这一步做什么】
#    把「谁能登录、用什么方式登录」收口：
#      1) PermitRootLogin no        切断 root 直连，强制走普通账户 + sudo
#      2) PasswordAuthentication no 只留公钥认证
#      3) 关闭旧端口                 监听集合收窄到只剩新端口
#    本步做完，SSH 的攻击面从「端口 × 账户 × 认证方式」三个维度同时收窄，
#    且所有特权操作都会在 sudo 审计里留痕。
#
#  【什么时候能跑】
#    当前处于 S1（通道已建）或 S2（本步已完成，幂等重跑）。
#    处于 S0 时先跑 stage1.sh；处于 S3 时本脚本**拒绝执行**（会把固化成果倒退）。
#
#  【参数的含义】（脚本里的注释就是手册）
#    --port <n>       必填。**保留**的 SSH 端口（即第一步建立的那个新端口）。
#    --old-port <n>   可选，默认 22。本步要**关闭**的旧端口；none 表示没有要关的。
#                     这个参数只影响「关哪些端口」，不影响认证策略。
#    --user <name>    必填。日常管理用的非 root 账户（须已存在、在 sudo 组、有公钥）。
#    --allow <cidr>   可选，可重复。白名单来源网段，用于重写 nft 规则。
#                     不提供时会从现有的 nft 规则里**自动提取**并打印出来供你核对。
#    --conf <file>    可选。从文件读默认值（每行 KEY=VALUE，# 开头为注释）。
#    --apply          实际执行。**不加这个参数时脚本只读不改**（默认行为）。
#    --yes            跳过交互确认（用于无人值守）。
#    --rollback       按最近一次备份还原。
#
#  【为什么有一道「活跃会话」闸门】
#    关掉旧端口之后，如果新端口有问题，你就没有第二条路进来了。
#    所以本脚本强制要求：必须已有一条走**新端口**的活跃连接，否则拒绝执行。
#    这是整个方案里唯一一道「不满足就绝不往下走」的硬闸门。
#
#  【为什么验证要「自校准」】
#    黑盒探针（本机回环发起连接，读服务端宣告的认证方式）必须先证明它
#    在改动**之前**能看到 password —— 否则改动后「看不到 password」
#    可能只是因为探针根本没工作。没有校准的通过，等于没验证。
#
#  【典型用法】
#    ./stage2.sh --port 2222 --user deploy                                   # 只检查
#    ./stage2.sh --port 2222 --user deploy --apply                           # 执行
#    ./stage2.sh --rollback                                                  # 回滚
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
DROPIN_ROOT=/etc/ssh/sshd_config.d/10-permit-root-login.conf
DROPIN_PASS=/etc/ssh/sshd_config.d/20-disable-password-auth.conf
NFT_RULES=/etc/nftables.d/ssh-allowlist.nft
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
用法: stage2.sh --port <n> --user <name> [--old-port <n>] [--allow <cidr>...] [选项]

必填:
  --port <n>        保留的 SSH 端口（第一步建立的那个）
  --user <name>     日常管理用的非 root 账户（须已存在、在 sudo 组、有公钥）

选项:
  --old-port <n>    要关闭的旧端口，默认 22；none 表示没有要关的
  --allow <cidr>    白名单来源网段，可重复；不提供则从现有 nft 规则自动提取
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

if [[ -n "$CONF" ]]; then
  [[ -r "$CONF" ]] || die "配置文件不可读: $CONF"
  while IFS='=' read -r k v; do
    k="${k%%#*}"; k="$(printf '%s' "$k" | tr -d '[:space:]')"
    v="$(printf '%s' "$v" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "$k" || -z "$v" ]] && continue
    case "$k" in
      PORT)     [[ -z "$PORT" ]]      && PORT="$v" ;;
      OLD_PORT) [[ "$OLD_PORT" == "22" ]] && OLD_PORT="$v" ;;
      USER)     [[ -z "$USERNAME" ]]  && USERNAME="$v" ;;
      ALLOW)    ALLOWS+=("$v") ;;
    esac
  done < "$CONF"
fi

require_params() {
  local miss=0
  [[ -z "$PORT" ]]     && { fail "--port 未提供"; miss=1; }
  [[ -z "$USERNAME" ]] && { fail "--user 未提供"; miss=1; }
  if [[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT < 1 || PORT > 65535 )); then
    fail "--port 非法: $PORT"; miss=1
  fi
  if [[ "$OLD_PORT" != "none" ]] && ! [[ "$OLD_PORT" =~ ^[0-9]+$ ]]; then
    fail "--old-port 非法: $OLD_PORT（应为端口号或 none）"; miss=1
  fi
  if [[ "$OLD_PORT" != "none" && "$OLD_PORT" == "$PORT" ]]; then
    fail "--old-port 与 --port 相同（$PORT）"; miss=1
  fi
  if (( miss )); then
    printf '\n'
    die "参数不完整。用 -h 看用法，完整说明见脚本头部注释。"
  fi
}

# ─────────────────────── 共享框架 · 3. 备份与回滚 ───────────────────────

TS=""; MANIFEST=""

backup_begin() {
  TS="$(date +%Y%m%d-%H%M%S)"
  MANIFEST="$BACKUP_ROOT/$TS"
  if ! mkdir -p "$MANIFEST" 2>/dev/null; then
    die "无法创建备份目录 $MANIFEST —— 备份失败必须中止，不能「没备成也接着改」"
  fi
  [[ -w "$MANIFEST" ]] || die "备份目录不可写 $MANIFEST —— 同上，中止"
  : > "$MANIFEST/MANIFEST"
  ok "备份目录 $MANIFEST"
}

backup_file() {
  local f="$1" base
  base="$(printf '%s' "$f" | tr '/' '_')"
  if [[ -e "$f" ]]; then
    cp -p "$f" "$MANIFEST/$base" 2>/dev/null || die "备份失败: $f —— 中止（不留半个改动）"
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
  local d="$1" kind orig base
  [[ -f "$d/MANIFEST" ]] || die "备份目录里没有 MANIFEST: $d"
  hdr "回滚 · 依据 $d/MANIFEST"
  while read -r kind orig base; do
    [[ -z "${orig:-}" ]] && continue
    if [[ "$kind" == "EXIST" ]]; then
      cp -f "$d/$base" "$orig" 2>/dev/null && act "还原 $orig" || fail "还原失败 $orig"
    else
      if [[ -e "$orig" ]]; then rm -f "$orig" && act "删除 $orig（原本不存在）"; else skip "$orig 本就不存在"; fi
    fi
  done < "$d/MANIFEST"
  if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
    # nft 表内容不在 MANIFEST 里（它是内核态），从备份的规则文件重载
    local nb; nb="$(ls -1 "$d"/etc_nftables.d_ssh-allowlist.nft 2>/dev/null | head -1)"
    if [[ -n "$nb" ]] && nft -f "$nb" 2>/dev/null; then
      act "已按备份重载 nft 规则"
    fi
  fi
  systemctl daemon-reload 2>/dev/null || true
  systemctl restart ssh.socket 2>/dev/null || true
  printf '\n'
  ok "回滚完成"
  inf "当前监听："
  ss -tlnH 2>/dev/null | awk '{print $4}' | grep -E ':[0-9]+$' | sort -u | sed 's/^/        /'
}

# ─────────────────────── 共享框架 · 4. 状态探测 ───────────────────────

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
  systemctl is-active --quiet ssh-firewall.service 2>/dev/null && fw_ok=1
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

port_listening() { ss -tlnH 2>/dev/null | grep -qE "[:.]$1\b"; }

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

# 从现有 nft 规则文件里提取白名单网段（用于 --allow 未提供时）
extract_allows() {
  grep -oE 'saddr[[:space:]]+[0-9a-fA-F:.]+(/[0-9]+)?' "$NFT_RULES" 2>/dev/null \
    | awk '{print $2}' | grep -vE '^(127\.0\.0\.1|::1)$' | sort -u
}

# 黑盒探针：从本机回环发一次真实连接，读服务端宣告的认证方式。
# 两个坑，缺一不可：
#   1) 'Authentications that can continue' 是 debug1 级消息，必须 -v（LogLevel=DEBUG）
#      才输出；LogLevel=VERBOSE 级别不够，那一行根本取不到。
#   2) ssh 客户端在非 tty 下输出的行尾会多带一个回车符（CR），会被一并取到。
#      所以下面用字符类 [a-z,]* 而不是 .*，借字符类把 CR 挡在匹配之外。
probe_line() {
  local u="$1"
  ssh -v -p "$PORT" -o PreferredAuthentications=password -o PubkeyAuthentication=no -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 "$u@127.0.0.1" true 2>&1 | grep -oE 'Authentications that can continue: [a-z,]*' | head -1
}

# ─────────────────────────────────────────────────────────────────────────
#                              第二步：认证收口
# ─────────────────────────────────────────────────────────────────────────

CHECK_FAILED=0
CHECKS=()

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

  # 2. 硬闸门：必须已有一条走新端口的活跃连接
  local alive pts
  alive="$(ss -tnH state established '( sport = :'"$PORT"' )' 2>/dev/null | wc -l)"
  pts="$(who 2>/dev/null | grep -c 'pts/' || true)"
  if (( alive > 0 )); then
    c_ok "端口 $PORT 上有 $alive 条活跃连接"
    if (( pts > 0 )); then
      c_ok "存在 $pts 个交互式会话（pts）—— 关旧端口后仍有路可回"
    else
      c_warn "没有交互式会话（pts），只有命令式连接" \
             "命令式连接随命令结束即断；建议先另开一个终端登进来再执行"
    fi
  else
    c_fail "端口 $PORT 上没有任何活跃连接" \
           "关掉旧端口后若出问题就没有回头路。请先另开终端：ssh -p $PORT $USERNAME@<地址>，保持该会话不断，再重跑"
  fi

  # 3. 管理账户
  if id "$USERNAME" >/dev/null 2>&1; then
    if id -nG "$USERNAME" 2>/dev/null | tr ' ' '\n' | grep -qx sudo; then
      c_ok "账户 $USERNAME 存在且在 sudo 组"
    else
      c_fail "账户 $USERNAME 不在 sudo 组" "本脚本只检查不代建"
    fi
  else
    c_fail "账户 $USERNAME 不存在" "本脚本只检查不代建"
  fi

  local home k
  home="$(getent passwd "$USERNAME" 2>/dev/null | cut -d: -f6)"
  if [[ -n "$home" && -r "$home/.ssh/authorized_keys" ]]; then
    k="$(ssh-keygen -lf "$home/.ssh/authorized_keys" 2>/dev/null | wc -l)"
    if (( k > 0 )); then
      c_ok "账户 $USERNAME 有 $k 条可解析公钥"
    else
      c_fail "账户 $USERNAME 没有可解析的公钥" "关掉密码后就没有登录手段了。本脚本只检查不代建"
    fi
  else
    c_fail "读不到 $USERNAME 的 authorized_keys" "本脚本只检查不代建"
  fi

  # 4. 公钥认证必须可用（否则关密码 = 自锁）
  local pub
  pub="$(sshd -T 2>/dev/null | awk '$1=="pubkeyauthentication"{print $2; exit}')"
  if [[ "$pub" == "yes" ]]; then
    c_ok "PubkeyAuthentication=yes（关掉密码后仍能进来）"
  else
    c_fail "PubkeyAuthentication=$pub —— 关掉密码会自锁" "先把它改回 yes"
  fi

  # 5. KbdInteractive 必须关 —— 否则密码可经 PAM 绕过后面的改动
  local kbd
  kbd="$(sshd -T 2>/dev/null | awk '$1=="kbdinteractiveauthentication"{print $2; exit}')"
  if [[ "$kbd" == "no" ]]; then
    c_ok "KbdInteractiveAuthentication=no（无 PAM 密码旁路）"
  else
    c_fail "KbdInteractiveAuthentication=$kbd —— 密码仍可经 PAM 登录，本步改动会无效" \
           "先把它设为 no（这是 PasswordAuthentication no 能否真正生效的前提）"
  fi

  # 6. 云厂商兜底通道
  if grep -q 'AuthorizedKeysCommand.*instance_connect\|AuthorizedKeysCommand.*ecs_config' /etc/ssh/sshd_config 2>/dev/null; then
    c_ok "云厂商控制台通道在位（AuthorizedKeysCommand 已配置）"
  else
    c_warn "未发现云厂商控制台通道" "请确认 VNC / 控制台救援可用，且其登录名不是 root"
  fi

  # 7. 备份可写
  if mkdir -p "$BACKUP_ROOT" 2>/dev/null && [[ -w "$BACKUP_ROOT" ]]; then
    c_ok "备份目录可写: $BACKUP_ROOT"
  else
    c_fail "备份目录不可写: $BACKUP_ROOT" "备份失败必须中止"
  fi

  # 8. 语法
  if sshd -t 2>/dev/null; then
    c_ok "当前 sshd 配置语法正确"
  else
    c_fail "当前 sshd 配置语法有错" "先修好现有配置"
  fi

  # 9. 白名单网段可得
  if (( ${#ALLOWS[@]} == 0 )); then
    mapfile -t ALLOWS < <(extract_allows)
    if (( ${#ALLOWS[@]} > 0 )); then
      c_ok "从现有 nft 规则提取到 ${#ALLOWS[@]} 个网段（未提供 --allow）"
      inf "提取结果：${ALLOWS[*]}"
    else
      c_fail "没有白名单网段，也无法从现有规则提取" "请显式提供 --allow"
    fi
  else
    c_ok "白名单网段由命令行提供：${#ALLOWS[@]} 个"
  fi

  # 10. 探针自校准 —— 证明探针本身工作
  local pre
  pre="$(probe_line root)"
  if [[ -z "$pre" ]]; then
    c_fail "黑盒探针取不到认证方式列表（探针本身有问题）" \
           "没有可靠探针，「验证通过」就没有意义。检查 ssh 客户端与回环可达性"
  elif [[ "$pre" == "Authentications that can continue: publickey,password" ]]; then
    c_ok "探针自校准通过（改动前服务端提供：publickey,password）"
  elif [[ "$pre" == "Authentications that can continue: publickey" ]]; then
    c_ok "探针自校准通过（密码通道已是关闭状态 —— 本步为幂等重跑）"
  else
    c_fail "探针取到意外结果：$pre" "无法据此判断改动效果"
  fi
}

print_dry_run_table() {
  sub "预期状态 vs 当前状态"
  printf '   %-6s %-52s %s\n' "" "检查项" "结论 / 建议"
  printf '   %s\n' "────────────────────────────────────────────────────────────────────"
  local e s d adv
  for e in "${CHECKS[@]}"; do
    IFS='|' read -r s d adv <<< "$e"
    printf '   %-6s %-52s %s\n' "[$s]" "$d" "${adv:-—}"
  done
}

print_plan() {
  local cur_root cur_pass
  cur_root="$(sshd -T 2>/dev/null | awk '$1=="permitrootlogin"{print $2; exit}')"
  cur_pass="$(sshd -T 2>/dev/null | awk '$1=="passwordauthentication"{print $2; exit}')"
  sub "本步将改动的项"
  printf '   %-26s %-22s %s\n' "配置项" "当前 → 目标" "落在哪个文件"
  printf '   %s\n' "────────────────────────── ────────────────────── ──────────────────────────────"
  printf '   %-26s %-22s %s\n' "PermitRootLogin"        "$cur_root → no" "$DROPIN_ROOT"
  printf '   %-26s %-22s %s\n' "PasswordAuthentication" "$cur_pass → no" "$DROPIN_PASS"
  printf '   %-26s %-22s %s\n' "监听端口"               "$(cur_port_set) → {$PORT}" "99-hardening.conf + socket override"
  printf '   %-26s %-22s %s\n' "nft 白名单端口"         "$(cur_port_set) → {$PORT}" "$NFT_RULES"
  printf '   %-26s %-22s %s\n' "fail2ban 端口"          "（对齐实际监听）" "$F2B_JAIL"
  printf '\n'
  inf "执行顺序："
  inf "  A) 写两个认证 drop-in → sshd -t → daemon-reload + restart ssh.socket"
  inf "  B) 收窄端口集合（sshd drop-in / socket override / nft / fail2ban）"
  inf "  C) daemon-reload（socket 单元有缓存，不 reload 会「文件改了端口没变」）"
}

# 当前实际监听的端口集合（去掉回环/内部端口）
cur_port_set() {
  sshd -T 2>/dev/null | awk '$1=="port"{printf "%s%s",sep,$2; sep=", "}' | sed 's/^/{/;s/$/}/'
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

gen_dropin_root() {
  {
    printf '# 禁止 root 通过 SSH 直接登录 —— 由 stage2.sh 生成于 %s\n' "$(date -Is)"
    printf '#\n'
    printf '# 生效原理：sshd 对多数指令采用「首次取值优先」，而 Include 的 drop-in\n'
    printf '# 位于 /etc/ssh/sshd_config 第一行，先于主文件正文被解析，因此本文件的\n'
    printf '# no 会覆盖主文件里后面的 PermitRootLogin yes。\n'
    printf '#\n'
    printf '# 为什么这样做：root 凭证一旦泄露，攻击者即完全控制服务器，且特权操作\n'
    printf '# 不留可审计的痕迹。改为「普通账户 + sudo」后权限等价，但每一步提权都\n'
    printf '# 在 sudo 审计里留痕，操作责任人明确。\n'
    printf '#\n'
    printf '# 影响：Workbench / 控制台一律用普通账户登录后 sudo 提权。\n'
    printf '# 预期噪音：云厂商的「一键诊断 / 成熟度评估」会把本项报为「警告」，\n'
    printf '#           那是合规提示，不是故障 —— 不要照着「修复建议」把它改回去。\n'
    printf '# 回滚：删除本文件后 systemctl restart ssh.socket\n'
    printf 'PermitRootLogin no\n'
  } > "$1"
}

gen_dropin_pass() {
  {
    printf '# 关闭 SSH 密码认证，仅保留公钥 —— 由 stage2.sh 生成于 %s\n' "$(date -Is)"
    printf '#\n'
    printf '# 生效原理：同上，drop-in 先于主配置被解析，覆盖主配置里的\n'
    printf '#           PasswordAuthentication yes。\n'
    printf '#\n'
    printf '# ⚠ 前提条件：KbdInteractiveAuthentication 必须为 no。\n'
    printf '#   若它是 yes，密码仍可经 PAM 的键盘交互通道登录，\n'
    printf '#   本文件的 no 会看起来「生效了」但实际没堵住。\n'
    printf '#\n'
    printf '# 为什么不影响可用性：\n'
    printf '#   - 公网口已关闭（安全组 + nft 双侧），唯一入口是 nft 白名单内的来源\n'
    printf '#   - 管理账户已装配公钥\n'
    printf '#   - 云助手 / 运维编排 / 云监控均为 Agent 通道，不经 sshd\n'
    printf '#   - VNC 走 PAM + login，与 sshd 无关，实例密码仍可用于控制台兜底\n'
    printf '#\n'
    printf '# 影响：① 密码方式 SSH 登录全部失效（含 root）\n'
    printf '#       ② Workbench「终端连接 → 密码认证」失效；「免密连接」不受影响\n'
    printf '# 回滚：删除本文件后 systemctl restart ssh.socket\n'
    printf 'PasswordAuthentication no\n'
  } > "$1"
}

gen_sshd_dropin() {
  {
    printf '# SSH 加固配置 —— 由 stage2.sh 生成于 %s\n' "$(date -Is)"
    printf '# 监听端口：仅 %s（旧端口已在本次收口时关闭）\n' "$PORT"
    printf '# 监听地址：通配，不绑定具体 IP —— 绑具体 IP 后换网络环境可能整体失联\n'
    printf '# 来源限制：由 nftables 表 inet %s 按网段白名单控制\n' "$NFT_TABLE"
    printf '# 注意：Port 是多值指令，取值会累加；一条都不写时 sshd 会补上默认的 22。\n'
    printf 'Port %s\n' "$PORT"
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
    printf '# 必须与 sshd_config 的 Port 集合保持一致：sshd-socket-generator 会从\n'
    printf '# sshd_config 的 Port 反推 ListenStream，两边不一致时结果难以预测。\n'
    printf 'ListenStream=0.0.0.0:%s\n' "$PORT"
    printf 'ListenStream=[::]:%s\n'      "$PORT"
  } > "$1"
}

gen_nft_rules() {
  local f="$1" a fam
  {
    printf '#!/usr/sbin/nft -f\n'
    printf '# SSH 来源白名单 —— 由 stage2.sh 生成于 %s\n' "$(date -Is)"
    printf '# 只匹配本机 SSH 端口，不影响其他服务与出向流量。\n'
    printf '# policy accept：本表未匹配的流量一律放行，失败方向是「不拦」而非「断网」。\n'
    printf '# 末尾 counter drop：对本端口而言本表是默认拒绝，白名单是唯一入口。\n'
    printf '\n'
    printf 'table inet %s {\n' "$NFT_TABLE"
    printf '\tchain input {\n'
    printf '\t\ttype filter hook input priority -100; policy accept;\n'
    printf '\t\t# 回环隐式放行（fail2ban、本机自检、脚本自身验证都依赖它）\n'
    printf '\t\t# 每条规则都带 counter：既能看见「挡了多少」，也能看见「放了多少、被谁放的」\n'
    printf '\t\tip  saddr 127.0.0.1          tcp dport { %s } counter accept\n' "$PORT"
    printf '\t\tip6 saddr ::1                tcp dport { %s } counter accept\n' "$PORT"
    for a in "${ALLOWS[@]}"; do
      if [[ "$a" == *:* ]]; then fam="ip6"; else fam="ip"; fi
      printf '\t\t%s saddr %-22s tcp dport { %s } counter accept\n' "$fam" "$a" "$PORT"
    done
    printf '\t\ttcp dport { %s } ct state established,related counter accept\n' "$PORT"
    printf '\t\ttcp dport { %s } counter drop\n' "$PORT"
    printf '\t}\n}\n'
  } > "$f"
}

do_apply() {
  local tmp
  tmp="$(mktemp -d)" || die "无法创建临时目录"
  trap 'rm -rf "$tmp"' EXIT

  gen_dropin_root "$tmp/10-permit-root-login.conf"
  gen_dropin_pass "$tmp/20-disable-password-auth.conf"
  gen_sshd_dropin "$tmp/99-hardening.conf"
  gen_socket_override "$tmp/override.conf"
  gen_nft_rules "$tmp/ssh-allowlist.nft"

  if ! nft -c -f "$tmp/ssh-allowlist.nft" 2>"$tmp/nft.err"; then
    fail "nft 语法校验未通过：$(cat "$tmp/nft.err")"
    die "中止（未做任何修改）"
  fi
  ok "nft 语法校验通过"

  backup_begin
  backup_file "$DROPIN_ROOT"; backup_file "$DROPIN_PASS"
  backup_file "$SSHD_DROPIN"; backup_file "$SSH_SOCKET_OVERRIDE"; backup_file "$NFT_RULES"
  backup_file "$F2B_JAIL"

  sub "阶段 A · 认证策略"
  install -m 0644 -o root -g root "$tmp/10-permit-root-login.conf"    "$DROPIN_ROOT"
  install -m 0644 -o root -g root "$tmp/20-disable-password-auth.conf" "$DROPIN_PASS"
  act "已写入 $DROPIN_ROOT"
  act "已写入 $DROPIN_PASS"

  if ! sshd -t -f /etc/ssh/sshd_config; then
    fail "sshd -t 未通过，回滚"
    do_rollback "$MANIFEST"; exit 1
  fi
  ok "sshd 配置语法正确"

  systemctl daemon-reload
  systemctl restart ssh.socket || { fail "ssh.socket 重启失败，回滚"; do_rollback "$MANIFEST"; exit 1; }
  sleep 1
  systemctl is-failed --quiet ssh.socket && { fail "ssh.socket 处于 failed，回滚"; do_rollback "$MANIFEST"; exit 1; }

  local eff_root eff_pass
  eff_root="$(sshd -T 2>/dev/null | awk '$1=="permitrootlogin"{print $2; exit}')"
  eff_pass="$(sshd -T 2>/dev/null | awk '$1=="passwordauthentication"{print $2; exit}')"
  [[ "$eff_root" == "no" ]] && ok "生效：PermitRootLogin = no" || { fail "PermitRootLogin=$eff_root 未生效，回滚"; do_rollback "$MANIFEST"; exit 1; }
  [[ "$eff_pass" == "no" ]] && ok "生效：PasswordAuthentication = no" || { fail "PasswordAuthentication=$eff_pass 未生效，回滚"; do_rollback "$MANIFEST"; exit 1; }

  if [[ "$OLD_PORT" != "none" ]]; then
    sub "阶段 B · 关闭旧端口 $OLD_PORT"
    install -m 0644 -o root -g root "$tmp/99-hardening.conf" "$SSHD_DROPIN"
    install -m 0644 -o root -g root "$tmp/override.conf"     "$SSH_SOCKET_OVERRIDE"
    install -m 0644 -o root -g root "$tmp/ssh-allowlist.nft" "$NFT_RULES"
    act "已收窄 sshd drop-in / socket override / nft 规则到 {$PORT}"

    if ! sshd -t -f /etc/ssh/sshd_config; then
      fail "sshd -t 未通过，回滚"; do_rollback "$MANIFEST"; exit 1
    fi

    # socket 单元缓存：必须先 daemon-reload，否则沿用旧 ListenStream
    systemctl daemon-reload
    systemctl restart ssh-firewall.service || { fail "防火墙重载失败，回滚"; do_rollback "$MANIFEST"; exit 1; }
    systemctl restart ssh.socket || { fail "ssh.socket 重启失败，回滚"; do_rollback "$MANIFEST"; exit 1; }
    sleep 1
    systemctl is-failed --quiet ssh.socket && { fail "ssh.socket 处于 failed，回滚"; do_rollback "$MANIFEST"; exit 1; }

    local want got
    want="$(grep -cE '^ListenStream=(0\.0\.0\.0|\[::\]):' "$SSH_SOCKET_OVERRIDE")"
    got="$(systemctl show ssh.socket -p Listen --value 2>/dev/null | grep -c Stream)"
    if [[ "$want" -ne "$got" ]]; then
      fail "单元文件写了 $want 条监听，systemd 实际 $got 条 —— 缓存未刷新，回滚"
      do_rollback "$MANIFEST"; exit 1
    fi
    ok "systemd 实际监听 $got 条，与配置文件一致"
  else
    skip "未指定要关闭的旧端口（--old-port none）"
  fi

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
  local bad=0 u line

  # 黑盒自校准的「后」半段：改动后必须只剩 publickey
  for u in root "$USERNAME"; do
    line="$(probe_line "$u")"
    if [[ -z "$line" ]]; then
      fail "$u：探针取不到认证方式列表"; bad=1
    elif [[ "$line" == "Authentications that can continue: publickey" ]]; then
      ok "$u：服务端只提供 publickey —— 密码通道确已关闭"
    else
      fail "$u：$line"; bad=1
    fi
  done

  # root 必须彻底不能登录
  if ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
         -p "$PORT" -o ConnectTimeout=8 root@127.0.0.1 true >/dev/null 2>&1; then
    fail "root 仍能登录！"; bad=1
  else
    ok "root 已无法登录（密钥与密码均被拒）"
  fi

  local eff_root eff_pass
  eff_root="$(sshd -T 2>/dev/null | awk '$1=="permitrootlogin"{print $2; exit}')"
  eff_pass="$(sshd -T 2>/dev/null | awk '$1=="passwordauthentication"{print $2; exit}')"
  [[ "$eff_root" == "no" ]] && ok "sshd -T: permitrootlogin no" || { fail "permitrootlogin=$eff_root"; bad=1; }
  [[ "$eff_pass" == "no" ]] && ok "sshd -T: passwordauthentication no" || { fail "passwordauthentication=$eff_pass"; bad=1; }

  if port_listening "$PORT"; then ok "端口 $PORT 仍在监听"; else fail "端口 $PORT 未监听"; bad=1; fi

  if [[ "$OLD_PORT" != "none" ]]; then
    if port_listening "$OLD_PORT"; then
      fail "旧端口 $OLD_PORT 仍在监听"; bad=1
    else
      ok "旧端口 $OLD_PORT 已不再监听"
    fi
    if ss -tlnH 2>/dev/null | grep -qE ":$OLD_PORT\b"; then
      fail "仍有进程占用 $OLD_PORT"; bad=1
    fi
  fi

  local want got
  want="$(grep -cE '^ListenStream=(0\.0\.0\.0|\[::\]):' "$SSH_SOCKET_OVERRIDE")"
  got="$(systemctl show ssh.socket -p Listen --value 2>/dev/null | grep -c Stream)"
  [[ "$want" -eq "$got" ]] && ok "socket 监听条数与配置一致（$got）" || { fail "socket 监听 $got 条，期望 $want 条"; bad=1; }

  nft list table inet "$NFT_TABLE" >/dev/null 2>&1 \
    && ok "nft 白名单在位" || { fail "nft 白名单丢失"; bad=1; }

  note "本机验证到此为止。请再从**另一台机器**确认："
  note "    ssh -p $PORT $USERNAME@<地址>     ← 应成功"
  note "    ssh -p $PORT root@<地址>           ← 应被拒"

  (( bad == 0 ))
}

# ─────────────────────── 主流程 ───────────────────────

hdr "$SELF · 第二步：认证收口"

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
  S0) inf "未加固 —— 本步的前提（通道）还不存在 ❌"
      die "拒绝执行。请先跑 stage1.sh 建立新端口与白名单。" ;;
  S1) inf "通道已建 —— 本步适用 ✅" ;;
  S2) inf "认证已收口 —— 本步为幂等重跑 ✅" ;;
  S3) inf "已固化验证 —— 本步会把状态倒退回去 ❌"
      die "拒绝执行。先执行 stage3.sh --rollback 撤销固化，再来。" ;;
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
  printf '\n   %s即将执行变更。%s\n' "$C_WARN" "$C_RST"
  printf '   %s请确认你另有一条走端口 %s 的可用通道，然后输入 yes 继续：%s ' "$C_WARN" "$PORT" "$C_RST"
  read -r a
  [[ "$a" == "yes" ]] || { printf '   已取消。\n\n'; exit 1; }
fi

do_apply

if do_verify; then
  printf '\n   %s✅ 第二步完成。%s\n' "$C_OK" "$C_RST"
  printf '   备份：%s\n' "$MANIFEST"
  printf '   回滚：%s --rollback\n' "$SRC/$SELF"
  printf '   下一步：执行 stage3.sh 做固化与重启验证。\n\n'
else
  printf '\n   %s✗ 验证未通过。%s\n' "$C_FAIL" "$C_RST"
  printf '   可执行 %s --rollback 回滚。备份：%s\n\n' "$SRC/$SELF" "$MANIFEST"
  exit 1
fi