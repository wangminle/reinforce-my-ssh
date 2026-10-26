# reinforce-my-ssh

[English](#english) · [中文](#中文)

## English

SSH hardening for Ubuntu/Debian: audit an existing server, establish a new port, tighten authentication, then verify persistence after a real reboot.

### Scripts

| Entry | Purpose |
| --- | --- |
| [stage0-audit.sh](stage0-audit.sh) | Independent, read-only audit. Reports security findings, management ownership, migration blockers and reboot evidence separately. |
| [stage1-newport.sh](stage1-newport.sh) | Apply the source allowlist and create a candidate SSH port; retain the configured old port until stage2. |
| [stage2-harden.sh](stage2-harden.sh) | Disable root, password and keyboard-interactive login; require public keys and close the old port. |
| [stage3-reboot-check.sh](stage3-reboot-check.sh) | Record a baseline and verify after a real reboot. Does not change SSH/firewall settings or reboot the server. |

Stage0 can run independently; it does not enroll a server. Stages 1–3 use explicit state, policy and transaction records under `/var/lib/reinforce-my-ssh`. Deploy only the **four stage scripts** listed above: the audit implementation is embedded in stage0, with Python 3 still required. Old `stage1.sh` / `stage2.sh` / `stage3.sh` names remain optional compatibility entry points in the repository.

### Before you start

- Use Ubuntu/Debian with systemd, `ssh.socket` (`Accept=no`), `ssh.service` (`KillMode=process`) and IPv4/IPv6 support. Requires Bash, Python 3, OpenSSH, nftables, iproute2 and sudo.
- Log in as a non-root administrator, then use sudo. Direct root SSH login is unnecessary. Prepare the account, public key and cloud firewall rules yourself.
- Keep your current session open and test an independent VNC/serial/agent rescue path. Deployment rejects conflicting unmanaged directives and active `Match` blocks; existing setups should be audited before considering migration.

### Workflow

Examples assume the repository is at `/opt/reinforce-my-ssh`. Replace `SERVER`, `deploy`, `2222` and the documentation CIDR `203.0.113.0/24` with your actual values. Run server commands from that directory.

**Existing server: audit without changing configuration.**

```bash
sudo bash stage0-audit.sh --port 2222 --user deploy \
  --allow 203.0.113.0/24 --closed-port 22
```

Audit exit codes: `0` passed within scope, `1` confirmed noncompliance, `2` insufficient evidence/permissions/support. Missing management records alone do not mean the server is insecure. Use `--format json` for structured output.

**New managed deployment:**

```bash
# Server: check deployment prerequisites, then create the candidate port.
sudo bash stage1-newport.sh --port 2222 --user deploy --allow 203.0.113.0/24
sudo bash stage1-newport.sh --port 2222 --user deploy --allow 203.0.113.0/24 --apply

# Another client terminal: keep the original session open.
ssh -p 2222 deploy@SERVER

# New server session: return to the repository directory.
cd /opt/reinforce-my-ssh
sudo bash stage1-newport.sh --confirm
sudo bash stage2-harden.sh --apply

# Another client terminal: establish a fresh connection again.
ssh -p 2222 deploy@SERVER

# Fresh server session:
cd /opt/reinforce-my-ssh
sudo bash stage2-harden.sh --confirm
sudo bash stage3-reboot-check.sh --apply

# Reboot manually after checking rescue access, then reconnect and run:
cd /opt/reinforce-my-ssh
sudo bash stage3-reboot-check.sh --verify
```

Stages 1 and 2 remain pending until confirmed from the required external public-key/sudo session. Transaction backups, a lock and automatic rollback protect pending changes; the default confirmation window is **900 seconds**. `--yes` still requires `RESCUE_CONFIRMED=yes` in the configuration. The old port defaults to 22; use `--old-port none` only when no old entry should be retained—it is not proof that 22 is closed.

Rollback completed/pending stages in reverse order: stage3, stage2, stage1, each with `--rollback`; skip stages not entered. Stage3 rollback only clears verification state. Default stage1–3 invocations are deployment checks or managed-state verification, not a replacement for stage0.

### Tests and documentation

```bash
python3 tests/run_tests.py
sudo python3 tests/run_tests.py --integration
```

Integration tests use isolated nft namespaces and dedicated temporary systemd units. Full VM migration, cross-boot recovery and public-network acceptance remain pending; validate in a disposable VM before production use.

[Full runbook](plans/DESIGN.md) · [Audit scope](plans/AUDIT-EXISTING.md) · [Names and compatibility](plans/SCRIPT-NAMES.md) · [Tests](tests/README.md) · [Task ledger](task-list.md) · [MIT license](LICENSE)

## 中文

[Back to English](#english)

面向 Ubuntu/Debian 的 SSH 加固工具：先审计现状，再建立新端口、收紧认证，最后通过真实重启验证持久性。

### 脚本职责

| 入口 | 功能 |
| --- | --- |
| [stage0-audit.sh](stage0-audit.sh) | 独立只读审计，分别报告安全效果、管理归属、迁移阻断和重启证据。 |
| [stage1-newport.sh](stage1-newport.sh) | 加载来源白名单，建立候选新端口；按配置保留旧入口，直到 stage2 收口。 |
| [stage2-harden.sh](stage2-harden.sh) | 禁止 root、密码和键盘交互登录，仅允许公钥，并关闭旧端口。 |
| [stage3-reboot-check.sh](stage3-reboot-check.sh) | 记录基线，跨真实重启复验；不修改 SSH/防火墙配置，不代为重启。 |

stage0 可独立执行，不会自动纳管服务器。stage1–3 的策略、状态和事务记录保存在 `/var/lib/reinforce-my-ssh`。部署只需上述 **四个 stage 脚本**：审计实现已内嵌 stage0，环境仍需 Python 3。旧的 `stage1.sh`、`stage2.sh`、`stage3.sh` 仅作为仓库中的可选兼容入口。

### 使用前提

- Ubuntu/Debian、systemd、`ssh.socket`（`Accept=no`）、`ssh.service`（`KillMode=process`），支持 IPv4/IPv6；依赖 Bash、Python 3、OpenSSH、nftables、iproute2 和 sudo。
- 普通管理账户 SSH 登录后 sudo 执行即可，无需开放 root SSH 登录。账户、公钥和云防火墙规则需提前准备。
- 保留当前会话，并实际演练独立的 VNC、串口或 Agent 救援通道。部署会拒绝冲突的非受管指令和活动 `Match`；已有加固方案应先审计，再决定是否迁移。

### 操作流程

以下假设仓库位于 `/opt/reinforce-my-ssh`，服务器命令均在此目录执行。请替换 `SERVER`、账户、端口和示例网段 `203.0.113.0/24`。

**已有服务器：只审计，不改配置。**

```bash
sudo bash stage0-audit.sh --port 2222 --user deploy \
  --allow 203.0.113.0/24 --closed-port 22
```

审计退出码：`0` 为本次范围通过，`1` 为明确不符合，`2` 为权限、证据或支持范围不足。缺少新版管理记录本身不代表不安全；加 `--format json` 可输出结构化报告。

**新建受管部署：**

```bash
# 服务器：先检查部署前提，再建立候选端口。
sudo bash stage1-newport.sh --port 2222 --user deploy --allow 203.0.113.0/24
sudo bash stage1-newport.sh --port 2222 --user deploy --allow 203.0.113.0/24 --apply

# 客户端另开终端连接，保留原会话。
ssh -p 2222 deploy@SERVER

# 新服务器会话：回到仓库目录，确认第一阶段，再收紧认证。
cd /opt/reinforce-my-ssh
sudo bash stage1-newport.sh --confirm
sudo bash stage2-harden.sh --apply

# 客户端再次建立全新连接。
ssh -p 2222 deploy@SERVER

# 全新服务器会话：确认第二阶段，记录重启前基线。
cd /opt/reinforce-my-ssh
sudo bash stage2-harden.sh --confirm
sudo bash stage3-reboot-check.sh --apply

# 确认救援通道后自行重启，重新登录并执行：
cd /opt/reinforce-my-ssh
sudo bash stage3-reboot-check.sh --verify
```

stage1/2 的 apply 只进入待确认状态，必须通过规定的外部公钥登录和 sudo 会话确认。事务备份、互斥锁和自动回滚保护待确认变更，默认确认窗口为 **900 秒**。无人值守使用 `--yes` 时，配置中仍须声明 `RESCUE_CONFIRMED=yes`。旧端口默认 22；只有无需保留旧入口时才使用 `--old-port none`，它不证明 22 已关闭。

回滚按 stage3 → stage2 → stage1 逆序执行，各加 `--rollback`，未进入的阶段跳过。stage3 只撤销验证状态。stage1–3 默认执行部署检查或受管复验，不能代替 stage0 的独立审计。

### 测试与文档

```bash
python3 tests/run_tests.py
sudo python3 tests/run_tests.py --integration
```

集成测试使用隔离 nft 网络命名空间和专用临时 systemd 单元。真实 VM 迁移、跨启动恢复和公网验收仍待完成；生产使用前请在可销毁 VM 中验收。

[完整操作手册](plans/DESIGN.md) · [审计范围](plans/AUDIT-EXISTING.md) · [命名与兼容](plans/SCRIPT-NAMES.md) · [测试说明](tests/README.md) · [任务台账](task-list.md) · [MIT 许可证](LICENSE)
