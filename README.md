# reinforce-my-ssh

[English](#english) · [中文](#中文)

## English

Read-only, step-by-step **guidance** for SSH hardening on Ubuntu/Debian: check the current state, switch the port and public key, then lock down the firewall and authentication — with every change executed by you (or by an agent under your supervision), never by the tool.

**The tool never writes to the system.** It does not modify SSH/firewall/systemd configuration, writes no state files, installs no timers, runs no commands on your behalf, and has no automatic rollback of any kind. It inspects state read-only, tells you the current step, prints the exact manual commands with why/verify/undo, and re-checks after you execute them. Recovery is always manual, from the backup you created in step 1.

This is a direct response to the 2026-10-27 real lockout incident on a JD Cloud node caused by an earlier auto-execution design (transactional apply + timer-driven automatic rollback that stopped SSH when recovery failed). That legacy system is frozen under [`legacy/`](legacy/README.md) for forensics and remote old-transaction reference only and must never be run. Remote root cause is still unresolved ([incident record](plans/checkpoints/2026-10-27-lockout-incident.md), [BUG-016](task-list.md)); real-server acceptance of this new guidance flow is still pending, so treat any first run as a disposable-environment exercise.

### Scripts

| Entry | Purpose |
| --- | --- |
| [stage0-check.sh](stage0-check.sh) | Read-only current-state check and flow positioning: session facts, listeners/services, effective sshd config, accounts and keys, nft/UFW, backups, legacy traces, reboot evidence; compares against declared goals and tells you which script to run next. |
| [stage1-port-key.sh](stage1-port-key.sh) | Guidance for the port switch (open new → verify externally → close old), the key switch (non-root sudo account + public key) and sudo-user verification. |
| [stage2-lockdown.sh](stage2-lockdown.sh) | Guidance for the nft source allowlist, disabling root/password/keyboard-interactive login, the final confirmation checklist, and post-reboot re-verification. |

Each script is a self-contained bash wrapper with an embedded Python implementation. They only read; the command whitelist is `ss`, `id`, `getent`, `sshd -t/-T`, `nft list/-j`, `ufw status` and read-only `systemctl`/`journalctl` queries — enforced at execution time and asserted by the test suite.

### Before you start

- Ubuntu/Debian with systemd; Bash and Python 3; run with `sudo` (non-root runs degrade to a sudo hint).
- A non-root admin account, its public key, and cloud security-group rules to prepare yourself.
- A rescue channel (VNC/serial console) that you have **actually logged into once** — the guide records this as `--rescue-confirmed`, and it gates the dangerous steps.

### Workflow

Examples assume the repository is at `/opt/reinforce-my-ssh`. Replace `SERVER`, `deploy`, `62207` and the documentation CIDR `203.0.113.0/24`.

```bash
# 0) Where am I?
sudo bash stage0-check.sh --port 62207 --user deploy \
  --allow 203.0.113.0/24 --closed-port 22

# 1) Port + key + sudo user. Run, read the current step, execute it by hand, re-run.
sudo bash stage1-port-key.sh --port 62207 --user deploy --host SERVER --allow 203.0.113.0/24

# 2) Allowlist + disable root/password + final confirmation + reboot proof.
sudo bash stage2-lockdown.sh --port 62207 --user deploy \
  --allow 203.0.113.0/24 --host SERVER --rescue-confirmed
```

The loop is always: run the script → it confirms what is already done and prints the current step (why / do / verify / undo) → you execute the commands → you re-run the script to verify → move on. Steps whose gates are unmet are reported as blocked and print no actionable commands.

**Hard gates (anti-lockout):** rescue-channel drill confirmed; full manual backup under `/var/backups/ssh-hardening/`; the new port must be proven by re-running stage1 **from a new public-key session on that port** (a password session does not count) before the old port may be closed; stage2 refuses allowlist commands while your current source IP is outside `--allow`; disabling password login requires a verified public-key session on the new port; cross-reboot persistence requires the current boot to be later than every hardening file.

Exit codes: `0` declared goals fully met (or stage0 collection completed without declared goals); `1` blocking anomaly (legacy pending transaction/recovery timer, invalid sshd config, allowlist lockout risk); `2` steps outstanding or `sudo` required; `130` interrupted. Add `--format json` for machine-readable output.

**Backup acceptance.** Snapshots include SSH/drop-in files, nftables/UFW configuration directories, original socket/service enablement facts, nft JSON and the original `sshguard` table (or an absence record). Recovery removes only listed tool files, restores pre-existing versions and replaces the SSH table without flushing unrelated tables. Existing backups missing these facts or the `backup-complete` marker are incomplete: rerun stage1 step 1 to create a fresh backup. Do not add the marker by hand. `--backup-dir` accepts an absolute path and is retained in resume commands.

**Stage handoff.** stage1 accepts repeated `--allow` values and carries them, the backup path, host, tailnet and rescue confirmation into continuation commands. Without a declared source or `--tailnet`, its stage2 handoff is a commented template requiring an explicit trusted CIDR. An unknown old port is never rewritten as `--old-port none`.

**Tailscale topology (optional).** When management goes through a tailnet, add `--tailnet` to all three scripts. stage0 then reports `tailscale0`; stage1 adds a "join the tailnet" step; stage2 adds `iifname "tailscale0" accept` alongside every declared `--allow` source and rejects sources outside this combined allowlist. Declare trusted cloud LAN source IPs/CIDRs and selected public source IPs explicitly with repeated `--allow`; private ranges are never trusted automatically. Without `--allow`, only the tailnet path is retained. Tailscale SSH is terminated by `tailscaled` and never touches sshd, so it is a rescue/management path but **not** evidence that sshd hardening works. DERP/STUN ports (443/tcp, 3478/udp) are a separate rule domain and must not be folded into the SSH allowlist.

### Agent execution

An agent (e.g. Claude) can drive the steps from the JSON output, under operator supervision: execute only steps whose `blocked_by` is empty, re-run the script after every executed step, stop and print the manual `undo` commands on any failed verification, and never simulate the rescue drill or cloud-console changes. See the execution contract in [plans/DESIGN-v2.md](plans/DESIGN-v2.md).

### Tests

```bash
python3 tests/run-tests.py
```

105 tests covering read-only stubs and isolated shell fixtures; no production system changes. They do not replace real-server acceptance.

[Design (v2)](plans/DESIGN-v2.md) · [Tests](tests/README.md) · [Legacy (do not run)](legacy/README.md) · [Checkpoints](plans/checkpoints/README.md) · [Task ledger](task-list.md) · [MIT license](LICENSE)

## 中文

[Back to English](#english)

面向 Ubuntu/Debian 的 SSH 加固**只读分步指导**：检查现状、切端口与公钥、收紧防火墙与认证——每一步都由你（或你监督下的智能体）手工执行，工具绝不代劳。

**工具对系统零写入。** 不修改 SSH/防火墙/systemd 配置，不写状态文件，不装定时器，不代执行命令，不存在任何形式的自动回滚。它只读地检查现状、判断当前步骤、打印手工命令（含为什么/验证/撤销），并在你执行后重跑核对。恢复永远依赖第 1 步你亲手创建的备份，由人执行。

本版是对 2026-10-27 京东云真实失联事故的直接回应：旧版"事务化自动执行 + 定时器自动回滚（恢复失败即停止 SSH）"设计已全部冻结在 [`legacy/`](legacy/README.md)，仅作取证与远端旧事务对照，禁止运行。远端根因仍未查明（[事故记录](plans/checkpoints/2026-10-27-lockout-incident.md)、[BUG-016](task-list.md)）；新版指导流程的真实整机验收仍待完成，首次使用请在可销毁环境演练。

### 脚本职责

| 入口 | 功能 |
| --- | --- |
| [stage0-check.sh](stage0-check.sh) | 只读现状检查与流程定位：会话事实、监听/服务、sshd 有效配置、账户与公钥、nft/UFW、备份、旧版痕迹、重启证据；对照声明目标输出所在地步与下一步该跑的脚本。 |
| [stage1-port-key.sh](stage1-port-key.sh) | 指导切端口（开新→外部验证→关旧）、切密钥（sudo 组非 root 账户 + 公钥）与 sudo 用户验证。 |
| [stage2-lockdown.sh](stage2-lockdown.sh) | 指导 nft 来源白名单、禁 root/禁密码/禁键盘交互、最终确认清单与重启后复验。 |

三个脚本各自自包含（bash 包装 + 内嵌 Python）。只读命令白名单为 `ss`、`id`、`getent`、`sshd -t/-T`、`nft list/-j`、`ufw status` 与只读的 `systemctl`/`journalctl` 查询——执行层强制、测试断言。

### 使用前提

- Ubuntu/Debian、systemd；Bash 与 Python 3；以 `sudo` 运行（非 root 会降级为 sudo 提示）。
- 非 root 管理账户、其公钥、云安全组规则均需自行准备。
- 一条**真实登录演练过**的救援通道（VNC/串口）；向导以 `--rescue-confirmed` 记录该事实，并以此作为危险步骤的门槛。

### 操作流程

以下假设仓库位于 `/opt/reinforce-my-ssh`。请替换 `SERVER`、账户、端口和示例网段 `203.0.113.0/24`。

```bash
# 0) 我在哪一步？
sudo bash stage0-check.sh --port 62207 --user deploy \
  --allow 203.0.113.0/24 --closed-port 22

# 1) 切端口 / 装公钥 / 验证 sudo 用户。运行→读当前步骤→手工执行→重跑核对。
sudo bash stage1-port-key.sh --port 62207 --user deploy --host SERVER --allow 203.0.113.0/24

# 2) 白名单 + 禁 root/密码 + 最终确认 + 重启复验。
sudo bash stage2-lockdown.sh --port 62207 --user deploy \
  --allow 203.0.113.0/24 --host SERVER --rescue-confirmed
```

循环永远是：运行脚本 → 它确认哪些步骤已完成并打印当前步骤（为什么/执行/验证/撤销）→ 你手工执行 → 重跑脚本核对 → 进入下一步。门槛未满足的步骤显示"被门槛阻塞"，不给可执行命令。

**硬门槛（防锁死）**：救援通道演练确认；`/var/backups/ssh-hardening/` 手工备份；新端口必须**从该端口的新公钥会话重跑 stage1** 证明可用（密码会话不算）才允许关旧端口；stage2 在"当前来源不在 `--allow` 内"时拒绝给出白名单命令；禁用密码前必须有已验证的新端口公钥会话；跨重启持久化要求"本次启动晚于全部加固文件修改"。

退出码：`0` 已声明目标全部达成（stage0 未声明目标时表示采集完成）；`1` 阻断性异常（旧版待确认事务/恢复定时器残留、sshd 配置损坏、白名单锁死风险）；`2` 步骤未完成或需要 sudo；`130` 中断。加 `--format json` 输出机器可读结构。

**备份验收**：快照包含 SSH/drop-in、nftables/UFW 配置目录、原 socket/服务启用状态、nft JSON 和原 sshguard 表（或不存在记录）。完整恢复会移除指定的工具新增项、还原原有同名项、替换 SSH 白名单表，保留其它表；必须从救援通道手工执行，并复验监听和新连接。旧备份缺少这些恢复事实或 `backup-complete` 标记时显示未完成；请重新执行 stage1 第 1 步创建新备份，不要手工补标记。`--backup-dir` 接受绝对路径，续跑命令会保留该参数。

**阶段衔接**：stage1 可接收重复 `--allow`，续跑保留来源、备份目录、host、tailnet 与救援声明。既未声明来源也未选 tailnet 时，只显示须补可信 CIDR 的注释模板。旧端口未知时不会自动生成 `--old-port none`。

**Tailscale 拓扑（可选）**：管理通路走 tailnet 时，三个脚本都加 `--tailnet`。stage0 会报告 `tailscale0`；stage1 增加"接入 tailnet"步骤；stage2 叠加 `iifname "tailscale0" accept` 与每个 `--allow` 来源，后续步骤只拒绝白名单外来源。云内网可信来源 IP/CIDR、用户指定公网来源通过重复 `--allow` 明确声明，不自动信任全部私网；只传 `--tailnet` 时才仅保留 tailnet 通路。Tailscale SSH 由 `tailscaled` 终结、不经过 sshd，因此只能算救援/管理通路，**不能**作为 sshd 加固通过的证据；DERP/STUN（443/tcp、3478/udp）属于独立规则域，不要并入 SSH 白名单。

例如同时保留 Tailscale、云内网和指定公网来源（将示例地址替换为实际可信的**客户端来源**，不是服务器目标地址）：

```bash
sudo bash stage2-lockdown.sh --port 62207 --user fenix --tailnet \
  --allow 10.20.0.0/16 \
  --allow 203.0.113.9/32 \
  --rescue-confirmed
```

云厂商若使用 `100.64.0.0/10` 中的地址，也只声明实际可信来源；不会将整个共享地址段自动加入白名单。应用前核对规则，应用后分别从三类来源新建公钥会话验证，并从白名单外验证拒绝。脚本只输出指导，由人或 agent 执行。


### 智能体执行

智能体（如 Claude）可在操作员监督下按 JSON 输出驱动执行：只执行 `blocked_by` 为空的步骤；每步执行后重跑脚本；任何验证失败即停止并打印手工 `undo` 命令；不得代拟救援演练与云控制台操作。执行契约见 [plans/DESIGN-v2.md](plans/DESIGN-v2.md)。

### 测试

```bash
python3 tests/run-tests.py
```

105 项测试，覆盖只读桩件与隔离 shell 命令；不改生产系统，不替代真实整机验收。

[设计文档（v2）](plans/DESIGN-v2.md) · [测试说明](tests/README.md) · [legacy 冻结区（禁运行）](legacy/README.md) · [检查点索引](plans/checkpoints/README.md) · [任务台账](task-list.md) · [MIT 许可证](LICENSE)