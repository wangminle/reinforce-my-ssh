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

Each script is a self-contained bash wrapper with an embedded Python implementation. They only read; the execution layer accepts only the read-only argument forms used by the guide: `ss -tlnpH`, account queries, `sshd -t/-T`, `nft list`/`nft -j list`, `ufw status` and read-only `systemctl`/`journalctl` queries. Mutating variants such as `ss -K`, `nft -j flush ruleset`, and `journalctl --rotate` are rejected before subprocess execution.

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

**Hard gates (anti-lockout):** rescue-channel drill confirmed; full manual backup under `/var/backups/ssh-hardening/`; the new port must be proven by re-running stage1 **from a new public-key session on that port** (a password session does not count) before the old port may be closed; stage2 refuses allowlist commands while your current source IP is outside `--allow`; disabling password login requires a verified public-key session on the new port; file timestamps are only a reboot-evidence candidate. Completion also requires actual cold-boot and external allowlisted/rejected-source checks, recorded with `--reboot-confirmed`; any later runtime-only rule change invalidates that declaration until the cold-boot checks are repeated.

Exit codes: `0` declared goals fully met (or stage0 collection completed without declared goals); `1` blocking anomaly (legacy pending transaction/recovery timer or invalid sshd config); `2` invalid arguments, steps outstanding (including a source-lockout gate), missing evidence, or `sudo` required; `130` interrupted. Add `--format json` for machine-readable output.

**Backup acceptance.** Snapshots include SSH/drop-in files, nftables/UFW configuration directories, original socket/service enablement facts, the dedicated `ssh-allowlist.service` unit/drop-ins and its active/enabled state, nft JSON and the original `sshguard` table (or an absence record). Recovery removes only listed tool files, restores pre-existing versions and replaces the SSH table without flushing unrelated tables. Existing backups missing these facts or the `backup-complete` marker are incomplete: rerun stage1 step 1 to create a fresh backup. Do not add the marker by hand. `--backup-dir` accepts an absolute path and is retained in resume commands.

Manual recovery and socket switching require `busctl` and verify `KillMode=process`, `SendSIGHUP=no`, and empty `ExecStop`/`ExecStopPost` hooks before stopping the main process. They refuse unsupported settings without changing them. Socket and service are stopped together, then started together. Any failure stops execution immediately and prints diagnostic and manual recovery suggestions; it does not retry, restart, or roll back automatically. The operator decides what to execute next. Keep the rescue console open and verify a new SSH session. Missing units are recorded using `LoadState=not-found`; collection errors abort the backup without a completion marker.

**Stage handoff.** stage1 accepts repeated `--allow` values and carries them, the backup path, host, tailnet and rescue confirmation into continuation commands. Without a declared source or `--tailnet`, both stage0 and stage1 provide a commented stage2 template containing `REPLACE_WITH_TRUSTED_CIDR`. Rescue confirmation must be added only after a real rescue drill; stage0 never fabricates that declaration. An unknown old port is never rewritten as `--old-port none`.

**Tailscale topology (optional).** When management goes through a tailnet, add `--tailnet` to all three scripts. stage0 then reports `tailscale0`; stage1 adds a "join the tailnet" step; stage2 adds `iifname "tailscale0" accept` alongside every declared `--allow` source and rejects sources outside this combined allowlist. Declare trusted cloud LAN source IPs/CIDRs and selected public source IPs explicitly with repeated `--allow`; private ranges are never trusted automatically. Without `--allow`, only the tailnet path is retained. Tailscale SSH is terminated by `tailscaled` and never touches sshd, so it is a rescue/management path but **not** evidence that sshd hardening works. DERP/STUN ports (443/tcp, 3478/udp) are a separate rule domain and must not be folded into the SSH allowlist.

**Ingress evidence.** The shared `100.64.0.0/10` address range does not prove Tailscale ingress. A current session outside the explicit `--allow` list remains blocked unless the operator has actually verified that this session enters sshd through `tailscale0` and records that fact with `--tailnet-session-confirmed`. Merely having `tailscale0` up, or using a CGNAT source address, is insufficient. This is distinct from Tailscale SSH terminating in `tailscaled`.

**Firewall changes.** With nft input chains present, stage1 does not guess a chain or emit a transition `add rule`. Keep the step blocked and manually coordinate every relevant IPv4/IPv6 input chain, cloud rule and existing drop/reject rule; prove the new public-key session before continuing. Stage2 generates a single transaction that declares, deletes and recreates only `inet sshguard`, then loads it through the dedicated `ssh-allowlist.service`. The loader uses explicit early-boot dependencies and `WantedBy=sysinit.target` to avoid the socket/`basic.target` ordering cycle; real cold-boot acceptance is still required. It neither enables the global `nftables.service` nor adds an include to a configuration that may flush unrelated tables. UFW verbose `ALLOW IN`/`DENY IN` rules are parsed as input evidence; OUT/FWD rules are not. An interface-bound source allow is not proof that the entire declared CIDR is reachable.

The custom loaders and WebTerminal/VPC policy described in the JD Cloud records still need machine-specific backup, failure/reload and external connectivity acceptance (ADJ-012–014). These local changes do not prove that a remote deployment has been updated. The upload helpers under `working-scripts/` are locally ignored files and are not included in a clone.

### Agent execution

An agent (e.g. Claude) can drive the steps from the JSON output, under operator supervision: execute only steps whose `blocked_by` is empty, re-run the script after every executed step, stop and print the manual `undo` commands on any failed verification, and never simulate the rescue drill or cloud-console changes. See the execution contract in [plans/DESIGN-v2.md](plans/DESIGN-v2.md).

### Tests

```bash
python3 tests/run-tests.py
```

Tests cover read-only stubs and isolated shell fixtures; use the current runner output for the test count and results. Linux-only checks need their native dependencies; unsupported or unexecuted checks must not be reported as passing. No production system changes. They do not replace real-server acceptance. An explicit temporary systemd/socket integration check is documented in [tests/README.md](tests/README.md).

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

三个脚本各自自包含（bash 包装 + 内嵌 Python）。执行层只接受向导实际使用的只读参数形式：`ss -tlnpH`、账户查询、`sshd -t/-T`、`nft list`/`nft -j list`、`ufw status` 和只读 `systemctl`/`journalctl` 查询。`ss -K`、`nft -j flush ruleset`、`journalctl --rotate` 等变更形式会在子进程执行前被拒绝。

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

**硬门槛（防锁死）**：救援通道演练确认；`/var/backups/ssh-hardening/` 手工备份；新端口必须**从该端口的新公钥会话重跑 stage1** 证明可用（密码会话不算）才允许关旧端口；stage2 在"当前来源不在 `--allow` 内"时拒绝给出白名单命令；禁用密码前必须有已验证的新端口公钥会话；启动时间晚于全部相关配置文件只能提供重启候选证据；完成持久化验收还需真实冷启动，并从白名单内、外分别验证全新的连接，之后才可声明 `--reboot-confirmed`。任何后续仅运行态规则变更也会使该声明失效，须重新冷启动验收。

退出码：`0` 已声明目标全部达成（stage0 未声明目标时表示采集完成）；`1` 阻断性异常（旧版待确认事务/恢复定时器残留、sshd 配置损坏）；`2` 参数错误、步骤未完成（含来源锁死阻断）、证据不足或需要 sudo；`130` 中断。加 `--format json` 输出机器可读结构。

**备份验收**：快照包含 SSH/drop-in、nftables/UFW 配置目录、原 socket/服务启用状态、专用 `ssh-allowlist.service` 的 unit/drop-in 与 active/enabled 状态、nft JSON 和原 sshguard 表（或不存在记录）。完整恢复会移除指定的工具新增项、还原原有同名项、替换 SSH 白名单表，保留其它表；必须从救援通道手工执行，并复验监听和新连接。旧备份缺少这些恢复事实或 `backup-complete` 标记时显示未完成；请重新执行 stage1 第 1 步创建新备份，不要手工补标记。`--backup-dir` 接受绝对路径，续跑命令会保留该参数。

手工恢复与 socket 切换需要 `busctl`，停止主进程前核对 `KillMode=process`、`SendSIGHUP=no` 且无 `ExecStop`/`ExecStopPost`；不符合时明确拒绝，不自动更改保护参数。socket 与主服务协同停止、启动；任何一步失败立即停止，只输出状态检查和人工恢复建议，不自动重试、重启或回滚，由操作员决定后续执行。须保持救援控制台和复验新 SSH 会话。备份通过 `LoadState=not-found` 记录缺失单元；采集错误会终止备份，不写完成标记。

**阶段衔接**：stage1 可接收重复 `--allow`，续跑保留来源、备份目录、host、tailnet 与救援声明。stage0 和 stage1 在既未声明来源也未选 tailnet 时，只显示含 `REPLACE_WITH_TRUSTED_CIDR` 的 stage2 注释模板。必须真实演练救援后再补 `--rescue-confirmed`，stage0 不自动替操作员声明演练完成。旧端口未知时不会自动生成 `--old-port none`。

**Tailscale 拓扑（可选）**：管理通路走 tailnet 时，三个脚本都加 `--tailnet`。stage0 会报告 `tailscale0`；stage1 增加"接入 tailnet"步骤；stage2 叠加 `iifname "tailscale0" accept` 与每个 `--allow` 来源，后续步骤只拒绝白名单外来源。云内网可信来源 IP/CIDR、用户指定公网来源通过重复 `--allow` 明确声明，不自动信任全部私网；只传 `--tailnet` 时才仅保留 tailnet 通路。Tailscale SSH 由 `tailscaled` 终结、不经过 sshd，因此只能算救援/管理通路，**不能**作为 sshd 加固通过的证据；DERP/STUN（443/tcp、3478/udp）属于独立规则域，不要并入 SSH 白名单。

例如同时保留 Tailscale、云内网和指定公网来源（将示例地址替换为实际可信的**客户端来源**，不是服务器目标地址）：

```bash
sudo bash stage2-lockdown.sh --port 62207 --user fenix --tailnet \
  --allow 10.20.0.0/16 \
  --allow 203.0.113.9/32 \
  --rescue-confirmed
```

云厂商若使用 `100.64.0.0/10` 中的地址，也只声明实际可信来源；不会将整个共享地址段自动加入白名单。应用前核对规则，应用后分别从三类来源新建公钥会话验证，并从白名单外验证拒绝。脚本只输出指导，由人或 agent 执行。


**入口证据**：`100.64.0.0/10` 是共享地址空间，不能证明来自 Tailscale。当前来源不在显式 `--allow` 中时，必须由操作员核实本次会话确实从 `tailscale0` 进入 sshd，之后才可用 `--tailnet-session-confirmed` 记录；否则保持阻断。仅有接口 up 或 CGNAT 来源地址不够，不能把由 `tailscaled` 终结的 Tailscale SSH 当作 sshd 验证。

**防火墙操作**：存在 nft input 链时，stage1 不再猜测链或打印过渡 `add rule`，先保持阻断，提示人工协调所有相关 IPv4/IPv6 链、云规则及显式 drop/reject，再用新端口公钥会话证明可达。stage2 在同一事务内声明、删除并重建 `inet sshguard`，通过专用 `ssh-allowlist.service` 加载独立文件；加载器使用显式早期启动依赖和 `WantedBy=sysinit.target`，避免 socket/`basic.target` 排序环，但仍须真实冷启动验收。不启用全局 `nftables.service`，不向可能清空其它表的全局配置追加 include。UFW verbose 的 `ALLOW IN`/`DENY IN` 可作为入站证据，OUT/FWD 规则不计入；限定接口的来源放行不能证明整个声明 CIDR 均可达；数值 iif 与无法解析的入口条件保留限制，不据此宣称来源放行或全局拒绝。

京东云记录中的自建加载器、WebTerminal/VPC 授权仍须在对应机器完成备份恢复、重载失败与外部连通性验收（ADJ-012～014）。本地修复不证明远端已更新。`working-scripts/` 上传器是本地忽略文件，不随仓库克隆分发。

### 智能体执行

智能体（如 Claude）可在操作员监督下按 JSON 输出驱动执行：只执行 `blocked_by` 为空的步骤；每步执行后重跑脚本；任何验证失败即停止并打印手工 `undo` 命令；不得代拟救援演练与云控制台操作。执行契约见 [plans/DESIGN-v2.md](plans/DESIGN-v2.md)。

### 测试

```bash
python3 tests/run-tests.py
```

测试覆盖只读桩件与隔离 shell 命令，数量和结果以当前入口实际输出为准。Linux 原生用例需要相应依赖，未执行或被跳过的用例不能记作通过。不改生产系统，不替代真实整机验收。另有显式运行的临时 systemd/socket 集成检查，见 [测试说明](tests/README.md)。

[设计文档（v2）](plans/DESIGN-v2.md) · [测试说明](tests/README.md) · [legacy 冻结区（禁运行）](legacy/README.md) · [检查点索引](plans/checkpoints/README.md) · [任务台账](task-list.md) · [MIT 许可证](LICENSE)
