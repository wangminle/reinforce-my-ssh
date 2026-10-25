# SSH 加固重构设计与操作手册

> 适用对象：Ubuntu/Debian 上使用 systemd `ssh.socket` 激活的服务器。
> 本文描述三阶段重构后的目标架构、操作契约和验证边界，不是上线验收报告。
> 静态与隔离验证已完成；真实整机和公网验收仍未完成，详见 plans/AUDIT.md。

当前推荐入口：stage0-audit.sh、stage1-newport.sh、stage2-harden.sh、stage3-reboot-check.sh；旧文件名兼容关系和发布清单见 [脚本命名](SCRIPT-NAMES.md)。

## 1. 目标与非目标

已有旧方案或尚未纳管的服务器，请使用根目录 `stage0-audit.sh` 独立只读审计，说明见 [已有服务器审计](AUDIT-EXISTING.md)。三个阶段的默认模式属于部署前提检查/受管复验，缺少新版记录不等于服务器未加固。独立审计不创建状态，不接管配置，不放松下述 apply 保护。

这套脚本把 SSH 迁移收敛为一条可证明可用的管理通道：

- 只允许指定来源网段访问指定 SSH 端口；
- 使用已存在的非 root 管理账户和公钥认证；
- 禁止 root 直接 SSH 登录，关闭密码和键盘交互认证；
- 防火墙与 `ssh.socket` 均持久自启，并在真实重启后复验；
- 破坏性变更先建立事务和自动恢复，再由外部新会话确认提交。

换端口本身不是主要安全边界，也不能保证“绝对不失联”。错误的安全组、路由、白名单、密钥、sudoers、平台救援配置或上游网络故障仍可能中断管理访问。独立救援通道、保留旧会话、外部确认和限时回滚是在降低风险，而不是消除风险。

### 1.1 能缓解的威胁

- 针对 SSH 密码的自动化爆破；
- root 直接远程登录；
- 不必要的来源和旧端口暴露；
- 配置写入成功但运行时、持久配置或重启后状态不符合目标；
- 新通道未经验证就关闭旧入口所造成的自锁风险。

### 1.2 不解决的问题

- 已取得 root 权限的攻击者、恶意管理员或主机被入侵后的防护；
- 私钥失窃、终端失陷、账户/sudoers 生命周期和补丁管理；
- 云安全组、覆盖网络 ACL、路由、DNS、云平台控制面的自动配置；
- 同机其他服务、其他防火墙表或其他暴露面的加固；
- 对所有 SSH 用户、所有网络路径和所有故障组合的穷尽证明；
- fail2ban 的配置或有效性保证。本重构不修改 fail2ban。

## 2. 支持边界与预检拒绝

支持范围主动收窄为 **Ubuntu/Debian + systemd + `Accept=no` 的 `ssh.socket` + `KillMode=process` 的 `ssh.service` + 可用的 IPv4/IPv6 双栈回环与通配监听**。切换时只停止 sshd 主进程，保留其已建立会话的子进程；其他 KillMode 在预检时拒绝。这不是任意 Linux、传统 `ssh.service` 独立监听、Socket 未启用、单栈或其他 init 系统的通用模板。

前两阶段在修改前检查命令依赖、目标账户、sudo 组、`ssh.socket`、受管路径和 `sshd -t`，并要求当前远程来源位于 ALLOW 中。以下情况明确不受支持，应人工整理后重新预检，而不是让脚本猜测合并：

- `/etc/ssh/sshd_config` 及其 Include 中存在活动 `Match`；
- 非受管文件中有 `Port`、`ListenAddress`、`PermitRootLogin`、`PubkeyAuthentication`、`PasswordAuthentication`、`KbdInteractiveAuthentication` 或 `AuthenticationMethods`；
- 非绝对 Include、同一行多个 Include pattern、Include 递归过深或配置无法解析；
- 受管路径已被非本工具文件占用，或路径不是普通文件；
- 目标用户不存在、为 root/UID 0、不在 sudo 组；
- 新旧端口相同、端口越界、CIDR 非规范网络地址或带主机位。

`AuthenticationMethods publickey` 与各项认证开关共同构成目标策略。预检拒绝活动 `Match` 是支持边界，不是声称脚本能够安全改写任意既有 OpenSSH 配置。

目标账户和密钥需要管理员事先准备；脚本不创建账户、不安装公钥，也不把“在 sudo 组”当成已完成真实提权的证明。真实 sudo 由后续确认流程验证。

## 3. 架构

### 3.1 三阶段职责

| 阶段 | 修改内容 | 提交条件 | 完成状态 |
|---|---|---|---|
| stage1：候选通道 | 原子加载来源白名单；部署早期防火墙自启、`ssh.socket` 自启和新端口；默认同时保留旧端口 | 从外部经新端口以目标非 root 用户完成公钥登录，并在该会话真实执行 `sudo stage1-newport.sh --confirm` | `candidate-ready` |
| stage2：认证与端口收口 | 设置仅公钥、禁 root/密码/键盘交互；socket、sshd 和 nft 的端口集合只剩新端口 | 收口后另建一次全新的外部公钥登录，并只在该新会话执行 `sudo stage2-harden.sh --confirm` | `hardened` |
| stage3：重启验证 | 不修改 SSH、nft、socket 或单元；记录 pre/post 基线和 boot 状态 | `boot_id` 跨重启且完整复验通过 | `verified` |

阶段间不能跳跃。stage1 只允许从 `unconfigured` 部署；stage2 只允许从 `candidate-ready` 部署；stage3 只接受 `hardened` 或既有 stage3 状态。

### 3.2 两阶段提交闸门

stage1 `--apply` 和 stage2 `--apply` 都只进入 pending，不代表完成。确认时同时核对：

1. `SUDO_USER` 是策略中的目标用户，`SUDO_UID` 与其 UID 一致；
2. 当前 `SSH_CONNECTION` 四元组完整，服务器目标端口等于新端口，来源不是回环或本机其他地址（服务器自连不算外部验证），且在 ALLOW 中；
3. `ss` 中存在与该四元组精确对应的 established 连接，且持有连接的 sshd PID 位于当前 sudo 调用的祖先进程链；
4. 完整部署及运行时复验结束后记录 `confirmation.json`，其中保存当前 boot 的 journal cursor；确认只查询该 cursor 之后的结构化日志，并要求 `Accepted publickey` 的用户、来源 IP/端口、boot 和可信 `_PID` 与当前进程链一致。

因此，“新端口有 TCP 连接”和“另一条连接曾经通过公钥”不能拼接成通过证据。stage2 `--apply` 使用 stage1 的确认边界验证现有新端口会话；stage2 `--confirm` 使用收口完成后的新 cursor，必须另建连接，不能复用 apply 会话。秒级事务时间只用于诊断，不作为新会话闸门。缺少 cursor、跨 boot、日志被清理或无法关联进程链时均拒绝确认；旧版没有确认边界的 pending 事务需回滚重建。

确认还重新执行运行时检查。通过后才写提交状态、配置摘要和 `COMMITTED`，并取消该事务的恢复定时器。

### 3.3 原子 nft 与早期启动

专用表为 `inet sshguard`。磁盘规则在同一个 `nft -f` 输入中执行幂等 `add table`、`delete table` 和完整表定义，由 nftables 一次事务替换整个表，包括链等对象。单纯 `flush table` 会留下链，不能用于完整替换。加载或恢复后都规范化比较期望规则与内核规则；单元素端口集合、IPv4 /32、IPv6 /128 和计数值等价差异被规范化，额外规则、链和其他命令仍被拒绝。

input base chain 的策略是 `accept`，只对目标 SSH 端口依次设置：

- 回环来源 accept；
- 每个 ALLOW 网段 accept；
- `ct state established,related` accept；
- 末尾 drop。

该链是 **input hook**，处理进入本机的包。服务器发往客户端的回包走 output 路径，不会被这条 input 链“拦截”，`established,related` 也不是为服务器回包放行。它允许已建立/关联连接的后续入站包，因此收窄 ALLOW 不等于立即杀死既有连接；撤销会话需要另行处理。末尾 drop 只覆盖目标端口，不等于全主机默认拒绝。

防火墙单元使用 `DefaultDependencies=no`，显式设置 `local-fs.target`、`network-pre.target`、`ssh.socket` 和关机顺序，并安装到 `sysinit.target`。`ssh.socket` override 对防火墙单元设置 `Requires` 与 `After`。两者都被 enable；防火墙加载失败会阻止 socket 正常启动，避免无白名单开放，但也可能使 SSH 不可达，所以独立救援仍是必要条件。该设计不包含“30 次重试即可证明网络就绪”的逻辑。

socket 显式配置 `BindIPv6Only=ipv6-only`，分别绑定 IPv4/IPv6 通配地址；有效监听按 systemctl 的 `地址 (Stream)` 格式解析。SSH 配置切换先停止 `ssh.service` 主进程及 socket，再启动 socket 和 service，确保新主进程读入认证配置。stage2 确认旧端口已无监听后，使用防火墙 `ExecReload` 原子收窄 nft，避免 restart 防火墙连带重启有活跃配套服务的 socket。

### 3.4 持久状态、策略和摘要

权威状态位于 `/var/lib/reinforce-my-ssh`，不再根据“表是否存在”猜测阶段：

- `policy.conf` 保存 `PORT`、`OLD_PORT`、`USER`、有序 ALLOW 列表、`RECOVERY_SECONDS` 和 `RESCUE_CONFIRMED`；
- `state.conf` 保存 `STAGE`、当前 `TX`、`CONFIG_SHA` 以及 stage3 的 boot/基线字段；
- `transactions/<TX_ID>/` 保存前两阶段的事务备份和提交/回滚事实；
- `baselines/pre.*`、`baselines/post.*` 保存 stage3 基线。

阶段提交时计算配置摘要，将策略和五个受管文件绑定到提交状态。stage2 开始子事务前先核对父摘要，stage3 在除 `--rollback` 外的路径先核对摘要；漂移会使后续流程失效并拒绝继续。回滚同时恢复父策略及摘要。不要手改受管文件来“修复”漂移，应查明原因并按阶段回滚、重新部署。

状态目录、事务目录和策略/状态文件按 root 私密数据保护；操作使用 `/run/lock/reinforce-my-ssh.lock` 互斥。事务 ID 含时间、纳秒和 PID，避免并发或同秒覆盖。

## 4. 状态机

```text
unconfigured
  ── stage1 --apply ──▶ candidate-pending
                           ── stage1 --confirm ──▶ candidate-ready
                                                      ── stage2 --apply ──▶ hardening-pending
                                                                               ── stage2 --confirm ──▶ hardened
                                                                                                          ── stage3 --apply ──▶ reboot-pending
                                                                                                                                   ── 跨 boot 且 --verify 通过 ──▶ verified
```

回滚和重新验证的边：

- `candidate-pending` 经 stage1 回滚/自动恢复到 `unconfigured`；
- `hardening-pending` 经 stage2 回滚/自动恢复到 `candidate-ready`；
- `reboot-pending` 或 `verified` 经 stage3 `--rollback` 到 `hardened`；
- `verified` 可经 stage3 `--apply` 开始新一轮 `reboot-pending`。

补充规则：

- pending 未确认时，重复 `--apply` 只复验已部署目标并提示确认，不另起变更事务；
- 已提交的 stage1/stage2 状态也可由对应阶段手工回滚，但必须逆序；
- `reboot-pending` 和 `verified` 会阻止前两阶段直接回滚，先执行 stage3 `--rollback`；
- `verified` 只对登记的 `VERIFIED_BOOT` 和 `CONFIG_SHA` 有效。默认检查发现 boot 已变化时，原 verified 不再算当前开机已验证；
- stage3 `--rollback` 只清验证状态，不删除基线。

## 5. 参数与严格解析

### 5.1 stage1 / stage2

```text
--port <n>                 新 SSH 端口，1–65535
--old-port <n|none>        stage1 保留、stage2 关闭的旧端口；默认 22
--user <name>              已存在的非 root、非 UID 0 管理账户
--allow <cidr>             来源网段，可重复；至少一个
--conf <file>              严格 KEY=VALUE 配置文件
--recovery-seconds <n>     pending 自动恢复时限，60–86400，默认 900
--apply                    部署目标并进入 pending
--confirm                  用当前外部新会话证据提交 pending
--rollback                 回滚当前事务
--transaction <id>         精确指定当前事务，主要用于自动恢复
--yes                      跳过交互，但不替代 RESCUE_CONFIRMED=yes
-h, --help                 帮助
```

`--auto-recovery` 是恢复单元内部参数，只能与 `--rollback` 连用，不是日常操作接口。`--apply`、`--confirm`、`--rollback` 互斥。未知参数、缺值和非法值会拒绝执行。

stage1 初始部署必须提供端口、用户和至少一个 ALLOW。进入已存策略后，端口、用户和 ALLOW 只能核对，不能借 stage2 或重复 stage1 静默改策略；需要改策略时按顺序回滚后重新部署。stage2 不需要重新传完整策略，直接从 `policy.conf` 读取。

配置文件键为：

```text
PORT=2222
OLD_PORT=22
USER=deploy
ALLOW=203.0.113.0/24
RECOVERY_SECONDS=900
RESCUE_CONFIRMED=yes
```

规则如下：

- 只接受上述键；`ALLOW` 可重复，其他键不可重复；
- 空行和注释可存在，其他行必须是 `KEY=VALUE`；值不做 shell 展开；
- 文件必须为 LF，末行需要换行，拒绝 CR；
- 初始部署时命令行显式给出的 `PORT`、`OLD_PORT`、`USER`、`ALLOW` 优先于配置文件；
- CIDR 由 IP 地址库规范化并去重；带主机位的写法会被拒绝，单 IPv4 主机通常写 `/32`，单 IPv6 主机写 `/128`。

`RESCUE_CONFIRMED=yes` 是管理员对“已经实际登录并演练过独立于 sshd 的救援通道”的**人工事实声明**，不是脚本探测结果。未预先写入 yes 时，可在交互中确认；`--yes` 不能伪造这一事实。它也不证明救援永远可用，应在维护窗口前重新演练。

`AuthorizedKeysCommand` 是 sshd 在认证过程中调用的辅助机制，其存在不证明有带外救援。Workbench、Instance Connect 和其他浏览器连接也不能一概视为独立通道：具体模式可能仍连接 sshd、仍受端口和来源限制。只有确认实际实现不依赖本次修改的 SSH 路径并真实演练成功，才能作为救援；VNC/串口同样需要实测，而不是凭名称推定。

### 5.2 stage3

```text
stage3-reboot-check.sh [--port <n>] [--user <name>] [--old-port <n|none>] [--conf <file>] [模式]
```

- 默认：完整只读检查，不写状态或基线；
- `--apply`：从 `hardened` 或 `verified` 开始一轮重启验证，只写 pre 基线和 `reboot-pending`；
- `--verify`：仅在 `reboot-pending` 且 boot 已变化时完整复验，写 post 基线和 `verified`；
- `--rollback`：仅将 stage3 状态退回 `hardened`；
- `--yes`：只跳过 `--apply` 的交互确认，只能与 `--apply` 合用。

端口、用户、旧端口和 `--conf` 只用于核对权威策略，不覆盖 `policy.conf`。stage3 不修改 fail2ban，不 enable/disable 单元，不重启系统，也不改 SSH、nft 或 socket 配置。

## 6. 完整 SOP

以下示例使用文档保留地址 `203.0.113.0/24`、端口 `2222` 和账户 `deploy`，必须替换。假设脚本位于服务器 `/opt/reinforce-my-ssh/`。所有脚本均用 `sudo` 执行；先运行 `--help` 核对实际参数。

### 6.1 准备

1. 建立可销毁环境的演练或至少准备平台快照、维护窗口和明确回滚责任人。
2. 确认系统是支持的 Ubuntu/Debian + systemd `ssh.socket` 布局；先人工处理活动 Match 和非受管端口/认证指令。
3. 创建并验证非 root 管理账户、sudo 权限和公钥登录；不要等关闭 root 后才第一次试 sudo。
4. 从真实管理网络确认来源 IP/网段，并核对云安全组、覆盖网络 ACL 和路由。`100.64.0.0/10` 之类地址范围本身不是可信身份；只放行实际需要的节点或网段。
5. 实际登录一次独立于 sshd 的 VNC、串口或经确认独立的 Agent 救援通道，并验证能取得恢复所需权限。只有演练成功才设置 `RESCUE_CONFIRMED=yes`。
6. 在安全组中为新端口和迁移期需要的旧端口准备最小来源规则；不要对全网临时放开。
7. 保留当前旧会话，另备一台或另一条真实外部路径用于新连接。不要用服务器回环登录代替外部验收。

### 6.2 stage1：建立并确认候选通道

在现有、来源位于 ALLOW 的远程会话中先只读预检：

```bash
cd /opt/reinforce-my-ssh
sudo bash ./stage1-newport.sh --port 2222 --user deploy --allow 203.0.113.0/24
```

也可使用 §5.1 的配置文件：

```bash
sudo bash ./stage1-newport.sh --conf /root/reinforce.conf
sudo bash ./stage1-newport.sh --conf /root/reinforce.conf --apply
```

`--apply` 成功后状态是 `candidate-pending`，不是完成。记录输出的事务 ID，保留旧会话，在时限内从另一台外部机器执行：

```bash
ssh -p 2222 deploy@<服务器地址>
sudo bash /opt/reinforce-my-ssh/stage1-newport.sh --confirm
```

确认成功后才为 `candidate-ready`。若无法登录，不要关闭旧会话或继续 stage2；排查或等待/执行自动恢复。若 stage1 已 pending，重复 apply 不会缩短或重置确认要求。

### 6.3 stage2：收紧认证并关闭旧端口

必须保持 stage1 已确认的新端口会话。stage2 apply 本身也会验证当前会话四元组、存活 sshd 进程链、stage1 cursor 之后的公钥日志和真实 sudo：

```bash
sudo bash /opt/reinforce-my-ssh/stage2-harden.sh
sudo bash /opt/reinforce-my-ssh/stage2-harden.sh --apply
```

目标 sshd 策略精确包含：

```sshconfig
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
Port 2222
```

执行时先在仍保护新旧端口的防火墙下关闭旧 socket 监听，再原子收窄 nft，避免旧端口短暂失去白名单保护。此时 socket 和 nft 都只保留新端口，状态为 `hardening-pending`。保留 apply 会话作为临时救援，再从另一台机器建立一次**全新的**连接：

```bash
ssh -p 2222 deploy@<服务器地址>
sudo bash /opt/reinforce-my-ssh/stage2-harden.sh --confirm
```

只在旧 apply 会话里 confirm 不符合设计。成功后才为 `hardened`，对应自动恢复定时器才会取消。

随后人工对齐云安全组：新端口仅允许所需来源；旧端口不再使用时移除外层放行。若计划回滚 stage2，需同时恢复必要的旧端口外层规则。

### 6.4 stage3：真实重启和基线验证

先执行完整只读检查，再登记重启前状态：

```bash
sudo bash /opt/reinforce-my-ssh/stage3-reboot-check.sh
sudo bash /opt/reinforce-my-ssh/stage3-reboot-check.sh --apply
```

apply 通过完整检查后保存 pre 基线、当前 `PENDING_BOOT` 和 `reboot-pending`；它不会重启。再次确认独立救援，由管理员自行重启。重启回来后：

1. 从外部经新端口实际建立目标用户公钥登录并测试 sudo；
2. 执行 `sudo bash /opt/reinforce-my-ssh/stage3-reboot-check.sh --verify`；
3. 只有 boot 已变化且全部检查通过，脚本才保存 post 基线并写 `verified`；
4. 可再运行默认只读检查，确认 verified 对应当前 boot 和摘要。

若检查失败，状态保持 `reboot-pending`，不会写 verified。修复方式不是反复执行 verify 掩盖错误，而是从救援通道排查；需要回退配置时按 §7 逆序操作。

### 6.5 收尾

- 从 ALLOW 外和 ALLOW 内分别做外部正反向连接验收，并记录安全组与主机 nft 各自结果；
- 验证 root 直登、密码和键盘交互路径确实不可用，目标普通用户公钥与 sudo 可用；
- 复核安全组、覆盖网络 ACL、其他服务监听和其他防火墙层；
- 清理废弃密钥和凭据。保留必要的 sudo 审计，但不要宣称 `sudo -i` 后每条命令天然都有逐条归因；需要命令级审计时另配 sudoers 日志、审计框架或会话记录；
- 如使用 fail2ban，单独检查其有效 jail 和 `ignoreip`。`ignoreip` 是 fail2ban 的免封列表，不是本工具的 nft ALLOW，也不会决定 SSH 网络可达性；列入其中的可信来源同样可能失去 fail2ban 防护。本工具不修改它。

## 7. 回滚与自动恢复

### 7.1 自动恢复

stage1/stage2 在修改系统前创建事务并安装事务专属单元：

```text
/etc/systemd/system/reinforce-my-ssh-<TX_ID>.service
/etc/systemd/system/reinforce-my-ssh-<TX_ID>.timer
```

timer 只用 `OnActiveSec=<RECOVERY_SECONDS>` 控制本次启动的确认窗口，不使用可能从开机时刻起已经过期的 OnBootSec/OnStartupSec。service 自身安装到 `multi-user.target`：若 pending 期间重启，它在下次启动执行恢复；若事务已提交则空操作。service 从事务目录调用当时备份的恢复脚本，避免依赖工作副本后续内容。900 秒是默认确认窗口，不应理解为跨关机、时钟异常等所有场景下的精确墙钟保证。所有恢复进程取得全局锁后都会重新读取 state，防止拿锁前的 pending 覆盖刚提交的状态。

- pending 到期未确认：自动回滚当前事务并返回父状态；
- apply 中途失败：立即尝试事务回滚；
- confirm 成功：写提交事实后 disable/remove 该事务 timer/service；
- 提交后迟到的恢复任务：不回滚已提交或已结束的事务，仅清理本事务残留 service/timer；即使当前已进入后续事务，也不能清理其他事务的恢复单元；
- 清理 timer 失败会明确报警，不能把“已提交”误报成“又回滚”。

自动恢复本身可能因 systemd、磁盘、备份、nft 或权限故障失败。失败时事务保留以供重试，必须使用独立救援通道处理。

### 7.2 手工逆序回滚

始终按 **stage3 → stage2 → stage1**，不要跳步：

```bash
# 仅当当前为 reboot-pending 或 verified；只撤销验证状态
sudo bash /opt/reinforce-my-ssh/stage3-reboot-check.sh --rollback

# hardened/hardening-pending → candidate-ready，恢复 stage1 的候选配置
sudo bash /opt/reinforce-my-ssh/stage2-harden.sh --rollback

# candidate-ready/candidate-pending → unconfigured，恢复 stage1 前状态
sudo bash /opt/reinforce-my-ssh/stage1-newport.sh --rollback
```

`--transaction <TX_ID>` 只能指定当前事务；不是挑选任意历史备份绕过阶段顺序。每次回滚后先检查状态、监听和实际外部登录，再进入下一步，并同步调整云安全组。

stage3 回滚绝不承担配置恢复职责。stage1/stage2 回滚也只恢复各自事务管理的文件、策略、`inet sshguard`、防火墙/SSH 单元状态及监听目标，不是整机快照，不回滚用户、密钥、云安全组、fail2ban 或其他服务。

### 7.3 回滚完成条件

事务在修改前保存五个受管文件及元数据、防火墙、ssh.socket 和 ssh.service 的 active/enabled 状态、实际内核 nft 表或“不存在”事实、监听集合、父状态、策略备份和恢复脚本。恢复时：

1. 安全停止 SSH 主进程和 socket；核对全部文件备份摘要，再按 manifest 恢复文件、属主、权限和父策略；
2. daemon-reload 并恢复防火墙单元；首次部署前不存在的单元按不存在处理，不向缺失单元发送 stop；
3. 以一次 nft 事务恢复完整内核表或其不存在事实，重新核对完整语义；执行 `sshd -t` 后才恢复 socket 和 service；
4. 比较 PORT/OLD_PORT 相关监听和父配置摘要，不让无关服务变化阻塞 SSH 回滚；
5. 任一步失败则停止新的 SSH 接入、返回非 0、保留事务且不写 `ROLLED_BACK`；恢复成功、父阶段及其原摘要均落盘后才算完成，状态写失败会撤销完成标记以允许重试。

“命令执行过”不等于“回滚完成”。

## 8. 故障排查

先保留现有会话，从独立救援通道查看：

```bash
sudo cat /var/lib/reinforce-my-ssh/state.conf
sudo systemctl status ssh.socket reinforce-my-ssh-firewall.service
sudo systemctl list-timers 'reinforce-my-ssh-*'
sudo journalctl -b -u ssh -u sshd -u 'ssh@*' -u 'reinforce-my-ssh-*'
sudo ss -tlnp
sudo nft list table inet sshguard
```

| 现象 | 排查方向 |
|---|---|
| 新端口超时 | 可能来自云安全组、上游 ACL/路由、本机 nft 末尾 drop 或其他丢包；超时不能唯一归因安全组。核对真实来源、ALLOW、外层规则、路由和计数器。 |
| 新端口 RST/connection refused | 可能无监听、socket 未启动、主机或上游主动 reject 等；RST 也不能唯一证明“包到主机但无监听”。结合 `ss`、socket 状态、路径上各层规则判断。 |
| 防火墙失败且 SSH 不启动 | 这是 Requires 的失败关闭方向。从救援通道检查 loader、nft 语法/语义和 early boot 日志，不要为了临时连通直接移除依赖后长期运行。 |
| 预检报活动 Match/非受管指令 | 在维护窗口人工整理 OpenSSH 配置并重跑 `sshd -t`；本工具不会猜测哪个值应覆盖。 |
| confirm 找不到四元组/存活 sshd | 必须在目标外部 SSH 会话直接 sudo 执行；检查是否经过会改变环境的跳转、`su`、tmux 或会话已断开。 |
| confirm 找不到边界之后的公钥日志 | 核对目标用户、新端口、全新连接及 journal 中 ssh/sshd/ssh@ 的结构化日志；确认日志 PID 属于当前 sudo 的 sshd 进程链，cursor 与 boot 仍有效。TCP 可连不能替代公钥证据。 |
| stage2 提示不是全新会话 | 关闭用于 apply 的旧认证会话以外的歧义，重新从外部发起连接，在新会话执行 confirm；不要复用 stage2 apply 之前的日志。 |
| 配置摘要不一致 | 受管文件或策略已漂移。保存证据，按当前阶段回滚/重建；stage3 不会在漂移时写 verified。 |
| pending 被自动回滚 | 查看事务 unit 日志和 state，确认已回父状态后修复原因再重新 apply；不要继续使用已失效的 confirm 流程。 |
| 回滚失败 | 使用独立救援通道，按报错修复磁盘、nft、systemd 或配置问题后重试同一当前事务；事务未标完成，不应改行手工宣称成功。 |
| verified 在下次重启后失效 | 这是设计行为；重新 stage3 `--apply`，跨新 boot 后 `--verify`。 |
| 只需撤销一次重启验证 | 用 stage3 `--rollback`；它不会修复或修改 SSH/nft/单元。 |

## 9. 受管文件与运行数据

五个配置受管文件以脚本为准：

| 路径 | 内容 |
|---|---|
| `/etc/ssh/sshd_config.d/00-reinforce-my-ssh.conf` | 候选或 hardened 的 Port 与认证策略 |
| `/etc/nftables.d/reinforce-my-ssh.nft` | `inet sshguard` 的原子加载规则和 input 链 |
| `/usr/local/sbin/reinforce-my-ssh-firewall` | 调用 `/usr/sbin/nft -f` 的加载器 |
| `/etc/systemd/system/reinforce-my-ssh-firewall.service` | 早期 oneshot 防火墙单元 |
| `/etc/systemd/system/ssh.socket.d/00-reinforce-my-ssh.conf` | 清空并重写 IPv4/IPv6 ListenStream，声明防火墙 Requires/After |

状态和恢复数据：

| 路径 | 用途 |
|---|---|
| `/var/lib/reinforce-my-ssh/policy.conf` | 跨阶段权威目标策略 |
| `/var/lib/reinforce-my-ssh/state.conf` | 状态机、当前事务、摘要和 boot/基线引用 |
| `/var/lib/reinforce-my-ssh/transactions/<TX_ID>/` | manifest、文件备份、单元/nft/监听事实、started、confirmation.json、parent、恢复脚本及完成标记 |
| `/var/lib/reinforce-my-ssh/baselines/pre.*` | 重启前完整采集和 `META` |
| `/var/lib/reinforce-my-ssh/baselines/post.*` | 重启后完整采集和 `META` |
| `/etc/systemd/system/reinforce-my-ssh-<TX_ID>.{service,timer}` | pending 期间的事务专属自动恢复 |
| `/run/lock/reinforce-my-ssh.lock` | 阶段操作互斥锁 |
| 内核 `inet sshguard` | 实际防火墙状态，单独备份和语义复验 |

基线是诊断证据，不是可直接套用的配置备份；stage3 回滚会保留 pre/post 文件和引用。事务目录也不应被当作长期归档或任意选择的历史版本库。

## 10. 验证范围与验收边界

stage1/stage2 的运行时检查覆盖受管文件逐字一致、`sshd -t`、sshd/socket 端口集合、IPv4/IPv6 通配监听和回环连接、nft 磁盘/内核语义、单元 active/enabled、Requires/After，以及 hardened 下目标用户和 root 的 `sshd -T -C` 上下文。stage3 的完整复验还包括旧端口无实际监听、IPv4/IPv6 回环和当前外部来源上下文、磁盘/内核/策略三方 nft 精确一致，以及基线采集状态。

这些检查仍有明确边界：

- 回环 TCP 连接不是外部认证测试；配置解析不是密钥、sudoers、安全组或真实网络路径测试；
- 两阶段 confirm 证明指定用户的一条真实新通道，不证明所有来源和所有账户；
- stage3 的 `sshd -T -C` 覆盖设计上下文，不等于外部负向认证测试；
- 只规范化比较专用 nft 表，不证明其他防火墙层没有影响；
- `boot_id` 变化和重启后检查证明一次跨 boot 状态，不证明以后每次升级或重启都正常；
- 人工 RESCUE 声明不替代本次维护前的实际救援演练。

发布前至少需要在可销毁的真实 Ubuntu VM 上验收正常迁移、两阶段外部确认、超时自动恢复、apply 失败回滚、连续逆序回滚、IPv4/IPv6、非法配置拒绝、配置漂移和真实重启；公网/覆盖网络验收还需从允许与拒绝来源验证云安全组和真实路径。静态检查、隔离函数测试和本文审阅不能替代这些整机验收。

**静态与隔离验证已完成，但真实 VM、跨启动恢复和公网验收尚未完成；本文不声明已经可安全上线。**
