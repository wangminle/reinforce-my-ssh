# SSH 加固只读指导设计（v2）

面向 Ubuntu/Debian 的 SSH 加固工具。**本版定位为分步指导（guidance），不是执行器（executor）**：工具只读地检查现状、判断流程位置、打印下一步的手工命令与验证方法；所有系统变更由操作员本人（或其监督下的智能体）手工执行。

## 1. 铁律与设计动机

工具对系统**零写入**：不修改 SSH/nft/systemd 配置，不写状态文件，不安装 systemd 定时器，不代执行任何命令，不存在任何形式的自动回滚。恢复永远依赖操作员在流程早期手工创建的备份，且恢复命令同样由人执行。

本版是对 v1"自动执行 + 事务 + 定时回滚"体系的直接回应：2026-10-27 京东云真实节点发生失联事故（[[BUG-016]]，根因未查明；VNC 亦不可用；本地复现同族缺陷 [[BUG-015]]——初次回滚在复验前删除策略文件，恢复失败即停止 SSH 接入且回滚入口无法重试）。事故结论是：在只有 SSH 一条活路的机器上，把判断外包给定时器和自动回滚，任何未建模的故障都会把"保护"变成"自我锁死"。v1 全部脚本冻结在 `legacy/`，仅作取证与远端旧事务对照，禁止使用。

结构性对比：

| | v1（legacy/） | v2（本版） |
| --- | --- | --- |
| 修改系统 | 事务化自动 apply/rollback | 从不修改 |
| 失败处理 | 定时器无人值守自动回滚、失败即停 SSH | 停在原地，打印手工恢复命令 |
| 状态 | /var/lib 状态文件 + 摘要 | 无状态文件；每次只读探测推断 |
| 防失联 | 依赖"旧会话应保留"假设 | 硬门槛：新入口必须被外部实测证明后才允许关旧入口 |
| 救援通道 | 配置里一行 `RESCUE_CONFIRMED=yes` 声明 | 必须真实演练，`--rescue-confirmed` 只是记录该事实 |

## 2. 三个脚本

| 入口 | 职责 |
| --- | --- |
| `stage0-check.sh` | 只读现状检查与流程定位：会话事实、监听/服务、sshd 有效配置、账户与公钥、nft/UFW、备份、旧版痕迹、重启证据；对照声明的目标（`--port/--user/--allow/--closed-port`）输出所处位置与下一步该跑哪个脚本 |
| `stage1-port-key.sh` | 指导：切端口（开新端口→外部验证→关旧端口）、切密钥（sudo 组非 root 账户 + 公钥）、验证 sudo 用户 |
| `stage2-lockdown.sh` | 指导：nft 来源白名单、禁 root/禁密码/禁键盘交互、最终确认清单、重启后复验；`--tailnet` 时叠加接口与声明 CIDR 放行，拒绝白名单外来源 |

三个脚本各自自包含（bash 包装 + 内嵌 Python heredoc），只依赖 Bash、Python 3 与系统自带的 `ss`/`sshd`/`nft`/`ufw`/`systemctl`/`journalctl`。需要完整读取权限（`sudo`）；非 root 运行会降级并打印 sudo 命令（退出码 2）。

## 3. 只读契约（代码级保证）

- 命令白名单按完整参数形式验证：`ss -tlnpH`、账户查询、`sshd -t/-T`、`nft list`/`nft -j list`、`ufw status` 及指定只读的 `systemctl`/`journalctl` 查询。`nft -j` 不能绕过动词检查；`ss -K`、`journalctl --rotate` 等变更形式在执行层直接抛错，不创建子进程。
- 文件系统访问全部经 `System` 抽象（read/exists/is_dir/list_dir/stat/mtime），便于审计与桩件测试。
- 测试套件断言：完整跑一遍探测流程后，所有被执行的命令均在白名单内；源码扫描禁止 `shell=True`、`os.system` 与可写 systemctl 子命令。

## 4. 状态推断（无状态文件）

不写任何状态，位置由只读证据及明确记录的人工验收事实共同判断；人工声明不能替代实际验证：

| 信号 | 来源 |
| --- | --- |
| 会话事实（来源、端口、认证方式） | `SSH_CONNECTION`（含 sudo 后的祖先进程 environ 恢复）+ 本 boot journal 的四元组匹配 |
| 监听 | `ss -tlnpH` 的 sshd 归属 + `systemctl show ssh.socket -p Listen`（`(Stream)` 后缀解析） |
| 持久化配置 | `/etc/ssh/sshd_config(.d)` 的 Port 指令、`ssh.socket.d` 的 ListenStream |
| 有效认证策略 | `sshd -T -C user=...,addr=...` 上下文（Match 块单独警告，不自动解释） |
| 防火墙 | `nft -j list ruleset` 的指导级摘要（dport/saddr 字面量）+ `ufw status verbose` |
| 账户与公钥 | `id`/`getent` + authorized_keys 数量与权限 |
| 备份 | 约定目录（可用 `--backup-dir` 指定），必须有配置副本、服务/防火墙快照（工具缺失需显式记录）、可选目录的副本或缺省记录，以及成功后才写入的 `backup-complete` |
| 旧版残留 | `/var/lib/reinforce-my-ssh`、旧受管文件、`reinforce-my-ssh-*.timer` |
| 重启候选证据 | `/proc/stat` btime 与 SSH 主配置、drop-in、白名单文件、实际加载器 unit/drop-in 等相关文件的 mtime 比较；采集失败不认定通过 |

推断不确定时输出"无法证实"并给出补齐手段（`--old-port`、`--user`、`--port`），绝不猜测。

## 5. 硬门槛（防锁死设计）

每个步骤带 `blocked_by`；门槛未满足时只打印被阻塞状态与原因，不给可执行命令：

1. **救援通道演练**（`--rescue-confirmed`）：真实登录一次 VNC/串口后才可声明；没有它，关旧端口与禁用密码的步骤保持阻塞。
2. **手工全量备份**：无备份不开放"开新端口"及其后步骤。
3. **新入口外部证明**：第 4 步要求"从新端口、公钥、全新外部会话"重跑脚本；脚本以当前会话端口 + journal 公钥证据判定。密码会话不算通过（[[BUG-015]]、事故的直接教训）。
4. **白名单来源自检**：stage2 应用白名单前检查当前会话来源是否在 `--allow` 内；不在且没有实际核实入口的 `--tailnet-session-confirmed` 声明则硬阻断。`100.64.0.0/10` 或 Tailscale IPv6 地址范围只提供候选信息，不能证明报文来自 `tailscale0`。声明只记录操作员已核实本次会话从该接口进入 sshd 的事实，不能由智能体据地址自行补上。
5. **禁用密码前置**：必须已有新端口公钥会话验证通过。
6. **重启持久化**：文件 mtime 比较只产生候选证据。完整通过还需要相关文件均可采集、当前启动晚于其修改、运行态全部达标，以及实际冷启动后完成白名单内成功/外部拒绝的新连接验证，再用 `--reboot-confirmed` 记录该事实。仅运行态变更不修改文件 mtime，脚本无法自动识别；任何后续运行态改动后须撤销旧声明，重新冷启动并验证，不能把人工声明当作持续监测保证。

### 5.1 Tailscale 拓扑（可选）

管理通路是否经过 tailnet 不改变加固目标，只改变"白名单写什么、新入口用什么证据、最终还暴露什么"。三个脚本都接受 `--tailnet`；不声明时行为与默认流程完全一致。

| 场景 | 白名单 | 新入口证据 | 终态 |
| --- | --- | --- | --- |
| 不入 tailnet | `--allow` 来源 CIDR | 该端口上的公钥会话重跑 stage1 | 公网端口仅白名单可达 |
| 加入 tailnet | `iifname "tailscale0" accept` 加全部 `--allow` 云内网/指定公网来源 | 经 tailnet 到 **sshd** 的新端口公钥会话，并分别验证声明来源 | `1b-close-public` 拒绝白名单外来源；未声明 CIDR 时才只留 tailnet |
| tailnet + DERP | 同上 | 同上 | 443/tcp、3478/udp 属独立规则域，不并入 SSH 白名单 |

只读检测读取 `/sys/class/net/tailscale0`：存在且 `flags` 的 IFF_UP 位为 1 即视为可用（TUN 的 `operstate` 常为 `unknown`，只在读不到 flags 时回退）。地址识别同时覆盖 `100.64.0.0/10` 与 `fd7a:115c:a1e0::/48`。不调用 `tailscale` CLI，也不推断 Tailscale SSH 是否启用。接口 up 与候选地址只反映拓扑，当前会话是否真正经该接口进入由操作员核实，必要时显式声明 `--tailnet-session-confirmed`。

**混合白名单**：云服务商内网只保留用户明确声明的可信来源 IP/CIDR，不从私网属性或当前连接自动推导信任。`--tailnet` 与重复 `--allow` 为并集；规则生成、最终确认和重启续跑都保留该并集。每个声明来源必须有放行证据，不能仅凭 tailnet 放行即判定达标。混合模式不再提示仅绑定 tailnet，也不要求指定公网来源连接失败。

**证据边界**：Tailscale SSH 由 `tailscaled` 终结认证，不经过 sshd。它可以作为救援/管理通路，但**不能**作为 sshd 加固通过的证据；stage1 在第 4 步会明确区分"经 tailnet 到 sshd"与"Tailscale SSH"。`--tailnet` 只改变指导内容，不写任何系统状态。

## 6. 输出约定

文本模式面向人：步骤清单（已完成/未完成/被门槛阻塞）+ 当前步骤的"为什么/执行/验证/手工撤销"。JSON 模式面向智能体：

```json
{
  "schema": 1, "script": "stage1-port-key.sh", "read_only": true, "time": "...",
  "goals": {"port": 62207, "user": "deploy", "old_port": 22, "host": "..."},
  "rescue_confirmed": true,
  "session": {"source": "...", "port": 62207}, "session_auth": "publickey",
  "steps": [{"id": "3-new-port", "title": "...", "status": "todo", "evidence": "...",
             "why": "...", "do": ["..."], "verify": ["..."], "undo": ["..."],
             "blocked_by": ["1-backup"]}],
  "complete": false, "next_step": "3-new-port"
}
```

退出码：`0` 已声明目标全部达成（stage0 未声明目标时表示采集完成）；`1` 阻断性异常（旧版待确认事务/恢复定时器残留、sshd 配置损坏）；`2` 参数错误、步骤未完成（含白名单来源阻断）、证据不足或需要 sudo；`130` 中断。

## 7. 智能体执行契约

智能体（如 Claude）可以按 JSON 驱动执行，但必须遵守：

1. 只执行 `blocked_by` 为空的步骤的 `do` 命令；被阻塞时先完成被依赖的步骤；
2. 每个步骤执行后重跑同一脚本核对状态，再进入下一步；不跳步、不合并步骤；
3. `0-rescue`、当前会话的 tailnet 入口及冷启动验收，只能依据实际验证记录对应声明；智能体不得代为声称，也不能在续跑命令中自动制造已完成事实；
4. 云安全组/云控制台的放行与删除只能由操作员完成（脚本不模拟）；
5. 任何验证失败：停止推进，输出 `undo` 手工恢复命令清单，交由操作员执行；不存在自动回滚。

可选后续（待办）：`run.sh` 交互式执行器（逐步确认、逐步复核、无定时器）。当前先以"人工执行 + 智能体按 JSON 执行"为主。

## 8. 分发与旧版处置

部署只包含三个指导脚本 + Python 3；`legacy/` 与 `tests/` 不随部署分发。远端曾部署的旧版（OPS-015/016/019 记录了 md5）在本地 `legacy/` 与台账中保留取证；aliyun-1 的旧 `~/ssh-apply` 已按用户要求于 2026-10-27 整体删除（OPS-024），其他机器上遗留的旧目录不由上传器更新或删除。上传器位于本地忽略的 `working-scripts/`，不随克隆分发。本地上传器 `working-scripts/upload-ssh-guides-to-aliyun-1.sh` 与 `upload-ssh-guides-to-jdcloud-1.sh` 只把三个脚本上传到远端 `~/ssh-guides`，逐文件核对 md5 并分别验证远端 `--help`；上传不等于部署，实际执行仍需按机器逐个授权（台账 DEV-013）。

## 9. 验证范围与验收边界

- 回归（桩件、隔离 shell 与 nft 语法）：`python3 tests/run-tests.py`，测试数量和结果以本次实际输出为准（解析、判定、门槛、退出码、只读契约、Tailscale 拓扑、socket 激活与防火墙规则顺序）。隔离 shell/nft 需在 Linux/WSL 运行。
- 未闭环（不得省略）：在可销毁整机上完成真实迁移与故障注入——外部连接成功/失败、白名单外来源拒绝、救援通道真实可用、跨重启复验；京东云节点的远端根因与旧事务处置（[[BUG-016]]、[[CHK-013]]）。桩件测试不替代整机验收。

## 剩余路径复核修复（2026-10-30）

后续 2026-10-31：BUG-037 的服务切换与 BUG-047 的缺失单元备份已完成本地修复。恢复写文件前先验证会话保护条件，daemon-reload 后再次验证；要求 KillMode=process、SendSIGHUP=no 且停止钩子为空，手工程序以 busctl 读取 D-Bus 明确数组。socket 与主进程协同切换，任何一步失败立即停止，只输出状态检查和人工恢复建议；不在失败分支继续执行查询、启动、停止或回滚，不清理备份，后续执行由操作员决定。备份的 not-found 必须来自成功的 LoadState 查询，不能把空 stdout 当成缺失。验证细节与局限见 [修复记录](checkpoints/2026-10-31-service-recovery-fixes.md)。

设计复核补充（[[CHK-027]]）：首轮生成的手工程序曾在失败后自动再尝试 start，与第 7 节失败停止原则不一致。[[ADJ-015]] 已完成调整：失败分支不调用系统命令，只提供独立的人工建议。只读指导脚本本身仍不执行这些变更命令，执行权始终属于操作员；此说明不放宽原有设计原则。

- stage0 端口解析支持裸数字及 IPv4/IPv6 端点；socket drop-in 全部经 System 读取，桩件能覆盖 stage1 实际生成内容。公钥读失败和确认空文件分开判定。
- stage1 所有续跑与阶段衔接共用参数拼接；旧端口未知时省略该声明并保持阻断，显式 none 也不能绕过其它监听或新会话验证。stage1 的可选重复 --allow 仅用于明确声明并传给 stage2，不推导信任范围。
- 手工备份新增 nftables.d、ufw、nft JSON、原 sshguard 表/缺省记录、socket 活跃及 nftables 启用状态。旧快照缺少这些事实时应重做，不手工伪造完成标记。
- 撤销与救援生成同一份自包含 Python 程序，仅供操作员从救援通道手工执行。先验证备份和 nft 替换事务，再还原文件；指定工具文件原来不存在则移除，原来存在则恢复。仅替换 inet sshguard 和删除本流程新增的带标记过渡规则，不 flush ruleset；原 UFW active 时重载备份配置，不 stop nftables.service。最后校验 sshd、重载 systemd 并恢复监听/认证配置，须另做外部连接验证。
- tests/recovery-program.txt 是恢复程序的测试参考，部署脚本已内嵌完整副本，不依赖该文件。测试验证两处内嵌内容一致，并在临时文件系统及独立用户/网络命名空间中实际执行文件恢复和 nft 事务；sshd/systemctl/ufw 为假命令，不冒充真实整机恢复。


## 2026-10-31 全量复核修复

- **UFW 方向**：支持 verbose 动作列的 `IN`；无方向兼容已有输入。`OUT`/`FWD` 不能充当 input 放行或拒绝证据。
- **nft 过渡规则**：stage1 不再选择第一个 input 链，不生成可能丢失注释定界符、追加在旧 drop 后或漏过其它 family/链的过渡写命令。检测到 nft input 链而新入口尚未证明时保持阻断，要求人工协调完整规则域并从新端口公钥会话复验。
- **专用加载器**：stage2 生成仅替换 `inet sshguard` 的单次事务（table 声明、delete table、完整重建），重复装载不会追加在旧 drop 后；事务失败保留旧表。不修改或启用全局 `nftables.service`，不调用全局 `flush ruleset`。专用 `ssh-allowlist.service` 只加载独立白名单文件；运行中重载由操作员显式执行，不能以 `enable --now` 冒充 active oneshot 的重载。
- **备份与恢复**：覆盖专用加载器 unit/drop-in、存在/缺省记录以及 active/enabled 状态。恢复先验证备份完整性，再分别处理磁盘配置、定向 nft 表及开机状态，失败即停止；旧备份缺这些事实时重新创建，不补造快照或完成标记。稳态备份不等于加固前基线。未知加载器 drop-in 须先人工协调；原 active 加载器无法安全重现时以未完成退出，保留独立人工恢复建议，不盲目执行未知 ExecStart。
- **阶段衔接与声明**：stage0 无来源时只打印含 `REPLACE_WITH_TRUSTED_CIDR` 的注释模板；未演练救援时只提示如何核实后补 `--rescue-confirmed`，不自动代填。`Port` 解析允许行尾注释，socket 目录采集失败不使指导进程崩溃；重启比较所需时间或目录采集失败时证据为未知。

实现及本地验证记录见 [全量复核修复检查点](checkpoints/2026-10-31-review-fixes.md)。ADJ-012～014 的远端加载器故障、实际备份、WebTerminal/VPC 需求和外部连通性验收仍待执行；未连接、更新或验证真实服务器，不将这些事项标成完成。
