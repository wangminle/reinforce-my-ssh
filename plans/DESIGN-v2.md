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
| `stage2-lockdown.sh` | 指导：nft 来源白名单、禁 root/禁密码/禁键盘交互、最终确认清单、重启后复验；`--tailnet` 时改用接口放行并可关闭公网入口 |

三个脚本各自自包含（bash 包装 + 内嵌 Python heredoc），只依赖 Bash、Python 3 与系统自带的 `ss`/`sshd`/`nft`/`ufw`/`systemctl`/`journalctl`。需要完整读取权限（`sudo`）；非 root 运行会降级并打印 sudo 命令（退出码 2）。

## 3. 只读契约（代码级保证）

- 命令白名单：`ss`、`id`、`getent`、`sshd -t/-T`、`nft list/-j`、`ufw status`、`systemctl show/is-active/is-enabled/cat/status`、`journalctl`。白名单之外的命令在执行层直接抛错。
- 文件系统访问全部经 `System` 抽象（read/exists/is_dir/list_dir/stat/mtime），便于审计与桩件测试。
- 测试套件断言：完整跑一遍探测流程后，所有被执行的命令均在白名单内；源码扫描禁止 `shell=True`、`os.system` 与可写 systemctl 子命令。

## 4. 状态推断（无状态文件）

不写任何状态，位置完全由只读证据推断：

| 信号 | 来源 |
| --- | --- |
| 会话事实（来源、端口、认证方式） | `SSH_CONNECTION`（含 sudo 后的祖先进程 environ 恢复）+ 本 boot journal 的四元组匹配 |
| 监听 | `ss -tlnpH` 的 sshd 归属 + `systemctl show ssh.socket -p Listen`（`(Stream)` 后缀解析） |
| 持久化配置 | `/etc/ssh/sshd_config(.d)` 的 Port 指令、`ssh.socket.d` 的 ListenStream |
| 有效认证策略 | `sshd -T -C user=...,addr=...` 上下文（Match 块单独警告，不自动解释） |
| 防火墙 | `nft -j list ruleset` 的指导级摘要（dport/saddr 字面量）+ `ufw status verbose` |
| 账户与公钥 | `id`/`getent` + authorized_keys 数量与权限 |
| 备份 | 约定目录 `/var/backups/ssh-hardening/<ts>/` 且含 sshd_config |
| 旧版残留 | `/var/lib/reinforce-my-ssh`、旧受管文件、`reinforce-my-ssh-*.timer` |
| 重启证据 | `/proc/stat` btime 与全部加固文件的 mtime 比较 |

推断不确定时输出"无法证实"并给出补齐手段（`--old-port`、`--user`、`--port`），绝不猜测。

## 5. 硬门槛（防锁死设计）

每个步骤带 `blocked_by`；门槛未满足时只打印被阻塞状态与原因，不给可执行命令：

1. **救援通道演练**（`--rescue-confirmed`）：真实登录一次 VNC/串口后才可声明；没有它，关旧端口与禁用密码的步骤保持阻塞。
2. **手工全量备份**：无备份不开放"开新端口"及其后步骤。
3. **新入口外部证明**：第 4 步要求"从新端口、公钥、全新外部会话"重跑脚本；脚本以当前会话端口 + journal 公钥证据判定。密码会话不算通过（[[BUG-015]]、事故的直接教训）。
4. **白名单来源自检**：stage2 应用白名单前检查当前会话来源是否在 `--allow` 内；不在则硬阻断（"应用白名单将立即断掉你现在的连接"）。
5. **禁用密码前置**：必须已有新端口公钥会话验证通过。
6. **重启持久化**：只有"启动时间晚于全部加固文件修改 + 运行态全部达标"才计为跨重启验证。

### 5.1 Tailscale 拓扑（可选）

管理通路是否经过 tailnet 不改变加固目标，只改变"白名单写什么、新入口用什么证据、最终还暴露什么"。三个脚本都接受 `--tailnet`；不声明时行为与默认流程完全一致。

| 场景 | 白名单 | 新入口证据 | 终态 |
| --- | --- | --- | --- |
| 不入 tailnet | `--allow` 来源 CIDR | 该端口上的公钥会话重跑 stage1 | 公网端口仅白名单可达 |
| 加入 tailnet | `iifname "tailscale0" accept`（stage2 自动生成） | 经 tailnet 到 **sshd** 的新端口公钥会话 | 推荐再用 `1b-close-public` 关闭公网入口 |
| tailnet + DERP | 同上 | 同上 | 443/tcp、3478/udp 属独立规则域，不并入 SSH 白名单 |

只读检测读取 `/sys/class/net/tailscale0`：存在且 `flags` 的 IFF_UP 位为 1 即视为可用（TUN 的 `operstate` 常为 `unknown`，只在读不到 flags 时回退）。地址识别同时覆盖 `100.64.0.0/10` 与 `fd7a:115c:a1e0::/48`。不调用 `tailscale` CLI，也不推断 Tailscale SSH 是否启用。

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

退出码：`0` 本阶段目标全部达成；`1` 阻断性异常（旧版待确认事务/恢复定时器残留、sshd 配置损坏、白名单锁死风险）；`2` 步骤未完成或需要 sudo；`130` 中断。

## 7. 智能体执行契约

智能体（如 Claude）可以按 JSON 驱动执行，但必须遵守：

1. 只执行 `blocked_by` 为空的步骤的 `do` 命令；被阻塞时先完成被依赖的步骤；
2. 每个步骤执行后重跑同一脚本核对状态，再进入下一步；不跳步、不合并步骤；
3. `0-rescue` 只能由操作员真实演练后声明，智能体不得代为声称；
4. 云安全组/云控制台的放行与删除只能由操作员完成（脚本不模拟）；
5. 任何验证失败：停止推进，输出 `undo` 手工恢复命令清单，交由操作员执行；不存在自动回滚。

可选后续（待办）：`run.sh` 交互式执行器（逐步确认、逐步复核、无定时器）。当前先以"人工执行 + 智能体按 JSON 执行"为主。

## 8. 分发与旧版处置

部署只包含三个指导脚本 + Python 3；`legacy/` 与 `tests/` 不随部署分发。远端曾部署的旧版（OPS-015/016/019 记录了 md5）保持字节冻结用于取证；`working-scripts/` 上传器仍指向旧文件名，待真实部署计划确定后更新（台账 DEV 待办）。

## 9. 验证范围与验收边界

- 桩件回归：`python3 tests/run-tests.py`，55 项全部通过（解析、判定、门槛、退出码、只读契约、Tailscale 拓扑、socket 激活与防火墙规则顺序）。
- 未闭环（不得省略）：在可销毁整机上完成真实迁移与故障注入——外部连接成功/失败、白名单外来源拒绝、救援通道真实可用、跨重启复验；京东云节点的远端根因与旧事务处置（[[BUG-016]]、[[CHK-013]]）。桩件测试不替代整机验收。