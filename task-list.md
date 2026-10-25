# 任务跟踪列表

记录本项目所有任务：代码 bug、bug 转需求、新增需求、需求调整、功能开发、代码审查、测试数据、文档维护、配置运维等。

> 说明：本文件是当前项目的任务清单。所有新增事项、状态变更和完成记录都应同步写入本文件。
> 字段说明：动作字段只允许以下 8 个固定枚举：修复、开发、优化、调整、规划、检查、文档、运维。
> 时间说明：发现时间和完成时间分开记录，格式为 YYYY-MM-DD HH:MM，使用机器本地时区的 24 小时制时间；未完成事项的完成时间填 -。
> 状态说明：Bug 未完成用待修复，通用未完成用待办（或待开发），进行中/已完成/已修复/已关闭/已解决按语义选用；条目互引用 [[BUG-001]] 语法。
> 归并规则：审计、复核、核查、审查、验证、评估统一记为“检查”；重构、清理统一记为“优化”；方案、梳理统一记为“规划”；记录类文档事项统一记为“文档”。

## 代码 Bug

| ID | 动作 | 问题描述 | 发现时间 | 完成时间 | 状态 | 备注 |
| --- | --- | --- | --- | --- | --- | --- |
| BUG-001 | 修复 | P0：systemctl show -p Listen --value 解析错误。实际输出为「0.0.0.0:22 (Stream)」（类型在括号内），脚本用 awk '$1=="Stream"' 永远解析为空 | 2026-10-25 14:10 | 2026-10-25 14:51 | 已修复 | 影响：stage1/stage2 的 socket_addrs（stage1.sh:433、stage2.sh:438）与 stage3 的 ListenStream 校验（stage3.sh:381）必然失败——stage1 --apply 永远触发自动回滚、stage2 --apply 前置校验失败、stage3 默认/--apply/--verify 全部报失败。已实证：WSL Ubuntu 24.04 systemd 255，test99.socket 双 ListenStream 输出即此格式。修复方向：按 ' (Stream)' 后缀解析，如 awk '$2=="(Stream)"{print $1}'。；三阶段已按地址后的 (Stream) 解析；真实临时 systemd 单元与回归测试通过。见 plans/checkpoints/2026-10-25-fix-summary.md。 |
| BUG-002 | 修复 | P0：nft 单元素匿名集合在运行时列表中被折叠。生成规则写 tcp dport { 2222 }，nft -s list 实际输出 tcp dport 2222（无大括号），语义比较必然 MISMATCH | 2026-10-25 14:15 | 2026-10-25 14:51 | 已修复 | 影响：stage2 hardened（必为单端口）verify_nft_semantics 失败导致 --apply 永远回滚（stage2.sh:722）；stage3 磁盘/内核 nft 对比必然不一致（stage3.sh:524）；--old-port none 时 stage1 也失败。已实证：WSL Debian 真实内核 + nft 1.1.3，两端口集合 { 22995, 22996 } 保留、单端口 { 22996 } 折叠为 22996。修复方向：normalize 时把单元素 { N } 折叠为 N（stage1/2 的 normalize_nft 与 stage3 的 tokenizer 都要改）。；三阶段统一规范化单端口、IPv4 /32、IPv6 /128 和计数值；真实 nft 命名空间候选/收口/stage3 规则比较通过，额外 accept 仍拒绝。 |
| BUG-003 | 修复 | P3：load_policy 用未规范化的 CLI ALLOW 与已规范化策略值比较，非规范 CIDR 重复运行误报「ALLOW 与已存策略冲突」 | 2026-10-25 14:20 | 2026-10-25 14:51 | 已修复 | 位置：stage1.sh:174-175、stage2.sh:175-176。load_policy 先于 normalize_params 执行，saved 取原始 CLI 值而 policy 存的是规范化值（如 2001:0DB8::/32 vs 2001:db8::/32）。安全上 fail-closed 无害，仅误拒。修复方向：比较前先规范化，或记录规范化后策略、允许等价写法。；load_policy 在核对 ALLOW 前规范化并去重排序，等价 IPv6 写法回归通过。 |
| BUG-004 | 修复 | P3：已提交后迟到的自动恢复任务走空操作路径但不清理残留的恢复 service/timer 单元 | 2026-10-25 14:20 | 2026-10-25 14:51 | 已修复 | 位置：stage1.sh:631-633、stage2.sh:636-638。commit 时 cancel_recovery 失败（已 warn）则 enabled 的恢复 service 残留，之后每次开机都空跑一次并留日志。修复方向：auto 且已提交的 no-op 分支调用 cancel_recovery 清理本事务单元。；迟到恢复允许跨后续事务清理自己的单元；清理失败保留文件重试；部分 arm 安装失败的清理回归通过。 |
| BUG-005 | 修复 | P1：活跃 ssh.service 下单独重启 socket 失败，认证配置未通过协同主进程切换生效 | 2026-10-25 14:51 | 2026-10-25 14:51 | 已修复 | BUG-005；协同停止并启动主进程/socket，预检 KillMode=process；防火墙使用 ExecReload；真实临时 systemd 切换通过。 |
| BUG-006 | 修复 | P1：IPv4/IPv6 通配监听缺少 BindIPv6Only 导致绑定冲突 | 2026-10-25 14:51 | 2026-10-25 14:51 | 已修复 | BUG-006；显式 ipv6-only 并复验有效属性；PrivateNetwork 双栈 socket 实测通过。 |
| BUG-007 | 修复 | P1：首次部署早期失败时，回滚将原本不存在的防火墙单元视为恢复失败 | 2026-10-25 14:51 | 2026-10-25 14:51 | 已修复 | BUG-007；处理 not-found/inactive，并在删除新建单元前清除 enable；arm 失败到 unconfigured 完整隔离回归通过。 |
| BUG-008 | 修复 | P1：公钥日志没有关联当前 SSH 连接与 sudo 祖先进程链 | 2026-10-25 14:51 | 2026-10-25 14:51 | 已修复 | BUG-008；结构化 journal 校验 boot/PID，关联 ss 四元组和当前祖先进程；错误 PID/socket/认证方法的负向函数测试通过；真实 SSH 验收留 [[CHK-001]]。 |
| BUG-009 | 修复 | P2：nft flush table 残留链，回滚缺少完整内核语义复验 | 2026-10-25 14:51 | 2026-10-25 14:51 | 已修复 | BUG-009；使用 add/delete/完整定义的原子事务，核对备份摘要与恢复语义，失败不提交；真实 nft 恢复删除额外链测试通过。 |
| BUG-010 | 修复 | P2：stage2 开始子事务前遗漏父摘要检查，回滚未恢复父策略 | 2026-10-25 14:51 | 2026-10-25 14:51 | 已修复 | BUG-010；子事务准入核对摘要，恢复 policy.before 并校验父摘要；漂移拒绝和父状态恢复测试通过。 |
| BUG-011 | 修复 | P2：使用秒级事务开始时间，无法保证确认连接建立于收口之后 | 2026-10-25 14:51 | 2026-10-25 14:51 | 已修复 | BUG-011；完整运行时复验后保存 journal cursor，仅接受 after-cursor 的同 boot 会话证据；边界前日志拒绝回归通过。 |

## 调整事项

| ID | 动作 | 事项 | 发现时间 | 完成时间 | 状态 | 备注 |
| --- | --- | --- | --- | --- | --- | --- |

## 检查事项

| ID | 动作 | 事项 | 发现时间 | 完成时间 | 状态 | 备注 |
| --- | --- | --- | --- | --- | --- | --- |
| CHK-001 | 检查 | 可销毁 Ubuntu VM 整机验收：完整 SOP、两阶段外部确认、超时/跨启动自动恢复、apply 失败回滚、连续逆序回滚、真实重启与允许/拒绝来源外部测试 | 2026-10-25 14:26 | - | 待办 | 对应 plans/AUDIT.md「尚未完成的验收」。静态与隔离验证已完成，但不等于整机或公网验收；BUG-001/BUG-002 修复后必须重跑相关隔离验证再进入整机验收。；本轮 [[CHK-002]] 的 19 项隔离回归通过；真实 SSH 认证/既有子会话存活、整机迁移、重启、跨启动恢复、连续逆序回滚和公网仍待验收。 |
| CHK-002 | 检查 | 完成本轮修复的语法、ShellCheck、隔离回归和台账门禁 | 2026-10-25 14:51 | 2026-10-25 14:51 | 已完成 | 19 项回归通过；bash -n、ShellCheck -S warning 通过；最终 git diff --check 与 task-list check 输出保存在 plans/checkpoints；不替代 [[CHK-001]]。 |

## 测试数据

| ID | 动作 | 事项 | 发现时间 | 完成时间 | 状态 | 备注 |
| --- | --- | --- | --- | --- | --- | --- |
| TST-001 | 开发 | 建立 tests 回归脚本和 PowerShell/WSL 入口，覆盖九项审查问题及既有边界 | 2026-10-25 14:51 | 2026-10-25 14:51 | 已完成 | tests/test_regressions.py、tests/run_tests.ps1、tests/README.md；19 项通过，其中三项为真实 nft/systemd 隔离测试。 |

## 文档维护

| ID | 动作 | 事项 | 发现时间 | 完成时间 | 状态 | 备注 |
| --- | --- | --- | --- | --- | --- | --- |
| DOC-001 | 文档 | 建立 plans/checkpoints 保存修复前报告、处理汇总和测试输出，同步设计与审计文档 | 2026-10-25 14:51 | 2026-10-25 14:51 | 已完成 | plans/checkpoints/README.md、2026-10-25-fix-summary.md 及原始输出；plans/DESIGN.md、plans/AUDIT.md 已同步新版 cursor、进程链、原子恢复与验证边界。 |

## 功能开发

| ID | 动作 | 事项 | 发现时间 | 完成时间 | 状态 | 备注 |
| --- | --- | --- | --- | --- | --- | --- |
| DEV-001 | 开发 | 新增 `working-scripts/upload-ssh-apply-to-aliyun-1.sh`：从开发目录上传 stage1/2/3 到 `fenix-aliyun-1:~/ssh-apply/`，支持 `--dry-run`，上传前检查纯 LF，上传后逐文件比对 md5 | 2026-10-25 14:38 | 2026-10-25 14:38 | 已完成 | 仅本机使用，`working-scripts/` 已加入 .gitignore（见 [[OPS-005]]）。当前工作区脚本为新设计版本，上传前需先修完 [[BUG-001]]、[[BUG-002]]，否则会把必然回滚的版本推上服务器。 |

## 配置运维

| ID | 动作 | 事项 | 发现时间 | 完成时间 | 状态 | 备注 |
| --- | --- | --- | --- | --- | --- | --- |
| OPS-001 | 运维 | 安装台账维护规则与 Stop hook：规则写入 CLAUDE.md 与 AGENTS.md（中文），.claude/settings.json 注册 Stop hook + 提醒脚本，hook 已自测 | 2026-10-25 14:29 | 2026-10-25 14:29 | 已完成 | hook 命令使用 ${CLAUDE_PROJECT_DIR}，每会话首次停止触发一次；需新会话生效。注意：.claude/ 已被 gitignore（见 [[OPS-002]]），hook 仅本机有效，其他机器由规则正文的自觉执行路径兜底。 |
| OPS-002 | 运维 | 新建 .gitignore，忽略 .claude/ 与 plans/ 两个目录 | 2026-10-25 14:32 | 2026-10-25 14:32 | 已完成 | git check-ignore 验证四个文件全部命中。影响：plans/ 下 DESIGN.md/AUDIT.md 不再入库（三个脚本头部注释引用了 plans/DESIGN.md，clone 方看不到）；.claude/ 下 hook 不随仓库分发。 |
| OPS-003 | 运维 | 从 .gitignore 移除 plans/，恢复 DESIGN.md/AUDIT.md 入库；.claude/ 保持忽略 | 2026-10-25 14:36 | 2026-10-25 14:36 | 已完成 | 撤销 [[OPS-002]] 中 plans/ 部分（保留 .claude/ 忽略）。原因：三个脚本头部注释引用 plans/DESIGN.md，设计文档需随仓库分发。plans/ 现为未跟踪状态，待提交。 |
| OPS-004 | 优化 | 删除旧本地目录 `C:\Users\wangminle\ssh-apply`（真实值原件、旧 DESIGN.md、publish 克隆）；部署与发布统一改以开发目录为唯一来源 | 2026-10-25 14:38 | 2026-10-25 14:38 | 已完成 | 删除前已确认：三个真实值脚本已部署到服务器且 md5 相符，脱敏版已推送 GitHub（commit `fc046c0`）。此后不再维护第二份本地副本，上传走 [[DEV-001]]。 |
| OPS-005 | 运维 | `.gitignore` 增加 `working-scripts/`，该目录仅本机使用、不入库 | 2026-10-25 14:38 | 2026-10-25 14:38 | 已完成 | `git check-ignore -v` 验证命中；`.claude/` 与 `working-scripts/` 均仅本机有效。 |
| OPS-006 | 运维 | 提交三阶段 SSH 重构、审查修复、回归测试、检查点文档及任务台账 | 2026-10-25 14:56 | 2026-10-25 14:56 | 已完成 | 本条随本次 commit 一并记录；提交前 19 项回归、bash -n、ShellCheck、差异检查及台账 check 通过；.claude/ 与 working-scripts/ 按既有规则保持本机忽略，未执行远程推送。 |
