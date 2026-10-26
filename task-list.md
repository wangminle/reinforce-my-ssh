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
| BUG-012 | 修复 | P1：tx_begin 将 nft list table 的任意失败误记为表不存在，回滚可删除原有防火墙表并误报完整恢复 | 2026-10-26 15:11 | 2026-10-26 19:16 | 已修复 | 影响 stage1-newport.sh 与 stage2-harden.sh 的 tx_begin/NFT_ABSENT 路径。故障注入证实查询失败仍返回 0 并写 NFT_ABSENT；隔离 nft 命名空间中，错误标记使回滚输出已完整回滚而原表实际被删除。应区分表不存在与采集失败，采集失败必须在任何系统修改前终止。；stage1/stage2 先成功枚举 nft 表，只有明确无目标表才写 NFT_ABSENT；目标表存在时备份失败立即拒绝，枚举失败也不再推断不存在。新增两阶段枚举/备份故障回归。；提交前原生 nft 核对发现新判断和测试替身漏掉 list tables 输出中的 table 前缀；已改为完整精确匹配 table inet sshguard。新增真实命名空间用例覆盖两阶段已有表完整备份、缺表标记、同名不同 family 和相似表名；57 项回归通过。 |
| BUG-013 | 修复 | P2：systemctl active/enabled 状态采集失败仍建立事务，unknown 备份无法被恢复函数处理 | 2026-10-26 15:11 | 2026-10-26 19:16 | 已修复 | stage1/stage2 的 tx_begin 对 systemctl 查询使用 \|\| true，故障注入得到 unknown 状态且事务返回 0；restore_unit_state 随后拒绝未知 active/enabled 状态，可能使自动或手工回滚失败。应在备份阶段校验每个采集结果，无法证明可恢复时不得进入 pending。；stage1/stage2 在写 units.conf 前校验 active/enabled 属于 restore_unit_state 支持的集合；空值、unknown、linked 及其他不支持状态在 pending 前拒绝。合法 disabled/inactive/not-found 保持兼容，既有首次部署回滚回归通过。 |

## 调整事项

| ID | 动作 | 事项 | 发现时间 | 完成时间 | 状态 | 备注 |
| --- | --- | --- | --- | --- | --- | --- |
| ADJ-001 | 调整 | aliyun-1 保持旧 apply.sh 加固方案，不迁移到新版三阶段；新版工具改用可销毁 Ubuntu VM 按 [[CHK-001]] 验收 | 2026-10-25 15:24 | 2026-10-25 15:24 | 已完成 | 依据 [[CHK-003]]：服务器已由旧方案完成同等加固，新版状态未初始化且拒绝接管 6 条非受管受控指令；迁移需清理旧 drop-in、旧 socket override 与旧防火墙单元，生产风险大于收益。已上传的新版脚本保留仅作只读参考，不执行 apply。 |
| ADJ-002 | 调整 | 明确三阶段默认检查的受管范围，修正未纳管诊断及上传脚本无条件提示 stage3 的指引 | 2026-10-25 15:30 | 2026-10-25 21:55 | 已完成 | 来自 [[CHK-004]]；未纳管不能表述为服务器安全失败，缺少权限/证据不能表述为不符合；上传仅替换脚本，不建立新版状态；保持 [[ADJ-001]] 的旧机器不迁移决定。；stage1 明确部署预检，stage2/3 未纳管时说明未执行安全复验；保留 apply 保护。本机上传脚本同时上传 audit.py，移除无条件 stage3 指引，保持 working-scripts 忽略；未执行远端上传。 |
| ADJ-003 | 调整 | 按职责统一 stage0-audit、stage1-newport、stage2-harden、stage3-reboot-check 入口名称并保留旧入口兼容 | 2026-10-25 22:24 | 2026-10-25 22:24 | 已完成 | stage0 为独立审计包装入口，audit.py 保留实现；三个旧 .sh 入口 exec 新主脚本。固定 STAGE_ID 为 stage1/stage2，避免改名破坏旧事务回滚。当前文档、上传集合及测试引用同步更新；未上传、未自动提交。 |
| ADJ-004 | 调整 | 实际部署收敛为四个 stage shell 文件，将审计实现内嵌 stage0 并移除外部 audit.py | 2026-10-26 07:48 | 2026-10-26 07:48 | 已完成 | 原审计代码逐字保留在 stage0 的引号 heredoc；环境仍需 Python 3。本机上传清单只含四个主脚本，旧兼容入口仅在仓库可选保留；未执行上传或提交。见 plans/checkpoints/2026-10-26-four-runtime-files.md。 |
| ADJ-005 | 调整 | 细化四文件上传器的本地预检、dry-run 文案和上传后执行指引 | 2026-10-26 07:49 | 2026-10-26 07:49 | 已完成 | 承接 [[ADJ-004]]；上传集合固定为 stage0-audit.sh、stage1-newport.sh、stage2-harden.sh、stage3-reboot-check.sh；新增存在性/纯 LF/`bash -n` 预检，dry-run 明确四文件与远端 python3 前提，上传后提示旧入口不更新、按新文件名执行并检查远端 python3；42 项回归和 ShellCheck 通过；未执行远端上传或 apply。 |
| ADJ-006 | 调整 | 按 Build0167 调整两个 working-scripts 上传器：同步 stage0 无参数现状审计、可选策略参数、远端 --help 验证与执行指引 | 2026-10-26 12:05 | 2026-10-26 12:05 | 已完成 | 承接 Build0167（`52ba8a1`）的 stage0 无参数现状审计：上传器说明区分 stage0 零参数与 stage1 仍须 `--port/--user/--allow`；dry-run 与上传后指引明确无 `--allow` 时 `policy_result=unknown`、不会把当前 IP 自动当白名单，并补充实际 SSH 会话直接 sudo 的限制。上传后由检查 `command -v python3` 改为执行远端 `stage0-audit.sh --help`，验证内嵌 Python 可运行；usage 改为按注释标记读取，避免增删说明后行号漂移。两个脚本除主机别名外保持等价。`bash -n`、ShellCheck -S warning、纯 LF、双脚本 `--help`/`--dry-run`、远端 JD `--help` 和 54 项回归通过；未上传文件、未执行 apply。 |

## 检查事项

| ID | 动作 | 事项 | 发现时间 | 完成时间 | 状态 | 备注 |
| --- | --- | --- | --- | --- | --- | --- |
| CHK-001 | 检查 | 可销毁 Ubuntu VM 整机验收：完整 SOP、两阶段外部确认、超时/跨启动自动恢复、apply 失败回滚、连续逆序回滚、真实重启与允许/拒绝来源外部测试 | 2026-10-25 14:26 | - | 待办 | 对应 plans/AUDIT.md「尚未完成的验收」。静态与隔离验证已完成，但不等于整机或公网验收；BUG-001/BUG-002 修复后必须重跑相关隔离验证再进入整机验收。；本轮 [[CHK-002]] 的 19 项隔离回归通过；真实 SSH 认证/既有子会话存活、整机迁移、重启、跨启动恢复、连续逆序回滚和公网仍待验收。 |
| CHK-002 | 检查 | 完成本轮修复的语法、ShellCheck、隔离回归和台账门禁 | 2026-10-25 14:51 | 2026-10-25 14:51 | 已完成 | 19 项回归通过；bash -n、ShellCheck -S warning 通过；最终 git diff --check 与 task-list check 输出保存在 plans/checkpoints；不替代 [[CHK-001]]。 |
| CHK-003 | 检查 | 在 fenix-aliyun-1 上执行新版 stage1/2/3 只读预检，确认新旧方案能否直接衔接 | 2026-10-25 15:22 | 2026-10-25 15:22 | 已完成 | stage1 拒绝接管旧手工配置：`/etc/ssh/sshd_config` 第 42/71/135 行与 3 个旧 drop-in 共 6 条非受管受控指令；当前来源 100.116.250.20 在 `--allow` 内。stage2 报「请先完成 stage1」，stage3 报策略文件不可读，因 `/var/lib/reinforce-my-ssh` 从未初始化。结论：aliyun-1 已由旧 apply.sh 方案完成同等加固，新版三阶段未接管；另有旧 `/etc/systemd/system/ssh.socket.d/override.conf` 与仍 enabled 的 `ssh-firewall.service` 会和新工具叠加，若将来迁移必须处理；当前决定见 [[ADJ-001]]。；[[CHK-004]] 补充证据边界：这些入口输出只证明新版未纳管/未执行复验，不能单独证明旧方案满足新版全部安全目标，也不能证明旧方案不安全；既有状态描述保留为此前记录，不视为本轮重新实测。 |
| CHK-004 | 检查 | 分析旧方案已加固而新版脚本拒绝检查的原因，区分实际安全效果、工具归属和迁移准备 | 2026-10-25 15:30 | 2026-10-25 15:30 | 已完成 | 依据用户远端执行记录及本地源码核对；未连接远端。stage1 是所有权拒绝，stage2/3 在安全复验前因缺少新版状态/策略退出，不能据此判定服务器未加固；同等安全与重启证据需独立核验。报告见 plans/checkpoints/2026-10-25-legacy-vs-managed-analysis.md。 |
| CHK-005 | 检查 | 验证独立审计及未纳管诊断：22 项三阶段/原生集成回归和 17 项审计专项全部通过 | 2026-10-25 21:55 | 2026-10-25 21:55 | 已完成 | 合计 39 项，无跳过；包含真实 nft JSON、v6only socket、原子替换/恢复和临时 systemd，使用隔离资源；不代表远端整机验收。见 plans/checkpoints/2026-10-25-independent-audit-implementation.md。 |
| CHK-006 | 检查 | 复核 Build0092 后的工作区一致性：重命名入口、独立审计、README、测试、上传集合与行尾 | 2026-10-25 23:34 | 2026-10-25 23:34 | 已完成 | 七个 Bash 入口 bash -n 与 ShellCheck -S warning 通过；`python3 tests/run_tests.py --integration`（WSL root）41 项全部通过、无跳过；上传脚本 dry-run 列出 8 个文件且未执行远端动作。发现并修复 `CLAUDE.md` 8 个、`task-list.md` 78 个 CRLF，统一为 LF；刷新 Git 索引过期 stat 缓存后内容未变。Markdown 表格/围栏/反引号/本地链接检查通过；工作区仍有未提交的新文件，未执行提交或推送。 |
| CHK-007 | 检查 | 复核 Build0122 提交 6b1102e 后的工作区、远端、回归与台账一致性 | 2026-10-26 07:15 | 2026-10-26 07:15 | 已完成 | HEAD 与 origin/main 同为 `6b1102e`；41 项回归（24 项三阶段/原生集成 + 17 项审计）、七个 Bash 入口 `bash -n`/ShellCheck、上传 dry-run 8 文件、Markdown 门禁（15 文件/7 表/38 ID）全部通过；修复 `task-list.md` 工作区 80 处 CRLF（HEAD 为 LF）后内容散列不变；未发现代码或文档缺陷。远端推送见 [[OPS-010]]。 |
| CHK-008 | 检查 | 在 fenix-jdcloud-1 的真实普通账户 SSH/sudo 会话执行无参数 stage0 现状审计 | 2026-10-26 10:12 | 2026-10-26 10:43 | 已完成 | 用户已授权远端执行；SSH 密钥登录成功。sudo -n 提示需要密码，已打开交互 PowerShell 终端供用户直接输入；结果将保存在远端 ~/ssh-apply/stage0-audit-20261026.json 与 .exit，待读取分析，不把尚未执行视为审计通过。；实际执行完成（无参数 inspect，exit=1；远端 JSON md5 `1f6ed7e10240b6aaf3aa77ed30d9cde3`，保存于 ~/ssh-apply/stage0-audit-20261026.json）。识别 fenix@120.244.186.124、端口 22；当前会话 publickey 与 sudo 链验证通过。security_result=fail：fenix 和 root 均 permitrootlogin=yes、passwordauthentication=yes；22 在 IPv4/IPv6 监听；nft 仅有 ip filter INPUT policy=accept，无 sshguard 表或白名单规则；无明确防火墙加载单元，主配置晚于 sshd 进程，reboot=unknown。ownership=unmanaged，migration=blocked（3 条非受管指令，仅阻止直接接管）。因未传 --allow，policy_result=unknown，不能表述为白名单合规；本结果不替代云安全组、拒绝来源外测或整机重启验收。未执行 apply、未修改任何配置。；本轮已下载并分析报告，SHA-256 为 9c292ab9633634771f2a72893b5528b7f88afb6575e1cd13b740b433c1f62f75；普通权限复核配置原文与 systemd。主配置比 MainPID 725 启动晚约 3 秒，磁盘解析不符合不能直接当作运行进程已证实接受密码；此前无白名单规则的表述仅能限定为未发现所选 inet sshguard 表，其他表内限制及云安全组未证明。详细报告见 plans/checkpoints/2026-10-26-jdcloud-stage0-review.md。 |
| CHK-009 | 检查 | 再次复核 Build0167 当前仓库的三阶段事务、stage0 审计与测试盲区 | 2026-10-26 15:11 | 2026-10-26 15:11 | 已完成 | 54 项现有回归（25 项三阶段/原生集成 + 29 项审计）全部通过无跳过；git diff --check 通过。新发现 [[BUG-012]]、[[BUG-013]]，现有测试未覆盖对应故障分支。旧 9 项未见回潮；未执行真实整机迁移、外部 SSH、跨启动恢复或公网验收。本轮仅审查与台账登记，未修改脚本。 |
| CHK-010 | 检查 | 验证 BUG-012/BUG-013 修复及全部三阶段、审计隔离回归 | 2026-10-26 19:16 | 2026-10-26 19:16 | 已完成 | python3 tests/run_tests.py --integration（WSL Debian root）：27 项三阶段/原生集成 + 29 项审计，共 56 项全部通过无跳过；覆盖 bash -n、ShellCheck、真实 nft 与临时 systemd。git diff --check 通过；未执行真实服务器 apply、跨启动恢复或公网验收。；本次提交前补充原生 nft 事务备份回归后，最新结果为 28 项三阶段/原生集成加 29 项审计，共 57 项通过，无跳过；明确验证真实 table 前缀，修正替身未暴露的问题。 |

## 测试数据

| ID | 动作 | 事项 | 发现时间 | 完成时间 | 状态 | 备注 |
| --- | --- | --- | --- | --- | --- | --- |
| TST-001 | 开发 | 建立 tests 回归脚本和 PowerShell/WSL 入口，覆盖九项审查问题及既有边界 | 2026-10-25 14:51 | 2026-10-25 14:51 | 已完成 | tests/test_regressions.py、tests/run_tests.ps1、tests/README.md；19 项通过，其中三项为真实 nft/systemd 隔离测试。 |
| TST-002 | 检查 | 验证重命名入口兼容、审计参数/退出码透传及稳定事务阶段标识 | 2026-10-25 22:24 | 2026-10-25 22:24 | 已完成 | 41 项回归全部通过（24 项三阶段/原生集成及 17 项审计专项）；七个 Bash 入口 bash -n 和 ShellCheck 通过。检查点见 plans/checkpoints/2026-10-25-script-names.md。 |
| TST-003 | 开发 | 适配内嵌审计测试加载，新增四工作文件空目录运行回归 | 2026-10-26 07:48 | 2026-10-26 07:48 | 已完成 | tests/audit_source.py 仅供测试；25 项三阶段/原生集成 + 17 项审计专项共 42 项通过，无跳过；七个 Bash 入口语法/ShellCheck、参数和退出码保持通过。 |
| TST-004 | 检查 | 新增 12 项默认现状检查回归并完成 54 项隔离验证 | 2026-10-26 10:07 | 2026-10-26 10:07 | 已完成 | 25 项三阶段/原生集成加 29 项审计专项全部通过，无跳过；包括语法/ShellCheck、真实 nft、socket 与 systemd 隔离验证；不替代远端真实会话和整机验收。 |

## 文档维护

| ID | 动作 | 事项 | 发现时间 | 完成时间 | 状态 | 备注 |
| --- | --- | --- | --- | --- | --- | --- |
| DOC-001 | 文档 | 建立 plans/checkpoints 保存修复前报告、处理汇总和测试输出，同步设计与审计文档 | 2026-10-25 14:51 | 2026-10-25 14:51 | 已完成 | plans/checkpoints/README.md、2026-10-25-fix-summary.md 及原始输出；plans/DESIGN.md、plans/AUDIT.md 已同步新版 cursor、进程链、原子恢复与验证边界。 |
| DOC-002 | 文档 | 补充独立只读审计使用说明、支持范围、统一测试入口和实施检查点 | 2026-10-25 21:55 | 2026-10-25 21:55 | 已完成 | plans/AUDIT-EXISTING.md、plans/DESIGN.md、tests/README.md 与 checkpoints 已更新；明确未知项、旧方案保持和未执行远端操作。 |
| DOC-003 | 文档 | 新增简洁的英文/中文双语 README，顶部语言跳转，说明四阶段职责、审计与部署流程及验证边界 | 2026-10-25 22:49 | 2026-10-25 22:49 | 已完成 | 英文在前、中文在后，包含普通用户 sudo、外部新会话确认、重启验证、回滚、测试与详细文档链接；语言锚点、文件链接和围栏检查通过。 |
| DOC-004 | 文档 | 同步四工作文件部署说明，明确内嵌 Python 环境依赖与可选兼容文件 | 2026-10-26 07:48 | 2026-10-26 07:48 | 已完成 | 更新 README.md、plans/SCRIPT-NAMES.md、plans/AUDIT-EXISTING.md、tests/README.md 及检查点；历史报告保留原证据，不要求随部署分发测试辅助文件。 |
| DOC-005 | 文档 | 同步无参数审计的双语流程、模式边界、测试说明和检查点 | 2026-10-26 10:07 | 2026-10-26 10:07 | 已完成 | README.md、plans/AUDIT-EXISTING.md、plans/SCRIPT-NAMES.md、tests/README.md 及 plans/checkpoints/2026-10-26-auto-inspect.md；两个本地上传器提示同步但仍不入库。远端旧版需重新上传后才能无参数执行。；后续已重新上传新版，见 [[OPS-016]]；已补充 Build0167 自动计数及远端审计等待 sudo 的交付边界。 |
| DOC-006 | 文档 | 保存京东云真实 stage0 原始 JSON 与证据边界复核报告 | 2026-10-26 15:03 | 2026-10-26 15:03 | 已完成 | 已下载 JSON 并校验与远端 SHA-256 一致，补充配置原文、启动与修改时间、socket 和加载单元只读核对；明确磁盘不符合、主进程关联未知、白名单未评估三者区别。检查点索引同步；未修改远端配置、未执行 apply。；补充 plans/checkpoints/2026-10-26-build0179.md 和索引，保存本次事务修复验证及自动计数。 |

## 功能开发

| ID | 动作 | 事项 | 发现时间 | 完成时间 | 状态 | 备注 |
| --- | --- | --- | --- | --- | --- | --- |
| DEV-001 | 开发 | 新增 `working-scripts/upload-ssh-apply-to-aliyun-1.sh`：从开发目录上传 stage1/2/3 到 `fenix-aliyun-1:~/ssh-apply/`，支持 `--dry-run`，上传前检查纯 LF，上传后逐文件比对 md5 | 2026-10-25 14:38 | 2026-10-25 14:38 | 已完成 | 仅本机使用，`working-scripts/` 已加入 .gitignore（见 [[OPS-005]]）。当前工作区脚本为新设计版本，上传前需先修完 [[BUG-001]]、[[BUG-002]]，否则会把必然回滚的版本推上服务器。 |
| DEV-002 | 开发 | 增加独立于新版 state/policy 的只读现状审计，分别报告安全效果、管理归属、迁移准备和重启证据 | 2026-10-25 15:30 | 2026-10-25 21:55 | 已完成 | 方案见 [[CHK-004]]；接受满足目标的旧配置布局，显式传入审计策略；结果区分通过、不符合和证据不足，不修改状态、不自动接管、不放松 apply 的所有权/回滚保护。；已实现 audit.py：显式目标策略、独立四类报告、中文/JSON 和退出码 0/1/2；仅调用读取命令，不创建状态、不自动接管。39 项回归通过；文档见 plans/AUDIT-EXISTING.md。 |
| DEV-003 | 开发 | 新增 working-scripts/upload-ssh-apply-to-jdcloud-1.sh：仿照 to-aliyun 上传器，把四个自包含运行文件上传到 fenix-jdcloud-1:~/ssh-apply，支持 --dry-run、纯 LF/语法预检与逐文件 md5 核对 | 2026-10-26 08:31 | 2026-10-26 08:31 | 已完成 | 仿照 [[DEV-001]] 的 to-aliyun 版本按 aliyun-1→jdcloud-1 同名替换生成；上传清单同为 stage0-audit.sh、stage1-newport.sh、stage2-harden.sh、stage3-reboot-check.sh 四个自包含运行文件；默认 REMOTE_HOST=fenix-jdcloud-1、REMOTE_DIR=ssh-apply。bash -n、ShellCheck -S warning、纯 LF 和可执行位通过，--help 与 --dry-run 显示正确目标且无 audit.py/旧入口字样；未执行真实上传。 |
| DEV-004 | 开发 | stage0 默认自动识别当前 SSH 账户、端口和来源，保留可选目标策略审计 | 2026-10-26 10:07 | 2026-10-26 10:07 | 已完成 | 零参数 sudo 即可现状检查；SUDO_USER/SSH_CONNECTION 与祖先环境恢复；唯一监听回退，不猜测多端口；不自动生成白名单或关闭当前 22；填写 --allow 才比较完整 nft 策略。密码登录与无关 established 连接区分。未上传远端、未提交。；后续新版上传完成见 [[OPS-016]]，本次提交计数见 [[OPS-017]]；远端真实审计仍见 [[CHK-008]]。 |

## 配置运维

| ID | 动作 | 事项 | 发现时间 | 完成时间 | 状态 | 备注 |
| --- | --- | --- | --- | --- | --- | --- |
| OPS-001 | 运维 | 安装台账维护规则与 Stop hook：规则写入 CLAUDE.md 与 AGENTS.md（中文），.claude/settings.json 注册 Stop hook + 提醒脚本，hook 已自测 | 2026-10-25 14:29 | 2026-10-25 14:29 | 已完成 | hook 命令使用 ${CLAUDE_PROJECT_DIR}，每会话首次停止触发一次；需新会话生效。注意：.claude/ 已被 gitignore（见 [[OPS-002]]），hook 仅本机有效，其他机器由规则正文的自觉执行路径兜底。 |
| OPS-002 | 运维 | 新建 .gitignore，忽略 .claude/ 与 plans/ 两个目录 | 2026-10-25 14:32 | 2026-10-25 14:32 | 已完成 | git check-ignore 验证四个文件全部命中。影响：plans/ 下 DESIGN.md/AUDIT.md 不再入库（三个脚本头部注释引用了 plans/DESIGN.md，clone 方看不到）；.claude/ 下 hook 不随仓库分发。 |
| OPS-003 | 运维 | 从 .gitignore 移除 plans/，恢复 DESIGN.md/AUDIT.md 入库；.claude/ 保持忽略 | 2026-10-25 14:36 | 2026-10-25 14:36 | 已完成 | 撤销 [[OPS-002]] 中 plans/ 部分（保留 .claude/ 忽略）。原因：三个脚本头部注释引用 plans/DESIGN.md，设计文档需随仓库分发。plans/ 现为未跟踪状态，待提交。 |
| OPS-004 | 优化 | 删除旧本地目录 `C:\Users\wangminle\ssh-apply`（真实值原件、旧 DESIGN.md、publish 克隆）；部署与发布统一改以开发目录为唯一来源 | 2026-10-25 14:38 | 2026-10-25 14:38 | 已完成 | 删除前已确认：三个真实值脚本已部署到服务器且 md5 相符，脱敏版已推送 GitHub（commit `fc046c0`）。此后不再维护第二份本地副本，上传走 [[DEV-001]]。 |
| OPS-005 | 运维 | `.gitignore` 增加 `working-scripts/`，该目录仅本机使用、不入库 | 2026-10-25 14:38 | 2026-10-25 14:38 | 已完成 | `git check-ignore -v` 验证命中；`.claude/` 与 `working-scripts/` 均仅本机有效。 |
| OPS-006 | 运维 | 提交三阶段 SSH 重构、审查修复、回归测试、检查点文档及任务台账 | 2026-10-25 14:56 | 2026-10-25 14:56 | 已完成 | 本条随本次 commit 一并记录；提交前 19 项回归、bash -n、ShellCheck、差异检查及台账 check 通过；.claude/ 与 working-scripts/ 按既有规则保持本机忽略，未执行远程推送。 |
| OPS-007 | 运维 | 用 working-scripts/upload-ssh-apply-to-aliyun-1.sh 上传新版三阶段脚本到 fenix-aliyun-1:~/ssh-apply，并逐文件核对 md5 | 2026-10-25 15:10 | 2026-10-25 15:10 | 已完成 | 上传前核对：[[BUG-001]]/[[BUG-002]] 修复标记（`(Stream)` 解析、`normalize_nft` 单元素折叠）均在，bash -n 与纯 LF 通过；WSL Debian 默认回归 16 通过、3 项集成因 sudo 需密码跳过（不替代 [[CHK-001]]）。远端 md5：stage1 `14b7723f…`、stage2 `0d4b3b8f…`、stage3 `582b942b…`，替换原 fc046c0 部署；未执行远端 apply。 |
| OPS-008 | 运维 | 按本次两项完成功能使用 build2 标题提交独立审计与诊断改进，说明采用编号且少于 300 字 | 2026-10-25 21:55 | 2026-10-25 21:55 | 已完成 | 本条随本次 commit 提交；功能计数为 [[DEV-002]] 和 [[ADJ-002]]，测试/文档不重复计数；提交前差异与台账检查通过；当时未推送，后续推送见 [[OPS-010]]。；用户已将上次版本确认并调整为 Build0092，当前基线提交 17b729b；后续从 92 累加，不再沿用原 build2 试行编号。 |
| OPS-009 | 运维 | 按实际完成的小任务从 Build0092 累加至 Build0122 并提交阶段入口重构与双语 README | 2026-10-25 23:36 | 2026-10-25 23:36 | 已完成 | 计数明细：11 个生产函数修改、4 个入口新增/重构、8 个测试函数、7 份文档，共 30 项；同一对象不重复计数，台账/提交/忽略目录不额外增加 build。41 项回归及 README 链接检查通过，编号说明采用 1.2.3. 且少于 300 字；明细见 plans/checkpoints/2026-10-25-script-names.md。本条随本次提交，当时未推送；后续推送见 [[OPS-010]]。 |
| OPS-010 | 运维 | 补记 Build0092（17b729b）与 Build0122（6b1102e）推送 origin/main | 2026-10-25 22:06 | 2026-10-25 23:49 | 已完成 | 由其他会话执行；远端 reflog 分别显示 2026-10-25 22:06:38 和 23:49:50 的 update by push，本地与远端均指向对应提交；补齐 [[OPS-008]]/[[OPS-009]] 完成时「未推送」后的状态。 |
| OPS-011 | 运维 | 在本地生成 ed25519 密钥对 fenix-jdcloud-1，并核对 Windows ACL | 2026-10-26 07:58 | 2026-10-26 07:58 | 已完成 | 使用原生 OpenSSH ssh-keygen 生成，无口令；私钥 ACL 无继承项且不含 CodexSandboxUsers，仅当前用户/SYSTEM/Administrators；公钥指纹 SHA256:yV+kTGAlqIpRg5l7at6di1QH/1m2L1VvEDbmqkxrP+4；未修改 ~/.ssh/config；公钥安装与登录验证见 [[OPS-013]]。 |
| OPS-013 | 运维 | 将 fenix-jdcloud-1 公钥安装到京东云 114.67.236.43 并验证密钥登录 | 2026-10-26 08:05 | 2026-10-26 08:05 | 已完成 | 承接 [[OPS-011]]；在 fenix 用户下写入 ~/.ssh/authorized_keys（目录 700、文件 600）；本机以 `ssh -i ~/.ssh/fenix-jdcloud-1 -o IdentitiesOnly=yes -p 22 fenix@114.67.236.43` 非交互验证成功，hostname 1763017675236、用户 fenix、HOME /home/fenix；新增本地 config 记录见 [[OPS-014]]；未部署项目文件。 |
| OPS-014 | 运维 | 在本地 ~/.ssh/config 增加 fenix-jdcloud-1 主机记录 | 2026-10-26 08:07 | 2026-10-26 08:07 | 已完成 | 承接 [[OPS-013]]；仿照现有主机块配置 HostName 114.67.236.43、Port 22、User fenix、IdentityFile C:\Users\wangminle\.ssh\fenix-jdcloud-1、IdentitiesOnly yes 及 keepalive；`ssh -G` 解析正确，按别名非交互登录成功；修改前备份 config.bak-20261026-fenix-jdcloud-1。 |
| OPS-012 | 运维 | 按实际小任务从 Build0122 累加至 Build0137 并提交四工作文件收敛 | 2026-10-26 08:00 | 2026-10-26 08:00 | 已完成 | 1 项入口重构、8 个测试/辅助函数、6 份文档，共 15 项；审计源码逐字搬移不重复计数。42 项回归全部通过；计数见 plans/checkpoints/2026-10-26-four-runtime-files.md。本条随提交记录，提交说明按 1.2.3. 且不超过 300 字；未推送。 |
| OPS-015 | 运维 | 用 upload-ssh-apply-to-jdcloud-1.sh 上传四个自包含运行文件到 fenix-jdcloud-1:~/ssh-apply，并核对本地/远端 md5 与 python3 | 2026-10-26 09:46 | 2026-10-26 09:46 | 已完成 | 承接 [[DEV-003]]；上传到 fenix-jdcloud-1:~/ssh-apply，四个文件 md5 全部与本机一致：stage0 `5877e72e053d3f133d070eba06bac599`、stage1 `c3ae7153abc5fe4334a7391f20c88400`、stage2 `353996df4274443fda1e9d8f55b85ed2`、stage3 `95d5f13fc0623b401cfb22af29789f26`。远端复验目录 /home/fenix/ssh-apply、四文件均为 fenix 属主且可执行，/usr/bin/python3 为 3.12.3；未执行远端 apply 或审计。 |
| OPS-016 | 运维 | 重新上传新版四个运行脚本到 fenix-jdcloud-1 并逐文件校验 MD5 | 2026-10-26 10:12 | 2026-10-26 10:12 | 已完成 | 本轮连接发现远端 stage0 仍为 5877e72e053d3f133d070eba06bac599，使用现有 upload-ssh-apply-to-jdcloud-1.sh 同步后为 1fb3a972cbc22ef63cc8e7224df002ed；stage1/2/3 分别为 c3ae7153abc5fe4334a7391f20c88400、353996df4274443fda1e9d8f55b85ed2、95d5f13fc0623b401cfb22af29789f26，全部与本地一致。未执行 apply 或更改 SSH/防火墙配置。 |
| OPS-017 | 运维 | 自动统计 30 项已完成小任务，从 Build0137 累加至 Build0167 并提交无参数审计改进 | 2026-10-26 10:14 | 2026-10-26 10:14 | 已完成 | Python AST 对比得到 10 个生产函数、14 个测试/辅助函数，Git 文件清单得到 6 份文档，共 30 项；台账、提交、忽略目录和远端运维不额外计数。54 项回归已通过，本条随提交记录；说明按 1.2.3. 且少于 300 字，不推送。计数见 plans/checkpoints/2026-10-26-auto-inspect.md；CHK-008 仍待 sudo 验证。 |
| OPS-018 | 运维 | 自动计数从 Build0167 累加至 Build0179，提交事务备份修复及京东云审计归档 | 2026-10-26 22:57 | 2026-10-26 22:57 | 已完成 | 2 个生产函数、5 个测试/辅助函数、4 份文档、1 份原始 JSON 归档，共 12 项；台账、提交、运维及忽略目录不额外计数。57 项隔离回归全部通过。本条随提交记录，说明按 1.2.3. 编号且少于 300 字；不推送、不上传两阶段新修复、不执行远端 apply。 |
