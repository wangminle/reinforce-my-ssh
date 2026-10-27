# 检查点记录

本目录保存临时检查报告、测试原始输出和阶段性处理汇总，按日期命名，保留复现过程及验证边界。

- `2026-10-25-review-before-fix.md`：本轮修复前的九项审查问题，作为历史基线保留。
- `2026-10-25-fix-summary.md`：修复映射、复跑结果和剩余验收事项。
- `2026-10-25-regressions.txt`：本轮回归测试输出。
- `2026-10-25-task-list-check.txt`：最终台账门禁输出。
- `2026-10-25-legacy-vs-managed-analysis.md`：已有旧方案与新版受管状态的区别、证据边界及独立审计/迁移方案。
- `2026-10-25-independent-audit-implementation.md`：独立审计、诊断指引实施结果、39 项验证及 build2 功能计数说明。
- `2026-10-25-script-names.md`：四阶段入口命名、旧入口兼容与 41 项回归结果。
- `2026-10-26-four-runtime-files.md`：审计实现内嵌、四文件部署清单及 42 项回归结果。
- `2026-10-26-auto-inspect.md`：默认无参数现状检查、可选白名单策略审计、会话证据边界及 54 项回归结果。
- `2026-10-26-jdcloud-stage0-review.md`、`2026-10-26-jdcloud-stage0.json`：京东云真实会话的审计报告、只读交叉核对及磁盘/运行状态证据边界。
- `2026-10-26-build0179.md`：事务备份门禁修复、真实 nft 枚举格式补验、57 项回归与本次 build 计数。
- `2026-10-27-stage0-stage1-boundaries.md`：现状采集与终态基线混用、未纳管与迁移语义、防火墙共存准入缺口及调整建议。
- `2026-10-27-actionable-migration.md`：现状/基线分离、自动迁移与 UFW 协调的实施、支持边界和验证汇总。
- `2026-10-27-actionable-tests.txt`、`2026-10-27-native-migration.txt`：统一回归与原生 OpenSSH/UFW 隔离迁移验收输出。
- `2026-10-27-guided-workflow.md`、`2026-10-27-workflow-tests.txt`：按状态执行、sudo/输入/新会话/重启续跑指引及 91 项统一回归结果。
- `2026-10-27-confirm-recovery-analysis.md`、`2026-10-27-confirm-recovery-tests.txt`：密码会话确认拒绝、远端不可达证据、初始回滚丢失策略的可重试性修复与 94 项回归。
- `2026-10-27-lockout-incident.md`：用户报告 SSH/VNC 均不可用的真实事故、暂停部署、未查明根因及重新开放部署前的验收阻断。
- `2026-10-27-guidance-pivot.md`：转向决策——废弃自动执行与定时回滚，改为三脚本只读分步指导；交付、37 项桩件验证与未闭环事项。
- `2026-10-27-build0384.md`：v1 收尾修复与 legacy 冻结、v2 三脚本转向的合并提交、37 项桩件验证与本次 build 计数。

后续检查继续新增日期或主题文件，不把新的结果覆盖成历史报告当时已通过的结论。长期设计保存在 `../DESIGN-v2.md`（v2 只读指导）；v1 自动执行设计与旧审计文档随旧脚本冻结在 `../../legacy/plans/`；可执行测试保存在根目录 `tests/`（新指导套件）与 `legacy/tests/`（旧体系存档）。
