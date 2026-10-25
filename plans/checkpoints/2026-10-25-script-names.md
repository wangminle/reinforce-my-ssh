# 阶段入口命名检查点

采用 stage0-audit.sh、stage1-newport.sh、stage2-harden.sh、stage3-reboot-check.sh 四个入口。第一阶段建立候选通道，第二阶段负责认证和端口收口，第三阶段只验证重启；命名与职责对应。

保留 audit.py 审计实现及 stage1.sh/stage2.sh/stage3.sh 兼容入口。当前文档和本机上传指引同步更新，历史报告与已完成台账中的原始文件名不批量改写。

事务阶段标识固定为 stage1/stage2，不再由脚本文件名推导，兼容已有阶段记录。新事务保存实际主脚本副本，不把依赖旁边文件的兼容入口当作自动恢复脚本。

统一回归入口执行结果：24 项三阶段及原生集成测试、17 项审计专项测试，共 41 项全部通过，无跳过。新增覆盖新旧入口 help 一致、审计参数/退出码透传、主脚本改名后仍识别旧 stage 标识并拒绝跨阶段恢复；七个 Bash 入口的语法与 ShellCheck 均通过。

完整说明见 ../SCRIPT-NAMES.md。初次记录时仅完成本地修改；本次提交编号见下。没有远端上传或部署，真实服务器验收继续由 CHK-001 跟踪。

## 本次提交的 Build 计数

用户确认上次版本为 Build0092，Git 当前基线为 17b729b。本次按已完成的函数、入口脚本及说明文档逐项计数，合计 30 项，提交版本为 **Build0122 = 92 + 30**。

同一个函数的多处修改只计一次，重命名后未改变的函数不计，主实现的文件搬移不在函数修改之外重复计数。台账同步、提交说明、编号计算及提交操作不额外增加 build。本机忽略的上传脚本不进入本次提交计数。

| 类别 | 对象 | 数量 |
| --- | --- | --- |
| 生产函数修改 | stage1-newport.sh：usage、tx_restore、do_apply、do_confirm | 4 |
| 生产函数修改 | stage2-harden.sh：usage、tx_restore、do_apply、do_confirm | 4 |
| 生产函数修改 | stage3-reboot-check.sh：usage | 1 |
| 生产函数修改 | audit.py：arguments、main | 2 |
| 入口新增/重构 | stage0-audit.sh 新入口；stage1.sh、stage2.sh、stage3.sh 兼容入口 | 4 |
| 测试函数修改 | tests/test_regressions.py：function、library、Regression.test_static、Regression.test_socket_output_and_bind_configuration、Regression.test_unmanaged_diagnostics_do_not_report_security_failure | 5 |
| 测试函数新增 | Regression.test_old_entry_names_delegate_and_stage0_preserves_arguments、Regression.test_recovery_uses_stable_stage_id_after_rename | 2 |
| 测试函数修改 | tests/test_audit.py：AuditTests.test_upload_includes_audit_without_unconditional_stage3 | 1 |
| 文档新增 | README.md、plans/SCRIPT-NAMES.md、本检查点文件 | 3 |
| 文档更新 | plans/DESIGN.md、plans/AUDIT-EXISTING.md、plans/checkpoints/README.md、tests/README.md | 4 |
| 合计 | 11 个生产函数 + 4 个入口 + 8 个测试函数 + 7 份文档 | 30 |

其中测试为 2 个新增、6 个调整；文档为 3 份新增、4 份更新。这里统计的是本次实际完成的代码/重构/测试/文档小任务，并不声称新增了 30 项加固能力。
