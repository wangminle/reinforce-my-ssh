# 四个工作文件收敛检查点

用户期望实际部署只需要四个 stage shell 文件。原 stage0-audit.sh 是五行包装器，实际调用 audit.py；因此旧布局不能直接删除 audit.py。

## 处理

- 将原审计实现以带引号的 heredoc 完整内嵌 stage0-audit.sh，使用 exec python3 - 转交参数，不产生临时生产脚本、不改变现有审计逻辑。
- 移除根目录 audit.py；运行环境继续依赖 Python 3，与其他阶段已经使用 Python 的要求一致。
- 本机上传清单收敛为 stage0-audit.sh、stage1-newport.sh、stage2-harden.sh、stage3-reboot-check.sh。
- 三个旧文件名入口只保留为可选兼容文件，不进入新上传清单。没有删除远端历史文件。
- tests/audit_source.py 仅在开发测试中提取内嵌代码，测试和辅助文件不属于部署包。
- 同步双语 README、命名/发布清单、审计说明和测试说明；历史审查报告不改写。

## 验证

内嵌前后审计源码逐字一致，规范化 LF 后的 SHA-256：

```text
8b8af6d0b34134bb50e8231418eb936f183b1d9a95c47eaf1db17e57b74dcebc
```

统一集成回归入口实际结果：25 项三阶段/原生集成测试 + 17 项审计专项 = 42 项全部通过，无跳过。包括：

- 将四个工作文件复制到空目录，不带 audit.py、兼容入口或 tests，逐个执行 help 成功。
- stage0 命令行参数、help、非法 apply 拒绝及退出码保持一致。
- 实际 nft JSON、IPv6 双栈 socket、事务原子恢复和临时 systemd 切换仍通过。
- 上传 dry-run 只列出四个工作脚本；没有执行真实上传或远端操作。
- 七个仓库 Bash 入口的 bash -n 与 ShellCheck 通过；最终差异检查和台账门禁另行执行。

初次记录时未提交；本次提交编号见下。没有执行推送、远端部署或完整服务器验收，既有 CHK-001 保持待办。用户先前其他会话的台账改动在本轮保留。

## Build0137 计数

基线为 Build0122（6b1102e），本次完成 15 项小任务，因此版本为 **Build0137 = 122 + 15**。

| 类别 | 对象 | 数量 |
| --- | --- | --- |
| 入口重构 | stage0-audit.sh 内嵌审计实现，移除对外部 audit.py 的依赖 | 1 |
| 测试函数调整 | test_audit.py 中的 test_nonroot_exit_two_and_invalid_apply_rejected、test_upload_includes_audit_without_unconditional_stage3 | 2 |
| 测试函数调整 | test_regressions.py 中的 test_old_entry_names_delegate_and_stage0_preserves_arguments、test_native_audit_nft_json、test_native_audit_dual_stack_socket_option | 3 |
| 测试函数新增 | test_four_runtime_files_are_self_contained | 1 |
| 测试辅助函数新增 | tests/audit_source.py 中的 audit_source、load_audit | 2 |
| 文档新增 | 本检查点文件 | 1 |
| 文档更新 | README.md、plans/AUDIT-EXISTING.md、plans/SCRIPT-NAMES.md、plans/checkpoints/README.md、tests/README.md | 5 |
| 合计 | 1 项入口重构 + 8 个测试/辅助函数 + 6 份文档 | 15 |

原审计函数逻辑逐字未变，不按搬移后的函数数重复增加 build；删除旧 audit.py 属于同一入口重构。台账记录、提交操作及本机忽略的上传脚本不额外计数。
