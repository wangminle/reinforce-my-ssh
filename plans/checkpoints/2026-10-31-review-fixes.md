# 全量复核问题修复（2026-10-31）

## 修复目标

本轮依据 BUG-042～046、BUG-048～052、DOC-016 和 CHK-028 的复核意见调整本地脚本、回归和说明；不连接或部署远端，不变更远端规则和系统单元。

| 范围 | 调整 |
| --- | --- |
| UFW verbose | 正确读取 ALLOW IN / DENY IN；排除 OUT/FWD 作为入站证据 |
| 当前来源 | CGNAT 地址不能证明 tailnet；必须有显式可信来源，或操作员已核实本次 tailscale0 到 sshd 入口的声明 |
| stage1 nft 过渡 | 不猜链、不打印追加规则；存在 input 链时要求人工协调全部 family/链与 drop/reject，并用新公钥会话复验 |
| stage2 nft 装载 | 单次事务替换 inet sshguard，专用 ssh-allowlist.service 加载，避免全局 flush 与旧 drop 前置 |
| 备份/恢复 | 专用加载器 unit/drop-in、active/enabled 及存在/缺省状态进入备份和恢复；旧备份不得补造 |
| stage0 指引 | Port 行尾注释解析；无来源打印注释模板，不伪造救援演练声明 |
| 重启证据 | 文件比较仅候选，覆盖 SSH 主配置与加载器；需实际冷启动外部验证后声明，运行态改动后重新验收 |
| 只读边界与退出码 | 检查完整只读调用参数；文档按实际 0/1/2/130 行为说明，来源阻断与参数错误为 2 |

## 验证记录

- 新增 `test-review-fixes.py` 18 项回归：在 HEAD `9100eae` 快照上出现 30 个失败子项；修复后全部通过。
- macOS 完整套件：133 项，130 通过、3 跳过（两项缺 unshare/nft，一项缺可查询的 systemd 总线）。其它模拟故障路径继续执行。
- Docker 隔离 Linux 完整套件：133 项，132 通过、1 个真实 systemd 总线子项跳过；两项真实网络命名空间测试执行通过。
- 真实 nft 1.1.3：首次装载、第二次加入来源、始终仅 3 条规则且 drop 位于末尾、无效事务失败保留完整旧规则、无关 MUST_KEEP 表保留，均通过。
- ShellCheck 0.10.0（`-S warning`）、三个脚本各自 `bash -n`、完整台账门禁及 `git diff --check` 通过。
- 临时容器只使用独立网络/PID 与临时文件，已删除；未变更宿主 SSH、未连接远端。
- 持久化原生复验入口：`python3 tests/verify-nft-transaction.py`。它只通过 unshare 创建的独立用户/网络命名空间运行 nft，缺依赖退出 2；其事务验证逻辑来自本轮实际通过的隔离验证。

生产脚本与 Linux 验证版本 SHA256 一致：

```text
stage0 24958e95685be4a0f43d47073b7b2faee2006fc2999c1f50326247fb5616aa66
stage1 644c9f490efe3f315fd47e7305c3e3e4615d5761d081c51bc68698ab96c731a3
stage2 aa08cf27bb4b746e5f9f36c697e88e8e97b161b94ae18c390152a11359cb2321
```

独立复核还发现并修复：未知加载器 drop-in 的停止钩子风险，以及 IPv4 拒绝掩盖 IPv6 放行。加载器实际启用/重启前检查 FragmentPath、DropInPaths 和 D-Bus 空停止钩子；不满足即停止。原加载器 active 状态不能安全自动重现时，恢复程序保留核对建议并以未完成退出，不宣称完整恢复。

Linux 原生检查依赖 nft、unshare、systemctl 与相应隔离能力。缺少依赖的 macOS 结果不能当作 Linux 验收通过；桩件、静态文本及假命令结果也不替代真实 netfilter、systemd、OpenSSH 或整机冷启动验收。

## 保留的验收边界

- ADJ-012：原子重装与故意失败保留旧表已在隔离 Linux 实测；真实服务器开机排序与运行中加载器重载仍需验收。
- ADJ-013：远端实际 unit/drop-in、启用状态备份是否存在及恢复效果仍待核实；稳态快照不等于加固前基线。
- ADJ-014：WebTerminal/VPC 的需求、实际来源/入口接口、最小授权及外部新连接仍待核实。不能未验证即放行整个 CGNAT/VPC 段。
- 文件 mtime 无法证明启动后未修改运行态。`--reboot-confirmed` 记录真实外部验收事实，后续运行态改动后必须撤销旧声明并重新冷启动验收；脚本不提供持续完整性证明。
- 未推送、未上传、未执行任何远端操作。
