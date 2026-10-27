# legacy/ —— 已废弃的自动执行体系（冻结存档，禁止使用）

**状态：废弃（2026-10-27）。禁止对任何真实服务器运行本目录下的脚本。**

## 为什么废弃

本目录是旧版"自动执行 + 事务 + 定时回滚"体系：

- `stage0-audit.sh --guide` 会代操作员执行 stage1/2/3 的 `--apply`/`--confirm`；
- `stage1-newport.sh` / `stage2-harden.sh` 在 apply 时安装 systemd 恢复定时器，确认窗口（默认 900 秒）到期后**无人值守自动回滚**；
- 回滚路径 `tx_restore` 先 `systemctl stop ssh.service ssh.socket`，**恢复失败时再次停止全部 SSH 接入**，可能把救援路径一并堵死。

2026-10-27 京东云真实节点发生失联事故（台账 [[BUG-016]]，根因未查明）：确认被拒、策略文件不可读、随后 SSH 与 VNC 均不可达。本地已复现同族缺陷 [[BUG-015]]（初次回滚在复验前删除 policy.conf，恢复失败后停止 SSH 且回滚入口无法重试）。事故记录见 `../plans/checkpoints/2026-10-27-lockout-incident.md`。

结论：把"人的判断"外包给定时器和自动回滚，在只有 SSH 一条活路的机器上，任何未建模的故障都会把保护机制变成自我锁死。新版工具改为**纯只读的分步指导**，见仓库根目录的 `stage0-check.sh`、`stage1-port-key.sh`、`stage2-lockdown.sh` 与 `../plans/DESIGN-v2.md`。

## 为什么保留

1. **取证与对照**：远端节点（fenix-aliyun-1、fenix-jdcloud-1 的 `~/ssh-apply/`）部署过这些版本，台账 OPS-015/016/019 记录了逐文件 md5；本目录文件与当时部署版本保持字节一致，**不要再编辑**。
2. **旧事务参考**：京东云节点上可能残留旧版事务目录（`/var/lib/reinforce-my-ssh/transactions/`），恢复对照需要阅读本目录的 `tx_restore`/`--rollback` 逻辑。
3. **测试与文档**：`tests/` 是旧体系对应的 94 项回归（含向导与审计专项），`plans/` 是旧体系的设计与验收文档（DESIGN/AUDIT/AUDIT-EXISTING/SCRIPT-NAMES），仅随本目录存档参考。

## 目录内容

| 路径 | 说明 |
| --- | --- |
| `stage0-audit.sh` | 旧版只读审计 + `--guide` 代执行入口（审计引擎有参考价值，代执行已废弃） |
| `stage1-newport.sh` / `stage2-harden.sh` | 旧版事务化 apply/confirm/rollback（含自动恢复定时器，废弃） |
| `stage3-reboot-check.sh` | 旧版重启基线验证（本身只读，但其状态文件依赖旧事务体系） |
| `tests/` | 旧体系回归测试（相对路径按本目录布局仍可运行，仅供存档验证） |
| `plans/` | 旧体系设计与验收文档 |

2026-10-27：按用户要求删除 `stage1.sh` / `stage2.sh` / `stage3.sh` 三个兼容转发入口——它们只是五行 `exec` 包装，远端从未部署，没有取证价值。`tests/test_regressions.py` 中引用这些文件名的用例属于历史记录，随本目录存档，不再作为有效回归。

本目录不随新部署分发；上传/部署清单只包含根目录的三个指导脚本。
