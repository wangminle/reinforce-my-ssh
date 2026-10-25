# 回归测试

测试脚本只提取待测函数，不执行三个阶段脚本的完整 apply。默认测试使用临时目录和命令替身。

主脚本采用 stage1-newport.sh、stage2-harden.sh、stage3-reboot-check.sh，独立审计入口为 stage0-audit.sh。回归同时验证旧入口兼容、参数和退出码透传，以及改名后事务阶段标识仍然稳定。

Linux / WSL 中运行：

```bash
python3 tests/run_tests.py
sudo python3 tests/run_tests.py --integration
```

依赖：Python 3、Bash、ShellCheck；集成模式另需 root、nft、iproute2、systemd、unshare，且 systemd 必须是当前系统管理器。

`--integration` 中的 nft 操作位于独立网络命名空间。systemd 检查创建带 `PrivateNetwork=yes` 的临时 `reinforce-test-*` 单元，使用独立的测试端口，结束时停止单元并清理文件。不操作真实 ssh.service/ssh.socket，不改变主机 nft 表、不执行重启。

Windows PowerShell 可使用：

```powershell
./tests/run_tests.ps1 -Distribution Debian -Integration
```

输出可保存到 `plans/checkpoints/`。统一入口依次执行 `test_regressions.py` 和 `test_audit.py`，保留各自测试数量及跳过项。

三阶段回归覆盖监听解析、双栈绑定、SSH 主进程/socket 切换顺序、三个阶段 nft 规范化、额外规则拒绝、原子加载失败、完整表恢复、父策略/摘要恢复、失败不提交、早期自动恢复安装失败、迟到任务清理、CIDR 等价写法、journal cursor/boot/PID 关联和同 boot 验证拒绝。

独立审计回归覆盖安全旧配置无需新版状态即可通过、不安全受管配置仍失败、Match/权限/复杂 nft/加载器未知分类、规则顺序、boot 记录一致性与漂移、非法写入命令拒绝、上传提示。集成模式另用真实 nft JSON 和真实 v6only socket 验证审计解析。

这些测试没有覆盖真实 SSH 认证、原有 SSH 子会话存活、真实虚拟机迁移、真实重启、跨启动恢复或公网路径。上述整机验收仍由台账 `CHK-001` 跟踪。
