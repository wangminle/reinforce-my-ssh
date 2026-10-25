# 回归测试

测试脚本只提取待测函数，不执行三个阶段脚本的完整 apply。默认测试使用临时目录和命令替身。

Linux / WSL 中运行：

```bash
python3 tests/test_regressions.py
sudo python3 tests/test_regressions.py --integration
```

依赖：Python 3、Bash、ShellCheck；集成模式另需 root、nft、iproute2、systemd、unshare，且 systemd 必须是当前系统管理器。

`--integration` 中的 nft 操作位于独立网络命名空间。systemd 检查创建带 `PrivateNetwork=yes` 的临时 `reinforce-test-*` 单元，使用独立的测试端口，结束时停止单元并清理文件。不操作真实 ssh.service/ssh.socket，不改变主机 nft 表、不执行重启。

Windows PowerShell 可使用：

```powershell
./tests/run_tests.ps1 -Distribution Debian -Integration
```

输出可保存到 `plans/checkpoints/`。测试覆盖监听解析、双栈绑定、SSH 主进程/socket 切换顺序、三个阶段 nft 规范化、额外规则拒绝、原子加载失败、完整表恢复、父策略/摘要恢复、失败不提交、早期自动恢复安装失败、迟到任务清理、CIDR 等价写法、journal cursor/boot/PID 关联和同 boot 验证拒绝。

这些测试没有覆盖真实 SSH 认证、原有 SSH 子会话存活、真实虚拟机迁移、真实重启、跨启动恢复或公网路径。上述整机验收仍由台账 `CHK-001` 跟踪。
