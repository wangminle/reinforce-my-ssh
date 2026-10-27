# 回归测试

测试脚本只提取待测函数，不执行三个阶段脚本的完整 apply。默认测试使用临时目录和命令替身。

主脚本采用 stage1-newport.sh、stage2-harden.sh、stage3-reboot-check.sh，独立审计入口为 stage0-audit.sh。回归同时验证旧入口兼容、参数和退出码透传，以及改名后事务阶段标识仍然稳定。

生产部署只需这四个 shell 文件。stage0 的 Python 实现内嵌于文件中；tests/audit_source.py 仅为测试提取并加载它，不会分发到服务器。回归包含四文件独立目录运行检查，防止重新引入外部工作文件依赖。

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

输出可保存到 `plans/checkpoints/`。统一入口依次执行 `test_regressions.py`、`test_audit.py` 和 `test_workflow.py`，保留各自测试数量及跳过项。

三阶段回归覆盖监听解析、双栈绑定、SSH 主进程/socket 切换顺序、三个阶段 nft 规范化、额外规则拒绝、原子加载失败、完整表恢复、父策略/摘要恢复、失败不提交、早期自动恢复安装失败、迟到任务清理、CIDR 等价写法、journal cursor/boot/PID 关联和同 boot 验证拒绝。事务备份门禁另覆盖 nft 表枚举/备份失败，以及 systemctl active/enabled 状态为空或不受支持时在 pending 前拒绝。原生 nft 命名空间测试还核验带 table 前缀的真实枚举输出、目标表完整备份，以及不同 family/相似表名不被误认。

独立审计回归覆盖安全旧配置无需新版状态即可通过、不安全受管配置仍失败、Match/权限/复杂 nft/加载器未知分类、规则顺序、boot 记录一致性与漂移、非法写入命令拒绝、上传提示。集成模式另用真实 nft JSON 和真实 v6only socket 验证审计解析。

默认现状检查另覆盖零参数执行、sudo 祖先环境恢复、当前 22 不自动列为关闭、显式参数优先、唯一监听回退、多端口/控制台不猜测、白名单不自动生成、密码认证与无关日志区分、text/JSON/普通权限输出及自动识别目标与关闭端口冲突。

自动迁移回归覆盖：预览不改原文件、候选启用公钥而保留密码、stage2 实际生成认证指令、主配置/drop-in/socket/UFW 完整备份恢复、迁移输入漂移、路径越界和核心文件重叠拒绝、恢复失败重试、stage2→stage1 连续逆序回滚、迁移文件跨阶段摘要及 stage0 重启记录漂移。默认 stage0 采集完成与显式目标检查的退出码分别验证。

确认/恢复回归还覆盖：首次回滚的 nft 恢复失败保留策略并可重试成功、全局策略丢失时读取事务 policy.target，以及真实 tx_commit/cancel_recovery 在确认成功或拒绝时均不停止 SSH；拒绝时明确恢复倒计时仍在继续。

向导回归覆盖状态路由、每步后重新读取状态、权限交接与完整参数透传、首次缺项与目标冲突、无终端/救援声明拒绝、失败和无进展停止、新会话/跨 boot 边界、已有 verified 复验、初始部分配置不传给后续阶段，以及三个 `--guide` 入口转发。Linux root 下另使用真实 PTY 和临时阶段替身，验证 heredoc 不会吞掉用户或阶段的终端输入；不运行生产 apply。

## 可选的真实 UFW/OpenSSH 验收

`check_native_migration.py` 使用解包的 UFW、OpenSSH 程序；不安装包、不启动主机 SSH 服务。它在独立网络及挂载命名空间中使用私有配置、临时 host key 和账户视图，检查候选/加固配置的真实解析、UFW 双栈来源规则、启动依赖无环、完整回滚及业务规则保留。结束时比较命名空间外的账户文件与 nft 规则未变化。

Debian 中可这样准备测试运行目录（另需 iptables/ip6tables、nft、mount、unshare、systemd-analyze、ssh-keygen）：

```bash
mkdir -p /tmp/reinforce-test-runtime
cd /tmp/reinforce-test-runtime
apt-get download ufw openssh-server libwrap0
for package in ./*.deb; do dpkg-deb -x "$package" runtime; done
cd /path/to/reinforce-my-ssh
sudo python3 tests/check_native_migration.py --runtime /tmp/reinforce-test-runtime/runtime
```

通过时输出 `NATIVE_MIGRATION_PASS`。该验收独立于默认回归，不在每次测试中自动下载依赖。

这些测试没有覆盖真实 SSH 认证、原有 SSH 子会话存活、真实虚拟机迁移、真实重启、跨启动恢复或公网路径。上述整机验收仍由台账 `CHK-001` 跟踪。
