# stage0 默认现状检查与可选策略审计

## 问题与处理

远端不传参数、漏填 `--allow` 或把 ALLOW 当字面值时，旧版均在 argparse 校验退出，尚未检查 SSH。这反映了默认入口要求操作者先声明完整目标，无法直接回答当前账户与会话实际状态的问题。

`stage0-audit.sh` 现在支持直接 `sudo bash ~/ssh-apply/stage0-audit.sh`：

- 从 `SUDO_USER` 识别普通账户；从当前环境或祖先进程的 `SSH_CONNECTION` 识别 SSH 四元组。没有连接时仅在 socket/sshd 的监听端口唯一时回退选择，不任意挑选端口。
- 检查目标账户及 root 的有效认证、实际监听、主进程配置关联、当前登录认证方式与 sudo 关系；采集 nft、持久加载和启动依赖。
- 默认 `mode=inspect`。禁 root、禁密码、仅公钥仍是项目明确基线；来源白名单没有声明时，`policy_result=unknown`。nft 表、input 链、accept 来源字面值仅作观察，不能当作有效白名单或完整可达性证明。
- 填写 `--allow CIDR` 后进入 `mode=policy`，保留原有完整规则语义比较；账户和端口仍可自动识别，也可显式覆盖。
- 不自动把当前公网 IP 设成 `/32` 白名单，不默认要求关闭 22。多端口、无普通账户、无会话日志或不支持的启动布局等情况保留证据不足。
- 当前会话记录 publickey/password 等实际认证方式，密码不符合公钥基线。单独看到其他 established 连接不能证明已认证或他人已登录。

四个运行文件的边界保持不变，Python 实现继续内嵌 stage0；没有新增外部分发依赖。没有放松 stage1–3 的接管、事务及确认保护。

## 验证

执行 `./tests/run_tests.ps1 -Distribution Debian -Integration`：25 项三阶段/原生集成 + 29 项审计专项，共 **54 项通过，无跳过**。包括七个 Bash 入口的语法和 ShellCheck 检查。

新增 12 项回归覆盖零参数现状检查、sudo 祖先环境恢复、当前 22 不自动关闭、显式参数优先、唯一监听回退、多端口/控制台不猜测、白名单事实与目标区别、密码日志与无关 PID、文本/JSON/普通权限输出、自动端口与关闭目标冲突、systemctl 失败后仍读取实际监听，以及额外端口的分模式判断。

README 的英文/中文操作流程、独立审计文档、命名示例和测试说明已同步。本地两个被忽略的上传脚本也改为提示无参数审计；未将这些本机工具加入版本控制。

## 初次实现时的交付边界

本轮没有连接、上传或操作远端；远端现存脚本仍是此前 MD5 版本，需重新上传新版 stage0 后才能使用无参数入口。本轮未提交或推送。真实远端无参数会话恢复和整机验收没有由隔离测试替代，继续由台账跟踪。

后续已获用户授权连接 fenix-jdcloud-1，并用现有上传器同步四个文件、逐文件校验 MD5（OPS-016）。stage0 当前远端摘要为 `1fb3a972cbc22ef63cc8e7224df002ed`。真实审计需要 sudo 密码，已打开交互终端，尚未取得审计结果，CHK-008 保持进行中；没有执行 apply 或更改 SSH/防火墙配置。

## Build0167 自动计数

基线为 Build0137（b56ca34）。通过 Python AST 比较 HEAD 和工作区中的函数定义，忽略行号变化；文档按 Git 已修改与新增文件去重统计，排除台账。结果为 **Build0167 = 137 + 30**。

| 类别 | 对象 | 数量 |
| --- | --- | --- |
| 生产函数新增 | Auditor.resolve_target | 1 |
| 生产函数调整 | Auditor.__init__、audit、authentication、find_connection、firewall、listeners、session，以及 arguments、main | 9 |
| 测试函数新增 | tests/test_audit.py 中本检查点列出的 12 个现状检查用例 | 12 |
| 测试辅助函数调整 | FakeSystem.__init__、FakeSystem.run | 2 |
| 文档新增 | 本检查点文件 | 1 |
| 文档更新 | README.md、plans/AUDIT-EXISTING.md、plans/SCRIPT-NAMES.md、plans/checkpoints/README.md、tests/README.md | 5 |
| 合计 | 10 个生产函数 + 14 个测试/辅助函数 + 6 份文档 | 30 |

同一函数内多处修改只计一次；台账补记、提交操作、远端运维和忽略目录内的本机工具不额外增加 build，沿用 Build0137 的计数口径。提交说明使用 1.、2.、3. 编号且少于 300 字；本次只提交，不推送。
