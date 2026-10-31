# BUG-037 / BUG-047 修复与验证

2026-10-31。基线 HEAD `8280b78`，保留工作区已有实践记录、复盘、索引和台账修改。本轮修改本地指导脚本及测试，未上传远端、未操作真实 SSH 服务。

## BUG-037：协调切换并检查会话保护

stage1/2 生成的恢复程序原先先重启 ssh.socket，再重载 ssh.service。真实 systemd 在活跃服务持有继承监听 fd 时拒绝单独重启 socket，程序因 check=True 中止。

两个脚本现在生成同一份服务切换程序；stage1 开新端口、关旧端口也使用它：

1. 恢复写文件前先查询保护条件，恢复末尾执行 sshd 校验、daemon-reload 后再次核对。
2. 要求 KillMode=process、SendSIGHUP=no，ExecStop/ExecStopPost 为明确空数组。systemctl 可能省略空数组，因此通过 busctl 的 JSON D-Bus 属性读取，失败就拒绝继续；不自动修改服务保护设置。
3. socket 模式用同一 stop 事务停止 socket/主服务，再一起 start，释放主进程持有的监听 fd；已有会话子进程按保护条件保留。
4. 恢复传统模式时，如果当前 socket 仍 active/failed，同样协调停止后仅启动主服务；本来就无活跃 socket 时沿用 reload-or-restart。启动后检查目标服务 active，socket 模式另查 socket active。
5. 任何步骤失败时立即停止，仅输出状态、日志检查与配置校验、人工启动建议；不自动执行输出的命令，不重试、不回滚、不删除恢复入口或备份。操作者保持控制台，检查并修正后另行决定后续动作。

这是一份操作员手工执行的程序，不改变工具只读定位，也没有自动配置回滚。保护条件不满足时，会拒绝这条恢复路径，需从控制台人工处理；并不承诺支持任意自定义服务。systemd 对 KillMode 的定义参见 [官方手册](https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html#KillMode=)，本项目不自动把任意服务修改成 process。

## BUG-047：缺失单元与采集失败分开

备份先用 systemctl show 查询每个目标单元的 LoadState：

- 明确 not-found：写入 not-found 状态，继续备份，无需 is-enabled 有 stdout。
- loaded/masked：继续查询 active/enabled，并校验返回码与状态的合法组合。
- bus 失败、空值、错误加载状态、非法状态或不支持组合：立即退出，不写 backup-complete。

保留既有快照格式和恢复器支持的状态集合，不把“查询失败”降级为“单元不存在”。

## 首轮修复验证（ADJ-015 调整前）

- 新回归在旧代码上失败：缺失单元的空 stdout 使备份退出，socket 指导仍输出单独 restart；保护切换辅助程序不存在。
- Debian WSL：完整套件 115 项通过、无跳过（原 105 项，加 10 项）。包含原有真实 cp/nft 的隔离恢复和新的 shell 状态故障测试。缺失单元用例另通过真实 systemctl 查询一个不存在的夹具单元。
- 三脚本 ShellCheck warning 级别及套件内 bash -n 通过。
- 显式 systemd 集成检查：Debian WSL、systemd 257；临时单元 `codex-ssh-test-d6c7c00e5600`。旧实现真实复现，修复后旧 TCP 连接与新连接均成功；改成 control-group 时明确拒绝且服务仍可用；故意将 ExecStart 指向不存在的程序后失败，旧连接保留，修正后重试成功。
- 临时单元结束后为 not-found/inactive；只操作临时回环单元，不操作真实 ssh.service/socket。

集成夹具使用 fork TCP 服务持有 systemd 监听 fd，sshd -t 替换为成功。本轮没有真实 OpenSSH 端口迁移/认证验收、没有 Debian 12 systemd 252 的同环境测试，也没有云主机重启；不能把本地修复通过扩大为所有整机验收通过。原有其它未修问题（例如全局 nft 加载器、过渡规则顺序和引用）保持原状态。

## ADJ-015：恢复失败即停止的设计边界

首轮修复在异常分支增加了一次自动 start，虽然只读指导脚本不执行该程序，仍不符合 DESIGN-v2 第 7 节的失败停止原则。现已删除该分支的系统调用，并将配置校验和预检异常纳入统一失败提示；失败时不自动采集后续状态，不猜测当前服务是否存活。只打印 systemctl status、journalctl、sshd -t 和待操作员决定的启动命令。

修改后的失败停止回归在调整前代码上失败；调整后完整套件仍为 115 项，Debian WSL 全通过无跳过，三脚本 ShellCheck 和套件内 bash -n 通过。测试覆盖两个阶段和配置校验、daemon-reload、stop、start、运行态校验、传统模式重载等故障，断言失败命令后没有进一步系统调用，且人工建议包含在错误输出中。

真实 systemd 临时单元 `codex-ssh-test-53042d42e2e3` 验证：启动失败只尝试一次且立即停止，旧连接仍保留；输出的建议没有被执行。随后由夹具模拟操作员修正配置并另行手工运行，连接恢复；临时单元最终清理为 not-found/inactive。正常协调切换、危险 KillMode 拒绝亦通过。此夹具与远端/真实 OpenSSH/整机验收的边界沿用上文。
