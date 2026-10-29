# 修复后的独立验收

2026-10-30，对 BUG-031、BUG-035～041 修复后的当前工作区进行验收。结论：**未通过完整验收**。现有 105 项回归全部通过，但扩大到真实 systemd 与生成命令的实际 nft 执行后，复现了四项剩余问题。

本轮未修改三个生产脚本，未连接或部署远端。仅新增验收文档、索引及台账状态。原有其它工作区改动和运维记录保持。

## 已通过的部分

- Debian WSL：`python3 tests/run-tests.py`，105 项通过，无跳过。
- 三脚本 `shellcheck -S warning` 通过；套件中的 `bash -n` 通过。
- BUG-031 的未知旧端口续跑、BUG-035 退出码、BUG-036 裸 ListenStream 解析、BUG-038/039 参数衔接、BUG-040 读取证据与 BUG-041 路径校验，在当前源码及既有回归中未发现原问题回潮。
- BUG-037 的配置文件和定向 nft 表恢复子目标通过；服务切换子目标仍未通过，不能把整个问题视为已解决。

## 未通过项

### P1：BUG-037 重开——活跃服务下重启 socket 被 systemd 拒绝

位置：`stage1-port-key.sh:682`、`:810`、`:914`；`stage2-lockdown.sh:901`。前两脚本内嵌的恢复程序都先 restart ssh.socket，再 reload-or-restart ssh.service。stage1 开新端口、关旧端口也使用单独重启 socket。

在本地 Debian WSL 用 `systemd-run` 建立临时 TCP socket/service，只绑定回环随机端口。连接触发服务，Python 服务通过 `os.fstat(3)` 确认持有 systemd 传入的监听描述符；随后调用实际 `systemctl restart`。

实测结果：

```text
create temporary socket: 0
holding inherited socket service: active
restart socket with active service: 1
Socket service ...service already active, refusing.
service after failed restart: active
```

恢复程序的 subprocess 使用 check=True，因此在这里退出，后面的 ssh.service 认证重载不会执行；“文件已经还原”不能证明旧入口和认证配置已恢复。该问题也影响 stage1 的 socket 模式端口切换。仓库历史 BUG-005 曾处理相同的 systemd 约束，但旧实现的处理没有进入当前指导路径。

测试临时单元为 `codex-ssh-acceptance-a54a0e4027`，结束后复查 service/socket 均为 `LoadState=not-found`、`ActiveState=inactive`，服务 MainPID=0；没有遗留测试服务。未操作真实 ssh.service/ssh.socket。

修复方向：明确活跃服务/socket 的协调切换方案及现有会话保护条件，不能只调整两个 restart/reload 的书写顺序。需要实际 systemd 验证正常与恢复路径，失败应留在可继续操作的救援通道。

### P2：BUG-042——stage1 生成的 nft 命令在 shell 展开后语法错误

位置：`stage1-port-key.sh:831`。

原样生成的指令是：

```bash
sudo nft add rule inet sshguard ssh_allow tcp dport 62207 ct state new accept comment "stage1 new-port bridge"
```

在独立用户/网络命名空间中原样交给 sh 执行，仅移除测试不需要的 sudo 前缀，实际退出 1：

```text
Error: syntax error, unexpected string, expecting end of file or newline or semicolon
... accept comment stage1 new-port bridge
```

shell 消耗了双引号，nft 拼接参数时没有得到字符串定界符。内存桩件只检查生成文本，没有运行此条命令，因此未发现问题。

修复方向：让引号实际传到 nft 解析器，或改用经过真实 nft 执行验证的文件/heredoc 输入。只通过 bash -n 不能证明 nft 语法可执行。

### P2：BUG-043——追加的过渡 accept 可被既有 drop 遮蔽

位置：`stage1-port-key.sh:831`，`firewall_summary` 只采集 input 链身份及策略，随后用 add rule 追加。

在同一隔离命名空间建立 input 链，先有目标端口的 counter drop，再追加过渡 accept。为了单独验证顺序，仅在测试命令中修正 BUG-042 的注释引号，未改仓库。

真实回环 TCP 服务监听 62207，客户端连接结果为 TimeoutError；nft 输出证明数据包命中前面的 drop：

```text
tcp dport 62207 counter packets 1 bytes 60 drop
tcp dport 62207 ct state new accept comment "stage1 new-port bridge"
```

这是“链中已有显式 drop/reject”条件下的失败，不是说 policy drop 的链末尾追加必然无效。修复方向：检查并选择可达的插入位置，或在不能证明规则顺序时阻断并给出明确协调指引；修正引号不能同时解决顺序问题。

### P1：BUG-044——持久化步骤加载既有 flush ruleset，删除其它表

位置：`stage2-lockdown.sh:1006-1007`。脚本向已有 nftables.conf 追加 include，然后直接 enable --now nftables.service。

本机实际 nftables.service 的 ExecStart 是 `/usr/sbin/nft -f /etc/nftables.conf`。如果服务原来 inactive，现有配置含 flush ruleset，本步骤将执行该清空指令；脚本没有检测并阻断这种情况。

在独立用户/网络命名空间中先建立带 MUST-KEEP 标记的无关表，加载脚本生成的 sshguard，再模拟服务读取保留原 flush 的配置：

```text
before service-style load: unrelated= True
after service-style load: unrelated= False sshguard= True
```

即 SSH 白名单仍在，但其它表已经丢失。具体影响取决于这些表的用途，可能涉及其它业务防护或 Tailscale 通路。现有测试的“不清空其它表”只覆盖恢复程序，没有覆盖这一步应用/持久化流程。

修复方向：先检查现有加载器和完整配置的语义，拒绝会清空非受管规则的持久化路径；选择独立、可协调的加载方案。不能直接删除用户现有 flush 行，也不能在未核对其它规则来源时启用全局加载器。

## 验收边界

systemd 试验仅创建临时回环监听单元，其余 nft/TCP 试验全部在独立用户/网络命名空间内；临时文件均已回收。未重启主机、未改远端配置。

现有回归是必要条件；其中 sshd/systemctl/ufw 的假实现不能替代真实服务切换。当前应先修复上述未通过项，再增加覆盖实际生成命令及服务状态的验收，最后安排真实服务器的外部连接与跨重启验收。本报告不授予“全部 bug 已修复”或“可直接生产部署”的结论。
