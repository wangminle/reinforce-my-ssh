# 京东云确认失败与恢复入口缺陷

## 用户提供的实际输出

- 01:39 左右，远端 `run.sh` 备份并注释主配置，调用旧版 stage1 建立 62207 候选；输出同时声称 22 已关闭。恢复窗口为 1800 秒，截止约 02:09:57。
- 新连接命令为 `ssh fenix@100.65.13.69 -p 62207`，出现 SSH `Password:` 提示。
- 首次 `stage1-newport.sh --confirm`：缺少边界之后、当前进程链的公钥日志；退出为外部登录/sudo 证据不足。
- 后续 confirm：已有阶段状态，但 `/var/lib/reinforce-my-ssh/policy.conf` 不可读，之后连接 reset。后一次命令没有独立时间戳。

第一次拒绝符合公钥确认契约。裸 IP 未命中本地 `Host fenix-jdcloud-1` 的专用 IdentityFile 配置，不能把随后 sudo 的密码与 SSH 公钥混为一谈。已有密码会话可以采集与建立候选，但不能证明候选公钥通道已可用。

不能仅凭此输出认定 confirm 主动停止了 SSH。审阅当前代码及 HEAD 部署基线，do_confirm 没有调用停止/重启 SSH；验证失败直接退出，原恢复任务继续存在。超时恢复或恢复失败符合后续现象，但需要 unit journal 验证其实际时间和失败步骤，尚未确认远端根因。

## 只读远端核对结果

本次尝试通过别名 62207、公钥模式及覆盖为 22 的方式连接均被拒绝。直接 TCP 核对 Tailscale 地址的 22/62207 同样拒绝；公网两个目标端口在探测窗口内未连通。Tailscale 本地状态显示对应节点 Online。以上证据只能证明本次路径不可达，不能区分无监听、防火墙 reject 或其他路径因素。

因此未取得远端 state、policy、恢复 unit 日志和 run.sh 原文，未执行任何远端写入、apply、confirm、rollback 或重启。现有事务由旧脚本自包含备份恢复；本地修复不会改变该远端旧事务。

## 已复现并修复的本地缺陷

旧 tx_restore 向 unconfigured 恢复时，在 nft、sshd、监听和单元复验完成前删除 policy.conf。故障注入使 nft 恢复失败，证实它停止 SSH 接入、保留 pending 状态，却已删除全局策略；随后回滚入口的 load_policy 也会拒绝，造成“保留了事务但无法重试”。这属于脚本缺陷，不应归咎于用户密码会话。

修复 stage1/stage2：

1. tx_begin 保存 root 私有的 `transactions/<TX>/policy.target`；旧事务首次用新版回滚时，修改前补留当前策略。
2. 初次回滚延后到恢复检查通过后才删除全局策略；中间失败保持可重试。
3. `--rollback` 优先读取当前目标事务的 policy.target，即使全局策略已丢失或已变为父策略，也能进入重试；正常 apply/confirm 不使用该备份冒充权威策略。
4. 缺策略时明确提示可能恢复未完成、核对控制台及事务日志。旧事务如全局策略与 policy.target 都缺失，仍须从控制台核对证据后恢复，不能猜测或伪造完成状态。
5. confirm 拒绝时列出强制公钥新连接、sudo 密码区别与剩余恢复窗口；不取消、延期恢复，也不执行停止 SSH。

## 验证与仍需取得的证据

新增三项回归，包含两阶段确认成功/失败均不得调用 SSH 停止操作、失败初次回滚后重试成功，以及全局策略缺失时从目标策略恢复入口。成功确认使用真实 tx_commit/cancel_recovery、模拟 systemctl，仅允许清理本事务恢复 timer/service 和 daemon-reload。

统一集成回归 **42 + 35 + 17 = 94 项通过，无跳过**；含 bash -n、ShellCheck -S warning 与原生隔离 nft/systemd。原始输出在 `2026-10-27-confirm-recovery-tests.txt`。测试不替代远端根因确认及真实 VM/跨启动验收。

下一步必须在京东云 VNC/控制台取得：

```bash
sudo systemctl status ssh.service ssh.socket --no-pager -l
sudo cat /var/lib/reinforce-my-ssh/state.conf
sudo journalctl -b -u ssh.service -u ssh.socket \
  -u reinforce-my-ssh-20261027-013955-433794809-195911.service \
  --no-pager -n 120
```

根据日志确定恢复是否执行、失败在哪一步以及原单元/规则是否已恢复，再给出恢复命令。此时不盲目启动未知配置、不继续 confirm，也不把本地修复当作远端已经修复。

## 后续事故升级

用户随后报告 VNC 也不可用，认为只能重置镜像。上述控制台采集路径已不可用，不再作为当前可执行的下一步。远端根因保持未查明，本地修复未部署，节点未由本会话恢复或重置。已暂停部署推荐，详见 `2026-10-27-lockout-incident.md`。
