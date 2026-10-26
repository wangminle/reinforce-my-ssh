# fenix-jdcloud-1 真实 stage0 审计复核

## 执行与证据

用户在交互终端完成 sudo 验证后，已取得远端 `~/ssh-apply/stage0-audit-20261026.json` 与 `.exit`。本次读取报告并执行普通权限的只读补充核对，没有执行 apply、reload、restart、nft 修改或重启。

- 主机：`1763017675236`，SSH 别名 `fenix-jdcloud-1`。
- stage0 MD5：`1fb3a972cbc22ef63cc8e7224df002ed`，对应已上传的无参数检查实现。
- 报告完成时间：2026-10-26 10:43:20（Asia/Shanghai，由远端文件 UTC mtime 换算）。
- 报告文件权限：0600，属主 UID 1001。
- 退出码：1；mode=inspect；security_result=fail；policy_result=unknown。
- 本地保留 [原始 JSON](2026-10-26-jdcloud-stage0.json)，与远端 SHA-256 一致：`9c292ab9633634771f2a72893b5528b7f88afb6575e1cd13b740b433c1f62f75`。

## 发现及判定

| 项目 | 证据与结论 |
| --- | --- |
| 自动识别 | 正确识别 fenix、22、当前来源 120.244.186.124；未自动生成白名单，也未把 22 当作必须关闭端口 |
| 当前通道 | 同 boot 认证日志、SSH 四元组、sudo 进程链关联通过，认证方式为 publickey |
| 认证配置 | 对 fenix/root 来源上下文的磁盘解析均得到 PermitRootLogin=yes、PasswordAuthentication=yes；不符合项目禁 root/密码基线 |
| 配置原文 | 普通权限复核主配置第 59 行 KbdInteractiveAuthentication no，第 116 行 PermitRootLogin yes，第 117 行 PasswordAuthentication yes；Include 在第 12 行，本次 glob 未发现 .conf drop-in |
| 监听及自启 | 报告显示 IPv4/IPv6 的 22 端口；补充 systemctl 核实 ssh.socket 为 active/enabled，两个有效 Listen 均为 22 |
| 运行配置关联 | sshd MainPID=725；启动时间 2026-10-25 12:06:58 CST；配置 mtime 为 2026-10-25 12:07:01.342658 +08:00，晚约 3 秒；缺少重载证据，保留 unknown |
| 防火墙 | 报告采集到 ip filter 表、INPUT 链 policy=accept；未发现所选 inet sshguard 表。没有 --allow，未比较白名单；这些元数据不足以证明其他表内没有限制或公网全开放 |
| 开机保护 | ssh-firewall.service 和 reinforce-my-ssh-firewall.service 均为 not-found，未识别到支持的防火墙加载单元；其他机制及云安全组未验证 |
| 纳管及迁移 | 无新版记录；主配置三条受控指令阻止直接接管。安全值 KbdInteractiveAuthentication no 同样涉及配置归属，不能把此阻断当作认证失败 |
| 重启证据 | unknown；本次未执行重启，也未证明旧方案的历史重启情况 |

## 解释与后续

本次默认入口与会话识别工作正常。明确的不符合来自磁盘解析值，并非缺少新版 state、旧文件名或当前仍使用端口 22。

磁盘配置允许 root/密码认证，不等于已经证明 root 密码可用或存活主进程正在接受密码：账户锁定、其他访问限制及主进程采用的配置尚未全部证实。当前 fenix 的公钥登录成功也不代表其他认证方式已经关闭。报告中的 fail 与运行关联 unknown 必须一起解释。

报告没有声明来源白名单目标；accept 来源空列表仅代表所选表未提取到字面值，不能推出服务器没有任何白名单。其他 established 连接仍不构成已认证证据。

若后续进入受管加固，需要先确定新端口、明确预期来源及救援路径，再对三条非受管指令安排备份与迁移处理；不直接运行 apply、删除旧配置或伪造阶段状态。本轮只完成审计结果复核，不执行加固变更。
