# 三阶段 SSH 修复检查点

日期：2026-10-25。对应修复前报告 `2026-10-25-review-before-fix.md`。本记录区分代码实现、隔离测试与尚未完成的整机验收。

## 处理结果

| 审查项 | 处理 | 回归证据 |
| --- | --- | --- |
| 活跃 ssh.service 下单独重启 socket 失败 | 校验 KillMode=process；协同停止主进程/socket，依次启动 socket/service；备份并恢复 ssh.service 状态 | 真实 systemd 临时单元切换，MainPID 更新；错误 KillMode、socket 启动失败的拒绝路径 |
| IPv4/IPv6 绑定冲突 | 显式 BindIPv6Only=ipv6-only，并在复验时检查 | PrivateNetwork 临时双栈 socket 实际启动成功 |
| Listen 输出解析错误 | 三阶段统一按地址后面的 (Stream) 解析 | 真实 systemd 属性及包含 Datagram 的样本 |
| nft 单元素集合、主机前缀误报 | 三阶段统一 tokenizer，规范化单元素端口、IPv4 /32、IPv6 /128 和计数值 | 真实内核双端口/单端口规则、OLD_PORT=none、stage3 期望规则比较、额外 accept 拒绝 |
| 首次部署早期失败不能恢复不存在的单元 | 明确处理 not-found/inactive；删除新建单元前撤销 enable | 自动恢复安装故障后，原 do_apply/tx_restore 返回 unconfigured，不留下受管文件或策略 |
| 公钥日志关联到其他连接 | 用结构化日志 boot/PID，核对 ss 连接 PID 与 sudo 祖先进程链 | 正向函数测试；错误 PID、无关 socket、密码认证日志和其他 boot 均拒绝；真实 SSH 认证尚未验收 |
| flush 表残留链且误报恢复成功 | add/delete/完整定义放在单事务；恢复后重新比较内核语义；校验文件备份摘要 | 真实 nft 恢复删除候选多余链，失败不写完成标记；恢复父策略与原摘要 |
| stage2 遗漏父摘要核对 | 持锁路径核对父摘要后才开始子事务；回滚恢复 policy.before | 摘要漂移在系统改动前拒绝；父策略、状态、摘要一致性 |
| 事务开始时间误作新会话边界 | 完整部署复验后保存 journal cursor；confirm 使用 after-cursor，校验 boot | 正向边界采集；边界前日志拒绝；收口检查先于边界记录；同 boot stage3 验证拒绝 |

同时修复台账中已有的两项边界：CLI ALLOW 与策略先规范化再比较；迟到自动恢复只清理自己的 service/timer。定时器清理失败时保留单元文件以供重试，部分安装失败也可清理。

stage2 更新防火墙改用 ExecReload，避免 Requires 导致 SSH socket 随防火墙 restart 再次重启；只有确认旧端口已无监听才撤去其 nft 保护。stage1 配置生成失败现在会立即传播。

## 实际验证

- 命令：`./tests/run_tests.ps1 -Distribution Debian -Integration`。
- 环境：Windows + WSL Debian，systemd 257、nft 1.1.3；root 可创建独立网络命名空间。
- 19 个测试全部通过，无跳过；其中三项使用真实 nft / systemd，其他使用临时文件和明确的命令替身。
- 三脚本 bash -n、ShellCheck -S warning 通过；git diff --check 和 task-list check 在最终收尾时重新执行，原始输出单独保存。
- 真实 nft 操作均在独立网络命名空间；systemd 使用临时专用单元，不操作真实 SSH 单元。没有在主机执行完整 apply，没有改动主机 nft 表。

测试初期发现 nft 的 `-n` 会连同 ct state 输出为数字，已改为仅用 `-y` 固定优先级显示；复跑通过。临时 systemd 测试使用独立单元文件，避免 transient 单元停止后被回收而导致测试自身无法重启。最终原始输出见 `2026-10-25-regressions.txt`。

## 尚未完成

可销毁 Ubuntu VM 的完整迁移、真实 SSH 公钥认证及 sudo 进程/日志关联、既有 SSH 子会话保留、真实重启、跨启动自动恢复、连续逆序回滚和公网/覆盖网络允许及拒绝来源测试，仍由台账 CHK-001 跟踪。本次通过隔离回归不能扩大解释为整机上线验收。

新旧运行数据兼容边界：旧版 pending 没有 confirmation.json 时拒绝确认，必须先按原事务恢复后重建；没有 ssh.service 状态的旧备份不能冒充新版完整恢复记录。
