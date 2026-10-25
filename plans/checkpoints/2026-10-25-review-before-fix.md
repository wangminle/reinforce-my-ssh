# SSH 三阶段脚本审查报告

审查日期：2026-10-25。审查对象是当前工作区中未提交的 stage1.sh、stage2.sh、stage3.sh，以及 plans/DESIGN.md 和 plans/AUDIT.md。

发现 9 项需要修复的问题：6 项 P1、3 项 P2。前四项各自足以阻断正常迁移。未修改项目文件，未对真实 SSH 服务或主机防火墙执行加固操作。

## 1. P1：配套服务仍运行时，单独重启 socket 会失败

位置：stage1.sh:716、stage2.sh:720；同样影响 stage1.sh:591、stage2.sh:596 的回滚。

当前流程从 SSH 会话执行，通常已有运行中的 ssh.service。但 apply 只运行 `systemctl restart ssh.socket`，没有协调 ssh.service 主进程及其持有的监听文件描述符。Debian 软件包中的 ssh.service 没有随 socket 重启的依赖。

真实 systemd 隔离单元复现：先启动配套 service，再 restart socket，返回 1，日志为 `Socket service … already active, refusing.`；service 的 MainPID 保持不变。回滚再次单独 restart socket 也存在相同问题。`sshd -t/-T` 只能检查配置，不能证明存活主进程已重读认证配置。

建议：统一处理 service/socket 切换与恢复，在核实目标发行版 KillMode 和现存会话保留方式后，协调释放旧监听、启动新 socket 和加载新认证配置。整机测试需要核对旧会话存活、旧监听关闭和新连接实际认证行为。

## 2. P1：双栈监听缺少 BindIPv6Only，默认配置下地址冲突

位置：stage1.sh:405、stage2.sh:409。

生成器同时写入 `ListenStream=0.0.0.0:端口` 和 `ListenStream=[::]:端口`，但没有配置 `BindIPv6Only=ipv6-only`。[systemd 文档](https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html#BindIPv6Only=)说明，默认值跟随系统设置，通常 IPv6 通配 socket 也覆盖 IPv4。

真实 systemd 的 PrivateNetwork 临时 socket 测试：当前配置启动失败；只增加 `BindIPv6Only=ipv6-only` 后启动成功。这个问题独立于第 1 项，空闲 socket 也会失败。

建议：显式选择双栈绑定模式，并使生成配置、有效属性和实际监听的检查保持一致。

## 3. P1：三个阶段都误解析 systemctl Listen 输出

位置：stage1.sh:433、stage2.sh:438、stage3.sh:381。

当前 awk 要求第一列等于 `Stream`、第二列为地址。实际 `systemctl show … -p Listen --value` 输出为 `地址 (Stream)`。本机真实 dbus.socket 输出 `/run/dbus/system_bus_socket (Stream)`，现有解析器产生 0 条记录；临时双栈 socket 同样输出 `0.0.0.0:42222 (Stream)` 和 `[::]:42222 (Stream)`。

结果：配置和监听即使正确，stage1/stage2 也会判定失败并回滚，stage3 则无法通过验证。

建议：按真实输出格式或结构化 D-Bus 属性解析，避免用测试替身定义输出格式。

## 4. P1：nft 文本比较不能识别内核的等价规范化

位置：stage1.sh:420、stage2.sh:425、stage3.sh:254。

真实 nft 1.1.3 在独立网络命名空间中把 `tcp dport { 2222 }` 输出为 `tcp dport 2222`，把 `203.0.113.7/32` 输出为 `203.0.113.7`。现有规范化只处理空白、注释和 counter，不处理这些等价表达。

实测：双端口 /24 候选规则比较返回 0；收口后的单端口规则比较返回 1。stage2 必然使用单端口集合，因此正确加载后也会进入回滚；stage1 的 OLD_PORT=none 或 /32、/128 白名单同样受影响。stage3 的 token 比较也保留了同样的差异。

建议：统一使用 nft 的结构化表达做语义规范化，覆盖标量/单元素集合和主机前缀等价关系，同时继续严格核验链、hook、优先级、顺序和额外规则。

## 5. P1：首次部署早期失败时，回滚不能恢复“单元原本不存在”

位置：stage1.sh:591、stage1.sh:662；stage2.sh:596 为相同实现。

首次部署前自定义防火墙单元不存在，备份通常是 `not-found|inactive`。如果 arm_recovery 失败，流程会在防火墙单元创建之前进入回滚。restore_unit_state 先对不存在的单元执行 stop；该命令失败，函数还没比较 enabled 状态就返回 1。

实测：用原 restore_unit_state 和真实 systemctl 恢复 `not-found|inactive`，返回 1。调用者会把它升级为 fw_bad 并停止 ssh.socket，事务保持 pending；重试仍会遇到同一错误。一个尚未修改 SSH 的失败会进入不必要的接入停止路径。

建议：显式备份和恢复不存在状态，区分“从未创建”“本事务已创建且仍运行”等情形，完成清理后验证不存在，不把不存在本身当作恢复失败。

## 6. P1：公钥日志仍未绑定到当前 sshd 连接

位置：stage1.sh:286、stage2.sh:290。

ss 校验了四元组，但日志校验只有用户名、客户端 IP 和客户端源端口；`-o cat` 丢弃了 journal 的进程元数据，也没有把日志进程与当前连接关联。客户端可向服务器不同目标端口建立相同源 IP/源端口的两条连接；旧端口上的公钥认证日志仍可能给新端口上的另一条连接提供证据。

隔离函数测试：设定旧端口连接 PID=111 产生公钥日志、新端口存活连接 PID=222，原 session_evidence 返回 0，输出“已证明…经新端口公钥登录”。此处使用 ss/journalctl 替身，复现的是关联算法缺口，并未宣称完成真实 SSH 攻击演练。

建议：保留结构化日志的 PID/启动标识，把公钥成功事件绑定到当前 SSH 会话的真实 sshd 进程链和目标端点；不能只把两个独立查询的成功结果拼接。

## 7. P2：flush table 不会删除链，恢复可残留对象并误报完成

位置：stage1.sh:653、stage1.sh:677；stage2.sh:658 为相同实现。

`flush table` 仅清空规则，不删除链等对象。已有 sshguard 表若原本只有 original 链，候选部署添加 input 链之后，当前恢复事务重放备份仍会留下额外 input 链。

真实 nft 命名空间配合原 tx_restore 复现：防火墙和监听查询使用真实命令，systemd/sshd 使用替身避免影响主机；恢复返回 0，写入 ROLLED_BACK，并输出“已完整回滚”，但内核表保留备份中不存在的 input base chain。

建议：用真正重建表对象的原子事务恢复；在任何完成标记和父状态提交前，比较恢复后的完整内核对象与备份。不支持接管已有表时，应在修改前明确拒绝。

## 8. P2：stage2 apply 没有校验父阶段的配置摘要

位置：stage2.sh:705。

stage2 先按当前 policy 生成期望并执行 verify_runtime，却没有比较 config_digest 与 STATE_CONFIG_SHA。只改变 policy.conf 中合法的 RECOVERY_SECONDS（例如 900→600），不会改变受管配置或运行时检查结果，仍可进入新事务。回滚又会写回父摘要，但不会恢复 policy.before，使父摘要与保留的策略不一致。

隔离控制流测试确认，原 do_apply 在 STATE_CONFIG_SHA 与当前 config_digest 不同时仍进入 tx_begin；此测试替换了系统检查，不视为完整阶段验收。

建议：持锁后、开始子事务前核对父摘要；同时明确策略回滚规则，避免恢复旧摘要却保留新策略。

## 9. P2：事务开始时间不能证明连接建立于收口之后

位置：stage2.sh:549、stage2.sh:743、stage2.sh:745。

TX_STARTED 在写认证配置、重启 socket 和收窄 nft 之前记录，而 confirm 只要求日志晚于这个事务起点。配置切换过程中建立的连接也会被接受；时间只精确到秒，`journalctl --since @秒` 还会包含同一秒内更早的登录，因此快速执行时，apply 所在连接也可能满足条件。

此项为静态边界发现，未以真实 SSH 登录进行复现。

建议：完整收口及运行时验证结束后，记录 journal cursor 或等价的精确事件边界；confirm 必须关联边界之后建立的新会话，并结合第 6 项的进程身份验证。

## 验证边界

- 三个脚本的 bash -n、ShellCheck -S warning 均返回 0；git diff --check 通过。
- 监听解析、双栈绑定、活动服务下的 socket 重启使用真实 Debian systemd；临时单元已停止清理。
- nft 加载、打印和恢复使用真实 nft/内核，但均在独立网络命名空间，未更改主机防火墙。
- 缺失单元恢复使用真实 systemctl 和原函数；日志关联、摘要准入及恢复外围使用了明确的命令替身。
- 下载并解包了 Debian openssh-server 查看单元定义，没有安装该包。
- 没有执行真实 VM 的完整迁移、真实 SSH 认证、重启、跨启动自动恢复或公网验收。

复现脚本：audit_repro.py。原始输出：audit_repro_output.txt。它们位于本报告同一目录，可从项目根目录用 Python 执行脚本复跑；需要 Windows WSL 的 Debian、root、nft、systemd、ShellCheck 和可用的网络命名空间。复现脚本不会调用三个阶段的完整 apply。
