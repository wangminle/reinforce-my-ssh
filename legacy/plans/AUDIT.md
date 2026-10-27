# SSH 加固模板审计报告

审计日期：2026-10-24。审计基线：`fc046c0`。

## 结论与范围

三阶段迁移的总体思路合理：先建立新通道，再收紧认证，最后进行重启验证；默认只读、修改前备份、检查键盘交互认证，也都是应保留的设计。

但当前版本还不适合直接作为通用云服务器加固模板投入使用。发现 **7 项 P1 和 5 项 P2**，涉及开机依赖环、防火墙更新失去保护、登录证据错误关联、安全检查误报和回滚不可靠。这里的 P1 表示应在真实服务器使用前修复；P2 表示应在发布模板前修复的功能或可靠性问题。

本次没有修改三个业务脚本，没有连接或更改真实云服务器，也没有执行仓库脚本的真实 `--apply`、回滚或重启。仅新增本报告。

验证环境为本机 WSL Ubuntu 24.04、systemd 255；静态检查覆盖全部三个脚本和设计文档。危险操作采用从原脚本提取函数、替换外部命令的方式隔离复现。OpenSSH 配置实验使用从 Ubuntu 官方仓库下载并解包的 `openssh-server 1:9.6p1-3ubuntu13.20`，没有安装服务。没有进行完整虚拟机重启或公网端到端测试。

## 需要优先修复的问题

### 01 · P1：防火墙服务与 SSH socket 存在开机顺序依赖环

- 位置：`stage1.sh:639–654`、`stage1.sh:669–685`。
- 原因：生成的普通 service 没有关闭默认依赖，因此隐含 `After=basic.target`；同时又写了 `Before=ssh.socket`。而 socket 默认 `Before=sockets.target`，`basic.target` 又排在 `sockets.target` 后面。
- 形成的环为：`basic.target → ssh-firewall.service → ssh.socket → sockets.target → basic.target`，箭头表示必须先于。
- 影响：运行中的机器执行 `restart` 可能正常，完整开机事务却必须删除某个任务来打破依赖环。不能保证 SSH 与防火墙可靠自启，正好违背第三阶段的目标。
- 复现：在临时目录生成相同依赖关系的 service/socket，将加载器替换为 `/bin/true`，运行 `systemd-analyze verify <service> <socket> basic.target`，实际输出 `Found ordering cycle` 和 `Job sockets.target/start deleted`。注意该命令即使输出依赖环，也可能返回 0，不能只看退出码。
- 建议：将防火墙设计为适合 socket 之前启动的早期启动服务，明确补齐初始化、文件系统和关机依赖；校验完整启动图。不能只添加 `DefaultDependencies=no` 而省略必要依赖。

依据：[systemd.service 默认依赖](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)、[systemd.socket 默认依赖](https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html)。

### 02 · P1：防火墙替换与恢复不是原子操作，加载失败后旧保护已丢失

- 位置：`stage1.sh:620–632`、`stage1.sh:290–296`、`stage2.sh:254–262`。
- 原因：分别执行删除旧表和加载新表，中间存在表不存在的时间段；加载新规则失败时，旧表也已经被永久删除。
- 影响：回滚路径直接在 SSH 仍可能提供服务时删除防线，加载失败后仍继续恢复监听。加载器路径则取决于当时 SSH service/socket 的依赖与运行状态，不能笼统保证失败时始终关闭。`RemainAfterExit=yes` 也不能监测其他程序删除内核规则。
- 复现：运行原脚本生成的加载器，以临时文件模拟已存在的表，并模拟 `nft -f` 失败；重试结束返回 1，但原表已经不存在。
- 建议：删除/清空旧表与创建新规则必须放在同一个 `nft -f` 事务中；事务失败保留旧规则。回滚也使用同样机制，并在恢复监听前检查防线。备份实际内核表，而不仅是磁盘上的规则文件。

依据：[nftables 原子替换说明](https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement)。

### 03 · P1：第二阶段没有证明“该用户正在通过新端口使用公钥登录”

- 位置：`stage2.sh:361–373`、`stage2.sh:433–451`。
- 原因：两条检查分别证明“新端口有任意 TCP 连接”和“日志里该用户曾经公钥登录成功”，没有关联连接来源、客户端源端口、sshd 子进程、目标监听端口与存活会话。
- 触发示例：用户只在旧端口成功公钥登录过；新端口另有一个扫描器或 `nc` 建立但未认证的连接。两项检查都会通过，即使新端口因 `Match LocalPort`、密钥限制等原因无法完成该用户的登录。
- 日志中的 `from … port …` 是客户端源端口，不能直接拿来与服务器的新监听端口比较。备用读取 `/var/log/auth.log` 时也没有限定本次开机，证据还可能来自过去。
- 影响：关闭旧入口时缺少承诺的救援会话，可能失去远程管理能力。
- 复现：给原函数提供一条旧的成功日志和另一来源的新端口连接，成功记录与 `alive=1` 同时成立。
- 建议：关旧入口前，要求指定管理用户通过新端口完成一次新的公钥认证，并把证明关联到仍存活的 sshd 会话和连接四元组；至少将失败情形明确拒绝，不能用两个互不相关的布尔条件替代。

### 04 · P1：只检查一个管理账户和一个来源，其他 Match 分支仍可保留密码认证

- 位置：`stage2.sh:305–312`、`stage2.sh:848–854`、`stage3.sh:588–593`。
- 原因：全局 `PasswordAuthentication no` 不能消除允许密码的 `Match User legacy` 或其他地址分支；脚本只检查 `root` 和指定账户，来源也是当前会话一个地址。没有设置账户准入限制。
- 复现：配置全局 `PasswordAuthentication no`，追加 `Match User legacy` / `PasswordAuthentication yes`。真实 OpenSSH 输出：管理用户 `passwordauthentication no`，`legacy` 用户 `passwordauthentication yes`。
- 影响：管理账户和回环探针都通过，其他已有账户仍可从白名单来源使用密码登录，违反“关闭 SSH 密码认证、仅认公钥”的整体承诺。
- 建议：明确支持的账户集合、来源集合和 Match 策略；对允许连接的上下文逐类验证，或在无法完整评估已有 Match 配置时拒绝执行并给出具体冲突。只限制一个账户也必须作为明确的产品策略，不能静默加入。
- 另一个兼容性问题：`-C` 没有提供 `laddr`、`lport`，遇到 `Match LocalPort` 的真实 OpenSSH 会报缺少 `lport`；当前实现吞掉错误再尝试默认上下文，会掩盖诊断。实验中两次调用都失败，并未发生成功绕过。应将上下文解析失败作为明确错误，不要回退。

依据：[OpenSSH 的 Match 与认证配置](https://man.openbsd.org/sshd_config)、[sshd 连接测试参数](https://man.openbsd.org/sshd)。

### 05 · P1：存在任意 counter/drop 就能冒充有效白名单

- 位置：`stage1.sh:740`、`stage1.sh:813–818`、`stage2.sh:874–875`、`stage3.sh:551–558`。
- 原因：只搜索表里任意位置的 `counter.*drop`，没有核实是否为挂到 input 的 base chain、是否覆盖目标端口、是否存在优先放行所有来源的规则、是否与声明白名单一致。第二阶段最终复验甚至只检查表存在。
- 复现：给第三阶段提供下面的表，其余运行条件正常，`do_verify` 返回 0 并写入验证标记：

  ```nft
  table inet sshguard {
      chain unrelated {
          tcp dport 22 counter packets 0 bytes 0 drop
      }
  }
  ```

  这条链没有 input hook，而且要加固的端口是 2222，实际上完全没有限制它。
- 影响：防火墙被错误编辑、加载了错误规则或发生漂移时，脚本仍报告“重启验证通过”。
- 建议：使用 `nft -j` 检查规则结构、hook、端口集合、白名单集合和规则顺序；结合来自允许与拒绝来源的外部连接测试。仅增加更复杂的 grep 不足以覆盖这些语义。

### 06 · P1：回滚失败仍报告完成，并永久跳过失败的备份

- 位置：`stage1.sh:268–316`、`stage2.sh:240–275`。
- 原因：文件还原失败只打印消息；`daemon-reload`、socket 重启等错误被忽略；之后无条件生成 `ROLLED_BACK`，主流程也固定 `exit 0`。
- 复现：模拟 `cp`、`nft`、`systemctl` 失败，两个阶段仍输出“回滚完成”，返回成功并创建 `ROLLED_BACK`。
- 影响：紧急恢复失败被伪装为成功，同一个备份在下次恢复时还会被跳过，进一步削弱救援能力。
- 建议：聚合所有恢复错误；只有配置、内核规则和监听验证全部通过才写成功标记。失败返回非 0，保留可重试入口与明确的失败清单。

### 07 · P1：将依赖 sshd 的云连接误认为独立救援通道

- 位置：`DESIGN.md:140–177`、`DESIGN.md:224–240`；`stage1.sh:483–487`、`stage2.sh:499–503`、`stage3.sh:379–384`。
- 原因：以 `AuthorizedKeysCommand` 判断“控制台通道在位”，并在文档中将 Workbench 一概描述为不经过 sshd。`AuthorizedKeysCommand` 本身恰恰由 sshd 在公钥认证时调用，不证明带外救援存在。
- 影响：用户可能把仅有的浏览器 SSH 当成兜底，关端口、限制来源或禁 root 后，主通道与所谓救援通道一起失效。
- 建议：分别列出 VNC/串口、Agent 会话管理、浏览器 SSH/Instance Connect/Workbench SSH。只有实际演练过、与本次 SSH 改动独立的路径才能认作救援通道；不要根据 SSH 配置输出绿色通过。

依据：[AWS Instance Connect 前提条件](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-connect-prerequisites.html)、[阿里云 Workbench 的 SSH/RDP 连接与安全组要求](https://help.aliyun.com/en/ecs/user-guide/workbench-overview/)。Workbench 的具体连接模式应单独确认。

## 其他应修复的问题

### 08 · P2：跳过已回滚备份的输出污染了返回路径

- 位置：`stage1.sh:237–247`、`stage2.sh:222–232`。
- 原因：`newest_manifest_dir` 被 `$(...)` 捕获，但 `skip` 同样写 stdout。
- 复现：最新备份已标记回滚、较早备份仍有效时，`prev` 同时包含 `[SKIP] …` 提示和有效目录；`do_rollback` 将整个多行字符串作为路径，报找不到 MANIFEST。
- 建议：供程序消费的 stdout 只输出路径，日志统一输出 stderr，并检查候选备份是否完整。

### 09 · P2：`--old-port none` 时悄悄忽略新的 `--allow`

- 位置：`stage2.sh:773–800`。
- 原因：安装 nft 规则和重载防火墙放在“存在旧端口”的分支里。没有旧端口时，即使明确提供新的白名单，也只更新认证文件。
- 影响：例如原来放行整个 VPC，现在希望缩到单个 IP，参数校验和来源检查通过后，实际仍保留旧的宽白名单。
- 复现：调用原 `do_apply`，设置 `OLD_PORT=none` 并替换系统操作为记录器，最终只安装两个认证文件，返回 0，没有安装 nft 规则。
- 建议：将白名单更新与关闭旧端口分开；只要声明了新的目标策略，就必须应用并核实。

### 10 · P2：备份清单写失败没有触发“备份失败即中止”

- 位置：`stage1.sh:217`、`stage1.sh:229–233`；`stage2.sh:205`、`stage2.sh:214–217`。
- 原因：检查了复制文件，却没有检查创建/追加 MANIFEST 的结果。脚本没有 `set -e`，后面的输出命令会覆盖失败状态。
- 复现：将临时备份目录的 MANIFEST 指向 `/dev/full`，`backup_file` 显示写入失败，但仍返回 0。
- 影响：磁盘空间耗尽或清单写入故障时可能继续改配置，留下不能完整恢复的备份。
- 建议：每次清单写入都显式检查；整个备份完成、完整性核对通过后再允许修改。备份目录用唯一名称，增加互斥锁，避免同秒或并发执行覆盖清单。

### 11 · P2：端口正则会匹配 IP 地址中的数字

- 位置：`stage1.sh:381`、`stage2.sh:337`、`stage3.sh:262`，以及相似的占用检测表达式。
- 复现：唯一监听项为 `192.168.1.22:443` 时，原 `port_listening 22` 返回成功，因为 `.22:` 满足 `[.:]22\b`。
- 影响：错误判断端口占用、阶段和旧端口关闭状态；IPv6 地址段也可能触发类似问题。
- 建议：优先使用 `ss` 的端口过滤器；或仅解析 Local Address 列并严格匹配末尾端口，而不是对整行搜索。

### 12 · P2：`--verify` 绕过配置层检查，运行时正常仍可被误记为 S3

- 位置：`stage3.sh:286–348`、`stage3.sh:562–568`、`stage3.sh:716–733`。
- 原因：`--verify` 在 `run_checks` 前提前返回，未核实 SSH socket 是否仍然 enabled、有效的 Requires/After 依赖是否仍在、配置声明的端口是否已漂移。实际只核实防火墙的 enable 状态。
- 触发示例：重启后 socket 已 active，此时被 disable 但未停止；第三阶段仍可能标记通过，下一次开机的入口却已经不可靠。相同情况也发生在本次开机之后配置被修改、运行中的进程尚未重载时。
- 建议：普通只读检查和重启复验共用完整的策略验证；通过 systemd 的有效属性检查依赖，而非只 grep 某一个文件。只有运行时、持久配置和管理账户可用性同时符合目标，才能生成 S3 标记。

## 设计与维护建议

1. **收窄支持范围。** 当前代码实际依赖 Ubuntu/Debian 的 `sudo` 组、`ssh.socket`、systemd 和默认 Include 布局，不是任意 Linux 通用模板。预检应验证发行版、socket 激活模式、IPv6、Include、工具依赖、已有防火墙和 SELinux 等条件；不支持的环境在写入任何文件前退出。
2. **持久化目标策略。** 保存目标用户、新旧端口、白名单和配置摘要，跨阶段复用，避免每次重新传参。当前重启验证提示遗漏自定义 `--old-port`，容易按默认 22 验错旧入口。
3. **增加有期限的自动恢复。** 手工备份不能在断线后自行执行。应在破坏性改动前通过独立的 systemd 定时任务安排恢复，外部新连接和 sudo 验证成功后取消；必须先修复上述回滚问题。这属于改进建议，不是声称现有脚本承诺了自动恢复。
4. **确认真实提权能力。** 在 `sudo` 组只证明组成员身份，不能保证 sudoers 授权、账户状态和密码条件满足。关闭 root 前，应让新会话完成一次真实 sudo 操作。
5. **正确理解来源白名单。** `100.64.0.0/10` 本身不等于可信覆盖网络身份；若使用该范围，应核对实际隧道接口、路由和覆盖网络 ACL，优先限制所需节点。现有 established 规则也会保留已存在的非白名单连接，撤销来源不等于立即撤销会话。
6. **快照失败应可见。** `stage3.sh:428–445` 的关键采集命令失败后，最后的 `printf` 仍让 snapshot 返回 0；已隔离复现。快照应保存内容和采集状态，并检查错误，不能把错误输出文件当作有效基线。
7. **固化回滚记录应有生命周期。** `stage3 --rollback` 不清理 `.stage3-fixation-pre`。后续启动新一轮固化时会沿用旧基线；若管理员期间改了 enable 状态，再次回滚可能撤掉原本该保留的自启。应区分同一次事务重试与新一轮操作。
8. **避免跨 section 修改 fail2ban。** 两个阶段对 jail 文件的 sed 会修改所有 `port=`，文件包含多个 jail 时可能影响其他服务。应只操作 `[sshd]` 并核实实际有效配置。
9. **修正文档推断。** 超时也可能来自本机 nft drop，RST 也可能来自主动 reject；不能据此唯一归因安全组。仅按来源和端口匹配的规则通常不依赖网卡已拿到地址，30 次重试不能证明网络或覆盖网络就绪。普通账户执行 `sudo -i` 后也不能自然获得逐条命令审计，应降低相关承诺。
10. **保留三阶段设计。** 换端口主要减少扫描噪声；真正的安全边界是来源控制、密钥、账户准入、补丁和可靠恢复。不要为了“加固更多”无条件关闭业务需要的转发、替换算法或添加未验证的限制。

## 验证记录与修复顺序

| 验证 | 结果 |
|---|---|
| 三个脚本 `bash -n` | 全部通过 |
| `shellcheck -S warning` | 4 条警告：2 个未使用变量，2 个局部变量声明/赋值掩盖返回值；不是主要风险 |
| LF 行尾 | 三个脚本和设计文档均为 LF |
| systemd 启动依赖检查 | 复现顺序依赖环 |
| 端口解析、备份选择、回滚失败、清单写失败 | 均复现 |
| 新端口连接与历史公钥日志的错误关联 | 复现两项条件可由无关证据同时满足 |
| OpenSSH 不同用户的 Match 配置 | 复现管理用户禁密码而其他用户仍允许 |
| 错误 hook/端口的 nft 表 | 原复验函数返回 0，写入通过标记 |
| `--old-port none` 的白名单更新 | 原执行函数返回 0，未安装白名单 |
| 加载失败后旧规则保留 | 未保留，原保护表丢失 |
| 关键快照采集失败 | snapshot 仍返回 0 |

建议依次修复：**回滚可靠性与原子防火墙更新 → 启动依赖图 → 登录证据与认证覆盖 → 完整复验 → 参数和文档**。随后在可销毁的 Ubuntu 24.04 虚拟机上，验证正常迁移、失败自动恢复、连续回滚、IPv4/IPv6、已有 Match、已有防火墙以及真实重启。当前审计没有完成这些整机验收，因此不能据此声称模板已可安全上线。

---

## 重构响应

本节把原审计发现映射到当前重构机制，**不改变上述审计基线、历史发现和当时复现结果**。表中“对应机制”是对当前设计与脚本静态审阅的归纳，不等于该机制已在真实服务器验收通过，也不把历史隔离复现扩大解释为新版测试。

### 原 12 项发现

| 原编号 | 对应重构机制 | 仍需验收的重点 |
|---|---|---|
| 01 · 开机顺序依赖环 | 防火墙单元改为早期启动：`DefaultDependencies=no`，显式声明 `After=local-fs.target network-pre.target`、`Wants=network-pre.target`、`Before=ssh.socket shutdown.target`、`Conflicts=shutdown.target`，安装到 `sysinit.target`；socket 同时 `Requires`/`After` 防火墙。stage1 enable 防火墙和 socket，完整复验读取有效依赖与 enabled 状态。 | 用真实开机事务和重启检查早期文件系统、关机依赖及 socket 激活，不以运行中 restart 代替。 |
| 02 · nft 替换/恢复非原子 | 候选与恢复均把 `add table`、`flush table` 和规则放在同一次 `nft -f`；应用前备份实际内核表或不存在事实，应用后规范化比较语义，失败进入回滚。 | 在已有表、空表、语法错误和加载中断场景验证旧规则保留及恢复结果。 |
| 03 · 登录证据错误关联 | 两阶段统一以 `SSH_CONNECTION` 四元组关联来源/源端口/目标地址/目标端口，匹配仍存活的 sshd established 连接和本事务之后的 `Accepted publickey` 日志，并核对 `SUDO_USER`/`SUDO_UID`。stage1 confirm、stage2 apply 和 stage2 全新会话 confirm 都使用真实 sudo 与登录证据。 | 验证旧端口历史日志、无关扫描连接、复用旧会话、错误用户和断开连接均不能通过；验证目标发行版实际日志格式。 |
| 04 · Match 分支与上下文覆盖不足 | 支持范围收窄：预检遇到任何活动 Match，以及非受管的 Port、ListenAddress 或受控认证指令即拒绝。`sshd -T -C` 提供 user/host/addr/laddr/lport，解析失败不再回退为通过；stage3 覆盖 root/目标用户、IPv4/IPv6 回环及可发现的当前外部来源。 | 对既有复杂配置验证确实 fail closed，并用外部认证测试补充配置上下文检查。 |
| 05 · 任意 counter/drop 误报白名单 | 不再用 grep 判定安全性。按策略重新生成完整专用表，比较 input hook、端口集合、回环、有序 ALLOW、established/related 和末尾 drop；stage3 比较期望、磁盘和运行时规范化语义，额外/缺失规则均失败。 | 用错误 hook、错误端口、额外 accept、乱序和运行时漂移做负向验收，并从允许/拒绝来源做外部测试。 |
| 06 · 回滚失败伪装成功 | 回滚聚合文件、nft、daemon-reload、单元状态、`sshd -t` 和监听集合检查；全部成功才写 `ROLLED_BACK` 和父状态，失败返回非 0 并保留事务重试。自动恢复也走同一事务恢复入口。 | 分别注入每类失败，核对退出码、标记、可重试性以及恢复后的真实外部连接。 |
| 07 · 错认独立救援通道 | 删除以 AuthorizedKeysCommand 推断救援的逻辑。`RESCUE_CONFIRMED=yes` 仅是管理员实际演练独立救援后的事实声明，`--yes` 不能替代。DESIGN 区分 VNC/串口、Agent 与可能仍依赖 sshd 的 Workbench/浏览器 SSH。 | 每类平台按实际连接路径人工演练；脚本不自动给出救援“通过”结论。 |
| 08 · 备份选择 stdout 污染 | 不再通过命令替换选择“最新备份目录”。当前 `STAGE/TX` 直接绑定事务，`--transaction` 只能核对当前事务，路径由明确 TX_ID 构造。 | 检查重复回滚、错误/非当前事务 ID 和并发调用均不会跳阶段或拼出错误路径。 |
| 09 · old-port=none 忽略 ALLOW | 目标策略集中持久化，stage2 不允许静默改 ALLOW；无论 OLD_PORT 是否为 none，stage2 都生成、加载并复验只含新端口的 nft 规则。旧端口处理与白名单文件应用不再绑定。 | 验证 `OLD_PORT=none` 的正常迁移和漂移拒绝；需要改 ALLOW 时必须逆序回滚重建，而非沿用旧更新入口。 |
| 10 · 清单失败仍继续 | apply 先创建唯一事务目录并取得全局锁；manifest 以临时文件原子生成，备份时核对文件 SHA-256、类型和元数据。备份、单元/nft/监听事实、started、parent 或策略记录失败均中止，备份完成后才安装变更。 | 注入磁盘写满、权限、并发和摘要不匹配，确认任何修改前失败都不会留下半套事务。 |
| 11 · 端口正则误匹配 IP | 监听解析只取 `ss` 的本地 endpoint，按最后一个冒号拆分端口；socket/sshd/实际监听均形成精确端口集合。回滚只比较 PORT/OLD_PORT 相关监听，stage2/stage3 单独检查旧端口无监听。 | 覆盖 IPv4、括号 IPv6、相似数字地址/端口、多监听和非 SSH 监听场景。 |
| 12 · verify 绕过配置层检查 | stage3 默认、apply、verify 共用完整 `run_checks`；verify 先要求 boot_id 跨重启，再检查摘要、sshd/socket 端口、监听、active/enabled、有效 Requires/After、认证上下文和 nft 语义，全部通过才保存 post 并写 verified。配置或 boot 变化使旧验证失效。 | 注入 active 但 disabled、依赖漂移、配置未重载、同 boot verify 和采集失败，确认均不写 verified。 |

### 补查设计与维护问题

| 补查项 | 重构响应 |
|---|---|
| 1 · 支持范围过宽 | 明确只支持 Ubuntu/Debian + systemd + `ssh.socket`，目标账户使用 sudo 组；预检要求 socket、工具、sshd 配置和受管路径可管理，活动 Match 与冲突指令 fail closed。不再宣称通用 Linux 模板。 |
| 2 · 目标策略未持久化 | `/var/lib/reinforce-my-ssh/policy.conf` 保存用户、端口、OLD_PORT、ALLOW、恢复窗口和救援声明；state 保存阶段/TX/摘要/boot。后续参数只核对已存策略，stage3 使用登记的自定义旧端口。 |
| 3 · 缺少限时自动恢复 | 两个变更阶段在任何系统修改前安装事务专属 systemd service/timer；默认 `RECOVERY_SECONDS=900`，pending 超时回滚，真实外部 confirm 后取消。本次启动使用 OnActiveSec，pending 期间重启由 enabled 的恢复 service 处理；跨启动和恢复失败仍需整机测试。 |
| 4 · sudo 组不等于真实提权 | confirm 必须由目标用户实际通过 sudo 执行并匹配 UID；stage2 apply 也要求这一证据。组成员预检不再被当作唯一提权证明。 |
| 5 · 来源白名单与既有会话语义 | DESIGN 明确 CIDR/覆盖网络地址不等于可信身份，需结合路由、隧道和 ACL；明确 established 规则作用于 input 的后续入站包而非服务器 output 回包，也不负责撤销既有会话。 |
| 6 · 快照失败不可见 | stage3 聚合采集错误，关键命令失败会阻止 apply/verify；只有完整检查成功才保存 pre/post，META 记录 kind、时间、boot、摘要、TX 和 complete。 |
| 7 · 固化回滚记录生命周期 | 删除旧的“恢复 enable 状态”设计和 fixation-pre 文件。stage3 rollback 只清 reboot/verified 状态，保留基线；新一轮 apply 重建 pre 引用并清 post/verified 字段，不再复用旧单元状态作为回滚依据。 |
| 8 · fail2ban 跨 section 修改 | 重构完全不修改 fail2ban。文档也不再声称 ALLOW 与 `ignoreip` 等价或 fail2ban 只在白名单放宽时才有价值；其免封副作用需独立审计。 |
| 9 · 文档错误推断 | DESIGN 不再用 RST/超时唯一归因安全组，不再声称 Workbench 必然独立、AuthorizedKeysCommand 可证明救援、sudo -i 天然提供逐条命令审计，也不再用重试次数证明网络就绪；同时取消“保证不失联”的绝对表述。 |
| 10 · 保留合理三阶段边界 | 仍按候选通道、认证/端口收口、重启验证划分，但每阶段由显式状态机和真实外部确认连接；换端口不被当成独立安全边界，未添加转发、算法等无关收紧。 |

### 重构后的实际验证记录

以下验证在重构脚本及临时隔离环境中实际执行，不连接或更改真实云服务器：

| 验证 | 结果 |
|---|---|
| 三个脚本 `bash -n`、ShellCheck `-S warning`、`git diff --check` | 通过；三个脚本保持 755 |
| systemd 完整启动图（防火墙、带 Requires/After 的 socket、ssh.service、basic.target） | `systemd-analyze verify` 未发现 ordering cycle |
| nft 候选规则 | 在 Debian 的 nft 上通过 `nft -c -f`；使用单次 add/flush/重建事务 |
| 参数与配置解析 | 无 LF 末行、未知键、前导零同端口、root、非法值均拒绝；CLI 恢复时限优先于 conf |
| 三阶段配置摘要 | 对同一 policy 和五个受管文件，stage1/stage2/stage3 摘要一致 |
| nft 期望/磁盘/运行时语义 | 规范化后一致；额外 accept 被拒绝；add/flush/counter 不产生误判 |
| 外部会话来源 | 回环和本机地址识别生效，服务器自连不能作为外部证据 |
| 回滚故障注入 | nft 失败返回非 0、停止 socket、无 ROLLED_BACK/父状态提交；成功路径恢复文件、父 STAGE/TX/SHA；跨阶段回滚被拒绝 |
| stage3 隔离状态检查 | 同 boot verify 和摘要漂移被拒绝；默认完整只读检查不留下持久状态、锁或基线 |
| 交叉静态复核 | 启动时限、锁后状态重读、提交错误传播、Match 漂移、空 state 等发现已修复并复核 |

隔离测试曾发现并成功复跑修复一处回滚监听比较的 Python 集合运算错误。早期测试模板要求 OnBootSec，后续设计评审确认它会在 uptime 已超过期限时立即触发，因此最终实现改为 OnActiveSec 加下次启动的恢复 service；不把该预期变化计为产品缺陷。

### 尚未完成的验收

以上属于静态检查、生成器检查和临时目录/命令替身的隔离验证，**不等于真实整机或公网验收**。尚未在可销毁 Ubuntu VM 执行完整 SOP、真实 `--apply`、外部 SSH 登录和 sudo、超时/跨启动自动恢复、连续逆序回滚、真实 nft 内核故障注入及真实重启；也未从允许和拒绝来源验证云安全组、NAT、路由与覆盖网络 ACL。

因此，本轮可以确认实现和隔离验证完成，但不能据此宣称已经在真实服务器安全上线。发布前仍必须完成上述整机和真实网络验收。

---

## 2026-10-25 补充审查与修复

后续审查发现九项遗漏：SSH 主进程/socket 切换、双栈绑定、Listen 属性解析、nft 等价输出、首次部署缺失单元恢复、公钥日志进程关联、完整表恢复、父摘要核对和收口后新连接边界。本轮已实现修复，并处理现有台账的 CIDR 等价写法及迟到恢复清理。

修复前报告保存在 `checkpoints/2026-10-25-review-before-fix.md`；实现与测试映射见 `checkpoints/2026-10-25-fix-summary.md`；可执行测试在根目录 `tests/`，原始输出保存在 checkpoints。此前的表格和实测记录保留为历史，不视为本轮测试结果。

本轮 WSL Debian 的 19 项回归全部通过，包含独立网络命名空间中的真实 nft 加载/恢复、临时 systemd 单元双栈启动及主进程切换。真实 SSH 登录、会话存活、真实 VM 迁移、跨启动恢复和公网验收仍未完成，继续由 CHK-001 跟踪。
