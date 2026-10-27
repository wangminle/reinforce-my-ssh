# 从现状采集到事务迁移的实施记录

## 已实现行为

### stage0：采集完成与加固达标分开

- 默认只读采集，password 会话、root 登录/密码开关开放都显示为待加固事实，不再使默认采集退出 1。初始 root 会话也能采集；不把 root 自动当作合法部署目标。
- 默认退出码按 collection_result 决定：必要采集完成为 0，缺少权限/必要证据为 2。baseline_result 单列差距，security_result 保留兼容；`--check-baseline` 与显式 `--allow` 模式继续严格返回 0/1/2。
- 实际磁盘值与运行进程证据分别描述。缺少状态是首次部署起点，常规非受管指令列为待迁移项；活动 Match 仍明确说明支持缺口。
- 采集 UFW/firewalld/nftables 服务；UFW 已启用时读取其实际状态。禁用的旧 oneshot 不再与新持久加载器混为两个所有者。

### stage1：先预览，再由工具执行迁移

- 根据 sudo 用户与当前 SSH 端口补全目标账户/旧入口，显式参数和配置优先。目标端口等于当前端口时不保留额外旧端口；目标端口与允许来源仍由操作者声明。
- 预检生成逐文件清单，读取原认证值。常规主配置和单个绝对 Include 下的全局受控指令会在 apply 时保留为注释，并由受管文件接管；沿用已有 Include，没有匹配项才插入，避免重复加载端口。
- 候选阶段启用公钥，并保留原 root/密码等开关。原多因素要求不静默放宽；最终禁 root/密码仍在 stage2。
- 备份本地 socket 主文件及 drop-in，将旧 ListenStream/BindIPv6Only 和旧防火墙依赖迁到受管设置，保留其他配置。
- 旧 ssh-firewall 为可识别的普通 oneshot 时，仅撤销开机重放，不执行旧停止逻辑；其单元状态与原内核表进入回滚。
- 常规 active UFW 前置新增候选 CIDR/端口放行，保留业务规则；新加载器显式依赖 UFW，之后才启动 SSH。UFW 文件和状态配置进入备份，回滚恢复文件并 reload。

### stage2/3：继承迁移记录

- migration.json 及其列出的配置进入前两阶段事务、父状态摘要和 stage3 跨启动摘要；路径限定在 SSH、本地 socket、UFW 范围，禁止越界、重复及与核心文件重叠。
- apply 前核对全部输入摘要，再修改文件；失败保留事务和重试入口。兼容防火墙恢复失败时停止新 SSH 接入，不写已回滚标记。
- confirm 与 stage2 从持久迁移记录重建候选文件，临时预览文件删除不影响新会话和后续阶段。
- stage2→stage1 连续逆序回滚恢复各自父状态和原业务规则；回滚从事务备份读取清单，不被损坏的当前清单阻断。stage3 只撤销验证状态时不依赖迁移元数据有效，避免损坏记录阻断回退。
- 修复原认证生成函数误把输出文件名当阶段名的问题；现在 hardened 分支实际写入禁 root、禁密码及 AuthenticationMethods publickey。

## 验证

统一入口 `./tests/run_tests.ps1 -Distribution Debian -Integration`：**39 项三阶段/原生集成 + 35 项审计，共 74 项通过，无跳过**。最终输出见 [统一回归记录](2026-10-27-actionable-tests.txt)。包含语法、ShellCheck、真实 nft/socket/临时 systemd，以及新增采集语义、迁移、漂移、失败重试和连续回滚用例。

另执行 `tests/check_native_migration.py`：使用 apt 下载并解包的 UFW 0.36.2、OpenSSH 10.0p1 程序，不安装主机服务。独立网络/挂载命名空间内：

1. 验证真实 sshd 对 candidate/hardened 配置的解析，root/密码策略先保留后收紧，端口没有因 Include 重复载入。
2. 验证真实 UFW IPv4/IPv6 候选来源规则、原 HTTPS 放行及额外非 UFW 业务链。
3. 验证 UFW→项目防火墙→SSH 的 systemd 启动图无环（仅验证单元，不启动主机服务）。
4. 完整回滚后候选规则消失、原认证与业务规则恢复，输出 NATIVE_MIGRATION_PASS。
5. 比较命名空间外 /etc/passwd 摘要和 nft 规则未变。

原始输出见 [原生迁移记录](2026-10-27-native-migration.txt)。普通安装的非可执行 before.init/after.init 也已纳入此原生场景和备份。

## 仍有边界

自动迁移针对常规全局配置、root 管理的普通文件、本地 socket 设置、标准 UFW 与简单旧 oneshot。活动 Match、重叠 Include、复杂多因素、符号链接/可被普通用户替换的配置、firewalld、UFW 清理外部链或自定义可执行钩子、旧加载器定时/路径触发或反向生命周期依赖，仍不能保证等价接管，会在写入前说明原因。

回滚恢复的是事务快照，不自动三方合并维护窗口内其他操作者的并发修改。

目标账户、公钥材料、来源策略与云安全组仍需要真实输入；脚本不会伪造密钥验证或救援演练。stage1/2 的外部新会话公钥及 sudo 确认、限时/跨启动恢复继续保留。尚未执行真实 VM 整机迁移、跨启动恢复或公网验收，CHK-001 仍待办。

本轮只修改本地实现、测试及文档，没有上传、执行远端 apply 或提交 commit。生产发布仍仅四个 stage shell 文件，新增 Python 文件仅用于开发测试。
