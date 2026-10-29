# tests/ —— 三个只读指导脚本的回归测试

```bash
python3 tests/run-tests.py
```

完整测试请在 Linux/WSL 中运行，需要 Bash、Python 3、nftables 和 util-linux 的 `unshare`；nft 测试使用非特权用户/网络命名空间，不需要改动主机规则。ShellCheck 作为独立静态检查运行。

当前 105 项测试。主体通过内存桩件验证；新增的 shell 测试只在临时目录内使用假命令执行备份，验证目录引用与失败停止，不修改系统配置；另在用户/网络命名空间内用真实 nft 检查生成规则语法。主体测试方式：通过 `tests/guide-support.py` 提取三个脚本内嵌的 Python 实现，并把 `System` 替换为内存桩件（`StubSystem`），因此文件系统、`ss`/`sshd`/`nft`/`systemctl`/`journalctl` 全部为预置输出。Windows 上若 `bash` 是 WSL 转发桩，套件内 `bash -n` 会失败，需改用 Git Bash；依赖 `unshare` 的隔离测试在 Windows 上跳过。

命名约定：仓库内脚本与辅助文件统一使用连字符风格（如 `stage0-check.sh`、`run-tests.py`，不使用空格或下划线分隔）。由于 `unittest` 的发现机制拒绝非标识符文件名（`VALID_MODULE_NAME`），`run-tests.py` 按路径用 `importlib` 显式加载 `test-*.py`，`test-guides.py` 同样以模块名导入 `guide-support`。

## 覆盖范围

- **脚本完整性**：三个脚本 `bash -n` 通过；heredoc 内嵌边界唯一且完整。
- **只读保证**：命令白名单逐项断言（`nft` 仅 `list/-j`、`sshd` 仅 `-t/-T`、`ufw` 仅 `status`、`systemctl` 仅查询子命令），并实测一遍完整探测流程，断言所有被执行命令都未越过白名单；源码级扫描禁止 `shell=True`/`os.system`/可写 systemctl 子命令。
- **解析**：`SSH_CONNECTION`（含非法值报错）、journal 四元组公钥证据匹配、`ss -tlnpH` 的 sshd 归属与 `(Stream)` 后缀、socket `Listen` 解析、账户/公钥权限、nft `-j` 单元素集合折叠。
- **白名单判定**：nft 通过 / 无来源限制 / 缺默认拒绝 / 来源超出声明 / ufw 变体 五条路径。
- **stage1 步骤**：初始态与门槛（`1-backup`、`0-rescue`、`4-verify-new`）、监听但未持久化（warn）、新端口公钥会话满足硬门槛、**密码会话不满足硬门槛**、`--old-port none`。
- **混合白名单**：Tailscale + 云内网 + 指定公网（IPv4/IPv6）可完成最终确认与重启复验；缺失声明来源/接口、拒绝前置、额外公网来源、缺默认拒绝不能通过；覆盖 UFW 等效路径、续跑参数和真实 nft prefix JSON。stage0 同步验证全部声明来源。
- **stage2 步骤**：前置阻塞、来源不在白名单的硬阻断、全部达成但未重启、跨重启复验完成、禁用密码前必须有已验证公钥会话。
- **stage0 定位**：进行中 / 待跨重启验证 / 已通过跨重启验证三种位置、旧版待确认事务阻断（退出码 1）、非 root 与已声明目标未达成（退出码 2）、未声明目标且采集完成（退出码 0）、公钥认证未启用不能标为已验证、JSON 结构。
- **Tailscale 拓扑**：`tailscale0` 的 IFF_UP 检测（含 `operstate=unknown`）、IPv4/IPv6 地址识别；`--tailnet` 下的接口放行判定（`iifname tailscale0 accept` + 默认拒绝）、缺少接口时的目标不达标、缺少 tailnet 接口时 stage2 前置阻塞、stage1 仅在声明时增加接入步骤。
- **socket 激活与规则顺序**：`ss` 中归属 systemd 的监听不被当作“无监听”；UFW 宽泛 ALLOW 与 tailnet→deny 的顺序按首条匹配判定；续跑命令保留 `--tailnet`。
- **参数与输出**：非法端口/root 账户/缺失 `--allow`/端口冲突被拒；严格 CIDR 规范化；JSON 报告可序列化且退出码正确。

## 京东云反馈回归

`test-safety-regressions.py` 覆盖非 root 的 EACCES、不可见监听、host key 权限不足、公钥认证假阳性、危险权限和错误属主、完整备份门槛、未知旧端口、主配置旧 Port 清理、定时器 active/enabled 组合、UFW/nft 过渡规则收口及自定义路径引用。生成的备份命令通过临时目录内的假命令实际执行，验证成功和失败退出；生成的混合 IPv4/IPv6/Tailscale 规则通过真实 `nft -c` 检查，运行在独立用户/网络命名空间。

## 边界

桩件测试证明的是脚本的判定与只读契约，**不替代真实服务器验收**：真实整机迁移、外部连接成功/失败、跨重启持久化仍需在可销毁环境按 `plans/DESIGN-v2.md` 的验收边界执行（台账 CHK-001、BUG-016 范围）。


## 续跑与救援回归（BUG-031、035～041）

`test-followup-regressions.py` 覆盖旧端口未知续跑不变成 none、显式 none 不能跳过已有监听、补录参数完整保留、stage2 衔接的来源与救援声明、stage0 裸 ListenStream/公钥读取证据/退出码、三个脚本的根目录别名拒绝。

恢复程序参考为 `recovery-program.txt`，同时内嵌在 stage1/2，两份内容必须逐字一致；测试在临时目录和独立用户/网络命名空间中使用真实 cp/nft 执行“原表存在”和“原表不存在”两种恢复，断言新增工具文件及表被清理、原有项恢复、无关文件及表保留。sshd、systemctl 和 ufw 仍为假命令，不能替代真实监听、认证和整机重启验收。备份不完整时测试确认程序在删除文件前停止。
