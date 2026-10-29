# tests/ —— 三个只读指导脚本的回归测试

```bash
python3 tests/run-tests.py
```

当前 68 项测试全部通过。测试**不接触真实系统**：通过 `tests/guide-support.py` 提取三个脚本内嵌的 Python 实现，并把 `System` 替换为内存桩件（`StubSystem`），因此文件系统、`ss`/`sshd`/`nft`/`systemctl`/`journalctl` 全部为预置输出。

命名约定：仓库内脚本与辅助文件统一使用连字符风格（如 `stage0-check.sh`、`run-tests.py`，不使用空格或下划线分隔）。由于 `unittest` 的发现机制拒绝非标识符文件名（`VALID_MODULE_NAME`），`run-tests.py` 按路径用 `importlib` 显式加载 `test-*.py`，`test-guides.py` 同样以模块名导入 `guide-support`。

## 覆盖范围

- **脚本完整性**：三个脚本 `bash -n` 通过；heredoc 内嵌边界唯一且完整。
- **只读保证**：命令白名单逐项断言（`nft` 仅 `list/-j`、`sshd` 仅 `-t/-T`、`ufw` 仅 `status`、`systemctl` 仅查询子命令），并实测一遍完整探测流程，断言所有被执行命令都未越过白名单；源码级扫描禁止 `shell=True`/`os.system`/可写 systemctl 子命令。
- **解析**：`SSH_CONNECTION`（含非法值报错）、journal 四元组公钥证据匹配、`ss -tlnpH` 的 sshd 归属与 `(Stream)` 后缀、socket `Listen` 解析、账户/公钥权限、nft `-j` 单元素集合折叠。
- **白名单判定**：nft 通过 / 无来源限制 / 缺默认拒绝 / 来源超出声明 / ufw 变体 五条路径。
- **stage1 步骤**：初始态与门槛（`1-backup`、`0-rescue`、`4-verify-new`）、监听但未持久化（warn）、新端口公钥会话满足硬门槛、**密码会话不满足硬门槛**、`--old-port none`。
- **混合白名单**：Tailscale + 云内网 + 指定公网（IPv4/IPv6）可完成最终确认与重启复验；缺失声明来源/接口、拒绝前置、额外公网来源、缺默认拒绝不能通过；覆盖 UFW 等效路径、续跑参数和真实 nft prefix JSON。stage0 同步验证全部声明来源。
- **stage2 步骤**：前置阻塞、来源不在白名单的硬阻断、全部达成但未重启、跨重启复验完成、禁用密码前必须有已验证公钥会话。
- **stage0 定位**：进行中 / 待跨重启验证 / 已通过跨重启验证三种位置、旧版待确认事务阻断（退出码 1）、非 root 退出码 2、JSON 结构。
- **Tailscale 拓扑**：`tailscale0` 的 IFF_UP 检测（含 `operstate=unknown`）、IPv4/IPv6 地址识别；`--tailnet` 下的接口放行判定（`iifname tailscale0 accept` + 默认拒绝）、缺少接口时的目标不达标、缺少 tailnet 接口时 stage2 前置阻塞、stage1 仅在声明时增加接入步骤。
- **socket 激活与规则顺序**：`ss` 中归属 systemd 的监听不被当作“无监听”；UFW 宽泛 ALLOW 与 tailnet→deny 的顺序按首条匹配判定；续跑命令保留 `--tailnet`。
- **参数与输出**：非法端口/root 账户/缺失 `--allow`/端口冲突被拒；严格 CIDR 规范化；JSON 报告可序列化且退出码正确。

## 边界

桩件测试证明的是脚本的判定与只读契约，**不替代真实服务器验收**：真实整机迁移、外部连接成功/失败、跨重启持久化仍需在可销毁环境按 `plans/DESIGN-v2.md` 的验收边界执行（台账 CHK-001、BUG-016 范围）。