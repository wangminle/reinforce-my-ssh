# Tailscale 拓扑指导扩展

## 背景

其他会话讨论了同一台云服务器在三种 Tailscale 拓扑下的加固差异：①不加入 tailnet；②加入 tailnet 但只作管理通路；③在②之上自建 DERP。结论是核心加固流程不变，变的是白名单写法、新入口证据和最终暴露面。用户重申工具定位：**要的是 SSH 增强步骤的指导，不是乱作为、瞎回退**。

## 复核结论

- 三个脚本的只读契约成立：源码无写操作，`subprocess` 仅经命令白名单调用，`systemctl` 只有查询子命令；所有 `sudo` 命令只出现在打印的指导文本中。
- 复核确认三处缺口：stage0 不报告 tailnet 状态；stage1 没有接入 tailnet 的步骤；stage2 只能按来源 CIDR 生成白名单，无法表达 `iifname "tailscale0"`，也没有关闭公网入口的步骤。
- 另确认一条证据边界：Tailscale SSH 由 `tailscaled` 终结，不写入 sshd journal；现有 `session_auth` 只认 sshd 的 `Accepted` 记录，因此它天然不会被当作 sshd 证据，但此前没有明确提示。

## 本次改动

- 三个脚本统一增加 `--tailnet`（可选，默认行为不变）。
- `tailnet_facts`：只读 `/sys/class/net/tailscale0` 与 `operstate`，不调用 `tailscale` CLI；`is_tailnet_address` 识别 `100.64.0.0/10`。
- stage0：报告 `tailscale0` 状态；声明 `--tailnet` 时把"Tailscale 接入"纳入目标比较；白名单判定承认 `iifname tailscale0` 放行（nft 与 ufw `on tailscale0` 两种写法），并在输出中声明 Tailscale SSH 不作 sshd 证据。
- stage1：新增 `2b-tailnet` 步骤（接入、验证、撤销，受备份门槛约束）；第 4 步区分"经 tailnet 到 sshd"与"可能是 Tailscale SSH"；关闭旧端口步骤提示与 stage2 的分工。
- stage2：`--allow` 与 `--tailnet` 至少给一个；白名单生成 `iifname "tailscale0" tcp dport <port> accept`（UFW 用 `allow in on tailscale0`）；新增 `1b-close-public` 步骤（防火墙或 `ListenAddress` 两种收口方式，含公网侧验证与撤销）；前置条件增加 tailnet 接入；最终确认清单增加 Tailscale 与公网入口两项。
- 规则摘要改为记录 `iifname` 集合（保留 `loopback` 字段兼容），以支持接口级判定。

## 验证

`python3 tests/run-tests.py`：**44 项全部通过**（原 37 项无回归，新增 7 项 Tailscale 拓扑用例：stage0 接口规则判定与缺接口不达标、stage1 仅声明时新增步骤与接口缺失提示、stage2 无 `--allow` 的接口规则生成与前置阻断）。三个脚本 `bash -n` 通过。

未连接远端、未安装或修改任何 Tailscale 配置，也未执行 apply。

## 未闭环

1. 真实 tailnet 环境验证：`tailscale0` 的 `operstate` 在部分内核/容器中可能为 `unknown`，需要在可销毁 VM 上确认；检测只说明"接口存在且 up"，不证明节点未被登出。
2. Tailscale 与 UFW 的规则顺序、`ts-input` 链共存仍需真实环境核对。
3. DERP 部署步骤不在本工具范围内；README/DESIGN 仅声明端口规则域与救援边界。
4. 整机验收（CHK-001）与 [[BUG-016]] 仍是发布阻断。