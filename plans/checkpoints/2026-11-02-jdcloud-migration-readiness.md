# 京东云重启后复核与腾讯云使用前检查

本轮仅执行远端只读查询、连接测试与本地回归，未修改远端配置，未重启。结论：未发现需要立即修改生产脚本的新阻断问题；京东云完整验收与腾讯云新机全流程验证仍有缺项。

## 已取得的证据

- 京东云为 Debian 12；三个远端脚本 SHA256 与当前本地源码逐一一致。
- 本次启动为 2026-11-01 23:28:38，新的独立公钥 SSH 会话通过 `100.72.213.8:62207` 登录成功。
- `ssh.service`、`tailscaled.service`、`ssh-allowlist.service` 已启用；`ssh.socket` 为 disabled；systemd 无失败单元；62207 在 IPv4/IPv6 通配地址监听，未见22监听。
- 专用加载器内容为新结构：`DefaultDependencies=no`、显式启动顺序、`WantedBy=sysinit.target`，且 sysinit 启用链接存在；没有旧的清表停止钩子。
- 在 tailnet 同一入口禁用客户端公钥认证，服务端仅宣告 `publickey`，连接返回 `Permission denied (publickey)`。这验证了当前 fenix 连接上下文，不代替 root/其它 Match 上下文的有效配置检查。
- 本机直连公网 `114.67.236.43:62207` 超时；只证明该公网路径不可达，不能单独证明 nft 拒绝规则生效，云安全组也可能拦截。
- 本轮 Debian WSL 执行 `python3 tests/run-tests.py`：140 项全部通过，无跳过；ShellCheck warning 级检查通过。
- `sudo -n` 需要密码，因此本轮未取得 root 权限，未独立读取有效 sshd 配置、内核 nft 规则及完整备份内容。
- 用户随后提供京东云 VNC 截图：Debian 12 的本地 `tty1` 上，`fenix` 经密码登录并成功执行 `sudo apt update` 后回到 shell。京东云独立救援控制台登录及 sudo 演练已确认，可在该节点后续检查中使用 `--rescue-confirmed`。此证据不代表已核验 SSH 有效配置或内核白名单，也不自动适用于腾讯云新机。截图中的控制台会话凭据不转录。

## 京东云还要完成的检查

1. VNC 登录及 sudo 演练已由用户截图确认完成；保持该救援入口可用。
2. 从重启后的新公钥会话执行下面三个只读脚本，核对备份、有效认证配置、内核规则和加载器。只运行检查命令，不批量执行输出里的指导、恢复或 reboot 命令。
3. 对仍需保留的 VPC 和 WebTerminal 入口逐一建立新公钥连接；没有测试来源时保持未验证。`100.64.0.0/10` 不等于已证实的 WebTerminal 来源，不能由地址段推断其用途；是否继续授权应另按实际需求核对。
4. 从白名单外测试公网连接；如需归因到本机 nft，应在服务端核对实际入站/规则命中证据。不要为了验收临时扩大安全组授权。
5. 检查双栈适用性：主机存在 IPv6 监听；如配置了公网 IPv6，单独验证其安全组与白名单外拒绝行为。

在京东云的新 SSH 会话中执行：

```bash
cd /home/fenix/ssh-guides

sudo bash stage0-check.sh --port 62207 --user fenix \
  --allow 172.30.0.0/20 --allow 100.64.0.0/10 --closed-port 22 --tailnet --rescue-confirmed
echo "stage0 exit=$?"

sudo bash stage1-port-key.sh --port 62207 --user fenix --old-port none \
  --allow 172.30.0.0/20 --allow 100.64.0.0/10 --tailnet --rescue-confirmed
echo "stage1 exit=$?"

sudo bash stage2-lockdown.sh --port 62207 --user fenix \
  --allow 172.30.0.0/20 --allow 100.64.0.0/10 --tailnet --rescue-confirmed
echo "stage2 exit=$?"
```

以上 `--rescue-confirmed` 依据用户本次提供的京东云 VNC 登录与 sudo 成功截图填写。在本次启动后完成全部保留来源成功、白名单外拒绝且期间未改规则，再补 `--reboot-confirmed`。缺少完整重启验收声明时退出2可能只是门槛未完成，应看具体未完成项。当前已经重启成功，不要仅因缺少声明而再次照抄输出中的 reboot。

## 腾讯云使用边界

- 当前代码和说明面向 Ubuntu/Debian + systemd。若新机是 TencentOS/CentOS/Rocky，须先适配和验证账户组、服务名、防火墙与依赖，不能仅更换 IP 后直接套用。
- 腾讯云必须重新确认系统版本、管理账户、现有 SSH 端口、Tailscale 地址和实际可信来源；不要复制京东云的 `172.30.0.0/20`、`100.64.0.0/10` 或旧机 IP。
- `--old-port none` 只适用于京东云当前已无旧端口的事实。腾讯云新机若仍用22，应保留它，先证明新端口公钥新会话成功，再关闭旧端口。
- 先真实演练腾讯云 VNC，再按 stage1 创建该机器自己的初始备份；不要把京东云备份或认证收紧后的快照当成腾讯云初始恢复基线。
- 云安全组与本机防火墙分别核对；如使用轻量应用服务器，还须按其控制台防火墙配置检查，不能假设 CVM 界面和规则相同。
- 腾讯云首次执行从 stage0 开始；先确认检测适配且不改配置，再逐步执行指导。生产机不要为测试故障或恢复程序主动破坏当前配置，完整恢复及故障注入应在可销毁同系统机器上演练。
- 京东云本轮是既有加固状态复验与加载器迁移后的重启检查，不能替代从新机创建账户、切换端口、收紧认证到恢复的全流程验收。

腾讯云官方参考：[安全组规则](https://cloud.tencent.com/document/product/213/112614/)、[VNC 登录](https://cloud.tencent.cn/document/product/213/35701)。
