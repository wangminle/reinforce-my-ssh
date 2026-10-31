# SSH 加固实施记录

- 记录日期：2026-10-30
- 系统：Debian GNU/Linux 12 (bookworm)，JD Cloud CVM
- 脚本目录：`/home/fenix/ssh-guides/`
- 当前 SSH 端口：`62207`
- 结论：**SSH 加固完成，stage0/stage1/stage2 全部通过，并已完成真实重启复验。**

---

## 1. 初始背景

- 系统软件源已切换为中科大 USTC 镜像，`apt update` 正常。
- 初始 SSH 状态：
  - 已使用 62207 端口，旧端口 22 未监听。
  - `PermitRootLogin no` 已配置。
  - `PasswordAuthentication` 仍为默认 `yes`。
  - 没有针对 62207 的本地 nft 白名单。
  - 旧备份 `/var/backups/ssh-hardening/20261028-175314` 结构不完整且早于当前配置。
- 云主机内网地址：`172.30.0.5/20`，VPC 网段 `172.30.0.0/20`。
- Tailscale 已接入，管理入口为 `100.72.213.8:62207`。

---

## 2. 脚本审查与更新

### 2.1 旧版脚本发现的问题

审查 `/home/fenix/ssh-guides/` 下三个脚本时，确认过以下问题：

1. `stage0-check.sh` 非 root 运行时，`Path.exists()` 遇到权限拒绝会抛 `PermissionError` 并崩溃；同时会把无法采集的监听状态误判为“端口已关闭/未监听”。
2. `stage1-port-key.sh` 的备份命令使用 `sudo sh -c '... $DIR ...'`，`$DIR` 不会展开，nft/ufw/systemd 快照可能写到根目录。
3. `stage2-lockdown.sh` 取回了 `pubkeyauthentication`，但最终检查没有使用它，可能出现 `PubkeyAuthentication no` 仍判“公钥认证生效”的假阳性。
4. `stage2` 的白名单评估会拒绝 stage1 遗留的宽泛放行规则，但清理步骤没有删除旧规则，UFW 环境下可能一直无法完成。
5. `stage1` 公钥权限异常时仍把账户步骤判为完成，且声称会给出 chmod/chown 命令但实际上没有。
6. `stage1` 关闭旧端口时只改 drop-in，不处理主配置里的 `Port`。
7. `stage1` 旧端口验证使用 `grep -E ':(22)\\b'`，转义错误，可能把仍在监听的端口判为已关闭。
8. 旧版 timer 检测在 stage0 与 stage1/stage2 之间不一致。

### 2.2 更新后的脚本

2026-10-29 23:52 至 2026-10-30 00:18 之间，三个脚本更新。新版已修复上述大部分问题，新增了：

- `System.exists()` / `is_dir()` 的 `OSError` 处理。
- stage0 非 root 时使用 `UNKNOWN`，并返回退出码 2。
- 更严格的备份完整性校验：`backup-complete`、`units.txt`、`ssh.socket.active`、`nftables.enabled`、nft JSON、sshguard 快照等。
- stage1 新增 `--allow`，用于向 stage2 传递可信来源。
- stage1 生成完整的恢复程序。
- stage2 检查 `PubkeyAuthentication`。
- stage2 清理 stage1 过渡规则（UFW/nft）。
- stage1 处理主配置中的旧 `Port`。
- 旧端口验证改为 `ss -H -ltn 'sport = :PORT'`。
- timer 同时检查 `is-active` 与 `is-enabled`。
- `--backup-dir` 绝对路径校验。

新脚本仍有两个注意点：

- 新备份命令使用 `nft list ruleset` 和 `nft -j list ruleset`，在 iptables-nft 主机上会打印警告；本机实测两者退出码均为 0，因此备份成功。
- 新版脚本的恢复程序不管理自建的 `ssh-allowlist.service`；该 unit 已额外存入备份，恢复时需手动放回。

---

## 3. 实施过程

### 3.1 基线检查

2026-10-29 22:33，使用 sudo 运行 stage0：

- 62207 正在监听，22 未监听。
- `PermitRootLogin no`、`PubkeyAuthentication yes` 已满足。
- `PasswordAuthentication yes`、`AuthenticationMethods any` 未满足。
- nft 中没有 62207 白名单规则，UFW inactive。
- stage0 判定为“stage1 目标已达成，认证尚未收紧”。

### 3.2 手工备份

创建了过渡备份：

```text
/var/backups/ssh-hardening/20261029-225542
```

后续确认该备份结构不符合新版脚本的完整备份标准，仅作为过渡备份保留。

### 3.3 认证收紧

写入 `/etc/ssh/sshd_config.d/20-hardening.conf`：

```sshconfig
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
```

执行：

```bash
sudo sshd -t
sudo systemctl reload ssh.service
```

新会话验证时发现，使用 IP 直接连接会失败：

```powershell
ssh -p 62207 fenix@100.72.213.8
# Permission denied (publickey)
```

原因是 Windows 的 `~/.ssh/config` 中 `Host fenix-jdcloud-1` 的 `IdentityFile` 只在**使用别名**时生效；直接写 IP 不会应用该配置。改用：

```powershell
ssh fenix-jdcloud-1
```

或显式指定私钥：

```powershell
ssh -i "$env:USERPROFILE\.ssh\fenix-jdcloud-1" -o IdentitiesOnly=yes -p 62207 fenix@100.72.213.8
```

之后公钥登录正常。

### 3.4 防火墙白名单

2026-10-30 00:07，创建 `/etc/nftables.d/ssh-allowlist.nft`：

```nft
table inet sshguard {
  chain ssh_allow {
    type filter hook input priority filter - 10; policy accept;

    ct state established,related accept

    # tailnet
    iifname "tailscale0" tcp dport 62207 accept

    # 云服务器 VPC 内网
    tcp dport 62207 ip saddr 172.30.0.0/20 accept

    # 其余公网来源全部拒绝
    tcp dport 62207 drop
  }
}
```

创建并启用 `/etc/systemd/system/ssh-allowlist.service`：

```ini
[Unit]
Description=SSH allowlist nftables rules
Before=ssh.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/usr/sbin/nft delete table inet sshguard
ExecStart=/usr/sbin/nft -f /etc/nftables.d/ssh-allowlist.nft

[Install]
WantedBy=multi-user.target
```

说明：

- `nftables.service` 保持 disabled，避免执行 `/etc/nftables.conf` 中的 `flush ruleset` 清空 Tailscale 的运行态表。
- `ssh-allowlist.service` 在 `ssh.service` 之前加载，避免 sshd 启动后出现白名单空窗。
- 已建立连接由 `ct state established,related` 保留。

### 3.5 增加京东云 WebTerminal 内网转发

京东云 WebTerminal 需要使用以下来源网段：

- 内网转发：`100.64.0.0/10`
- 公网转发：`114.67.239.0/24`（本次未启用，公网不需要）

在 nft 中增加：

```nft
# 京东云 WebTerminal 内网转发
tcp dport 62207 ip saddr 100.64.0.0/10 accept
```

该规则放在 `drop` 之前。没有加 `iifname "eth0"`，原因是新版 stage0 的白名单判断只把没有接口限定的 saddr 放行计入已验证来源；带接口限定时会被判定为“无法证实”。

注意：`100.64.0.0/10` 同时是 Tailscale 的 CGNAT 网段；Tailscale 流量仍由 `iifname "tailscale0"` 单独放行，两者不冲突。

### 3.6 重启复验

在确认 tailnet 和 VNC 控制台可用后重启；内网只确认了 nft 规则放行，未保留“从同 VPC 主机实际登录”的证据。

- 本次启动时间：`2026-10-30 20:34:41`
- `ssh-allowlist.service` 重启后 active + enabled
- `nftables.service` 仍为 disabled
- nft 表 `inet sshguard` 重启后仍存在
- 62207 仅对 tailnet、`172.30.0.0/20`、`100.64.0.0/10` 放行

### 3.7 新版脚本复核与最终备份

使用新版 stage1 的完整性标准重新检查备份，发现旧备份缺少 `backup-complete` 等标记。执行与新版 stage1 `backup_commands` 等价的备份脚本，生成：

```text
/var/backups/ssh-hardening/20261030-202134-618960
```

此时 stage1 显示 `1-backup done`。

随后在 nft 中增加 `100.64.0.0/10`，于 20:34 重启。重启后：

- stage2：全部步骤完成。
- stage0：`当前位置：已完成并通过跨重启验证`。
- stage1：`complete: True`。

最终再生成一份包含 `100.64.0.0/10` 规则的备份：

```text
/var/backups/ssh-hardening/20261030-204057-3795
```

该备份目录中由辅助脚本额外保存了 `/etc/systemd/system/ssh-allowlist.service`（建议用 `sudo ls -l` 最终确认一次）。

---

## 4. 当前配置

### 4.1 SSH

- 监听端口：`62207`
- `ssh.service`：active / enabled
- `ssh.socket`：inactive / disabled，Listen 仍为 22，但不会在启动时占用 22
- 旧端口 22：未监听
- 有效认证配置：
  - `PermitRootLogin no`
  - `PubkeyAuthentication yes`
  - `PasswordAuthentication no`
  - `KbdInteractiveAuthentication no`
  - `AuthenticationMethods publickey`
- `fenix`：uid 1000，sudo 组，`authorized_keys` 1 个公钥
- `~/.ssh` 权限 `0700`，`authorized_keys` 权限 `0600`

### 4.2 nft

`inet sshguard` / `ssh_allow`：

```nft
ct state established,related accept
iifname "tailscale0" tcp dport 62207 accept
tcp dport 62207 ip saddr 172.30.0.0/20 accept
tcp dport 62207 ip saddr 100.64.0.0/10 accept
tcp dport 62207 drop
```

- UFW：inactive
- `nftables.service`：disabled
- `ssh-allowlist.service`：active / enabled

### 4.3 备份

当前最终备份：

```text
/var/backups/ssh-hardening/20261030-204057-3795
```

包含：

- `sshd_config`、`sshd_config.d/`
- `ssh.socket.active`、`units.txt`
- `nftables.conf`、`nftables.d/`
- `nft-ruleset.nft`、`nft-ruleset.json`
- `sshguard.nft`
- `ufw-status.txt`
- `backup-complete`
- `ssh-allowlist.service`（辅助脚本额外保存；建议用 `sudo ls -l` 确认）

保留的历史备份：

```text
/var/backups/ssh-hardening/20261028-175314
/var/backups/ssh-hardening/20261029-225542
/var/backups/ssh-hardening/20261030-202134-618960
```

---

## 5. 验证结果

- stage0：`已完成并通过跨重启验证`
- stage1：全部 `done`，`complete: True`
- stage2：全部 `done`
- 重启后 tailnet 公钥会话正常
- VNC 控制台在重启**前**已实际登录验证；重启后 `tty1` 只有 agetty，尚未重新登录验证
- 公网 62207 由本机 nft 拒绝（云安全组状态未在本机验证）
- nft 规则放行内网 `172.30.0.0/20`；尚未保留同 VPC 主机实际登录记录
- 京东云 WebTerminal 内网来源 `100.64.0.0/10` 已加入本机 nft；**WebTerminal 本身尚未做最终登录验证**

---

## 6. 剩余事项

### 6.1 云安全组

本机 nft 已完成公网收口，云控制台还需要最后确认：

- 删除 `62207/tcp` 的 `0.0.0.0/0` 入站规则。
- 保留/添加 `172.30.0.0/20` → `62207/tcp`。
- 如果使用京东云 WebTerminal，保留/添加 `100.64.0.0/10` → `62207/tcp`。
- 保留/添加 Tailscale 需要的 `UDP 41641`。
- 保留/添加 DERP/STUN 端口：`30399/tcp`、`3478/udp` 等现有规则。
- 不要添加 `22/tcp` 公网放行。

### 6.2 WebTerminal

WebTerminal 有两个前置条件：

1. 它必须连接 `62207`，不是默认的 22。
2. 它必须支持公钥登录，因为密码登录已全局关闭。

如果它只能使用密码或只能连 22，不要为了它降低 SSH 安全配置；继续使用 VNC + tailnet + 内网。

### 6.3 恢复注意

新版 stage1/stage2 的恢复程序不会自动恢复 `ssh-allowlist.service`。如果将来需要从备份恢复，在该 unit 文件缺失时手动执行：

```bash
sudo cp -a \
  /var/backups/ssh-hardening/20261030-204057-3795/ssh-allowlist.service \
  /etc/systemd/system/ssh-allowlist.service

sudo systemctl daemon-reload
sudo systemctl enable --now ssh-allowlist.service
```

不要启用 `nftables.service`，否则其 `flush ruleset` 可能清空 Tailscale 的运行态规则。

### 6.4 iptables-nft 快照

本机 `nft list ruleset` 会提示部分表由 iptables-nft 管理，并出现 `XT target MASQUERADE not found`。新版脚本的恢复逻辑主要针对 sshguard 和 stage1 过渡规则，不做全量 iptables 恢复。本次最终备份没有单独保存 `iptables-save` / `ip6tables-save`；若需要覆盖 iptables-nft 表的完整回滚点，应补做：`sudo iptables-save > <备份目录>/iptables.v4`、`sudo ip6tables-save > <备份目录>/iptables.v6`。

---

## 7. 日常检查命令

### stage0 只读体检

```bash
sudo bash /home/fenix/ssh-guides/stage0-check.sh \
  --port 62207 \
  --user fenix \
  --allow 172.30.0.0/20 \
  --allow 100.64.0.0/10 \
  --closed-port 22 \
  --tailnet
```

### stage1 检查

> `--rescue-confirmed` 只在你确实完成 VNC/串口登录演练后使用；只是日常只读检查时可以去掉，`0-rescue` 会显示未完成，但不影响其它步骤的只读检查。

```bash
sudo bash /home/fenix/ssh-guides/stage1-port-key.sh \
  --port 62207 \
  --user fenix \
  --old-port none \
  --allow 172.30.0.0/20 \
  --allow 100.64.0.0/10 \
  --tailnet \
  --rescue-confirmed
```

### stage2 检查

```bash
sudo bash /home/fenix/ssh-guides/stage2-lockdown.sh \
  --port 62207 \
  --user fenix \
  --allow 172.30.0.0/20 \
  --allow 100.64.0.0/10 \
  --tailnet \
  --rescue-confirmed
```

### nft 修改后重载

```bash
sudo nft -c -f /etc/nftables.d/ssh-allowlist.nft
sudo systemctl restart ssh-allowlist.service
sudo nft list chain inet sshguard ssh_allow
```

### 服务状态

```bash
systemctl is-active ssh-allowlist.service
systemctl is-enabled ssh-allowlist.service
systemctl is-enabled nftables.service
systemctl is-active ssh.service
systemctl is-enabled ssh.socket
```

---

## 8. 关键文件

| 文件 | 用途 |
|---|---|
| `/etc/ssh/sshd_config.d/20-new-port.conf` | SSH 端口 62207 |
| `/etc/ssh/sshd_config.d/20-hardening.conf` | 禁止 root/密码/键盘交互，强制公钥 |
| `/etc/nftables.d/ssh-allowlist.nft` | SSH 来源白名单 |
| `/etc/systemd/system/ssh-allowlist.service` | 开机加载 SSH 白名单 |
| `/var/backups/ssh-hardening/20261030-204057-3795` | 最终备份（按新版标准完整） |
| `/home/fenix/ssh-guides/stage0-check.sh` | 只读体检/阶段定位 |
| `/home/fenix/ssh-guides/stage1-port-key.sh` | 端口/公钥/ sudo 账户指导 |
| `/home/fenix/ssh-guides/stage2-lockdown.sh` | 白名单/认证收紧/最终确认 |

---

## 9. 最终结论

SSH 已完成加固并通过真实重启复验：

- 唯一 SSH 入口为 `62207`。
- 只允许公钥认证，禁止 root、密码和键盘交互登录。
- 来源限制为 tailnet、VPC 内网 `172.30.0.0/20`、京东云 WebTerminal 内网 `100.64.0.0/10`，其余 62207 流量拒绝。
- 白名单 systemd unit 开机自动加载。
- 配置和 sshguard 规则有完整备份；自定义 `ssh-allowlist.service` 的备份建议再确认一次。
- VNC 控制台在重启前已验证；tailnet 重启后已验证；建议再通过 VNC 实际登录一次，确认重启后的控制台路径。

剩余工作主要是云安全组收口，以及可选的 WebTerminal 最终连通性验证。
