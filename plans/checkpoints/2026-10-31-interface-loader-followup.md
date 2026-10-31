# BUG-054 / BUG-056 后续修复

日期：2026-10-31。基线 HEAD `fd309df`（Build0585），保留此前未提交的 BUG-053～055 及 TST-016 修改。本轮未连接或部署远端。

## 数值与未知入口约束

stage0/stage2 的 rule_digest 现在识别 meta iif 与 iifname。无法直接解释的数值索引、集合/区间或不支持的操作符，会保留非空的 unresolved 接口证据，并标记 iif_unknown；不通过当前系统的接口编号猜测远端实际入口。

这些约束不会计入声明 CIDR 的通用来源可达证据，也不能单独证明 tailnet 放行、全局拒绝或公网开闭状态。即使同一条规则同时出现 tailscale0 和未知数值接口条件，也不能跳过未知条件给出通过结论。对普通无接口约束规则的判断保持既有行为。

新增反例先在旧代码上复现：数值 1、lo 字面量、集合、区间、命名集合及否定条件都被误当作无接口限制。修复后这些场景均不再通过；另使用真实 nft 在独立用户/网络命名空间中装载 iif 1 规则，读取实际内核 JSON，两个阶段均保留限制并不判 pass。

## 持久启用链接恢复

两份生成恢复程序对 enabled、enabled-runtime、static 状态，都先清理本工具已知的 `/etc/systemd/system/{multi-user,sysinit}.target.wants/ssh-allowlist.service`，然后：

- enabled：按已恢复备份单元的 Install 目标重新 enable。
- enabled-runtime：保留运行期链接域，按备份单元 enable --runtime。
- static：不执行 enable，不残留本工具创建的开机链接。

清理仅涉及上述明确路径，不递归删除或停用其它服务。自定义安装目标与无关服务链接保持原有内容；不猜测或清理任意非受管链接。

回归运行两份完整恢复程序，文件复制实际执行，enable 和 is-enabled 使用真实 `systemctl --root <临时目录>`，覆盖三种状态 × 三种安装目标 × 两个脚本，共 18 个组合。断言精确的持久链接集合、运行期链接和无关链接保留，以及离线 is-enabled 返回原状态。仅将清理条件回退为旧版 enabled-runtime 时，12 个 enabled/static 子项重新失败；修复后全部通过。

## DESIGN-v2 边界与验证

生产指导脚本仍只读探测并输出建议。恢复程序是输出文本，由操作员明确执行；失败停止原则未改变，没有自动重试、回滚、服务停止或额外恢复执行。没有自动补救援、接口或重启验证声明。

Debian WSL 完整套件 140 项全部通过、无跳过；三脚本 ShellCheck warning 级别及套件内 bash -n 通过。新增 nft 操作在独立网络命名空间；链接操作在 systemctl 离线临时根目录；没有在宿主启动服务或改写防火墙。尚未完成真实 OpenSSH 整机迁移、冷启动及远端验收，不能将本轮结果扩大为生产部署保证。
