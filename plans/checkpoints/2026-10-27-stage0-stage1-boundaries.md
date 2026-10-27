# stage0 现状检查与部署边界复核

## 范围与结论

依据用户粘贴的讨论及 Build0179 当前源码，只读复核 stage0 与 stage1 的职责、报告语义和防火墙共存检查。本轮没有连接远端，也没有执行粘贴内容中的 SSH 命令；UFW active/enabled 和本次 password 会话属于用户提供的现场信息，没有冒充本轮重新实测。

stage0 的读取操作不等于改配置。现有代码没有修改 SSH、UFW、nft 或部署状态的逻辑。但默认 inspect 同时执行终态安全基线比较，不能准确体现用户希望的“先摸清现状，再逐阶段改变”的流程；前次增加无参数入口没有完成事实采集与合规判断的分离。

## 代码发现

| 发现 | 依据 | 影响 |
| --- | --- | --- |
| 默认 inspect 仍比较最终认证基线 | stage0 的 authentication 固定要求禁 root/密码/键盘交互及仅公钥；session 把 password 标为 fail；audit 将全部 checks 合成为 security_result；main 据此返回 1 | 新机可以成功完成现状采集，同时被显示为整体不符合；用户容易误以为 stage0 未完成，或需先手工加固才能进入部署 |
| 无新版记录被列为迁移阻断 | stage0 的 migration 只要不是 managed-record 就增加 blocker；stage1 的 load_state 则允许受管文件不存在且无状态时保持 unconfigured | 未纳管与真正不能部署混在一起。缺少 state 本身是首次部署的正常起点，不应单独阻断新部署；有受管文件却丢失状态属于另一类错误，保护不能取消 |
| 非受管指令有保护，但没有配套迁移入口 | stage1 的 scan_sshd_config 拒绝非受管文件中的受控指令；事务主要覆盖受管路径，没有完成任意旧主配置、旧 drop-in 和其他防火墙机制的接管 | 不能为获得绿色结果让用户先删除或注释旧配置；需要先生成完整备份与可回滚的迁移方案 |
| 防火墙框架识别不足 | stage0 默认只尝试两个项目新旧加载服务名；stage1 的 preflight 没有 UFW/firewalld/其他加载器的专门采集与兼容性判断 | 无法从“需要唯一加载器”直接得到实际 UFW 状态，也没有在修改前证明多链共存下的候选端口可达性 |
| 磁盘解析结果与运行证据应分层 | authentication 通过 sshd -T 解析磁盘值，runtime_config 另行检查主进程与文件时间 | 当后者 unknown 时，前者应清楚标注“磁盘配置解析”，不能无保留地称为存活服务的有效配置 |

本次源码定位：stage0 的 authentication、firewall、persistence、session、migration、audit、main；stage1 的 load_state、require_source_allowed、scan_sshd_config、preflight、do_apply、do_confirm。

## 对粘贴讨论的纠正

1. stage0 应当允许在 password 会话中完成现状采集，并忠实显示 password。强制公钥重连可以用于特定证据核验，但不是审计入口的前提；password 也不能单独证明“密钥失败后回退”，用户可能主动选择了密码。
2. stage1 才建立候选新通道，并要求外部新会话公钥和 sudo 确认。关闭 root 和密码认证属于 stage2，不能提前要求 stage0 达到这些目标。stage3 负责真实重启前后验证，不负责修配置。
3. “UFW active/enabled 所以不能运行 stage1”过于绝对。应先读取 UFW 实际状态、完整规则、相关 input 链与候选端口路径，区分能够证明兼容、明确冲突和无法证明。发现框架不等于发现必然冲突，不能默认关闭 UFW。
4. nft 一个 base chain 的 accept 不保证最终接受，后续同 hook 链仍可 drop；所以工具自己的 sshguard accept 不能单独证明候选端口可达。依据：[nftables 官方链说明](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains)。
5. UFW status 展示的信息也不是完整规则集；完整性判断还需考虑其他规则文件和实际内核规则。依据：[Ubuntu UFW 手册](https://manpages.ubuntu.com/manpages/jammy/man8/ufw.8.html)。

## 建议的调整方案（尚未实现）

- stage0 默认返回采集结果：账户、连接、认证方式、磁盘配置、运行证据、防火墙框架/规则和纳管状态。终态基线作为单独的比较结果，不与采集完成混用；显式合规模式保留严格的通过/不符合/证据不足及退出码。
- 将“未纳管”“首次部署前提”“已有配置迁移阻断”“已纳管漂移”分别报告。缺少 state 不冒充已完成阶段，也不单独视为首次部署阻断。
- stage0 和 stage1 可共用只读环境采集；stage1 必须在修改前作明确的准入判断。UFW、iptables/nft、多链或不能完整解释的加载机制应给出具体证据与处理方案，不能静默忽略。
- 为已有配置生成只读迁移计划与变更清单；需要迁移时，把实际修改的主配置、drop-in、服务与防火墙状态纳入同一备份及回滚范围。未实现完整恢复前继续拒绝隐式接管，不让用户手工删配置绕过保护。
- 继续保留 stage1/2 新会话公钥确认及限时恢复；默认 stage0 的宽容采集不能削弱部署确认。

本轮完成设计复核与方案记录，未修改生产脚本、测试或远端配置；没有宣称已实现 UFW 兼容或迁移能力，也没有提交 commit。
