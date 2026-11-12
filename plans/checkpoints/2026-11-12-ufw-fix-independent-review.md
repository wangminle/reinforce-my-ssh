# BUG-061/062 修复独立复核（2026-11-12）

## 结论与范围

原始端口范围漏判、单族拒绝冒充双栈拒绝的反例已被当前实现拦截；两个脚本共用实现的 AST 一致性测试通过。但整轮仍有两项 P2 判定缺陷，不建议据此宣称所有声明入口已达标。

仅复核当前本地工作区并新增报告、台账，未修改生产脚本或回归测试，未连接、上传或变更腾讯云服务器。BUG-061/062 原始修复状态保留，新边界分别登记 BUG-063/064。

## BUG-063：未知拒绝被跳过，后续放行可被误当作可达证据

位置：stage0-check.sh:700–702；stage2-lockdown.sh:654–656。

当 covers=None 或 extra=True 时，拒绝规则被直接 continue；这些规则不能作为关闭证据，但也可能遮挡后续 allow，不能直接忽略其对可达性的影响。以下规则会拒绝服务器当前地址 10.0.0.5 的新连接：

```text
Status: active
10.0.0.5 62207/tcp DENY IN Anywhere
62207/tcp ALLOW IN 203.0.113.0/24
62207/tcp DENY IN Anywhere
62207/tcp (v6) DENY IN Anywhere (v6)
```

现有 g.make_stub 的 SSH_CONNECTION 本地地址正是 10.0.0.5。使用该规则替换既有完整场景中的 UFW 文本，其余前提均满足时，stage0/stage2 完整主入口实际均退出 0，stage2 complete=true，虽然首条规则已阻断后续新的白名单连接。既有会话可能仍因 established 规则保留，不能据此否认问题。

另外两种前置拒绝也被忽略：`OpenSSH DENY IN Anywhere`（应用 profile 实际含目标端口时），以及 `62207/tcp DENY IN 203.0.113.0/24 1024`（限制部分客户端来源端口）。三个反例在两个脚本的辅助判定均得到 pass。

建议：不能解释且可能涉及目标端口的拒绝，应阻止该族后续规则成为完整放行证据，返回需人工复核；或解析明确约束后证明其与声明入口无关。补充前置未知拒绝的完整入口反例及未知规则确实不相关时的正例。

## BUG-064：Tailscale 放行仍未分地址族及来源范围

位置：stage0-check.sh:686–687,714；stage2-lockdown.sh:640–641,668。

`tailnet_accept` 仍是单一布尔值，且遇到 tailscale0 的 allow 后未检查其来源是否覆盖完整 tailnet。以下规则仅允许 IPv4 tailnet 新连接，IPv6 tailnet 全部落入拒绝，但 `allowlist_assessment(..., allows=[], tailnet=True)` 在两个脚本均返回 pass：

```text
62207/tcp on tailscale0 ALLOW IN Anywhere
62207/tcp DENY IN Anywhere
62207/tcp (v6) DENY IN Anywhere (v6)
```

新测试 `test_tailnet_allow_still_needs_both_families_denied` 明确把这个不完整放行场景断言为 pass，因此当前套件无法揭露该问题。随机模型也未生成接口条件，只覆盖范围/来源/判决/地址族，不能证明这个边界正确。

建议：tailnet 放行证据按 IPv4/IPv6 分开保存；至少双栈模式须各自有完整接口放行，受来源限制的规则不能冒充整个接口放行。若仅支持一个地址族，需显式声明并取得另一个地址族无需访问的依据，避免隐式全局布尔值。

## 验证结果

- 独立运行 `python3 tests/run-tests.py`：Ran 187 tests，OK (skipped=7)，即 180 通过、7 跳过，0 失败/错误。
- 原描述及 CHK-043 的“187项通过、7项跳过”计数不准确；本报告记录实际总数，不改写历史验证过程。
- 三脚本 bash -n 通过，git diff --check 通过。
- 两个新问题只用现有内存桩件复现，不修改主机配置；未知目的地址拒绝另外通过完整主入口确认。
- 新增28项的 AST、首条匹配随机模型及原始 BUG-061/062 反例回归均随完整套件通过；随机模型样本域不包含本次两个缺口。
- ShellCheck 本机未安装，本轮未取得 ShellCheck 或 Linux 原生/真实外部连接/冷启动验收结论。

## 后续状态（2026-11-12）

本文件保留当时的审查证据。BUG-061/062 已先行本地修复，本轮继续修复 BUG-063/064，完整套件197项中190通过、7跳过，三脚本语法检查通过。未上传服务器；腾讯云未由本轮更新。最新实现、注释及验收边界见 [UFW后续修复记录](2026-11-12-ufw-063-064-fixes.md)。
