# 三脚本复核与腾讯云版本核对（2026-11-12）

审查范围：工作区 `stage0-check.sh`、`stage1-port-key.sh`、`stage2-lockdown.sh`，包含既有未提交修改；不审查已冻结的 legacy。仅新增本报告与台账记录，未修改生产脚本、上传文件或变更远端 SSH/防火墙/systemd。

## 结论

发现两项 P1 安全判定缺陷，均用内存桩件复现。既有测试通过不能排除这些未覆盖情形；不能据此认定真实服务器存在对应暴露，本次没有采集其特权防火墙状态。

### BUG-061：UFW 端口范围放行被忽略，错误宣告白名单完成

位置：`stage0-check.sh:614`、`stage2-lockdown.sh:568`；`stage2-lockdown.sh:815` 的公网入口判定也沿用相同的精确端口匹配方式。

解析器只识别目标单端口开头的行，不匹配包含目标端口的范围、多个端口或全端口放行。以下规则按顺序执行时，第一条已经允许任何 IPv4 来源访问 62207，后面的单端口 DENY 无法撤回该放行：

```text
Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)
62000:63000/tcp ALLOW IN Anywhere
62207/tcp ALLOW IN 203.0.113.0/24
62207/tcp DENY IN Anywhere
62207/tcp (v6) DENY IN Anywhere (v6)
```

两个脚本的 `allowlist_assessment` 均返回 pass。完整主入口在其它前提满足时均退出 0，stage2 全部步骤 done 且 complete=true。应识别可能覆盖目标端口的所有规则，无法可靠解释时拒绝认证为完成，并保持规则顺序语义。

### BUG-062：UFW 拒绝证据未分地址族，IPv4 拒绝掩盖 IPv6 未受限

位置：`stage0-check.sh:609,638,654`、`stage2-lockdown.sh:563,592,608`；公网入口函数 `stage2-lockdown.sh:830` 也可仅凭单族拒绝返回 False。

`restricting_drop` 为全局布尔值，不要求 IPv4/IPv6 各自具备拒绝证据。以下示例在默认允许入站、双栈监听时仍允许白名单外 IPv6 来源连接：

```text
Status: active
Default: allow (incoming), allow (outgoing), disabled (routed)
62207/tcp ALLOW IN 203.0.113.0/24
62207/tcp DENY IN Anywhere
```

两个脚本仍报告白名单 pass，完整入口退出 0；stage2 全部步骤 done 且 complete=true。应按地址族分别确认放行、拒绝及默认策略，缺少某一族证据时不可判定双栈达标。

## 最小复现方式

在仓库根目录执行以下 Python；全部使用现有内存桩件，不连接服务器、不操作主机防火墙：

```python
import importlib
import json
import sys
sys.path.insert(0, 'tests')
g = importlib.import_module('test-guides')
cases = [
    'Status: active\nDefault: deny (incoming)\n'
    '62000:63000/tcp ALLOW IN Anywhere\n'
    '62207/tcp ALLOW IN 203.0.113.0/24\n'
    '62207/tcp DENY IN Anywhere\n'
    '62207/tcp (v6) DENY IN Anywhere (v6)\n',
    'Status: active\nDefault: allow (incoming)\n'
    '62207/tcp ALLOW IN 203.0.113.0/24\n'
    '62207/tcp DENY IN Anywhere\n',
]
for text in cases:
    for module in (g.STAGE0, g.STAGE2):
        system = g.make_stub(module, session_port=62207, listeners=[62207],
            disk_ports=(62207,), backup=True, auth=g.HARDENED_AUTH,
            allowlist_rules=g.ALLOW_RULES, hardening_mtime=999999999,
            ufw_active=True, ufw_text=text)
        code, output = g.run_main(module, ['--port', '62207', '--user', 'fenix',
            '--allow', '203.0.113.0/24', '--rescue-confirmed',
            '--reboot-confirmed', '--format', 'json'], system)
        result = json.loads(output)
        print(module.SCRIPT, code, result.get('complete'))
```

实际结果：四次退出码均为 0，两次 stage2 complete 均为 True；预期不应通过。

## 腾讯云版本

`ssh tencent-4c4g-bj` 登录成功：fenix，VM-8-4-ubuntu；别名解析到 100.127.237.83:62207。发现三个脚本位于 `/home/fenix/ssh-guide/`。

远端三个文件的 SHA-256 与本地 HEAD `41158321713836f8278467c33b2a5a30552e875f`（Build0604）逐字一致；`git ls-remote origin refs/heads/main` 返回同一提交。因此：远端是当前 GitHub main 最新已提交版本，但不是本地工作区最新版本，不含本地 BUG-057～060 等未提交修复。远端目录未取得 Git 提交元数据，版本归属依据为三个文件逐一哈希匹配。

| 文件 | 远端/HEAD SHA-256 | 本地工作区 SHA-256 |
| --- | --- | --- |
| stage0-check.sh | bca46e1a89ac720baf0dacc56b98e0a21d6f021b9d267fd264dd79a023bdf369 | c830ce8d3663f0f5eb2fa0f953c0974aa7bf1a9a96bb461a595dbdca3eddcc4f |
| stage1-port-key.sh | 8d9987303206b387f4a30e2c8e7f73cf057a7d8e0cb6a4a77befa60f6ae4f940 | d6b2dc61ee37fc765e917c3a504749f2c531744e32b4ef782ae15d0cd739a683 |
| stage2-lockdown.sh | b038b90c202906eec8bbd89b9e8bbe16d4e8d3f0a7137adedea7cc27cb003409 | 9d223c9ad9a77547671058ef07d12a169dd9bc9b1a125c884d31e2dce32702b4 |

远端大小分别为 58953 / 67205 / 84263 字节，mtime 均为 2026-10-31 23:29～23:30（+0800）。哈希是判定依据，mtime 仅供定位。

## 验证边界

- `python3 tests/run-tests.py`：159 项，152 通过、7 跳过，0 失败/错误；跳过是本机缺少 Linux nft/unshare/systemd 等原生依赖。
- 三脚本 `bash -n` 通过；`git diff --check` 通过。
- 本机未安装 ShellCheck，本轮没有取得 ShellCheck 检查结果。
- 两组新反例是代码判定复现，不是实际网络连通性测试；没有变更主机或远端规则，没有冷启动验收。
- 台账 check 结果以本轮最终工具输出为准。

## 后续状态（2026-11-12）

本文件保留当时的审查证据。BUG-061/062 已先行本地修复，本轮继续修复 BUG-063/064，完整套件197项中190通过、7跳过，三脚本语法检查通过。未上传服务器；腾讯云未由本轮更新。最新实现、注释及验收边界见 [UFW后续修复记录](2026-11-12-ufw-063-064-fixes.md)。
