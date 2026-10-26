# 脚本入口与命名

| 推荐入口 | 职责 | 旧入口 |
| --- | --- | --- |
| stage0-audit.sh | 独立只读审计：安全效果、管理归属、迁移准备和重启证据；实现内嵌，环境仍需 Python 3 | 原 audit.py 已合并，不再单独发布 |
| stage1-newport.sh | 建立候选新端口通道，保留配置允许的旧入口，外部公钥与 sudo 确认后提交 | stage1.sh |
| stage2-harden.sh | 禁 root、密码和键盘交互，仅公钥认证，并关闭旧端口 | stage2.sh |
| stage3-reboot-check.sh | 记录基线，跨重启复验；不部署配置、不代为重启 | stage3.sh |

第二阶段不仅处理 root 登录，因此采用 harden；第三阶段专门验证跨重启状态，因此采用 reboot-check。

stage0 是独立入口，可在已有旧方案或新版机器上随时执行。编号不表示新增了一个持久化阶段，也不会自动把部署状态推进到 stage1。

## 使用

普通管理账户 SSH 登录后 sudo 执行即可：

```bash
sudo bash ./stage0-audit.sh
# 可选：声明目标策略后比较白名单和应关闭的端口
sudo bash ./stage0-audit.sh --allow 203.0.113.0/24 --closed-port 22
sudo bash ./stage1-newport.sh --help
sudo bash ./stage2-harden.sh --help
sudo bash ./stage3-reboot-check.sh --help
```

这里使用 bash，不依赖文件的执行位；参数和阶段语义均未变。已有旧方案先审计，不能因为入口改名就直接 apply。

## 兼容与发布

stage1.sh、stage2.sh、stage3.sh 是可选的旧文件名兼容入口，通过 exec 转入新实现，保留参数、退出码和 sudo 会话环境；新部署不需要它们。审计实现已内嵌 stage0-audit.sh，不再依赖外部 audit.py。仓库的 tests/ 下 Python 文件仅供开发测试，不属于部署文件。

部署只需分发以下四个工作文件：

```text
stage0-audit.sh
stage1-newport.sh
stage2-harden.sh
stage3-reboot-check.sh
```

本机上传脚本已将上传清单更新为这四个文件，保持 working-scripts 原有忽略规则。上传不会主动删除远端历史文件；遗留 audit.py 和兼容入口不再是新部署的依赖。没有在本轮执行远端上传或 apply。

持久状态的 stage1/stage2 标识保持不变；事务恢复使用独立 STAGE_ID，不从当前文件名推导。新事务备份的是实际的新主脚本，定时恢复继续调用其自包含备份；已有事务目录内的旧版自包含脚本不被替换。文件命名不修改五个受管配置路径或策略摘要规则。

历史审计和 checkpoints 按当时文件名保留，避免修改旧证据；当前设计和操作说明使用新名称。
