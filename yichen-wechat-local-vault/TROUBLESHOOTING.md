# yichen-wechat-local-vault Troubleshooting

本文件记录 macOS/WeChat/Frida 相关踩坑。不要写入真实用户标识、key、salt、wxid、数据库绝对路径或整库原文。

## Preflight

- 全量解密前脚本会提示确认，建议先关闭微信。
- Frida 抓 key 前脚本会提示确认，必须关闭所有微信实例且用户在场。
- 只读 Vault 查询不需要关闭微信。

## code signing

- Desktop 可能是 iCloud/File Provider，复制 WeChat.app 后会残留扩展属性，导致 `codesign` 报 `resource fork, Finder information, or similar detritus`。
- 不要直接签名 `/Applications/WeChat.app`。
- 使用本机私有临时目录保存签名副本，并通过 `--wechat-copy` 指定。
- 如果仍有扩展属性，可执行 `xattr -cr <copy>` 后再签名。

## Frida capture

- 直接 `frida.spawn` 原版微信可能因 SIP/权限返回 `PermissionDenied`。
- 对签名副本使用 Frida spawn 也可能在启动阶段崩溃。
- 更稳的流程：复制并签名副本，先手动启动副本，再运行 `extract_keys.py --mode attach --skip-prepare --wechat-copy <copy> --reuse-log`。
- 抓 key 前先关闭所有微信实例。
- 数据库 key 是按需触发：打开聊天列表、任意聊天、通讯录、朋友圈、收藏、搜索、公众号、表情/设置等页面。
- 签名副本在 UI 交互时可能闪退；建议分批抓取，每批结束后保留已匹配 key。

## Query accuracy

- `vault_cli.py search --chat X --limit N` 会先取最近 N 条候选再过滤关键词，可能漏命中。
- 需要准确计数时，应扫描完整时间范围并使用较大的扫描上限，再在本机过滤关键词。

## Safety

- 不输出 key、salt、wxid、数据库路径或整库原文。
- 抓 key 日志包含敏感派生信息，确认 key 已保存到本机配置后应删除。
- 使用 Skill 自带 venv，不污染系统 Python。
- 增量刷新可开微信执行；全量解密建议关闭微信。
