# 企微本地 Vault · 故障排查（实战补遗 2026-09-03）

> 以下全部来自 WeCom macOS 5.0.10 (arm64) 实战，对应修复见 `task-wecom-hook-fix`（已并入 main）。

## 1. attach 捕获零候选 / "unable to intercept function"
- 现象：CommonCrypto、sqlite3_key*、wxsqlite3-page-raw-key 钩子能装，但 DbKeyManager / GetAllLocalEncryptKey 报 `unable to intercept function at 0x…`，跑满 duration 无候选。
- 根因：脚本内三个硬编码偏移来自旧版构建；5.0.10 上这些地址落在无关函数的 epilogue/函数中段，Interceptor 无法重定位。运行中的进程 key 早已加载，被动钩子等不到事件。
- 处理：capture_key_macos.py 已改为「偏移 + prologue 字节校验 + Memory.scanSync 特征指纹回退（页密钥派生函数的 LCG 立即数 24 字节指纹）」。指纹比偏移耐版本迁移。失效的 DbKeyManager 两钩子已移除（page-derive 钩子对抓 key 是超集）。
- 附注：`sqlite3_key*` 钩子挂在系统 libsqlite3 上，而企微静态链自己的 wxsqlite3——无害但无效，别被"hooked:"日志迷惑。

## 2. spawn-signed-copy 报 frida.TimedOutError "initializing suspended process"
- 现象：副本创建、ad-hoc 重签、Frida spawn 均成功，attach 初始化恒超时；退出原版企微后重试依旧。
- 根因：SIP + 硬化运行时对新 ad-hoc 签名 app 的注入初始化阻塞，与单实例无关。skill 禁止关 SIP，此路线在 5.0.10 不可用。
- 替代：attach 模式 + 登录/切换企业动作触发密钥派生（见 §3）。

## 3. scan_dbkey_manager 扫描 8GB 零候选
- 现象：sudo 只读扫描 regions=621 / 7.6GB，candidates=0。
- 根因：vtable 常量与 5.0.10 不符（脚本内置 0x10C3550C8 已过期；实测候选 0x10c7836b0 未经对象布局实证）。且该扫描器只认 DbKeyManager raw-key 形态。
- 处理：改用修复后的 capture（页派生钩子）。多租户场景：**切换企业会派生新租户 key**，切换后立即跑一轮 capture 即可逐租户解锁。

## 4. 企微自动更新后，捕获脚本卡死在数据集发现阶段
- 现象：opendir/读文件无限阻塞（不是报错），kill 后企微无恙。
- 根因：企微更新触发 macOS TCC 收回 container 访问授权，新文件读取等待授权弹窗。
- 处理：点掉弹窗，或 系统设置→隐私与安全性→文件与文件夹 里重新授权；授权后用 `python3 -u`（关缓冲）重跑。

## 5. 解密后 message.db 只有几百条
- 根因：企微 Mac 客户端本地只保留近期消息（实测主账号 307 条），历史靠登录时的初始同步批次。
- 处理：挖历史前先 `SELECT COUNT(*)`；要深度就先做手机→电脑聊天记录迁移再解密。

## 6. 多租户识别
- datasets 按 WXWork/Data/<uid>/Data 划分，一账号一 dataset。租户名在解密后的 `company.db`（self_corp_list_table / external_company_table_v2），key 按租户隔离——A 租户的 key 解不了 B 租户的库（manifest 会显示 not_decrypted）。
