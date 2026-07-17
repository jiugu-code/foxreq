# Firefox 140 ESR 配置档

`firefox_140_esr` 对应 Firefox `140.12.0esr`。该配置档用于保存经过复核的
TLS ClientHello、HTTP/2 设置以及各平台运行时身份，不代表“随机 Firefox”。

## Windows 身份

- Firefox：`140.12.0esr`，BuildID `20260609153453`；
- NSS：`3.112.5`，`NSS_3_112_5_RTM`；
- NSPR：`4.36.2`，`NSPR_4_36_2_RTM`；
- 发布包：Mozilla 官方 `win64/en-US/Firefox Setup 140.12.0esr.exe`；
- 安装包及最小运行时文件均由
  `third_party/firefox-windows-firefox_140_esr.lock.json` 固定大小、SHA-256
  和 SHA-512，Python wheel 内嵌相同运行时清单。

真实回环证据显示，140 ESR 与 152 的关键区别之一是仍启用
`TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xC009)`。C 后端因此使用独立的
140 密码套件表，不会把 `firefox_140_esr` 静默回退到 152。

Windows 正式线级证据门槛已通过：Firefox 冷启动基线为 100 个有效样本，
恢复连接基线为 2 个有效样本；foxreq 对照为 5 个冷连接和 5 个恢复连接。
冷连接与恢复连接分别通过扩展顺序、稳定字段、长度分布、JA3 和 JA4 比较，
没有发现差异。原始 ClientHello 和生成的摘要仍只保存在 Git 忽略目录，不随
源码发布。

运行时约束：

- Windows 与 Linux 分别使用 schema 2 锁文件，不能跨平台复用；
- Firefox、NSS、NSPR 版本必须由发布包实际探测，不能从版本号推测；
- 发布包先对照 Mozilla `SHA512SUMS`，解包后再校验每个运行时文件的大小和
  SHA-256；
- Python worker 启动前会使用 wheel 内嵌清单再次校验 Runtime；
- TLS 参数只能来自本配置档的复现证据，缺少证据时拒绝降级到其他版本。

Linux 使用独立运行时锁。CentOS 7 上已经完成 GCC 4.8.5 严格语法检查和
NSS 3.112.5 / NSPR 4.36.2 Runtime 加载烟雾测试，但尚未构建
`manylinux_2_17` wheel，也未完成 Python API 与线级证据门槛；Windows 结果
不能替代这些 Linux 验证。

配置档和 Runtime 锁只描述身份与可复现来源。捕获文件、浏览器包、动态库、
证书私钥和其他本地产物均不得提交到 Git。
