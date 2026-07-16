# Firefox 140 ESR 配置档

`firefox_140_esr` 对应 Firefox `140.12.0esr`。该配置档用于保存经过复核的
TLS ClientHello、HTTP/2 设置以及各平台运行时身份，不代表“随机 Firefox”。

运行时约束：

- Windows 与 Linux 分别使用 schema 2 锁文件，不能跨平台复用；
- Firefox、NSS、NSPR 版本必须由发布包实际探测，不能从版本号推测；
- 发布包先对照 Mozilla `SHA512SUMS`，解包后再校验每个运行时文件的大小和
  SHA-256；
- Python worker 启动前会使用 wheel 内嵌清单再次校验 Runtime；
- TLS 参数只能来自本配置档的复现证据，缺少证据时拒绝降级到其他版本。

配置档和 Runtime 锁只描述身份与可复现来源。捕获文件、浏览器包、动态库、
证书私钥和其他本地产物均不得提交到 Git。
