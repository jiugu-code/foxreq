# foxreq 真实多 Firefox 档案与 HTTP 传输设计

## 1. 目标

本阶段在不降低现有证书校验、运行时哈希锁和错误边界的前提下，向
`foxreq` 核心库和 Python API 增加：

- 真实 `firefox_140_esr` 档案，精确绑定 Firefox 140.12.0esr 及其 NSS/NSPR
  运行时。
- 保留真实 `firefox_152` 档案，精确绑定 Firefox 152.0.6、NSS 3.124
  和 NSPR 4.39。
- 原生明文 HTTP/1.1 请求，与 HTTPS 共用请求序列化、响应分帧、超时和
  Python 响应模型。
- Windows x86-64 和 Linux x86-64 兼容；Linux 以 glibc 2.17 / manylinux2014
  为最低边界，并在 CentOS 7 上串行验证。
- 请求头未包含 `User-Agent` 时，按档案注入默认值；已包含时不覆盖。

Mozilla 官方归档是 Firefox 安装包和 Linux 归档的唯一下载源：
<https://archive.mozilla.org/pub/firefox/releases/>。

## 2. 非目标

- 本阶段不修改、提交或重启 FastAPI 单文件服务。
- 不用 Firefox 152 的 NSS 参数冒充 Firefox 140 ESR。
- 不增加 HTTP/2、代理、重定向、Cookie 管理或浏览器 JavaScript 指纹。
- 不将 Firefox/NSS 二进制、wheel、抓包、测试私钥或运行时目录提交到 Git。
- 不将档案支持声明扩大到未通过真实浏览器样本比较的版本。

## 3. 公开 API 契约

### 3.1 顶层请求

```python
foxreq.get(
    "https://example.test/",
    impersonate="firefox_140_esr",
    runtime_dir=".cache/firefox-runtime/firefox_140_esr/core",
)

foxreq.post(
    "http://example.test/submit",
    impersonate="firefox_152",
    json={"ok": True},
)
```

`impersonate` 只接受 `firefox_140_esr` 和 `firefox_152`，默认保持
`firefox_152`。顶层函数仍创建并关闭一个短生命周期 `Session`。

### 3.2 Session

`Session` 构造时固定一个档案；单个 Session 不允许在请求间切换
`impersonate`。这保证一个连接池不会混入不同 TLS 档案。一个 Session
可以同时请求 HTTP 和 HTTPS，但两种 scheme 使用独立的 origin 连接池。

### 3.3 User-Agent

默认值为：

- `firefox_140_esr`: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0`
- `firefox_152`: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0`

Linux 档案使用同一 Firefox 主版本，但平台 token 为 `X11; Linux x86_64`。
判断请求头名时大小写不敏感。如果调用方已传入任意大小写形式的
`User-Agent`，保留其值、重复项和相对顺序。如果缺失，将默认值插入为
`Host` 之后的第一个用户可见请求头。

## 4. 档案和运行时注册表

包内置只读 `ProfileSpec` 注册表，每个档案包含：

- 档案 ID、精确 Firefox 版本、User-Agent 主版本。
- Windows 和 Linux 的精确 NSS/NSPR 版本。
- 平台对应运行时文件的名称、大小和 SHA-256。
- TLS 密码套件、签名算法、named groups、key share 数、证书压缩、
  ECH GREASE 和 NSS 选项等档案参数。
- 真实浏览器样本证据状态。

运行时解析顺序：

1. `Session(runtime_dir=...)` 显式路径。
2. 档案专用环境变量：
   - `FOXREQ_RUNTIME_FIREFOX_140_ESR`
   - `FOXREQ_RUNTIME_FIREFOX_152`
3. 为向后兼容，`firefox_152` 最后允许使用旧的
   `FOXREQ_NSS_RUNTIME_DIR`。

纯 HTTP 请求不要求运行时。一个未配置运行时的 Session 可以正常使用 HTTP；
后续尝试 HTTPS 时返回 `ConfigurationError`。

## 5. 进程隔离和 IPC

NSS/NSPR 包含进程级全局状态，不同 Firefox 版本又使用相同库文件名。因此
真实多版本不在同一进程内动态切换。

Python `Session` 包含两条路径：

- HTTP：父进程内的 Rust `TcpConnector`，不启动档案子进程。
- HTTPS：首次请求时通过 `subprocess` 启动档案专用 worker。worker 在启动
  环境中获得唯一 Runtime 目录，并且只创建一个 NSS Session。

Linux worker 在 `exec` 前构造最小化环境，仅对子进程设置档案库搜索路径，
不修改父进程或系统的 `LD_LIBRARY_PATH`。Windows worker 使用绝对路径和安全
DLL 搜索标志。

IPC 使用带长度前缀的自定义帧：

- JSON 只传输有上限的结构化元数据。
- 请求和响应正文使用原始二进制帧，不做 Base64 膨胀。
- 不使用 `pickle`，不把正文或请求头写入临时文件。
- 帧长度在分配前校验，且不超过 HTTP 层已有上限。
- worker 异常退出、协议违反或响应截断映射为稳定的 `WorkerError`，
  不向调用方泄漏子进程日志或本地路径。

`Session.close()` 发送显式关闭帧、等待连接池和 NSS 关闭，然后回收子进程。
超时或协议破坏时只终止该 Session 拥有的 worker。

## 6. HTTP 和 HTTPS 核心传输

Rust URL 解析器改为显式返回 `Scheme::Http` 或 `Scheme::Https`，并按 scheme 设置
默认端口 80/443。origin key 必须包含 scheme，避免 HTTP 和 HTTPS 复用同一连接。

`TcpConnector` 使用 Rust 标准库的跨平台 TCP socket，实现现有 `TransportStream`
契约的读、写、关闭和截止时间。HTTPS 仍使用 `NssConnector`。两者共用：

- HTTP/1.1 请求序列化和重复请求头顺序。
- Content-Length/chunked/EOF 响应分帧。
- 累计截止时间、响应大小上限和连接可复用性判定。
- `ConnectionError`、`Timeout`、`ProtocolError` 和 `ClosedSessionError`
  等 Python 错误映射。

HTTP 不执行证书校验，不产生 TLS 指纹，也不因 `verify=False` 发出
`InsecureRequestWarning`。Session 中的信任策略仅在首次 HTTPS 请求时解析和传给
worker，使纯 HTTP 环境不需要 certifi 或 NSS Runtime。

## 7. Windows 和 Linux NSS 边界

C shim 将平台操作拆成窄接口：

- Windows：`LoadLibraryExW`、`GetProcAddress`、Winsock 和 BCrypt。
- Linux：`dlopen`/`dlsym`、POSIX socket、`poll`、`pthread` 和文件描述符检查。
- 证书安装、NSS API 表、TLS 档案配置和公开 C ABI 保持共用。

嵌入 wheel 的平台档案清单在 Rust 进入 C shim 前检查：

- Runtime 目录与档案 ID 匹配。
- 文件是普通文件，不是符号链接/重解析点。
- 大小和 SHA-256 与平台锁文件一致。
- 加载后的 `NSS_GetVersion`/`PR_GetVersion` 与档案精确版本一致。

Linux 子进程使用 `RTLD_NOW | RTLD_LOCAL`，不向父进程暴露 NSS 符号。

## 8. 运行时准备和供应链

运行时准备器改为按 `--profile` 和 `--platform` 选择锁文件：

- Windows 仅接受 Mozilla 官方 `.exe` 安装包，在忽略目录中解压。
- Linux 仅接受 Mozilla 官方 Firefox 归档，使用安全成员白名单解压。
- 解压前验证源包大小和 SHA-256；拷贝后再验证每个运行时文件。
- 拒绝绝对路径、`..` 路径穿越、符号链接、硬链接、设备文件和未列入
  档案的输出。
- 安装包、归档、解压结果和浏览器抓取档案均位于 `.cache/` 或
  `artifacts/` 忽略目录。

## 9. Linux 打包目标

- 源码支持 `x86_64-unknown-linux-gnu`。
- 发布轮子使用 manylinux2014 / manylinux_2_17 环境构建，不在轮子中携带
  Firefox/NSS 库。
- Python 版本契约保持 3.10+，Rust ABI 保持 `abi3-py310`。
- CentOS 7 `my-centos` 仅进行串行构建/安装/回环测试，不做并行编译或压测。
- 如 CentOS 7 系统 Python 低于 3.10，使用用户级隔离 Python/虚拟环境，不替换
  系统 Python。

## 10. 错误和资源管理

- 未知档案、档案与 Runtime 不匹配：`InvalidRequestError` 或
  `ConfigurationError`。
- HTTP/HTTPS URL 非法、userinfo、fragment、控制字符：`InvalidRequestError`。
- worker 启动失败、帧违反、崩溃或被终止：`WorkerError`。
- DNS/TCP 失败：`ConnectionError`。
- NSS/TLS 和证书错误：保持 `TlsError`/`CertificateError`。
- 请求截止时间包含 DNS、TCP、TLS、写入和读取的累计时间。
- 一个 Session 最多持有一个 HTTPS worker，不预加载其他档案。
- 测试全部串行；真实浏览器抓取一次只启动一个浏览器。

## 11. 测试和验收门槛

### 11.1 Rust

- HTTP/HTTPS URL 解析、默认端口和 scheme 隔离的 origin key。
- `TcpConnector` 回环 GET/POST、重复请求头、chunked/EOF、连接复用和超时。
- IPC 帧的部分读写、长度上限、未知消息、截断和 worker 退出。

### 11.2 Python

- 纯 HTTP 在没有 Runtime 环境变量时可用。
- 两个档案的默认 User-Agent，以及自定义 User-Agent 不覆盖。
- Session 档案不可切换，关闭幂等，worker 只由所属 Session 回收。
- 真实 HTTP 回环和真实 HTTPS/NSS 回环。

### 11.3 档案证据

每个档案、每个平台必须：

1. 使用对应官方 Firefox 浏览器进行串行回环 ClientHello 样本抓取。
2. 使用对应 foxreq 运行时抓取相同数量样本。
3. 比较 TLS 版本、密码套件集合/顺序、extensions、supported groups、key shares、
   signature algorithms、ALPN、压缩和 GREASE 规则。
4. 只有档案门槛通过时，才在文档中声明为支持。

### 11.4 平台验收

- Windows：完整 Rust/C/Python 回归，Firefox 140 ESR 与 152 真实回环 TLS。
- Linux：manylinux_2_17 wheel 构建、虚拟环境安装、HTTP 回环、两个 Runtime
  的 HTTPS 回环和 worker 回收。
- 测试后不留下 worker、Firefox、TLS fixture 或端口监听进程。

## 12. 兼容性和交付

- `firefox_152` 仍是默认档案，现有 HTTPS 调用无需修改。
- `FOXREQ_NSS_RUNTIME_DIR` 对 Firefox 152 保持向后兼容。
- 新增公开异常 `WorkerError`，并保持为 `FoxreqError` 子类。
- README 将明确区分 HTTP 请求头档案和 HTTPS TLS 档案。
- 核心库、测试、正式文档和平台锁文件可提交；FastAPI 源码与测试
  保持本地未跟踪，二进制、运行时、wheel 和测试产物保持在 Git 忽略目录。
