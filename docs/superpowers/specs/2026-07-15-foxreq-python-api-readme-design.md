# foxreq Python API 与根 README 设计

## 目标

本阶段交付一个真正调用 Rust/NSS 传输栈的同步 Python API，并在仓库根目录增加中文为主的 `README.md`。Python 层不能通过 subprocess 包装示例程序，也不能把设计目标写成已经实现的能力。

项目只用于自有系统、CTF 和明确授权的安全测试。本阶段的网络验证只访问 loopback fixture、Mozilla 官方资源或用户明确授权的目标，不把绕过第三方反自动化系统作为验收条件。

## 首版范围

首版聚焦 HTTPS/1.1 和 Firefox 152 / NSS 3.124 profile：

- 顶层函数：`foxreq.request()`、`foxreq.get()`、`foxreq.post()`；
- 会话对象：`Session.request()`、`get()`、`post()`、`close()` 和上下文管理器；
- 请求参数：`method`、`url`、`params`、`headers`、`data`、`json`、`timeout`、`verify`、`impersonate`；
- 响应对象：`status_code`、`reason`、`url`、`headers`、`content`、`text`、`http_version` 和 `json()`；
- 有序、重复请求头能够进入 Rust HTTP/1 serializer，不在 Python 映射中静默丢失；
- 阻塞的 DNS、连接、TLS 和收发阶段释放 Python GIL；
- Python 异常保留错误类别和可读上下文，不暴露私钥、key log 或原始内存内容。

重定向、Cookie 管理、代理、流式响应、HTTP/2 和异步 API 不属于首版。它们在基础生命周期、超时语义和连接复用稳定后再逐项设计。

### 公开契约

`headers` 接受映射或有序的 `(name, value)` 序列；需要重复字段时必须使用序列。响应头由只读、保持顺序和重复项的 `Headers` 对象承载，并提供 `items()`、`get()` 和 `get_all()`。`params` 接受映射或有序二元组序列。

`data` 只接受 `str` 或 bytes-like 对象，`json` 接受可由标准库 JSON 编码的对象，两者互斥。`timeout` 在首版只接受一个正浮点秒数，表示贯穿 DNS、连接、握手、写入和读取的同一个单调时钟总期限，不在不同阶段重新计时。

`verify=True` 使用项目固定并可复现的信任策略，`verify="path.pem"` 使用调用者提供的 PEM 信任锚，`verify=False` 必须显式指定并发出 `InsecureRequestWarning`。`impersonate` 首版只接受 `"firefox_152"`；省略时使用同一固定 profile，而不是随环境漂移的“最新版”。

## 架构

采用 PyO3 + maturin 的混合 Rust/Python 包结构：

1. `foxreq-core` 负责 URL、HTTP/1.1 framing、deadline、连接复用和传输错误；
2. 现有 C NSS shim 负责 NSS/NSPR 生命周期、Firefox profile 配置和 TLS I/O；
3. 新的 PyO3 原生扩展只做所有权、类型和异常转换，不复制协议逻辑；
4. `python/foxreq` 提供符合 Python 习惯的薄封装和公开 API；
5. `examples/` 提供可直接运行的 Python 调用示例。

包采用 Python 3.10+ 和 `abi3-py310`。不因当前机器只有旧解释器而降低公开版本下限。构建和测试环境需要单独准备 Python 3.10+；生成的扩展不得依赖开发机绝对路径。

## 请求与响应数据流

Python 调用先在薄封装层规范化 URL、查询参数、JSON 和请求头，再把拥有所有权的请求数据交给 PyO3。原生扩展释放 GIL，调用 `foxreq-core`；core 通过 NSS transport 完成 TLS 握手、HTTP/1.1 序列化与响应解析。完整响应回到 Python 后再提供文本和 JSON 便捷方法。

`Session` 独占其连接池和 NSS 客户端状态；`close()` 必须幂等。顶层便捷函数使用短生命周期会话，保证完成请求后回收资源。Response 内容在首版完整缓存在内存中，并受现有响应大小上限保护。

## 错误语义

至少区分参数/URL、DNS/连接、TLS、超时、HTTP framing、解压和 JSON 解码错误。Rust 和 C 层不得 panic 或越过 FFI 展开；Python 看到稳定的 `FoxreqError` 子类。错误消息可以包含阶段和目标主机，但不得包含认证头、Cookie、请求体或 TLS 密钥材料。

## Python 示例

示例覆盖：

- `foxreq.get()` 的最小调用；
- 带查询参数、重复请求头和超时的请求；
- `foxreq.post(json=...)`；
- `with foxreq.Session() as session` 的连接复用；
- 捕获 `FoxreqError`。

默认示例使用本地 fixture 或占位的授权 URL，并明确提示读者只对获准目标发起请求。

## 测试与资源约束

所有重型步骤串行执行，设置 `CARGO_BUILD_JOBS=1`，同一时间不并行启动 Cargo、CMake、Firefox 或多个 Python 测试进程。开始构建和压力测试前检查可用内存；低于 4096 MiB 时停止重型步骤，只允许静态检查和小型单元测试。

Windows 是当前主要构建环境。Python 测试包含：

- API 参数、异常映射和对象生命周期单元测试；
- loopback HTTPS fixture 上的 GET、POST、fixed-length、chunked、100 Continue、畸形响应和超时；
- 同一 `Session` 的连接复用与 `close()` 幂等；
- Python 示例作为可执行 smoke tests；
- Rust fmt、clippy、单元/集成测试和 C profile 测试；
- 敏感信息扫描、`git diff --check` 和最终差异复核。

已配置的 `my-centos` 作为补充 Linux 验证机。当前探测结果为 CentOS 7、3770 MiB 物理内存、约 2090 MiB 可用内存、Python 3.9.13，且未发现 Rust/Cargo/CMake。它当前不满足重型测试和 Python 3.10+ 构建门槛，因此不得在其上编译 NSS 或运行压力测试；只有在工具链和内存门槛满足后才执行 Linux 原生扩展测试。环境未准备完成前，Linux 支持必须标记为未验证。

## 根 README 内容

根 `README.md` 采用“当前状态优先”：

1. 项目定位与授权使用边界；
2. 明确的开发状态提示；
3. 已实现、部分验证和未实现能力表；
4. Rust core、C NSS shim、PyO3 和 Python facade 架构；
5. Windows 构建、安装和真实 Python 调用快速开始；
6. Firefox 152 profile 与 cold/resumed 指纹证据边界；
7. 串行测试、4096 MiB 内存门槛和 Linux 当前限制；
8. 目录结构、详细文档、路线图和许可证。

README 不使用“完全伪装”“已绕过 Akamai”等无证据表述。烟雾级指纹比较只能写为 partial；正式 G4/G5 通过仍要求规定数量的 Firefox baseline 和 foxreq candidate 样本。

## Git 与交付规则

设计文档先单独提交。实现阶段按可验证批次提交；每批代码和文档只有在对应测试通过、敏感信息扫描无异常且最终差异复核完成后，才推送到 `origin/feature/nss-http1-transport`。失败或未验证的改动不以“完成”名义推送。

仓库禁止提交账号密码、SSH 私钥、服务器配置、TLS key log、原始抓包、临时构建目录和 fixture 私钥。GitHub 文档以中文为主，必要的 API 标识和命令保留英文。

## 验收标准

- Python 示例确实经过原生 PyO3 扩展进入 Rust/NSS，而非模拟或 subprocess；
- loopback HTTPS 的核心请求、响应、超时和生命周期测试通过；
- README 中所有本地链接存在，命令与脚本参数一致；
- Python 3.10+ 的安装、导入和调用步骤可复现；
- Windows 验证结果如实记录，Linux 未满足门槛时如实标记未验证；
- `git diff --check`、格式检查、静态检查、测试和敏感信息扫描通过；
- 测试完成后提交并同步到 GitHub 远程分支。
