# foxreq

foxreq 是一个面向已授权安全测试与协议研究的同步 Python HTTP/HTTPS 请求库。当前实现通过 Rust HTTP/1.1 客户端、C 语言 NSS 边界和哈希锁定的 Firefox 运行时发起真实请求，并提供接近 Requests 的 `foxreq.get()`、`foxreq.post()` 与 `foxreq.Session` API。

> 本项目仍处于 `0.1.0` 开发阶段。它不是通用爬虫工具，也不承诺绕过任何风控、验证码或访问控制。使用者必须自行确认测试目标、测试时段、请求量和数据处理方式均在书面授权范围内。

## 项目状态

- 已实现：Windows x86-64 上的 Firefox 140 ESR（140.12.0esr）和 Firefox 152（152.0.6）真实 TLS 档案、HTTP/HTTPS 1.1、Python 3.10+ 同步 API、连接复用及严格证书验证。
- Windows 已验证：Python 3.12 独立环境、两个哈希锁定的 NSS/NSPR Runtime、GET/POST、JSON、重复有序请求头、明文 HTTP、HTTPS、超时与本地连接复用。
- 指纹证据：Firefox 140 ESR 已通过 100 个浏览器冷连接、2 个恢复连接及 foxreq 各 5 个对照样本的正式比较；Firefox 152 仍只有部分烟雾证据。
- Linux 初步验证：POSIX 加载、socket、mutex 和时钟适配已实现；CentOS 7 上两个 Runtime 的 C 编译及加载/版本探测烟雾测试通过，但 manylinux wheel 和 Python API 尚未完成正式验证。
- 尚未实现或验证：HTTP/2、代理、重定向、Cookie 管理、公开包发布及 Linux `manylinux_2_17` 完整交付门槛。

## 授权使用边界

允许的典型场景包括自有系统测试、CTF 环境、经委托的渗透测试、协议兼容性研究和本地 TLS 实验。禁止将本项目用于未授权访问、规避访问控制、凭据滥用、批量骚扰或隐私数据采集。

仓库中的自动化网络测试只绑定回环地址，使用短期生成的测试证书，并串行执行。两个可执行示例也默认拒绝非回环目标；只有在确认目标已授权后，才可显式使用 `--allow-authorized-target`。

## 能力矩阵

| 能力 | 当前状态 | 边界 |
| --- | --- | --- |
| Python API | Windows 已实测 | Python 3.10+，`abi3-py310`；Python 3.12.10 完整测试通过 |
| TLS 实现 | Windows 已实测 | Firefox 140.12.0esr 与 152.0.6 各自携带的精确 NSS/NSPR |
| HTTP | Windows 已实测 | HTTP 和 HTTPS 的 HTTP/1.1；支持固定长度、chunked、close-delimited 与 1xx |
| 请求输入 | 已实测 | 自定义方法、参数、重复有序请求头、`data`、JSON、有限正数超时 |
| 响应对象 | 已实测 | 状态、原因短语、版本、重复响应头、`content`、`text`、`json()` |
| 连接复用 | 已实测 | `Session` 每个源站保留一个空闲连接，失效时安全重连 |
| 证书验证 | 已实测 | 默认 certifi、指定 PEM、显式 `verify=False` 警告 |
| 默认请求头 | 已实测 | 未传 `User-Agent` 时按档案和平台注入；显式传入时保持原值 |
| TLS 指纹证据 | 分档案 | Firefox 140 ESR 正式通过；Firefox 152 仍为部分证据 |
| Linux / manylinux | 初步通过 | C/POSIX Runtime 烟雾通过；wheel、Python API 和完整门槛未通过 |
| HTTP/2、代理、重定向、Cookie | 未实现 | 不应按 Requests 的完整替代品使用 |

## 实现范围与架构

当前档案为 `impersonate="firefox_140_esr"` 和 `impersonate="firefox_152"`，默认使用后者。档案在一个 Session 内固定，不会随机切换，也不能在 Session 创建后改成另一个版本。缺少 `User-Agent` 时会注入与档案和操作系统一致的默认值；调用者明确传入后不会改写。

HTTPS 使用档案对应的 NSS/NSPR Runtime，版本、官方源文件、文件大小和 SHA-256 均由平台锁文件固定。明文 HTTP 直接使用 Rust TCP 传输，不需要 Firefox Runtime；HTTP 不包含 TLS 指纹，因此 `impersonate` 在 HTTP 请求上只影响可观测的档案级请求头等行为。

```text
Python foxreq API
    -> HTTP：Rust TCP + HTTP/1.1 连接复用
    -> HTTPS：档案专用 Python worker
        -> Rust HTTP/1.1 客户端
        -> C11 NSS shim
        -> 哈希锁定的 Firefox 140 ESR 或 152 NSS/NSPR Runtime
```

Python 层负责 URL、参数、请求头、正文、超时与 PEM 信任锚规范化；Rust 层负责截止时间、请求序列化、响应分帧及连接状态；C 层只暴露经过审计的 NSS 生命周期和 I/O ABI。详细状态见 [Firefox 140 ESR 档案](profiles/firefox_140_esr/README.md) 和 [Firefox 152 档案](profiles/firefox_152/README.md)。

## Python 安装

当前尚无 PyPI 包或正式发布的预编译 wheel。Windows x86-64 已完成源码构建和 `cp310-abi3-win_amd64` wheel 验证；Linux 构建目标已经接入，但 `manylinux_2_17` wheel 尚未通过正式交付门槛。Windows 构建需要 Python 3.10+、Rust 1.88.0 MSVC、Visual Studio C++ Build Tools、CMake、Ninja 与 maturin。完整要求见 [构建说明](docs/building.md)。

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install "maturin>=1,<2"
$env:CARGO_BUILD_JOBS = "1"
$env:PYTHONUTF8 = "1"
$env:FOXREQ_NSS_RUNTIME_DIR = (Resolve-Path .cache/firefox-runtime/core).Path
.\.venv\Scripts\python.exe -m maturin build --release --out dist
$wheel = Get-ChildItem dist -Filter "foxreq-*.whl" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
.\.venv\Scripts\python.exe -m pip install --force-reinstall --no-deps $wheel.FullName
```

`certifi` 是运行时依赖。构建 wheel 后若使用 `--no-deps` 安装，应在受控环境中另行安装 `certifi>=2025.8.3,<2027`。

若要运行仓库的真实回环验证，还需在本地虚拟环境安装测试可选依赖 `cryptography>=41`；它只负责生成短期 fixture 证书，不参与请求运行时。

## Firefox NSS 运行时

两个 HTTPS 档案必须使用各自的 Runtime，不能把 Firefox 152 的目录交给 Firefox 140 ESR。先从 Mozilla 官方归档获取锁定发布包并核对 `SHA512SUMS`，再提取最小运行时；脚本会重新检查每个文件的大小和 SHA-256，目标目录已存在时失败而不是覆盖。

```powershell
python -m scripts.runtime.prepare_firefox_runtime --profile firefox_140_esr --platform windows-x86_64 --artifact path\to\Firefox_Setup_140.12.0esr.exe --lock third_party/firefox-windows-firefox_140_esr.lock.json --output .cache/firefox-runtime/firefox_140_esr/core
python -m scripts.runtime.prepare_firefox_runtime --profile firefox_152 --platform windows-x86_64 --artifact path\to\Firefox_Setup_152.0.6.exe --lock third_party/firefox-windows-runtime.lock.json --output .cache/firefox-runtime/core
$env:FOXREQ_RUNTIME_FIREFOX_140_ESR = (Resolve-Path .cache/firefox-runtime/firefox_140_esr/core).Path
$env:FOXREQ_NSS_RUNTIME_DIR = (Resolve-Path .cache/firefox-runtime/core).Path
```

下载属于显式开发操作；包导入和请求路径不会自动联网获取 Firefox 或构建工具。

## Python 调用

以下地址仅代表本地授权测试服务。生产使用前应保留证书验证，并确认目标在授权清单内。

```python
from pathlib import Path

import foxreq

response = foxreq.get(
    "https://127.0.0.1:8443/status",
    impersonate="firefox_140_esr",
    runtime_dir=Path(".cache/firefox-runtime/firefox_140_esr/core"),
    params=(("item", "one"), ("item", "two")),
    headers=(("X-Test", "first"), ("X-Test", "second")),
    timeout=10.0,
    verify=Path("artifacts/fixtures/certs/local/ca.pem"),
)

print(response.status_code)
print(response.http_version)
print(response.text)
```

明文 HTTP 不需要 Runtime 或 CA：

```python
response = foxreq.get(
    "http://127.0.0.1:8080/status",
    impersonate="firefox_152",
    timeout=10.0,
)
```

顶层函数会为单次请求创建并关闭一个短生命周期 Session。对同一源站连续请求时，应显式复用 Session：

```python
from pathlib import Path

import foxreq

with foxreq.Session(
    impersonate="firefox_152",
    runtime_dir=Path(".cache/firefox-runtime/core"),
    verify=Path("artifacts/fixtures/certs/local/ca.pem"),
    timeout=10.0,
) as session:
    first = session.get("https://127.0.0.1:8443/one")
    second = session.post(
        "https://127.0.0.1:8443/two",
        json={"ok": True},
    )
```

`verify=True` 使用 certifi 信任包；`verify="path/to/ca.pem"` 使用指定 PEM；`verify=False` 会发出 `InsecureRequestWarning`，不应出现在成功路径示例或常规测试中。一个 Session 的信任锚与 TLS 档案在构造后固定，切换 CA 或 `impersonate` 应创建新的 Session。

可执行且经过真实回环测试的示例：

- [examples/python_basic.py](examples/python_basic.py)：顶层 GET 与 JSON POST。
- [examples/python_session.py](examples/python_session.py)：同一连接上的两个 Session 请求。

```powershell
.\.venv\Scripts\python.exe examples/python_basic.py --url https://127.0.0.1:8443/basic --impersonate firefox_152 --runtime .cache/firefox-runtime/core --ca-pem artifacts/fixtures/certs/local/ca.pem
.\.venv\Scripts\python.exe examples/python_session.py --origin https://127.0.0.1:8443 --impersonate firefox_140_esr --runtime .cache/firefox-runtime/firefox_140_esr/core --ca-pem artifacts/fixtures/certs/local/ca.pem
.\.venv\Scripts\python.exe examples/python_basic.py --url http://127.0.0.1:8080/basic --impersonate firefox_140_esr
```

示例只输出状态码、HTTP 版本和响应体长度，不输出请求头、Cookie 或响应正文。

## 串行验证

验证入口在运行任何重任务前检查 Python 版本和可用物理内存。可用内存低于 4096 MiB 时直接退出；所有 Cargo、CMake、C 与 Python 步骤依次运行，且强制 `CARGO_BUILD_JOBS=1`。它不会执行压测。

```powershell
$env:FOXREQ_NSS_RUNTIME_DIR = (Resolve-Path .cache/firefox-runtime/core).Path
$env:FOXREQ_RUNTIME_FIREFOX_140_ESR = (Resolve-Path .cache/firefox-runtime/firefox_140_esr/core).Path
$env:CARGO_BUILD_JOBS = "1"
.\scripts\verify_python.ps1
```

验证包括 Rust 格式化、Clippy、非压力单元测试、C stub ABI、真实 NSS 回环 TLS/HTTP/1.1、完整 Python API/示例/文档测试、依赖检查、`git diff --check` 与已跟踪文件敏感标记扫描。测试证书、私钥、wheel、抓包及临时运行时均位于 `.gitignore` 覆盖的路径。

## 指纹证据等级

合成测试只能证明解析器和比较器行为，不能标记为 Firefox 黄金证据。Firefox 140 ESR 的 Windows 正式门槛已经通过：100 个有效浏览器冷连接、2 个有效恢复连接，以及 foxreq 的 5 个冷连接和 5 个恢复连接均通过扩展顺序、稳定字段、长度、JA3 与 JA4 比较。Firefox 152 当前仍只有少量烟雾样本，不能据此声明正式线级一致。

正式结论需要 100 次冷连接 Firefox 样本、至少 2 次恢复连接样本，以及每种 foxreq 模式 5 个样本全部通过冻结比较。证据采集、归一化规则与禁入数据见 [指纹证据工作流](docs/fingerprint-evidence.md)。

## 平台限制与 Linux 审计

真实 NSS shim 已拆分为 Windows 与 POSIX 适配：Linux 使用 `dlopen`/`dlsym`、POSIX socket、`poll`、`pthread` 和 `clock_gettime`。官方 Linux 归档的 Firefox 140 ESR 与 152 文件身份分别由 schema 2 锁文件固定。

在授权 CentOS 7 主机上，GCC 4.8.5 的 C11 严格语法检查以及两个真实 Runtime 的有限加载/版本探测烟雾测试已经通过，观测到 Firefox 140 ESR 的 NSS 3.112.5 / NSPR 4.36.2 和 Firefox 152 的 NSS 3.124 / NSPR 4.39。该主机仍只有 Python 3.9.13、约 3.77 GiB 物理内存，且没有 Rust/CMake，不满足 Python 3.10+ 和 4096 MiB 可用内存门槛，因此没有构建 manylinux wheel，也没有执行 Linux Python API 完整验证或压测。

Linux 串行入口为 `scripts/verify_python.sh`。它要求预先提供 Python 3.10+、Rust、CMake、Ninja、两个 Runtime、短期本地证书和待检 `manylinux_2_17_x86_64` wheel；任一条件缺失或可用内存不足都会在重任务前失败关闭。因此当前只能称为“Linux C 后端初步兼容”，不能称为 Linux 平台完整通过。

## 目录结构

```text
crates/foxreq-core/   Rust HTTP/HTTPS 1.1、传输抽象与 NSS 适配
crates/foxreq-py/     PyO3 原生模块和 Session 工作线程
python/foxreq/        Python 公共 API、规范化、模型与异常
native/nss-shim/      C11 NSS ABI、stub、Windows 与 POSIX 真实后端
profiles/             Firefox 140 ESR / 152 档案与证据状态
tools/fingerprint/    TLS/HTTP/2 证据解析和比较开发工具
tests/                Rust、Python、C 与本地 TLS fixture
examples/             可执行 Python API 示例
scripts/              来源、运行时、抓取与串行验证入口
docs/                 构建和证据说明
third_party/           锁文件、补丁说明与第三方通知
```

## 路线图

1. 完成 Firefox 152 冷连接与恢复连接正式证据门槛，冻结第二个可复现指纹档案。
2. 在满足 Python 3.10+ 和 4 GiB 可用内存门槛的隔离 Linux 环境中构建并验证 `manylinux_2_17` wheel。
3. 通过 Linux 两个档案的 Runtime、HTTP/HTTPS、证书与 Python API 完整门槛。
4. 在证据和生命周期稳定后评估 HTTP/2、代理、重定向及 Cookie 功能。
5. 补齐发布许可证、第三方归属清单和可重复发布流程后再考虑公开发行。

## 贡献规则

- 新网络测试必须默认使用回环地址、有限请求数、明确超时和临时证书。
- 不提交真实凭据、Cookie、Authorization 值、私钥、TLS key log、用户流量抓包、wheel、Firefox 二进制或构建产物。
- 不降低证书验证、来源哈希、内存门槛或串行构建约束来换取测试通过。
- 功能和修复应先增加失败测试，再实现并运行最小相关验证；提交前运行完整串行入口。
- 文档必须区分“合成测试”“部分证据”“平台实测”和“正式通过”。

## 许可证

仓库当前尚未提供根目录项目许可证，因此不能推断 foxreq 源码已按某个开源许可证授权。第三方组件仍分别受其原始许可证约束，现有通知见 [certifi 说明](third_party/NOTICE-certifi.md)、[JA4 说明](third_party/NOTICE-JA4.md) 与 [NSS 补丁说明](third_party/patches/nss/README.md)。在正式发布前需要补齐项目许可证和锁定依赖的完整归属清单。
