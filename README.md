# foxreq

foxreq 是一个面向已授权安全测试与协议研究的同步 Python HTTPS 请求库。当前实现通过 Rust HTTP/1.1 客户端、C 语言 NSS 边界和哈希锁定的 Firefox 运行时发起真实请求，并提供接近 Requests 的 `foxreq.get()`、`foxreq.post()` 与 `foxreq.Session` API。

> 本项目仍处于 `0.1.0` 开发阶段。它不是通用爬虫工具，也不承诺绕过任何风控、验证码或访问控制。使用者必须自行确认测试目标、测试时段、请求量和数据处理方式均在书面授权范围内。

## 项目状态

- 已实现：Windows x86-64 上的 Firefox 152.0.6 / NSS 3.124 / NSPR 4.39 真实 TLS 后端、HTTPS/1.1 请求、Python 3.10+ 同步 API、连接复用、严格证书验证与回环集成测试。
- 已验证：哈希锁定运行时加载、TLS 生命周期、ALPN、证书校验、超时、HTTP/1.1 响应分帧、连续 Session、Python GET/POST 和本地连接复用。
- 部分证据：少量 Firefox 与 foxreq ClientHello 烟雾样本的稳定字段相符；尚未完成正式的 100 次冷连接基线，因此不能声明完整浏览器线级一致性。
- 尚未验证：Linux 真实 NSS 后端、manylinux wheel、HTTP/2、代理、重定向、Cookie 管理及公开包发布。

## 授权使用边界

允许的典型场景包括自有系统测试、CTF 环境、经委托的渗透测试、协议兼容性研究和本地 TLS 实验。禁止将本项目用于未授权访问、规避访问控制、凭据滥用、批量骚扰或隐私数据采集。

仓库中的自动化网络测试只绑定回环地址，使用短期生成的测试证书，并串行执行。两个可执行示例也默认拒绝非回环目标；只有在确认目标已授权后，才可显式使用 `--allow-authorized-target`。

## 能力矩阵

| 能力 | 当前状态 | 边界 |
| --- | --- | --- |
| Python API | Windows 已实测 | Python 3.10+，`abi3-py310` |
| TLS 实现 | Windows 已实测 | Firefox 152.0.6 所带 NSS 3.124 / NSPR 4.39 |
| HTTP | 已实测 | 仅 HTTPS、HTTP/1.1；支持固定长度、chunked、close-delimited 与 1xx |
| 请求输入 | 已实测 | 自定义方法、参数、重复有序请求头、`data`、JSON、有限正数超时 |
| 响应对象 | 已实测 | 状态、原因短语、版本、重复响应头、`content`、`text`、`json()` |
| 连接复用 | 已实测 | `Session` 每个源站保留一个空闲连接，失效时安全重连 |
| 证书验证 | 已实测 | 默认 certifi、指定 PEM、显式 `verify=False` 警告 |
| TLS 指纹证据 | 部分通过 | 烟雾样本相符；正式黄金样本门槛未完成 |
| Linux / manylinux | 未验证 | 当前真实 NSS shim 仍为 Windows 专用 |
| HTTP/2、代理、重定向、Cookie | 未实现 | 不应按 Requests 的完整替代品使用 |

## 实现范围与架构

当前唯一可选档案是 `impersonate="firefox_152"`。版本、官方源文件和 Windows NSS DLL 的大小及 SHA-256 均由锁文件固定；运行时只能从显式目录加载，不会在导入 Python 包或发请求时下载工具。

```text
Python foxreq API
    -> 每个 Session 的 PyO3 Rust 工作线程
    -> Rust HTTPS/1.1 客户端与连接复用
    -> C11 NSS shim
    -> 哈希锁定的 Firefox 152 NSS/NSPR DLL
```

Python 层负责 URL、参数、请求头、正文、超时与 PEM 信任锚规范化；Rust 层负责截止时间、请求序列化、响应分帧及连接状态；C 层只暴露经过审计的 NSS 生命周期和 I/O ABI。详细档案状态见 [Firefox 152 profile](profiles/firefox_152/README.md)。

## Python 安装

当前尚无 PyPI 包或正式发布的预编译 wheel，需要在 Windows x86-64 源码构建。先准备 Python 3.10+、Rust 1.88.0 MSVC、Visual Studio C++ Build Tools、CMake、Ninja 与 maturin；完整版本和来源要求见 [构建说明](docs/building.md)。

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install "maturin>=1,<2"
$env:CARGO_BUILD_JOBS = "1"
$env:PYTHONUTF8 = "1"
.\.venv\Scripts\python.exe -m maturin build --release --out dist
$wheel = Get-ChildItem dist -Filter "foxreq-*.whl" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
.\.venv\Scripts\python.exe -m pip install --force-reinstall --no-deps $wheel.FullName
```

`certifi` 是运行时依赖。构建 wheel 后若使用 `--no-deps` 安装，应在受控环境中另行安装 `certifi>=2025.8.3,<2027`。

## Firefox NSS 运行时

从官方 Mozilla 归档获取锁定的 Firefox 152.0.6 Windows x86-64 en-US 安装包后，先验证来源，再提取最小运行时。脚本会核对安装包及每个 DLL 的大小和 SHA-256，目标目录已存在时会失败而不是覆盖。

```powershell
python -m scripts.provenance.fetch_sources --lock third_party/native-sources.lock.json --cache .cache/sources --id firefox-windows-x86_64-en-us
python -m scripts.runtime.prepare_firefox_runtime --installer .cache/sources/firefox-152.0.6-windows-x86_64-en-us.exe --output .cache/firefox-runtime/core
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
    params=(("item", "one"), ("item", "two")),
    headers=(("X-Test", "first"), ("X-Test", "second")),
    timeout=10.0,
    verify=Path("artifacts/fixtures/certs/local/ca.pem"),
)

print(response.status_code)
print(response.http_version)
print(response.text)
```

顶层函数会为单次请求创建并关闭一个短生命周期 Session。对同一源站连续请求时，应显式复用 Session：

```python
from pathlib import Path

import foxreq

with foxreq.Session(
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

`verify=True` 使用 certifi 信任包；`verify="path/to/ca.pem"` 使用指定 PEM；`verify=False` 会发出 `InsecureRequestWarning`，不应出现在成功路径示例或常规测试中。一个 Session 的信任锚与 TLS 档案在构造后固定，切换 CA 应创建新的 Session。

可执行且经过真实回环测试的示例：

- [examples/python_basic.py](examples/python_basic.py)：顶层 GET 与 JSON POST。
- [examples/python_session.py](examples/python_session.py)：同一连接上的两个 Session 请求。

```powershell
.\.venv\Scripts\python.exe examples/python_basic.py --url https://127.0.0.1:8443/basic --runtime .cache/firefox-runtime/core --ca-pem artifacts/fixtures/certs/local/ca.pem
.\.venv\Scripts\python.exe examples/python_session.py --origin https://127.0.0.1:8443 --runtime .cache/firefox-runtime/core --ca-pem artifacts/fixtures/certs/local/ca.pem
```

示例只输出状态码、HTTP 版本和响应体长度，不输出请求头、Cookie 或响应正文。

## 串行验证

验证入口在运行任何重任务前检查 Python 版本和可用物理内存。可用内存低于 4096 MiB 时直接退出；所有 Cargo、CMake、C 与 Python 步骤依次运行，且强制 `CARGO_BUILD_JOBS=1`。它不会执行压测。

```powershell
$env:FOXREQ_NSS_RUNTIME_DIR = (Resolve-Path .cache/firefox-runtime/core).Path
$env:CARGO_BUILD_JOBS = "1"
.\scripts\verify_python.ps1
```

验证包括 Rust 格式化、Clippy、非压力单元测试、C stub ABI、真实 NSS 回环 TLS/HTTP/1.1、完整 Python API/示例/文档测试、依赖检查、`git diff --check` 与已跟踪文件敏感标记扫描。测试证书、私钥、wheel、抓包及临时运行时均位于 `.gitignore` 覆盖的路径。

## 指纹证据等级

合成测试只能证明解析器和比较器行为，不能标记为 Firefox 黄金证据。当前 Windows 烟雾样本覆盖 ClientHello 结构、JA3/JA4、密码套件、扩展顺序、supported groups、signature schemes、ALPN、key share 形状、证书压缩算法和 ECH 长度；样本量不足以满足正式门槛。

正式结论需要 100 次冷连接 Firefox 样本、至少 2 次恢复连接样本，以及每种 foxreq 模式 5 个样本全部通过冻结比较。证据采集、归一化规则与禁入数据见 [指纹证据工作流](docs/fingerprint-evidence.md)。

## 平台限制与 Linux 审计

Windows x86-64 是当前唯一完成真实后端验证的平台。C shim 使用 Windows 动态库加载和网络接口，不能据此宣称 Linux 原生兼容。

2026-07-15 对授权 CentOS 7 主机进行了只读环境审计：glibc 2.17、Python 3.9.13、约 3.77 GiB 物理内存，且未检测到 Rust/CMake。该 Python 版本低于 foxreq 的 Python 3.10+ 下限，可用内存也不足 4 GiB 验证门槛，因此未安装软件、未构建、未运行原生或压力测试。Linux 状态保持“未验证”。

## 目录结构

```text
crates/foxreq-core/   Rust HTTPS/1.1、传输抽象与 NSS 适配
crates/foxreq-py/     PyO3 原生模块和 Session 工作线程
python/foxreq/        Python 公共 API、规范化、模型与异常
native/nss-shim/      C11 NSS ABI、stub 与 Windows 真实后端
profiles/firefox_152/ Firefox 152 档案与证据状态
tools/fingerprint/    TLS/HTTP/2 证据解析和比较开发工具
tests/                Rust、Python、C 与本地 TLS fixture
examples/             可执行 Python API 示例
scripts/              来源、运行时、抓取与串行验证入口
docs/                 构建和证据说明
third_party/           锁文件、补丁说明与第三方通知
```

## 路线图

1. 完成 Firefox 冷连接与恢复连接正式证据门槛，冻结可复现的指纹档案。
2. 设计并审查 POSIX NSS 加载、socket 与 manylinux_2_17 构建边界。
3. 在满足 Python 3.10+ 和 4 GiB 内存门槛的隔离 Linux 环境中验证 wheel。
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
