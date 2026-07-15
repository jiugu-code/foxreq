# foxreq 构建与验证说明

foxreq 使用固定 Rust 工具链、C11 NSS shim 和 PyO3/maturin 混合包。依赖下载、Firefox 获取和 wheel 构建都属于显式开发操作；导入 `foxreq` 或发送请求不会自动下载或执行构建工具。

## Windows 开发基线

- Windows x86-64；
- Rust `1.88.0-x86_64-pc-windows-msvc`，包含 rustfmt 与 Clippy；
- Visual Studio 2022 Build Tools、x64 C++ 工具集和 Windows SDK；
- CMake 3.24+ 与 Ninja 1.11+；
- Python 3.10+；
- maturin 1.x。

首台验证机器使用 Visual Studio Build Tools 17.14.35、CMake 4.4.0、Ninja 1.11.1。这些只是开发环境观测值，不是 Python 包运行时依赖。

从普通 PowerShell 运行失败关闭的工具链检查：

```powershell
& .\scripts\check_toolchain.ps1
```

## 准备锁定的 Firefox NSS 运行时

Windows 真实后端只加载 Firefox 152.0.6 Windows x86-64 en-US 安装包中随附的 NSS/NSPR DLL。`third_party/native-sources.lock.json` 固定官方 HTTPS 地址、文件大小与 SHA-256；`third_party/firefox-windows-runtime.lock.json` 固定 Firefox build ID、NSS/NSPR 版本及最小 DLL 集。

```powershell
python -m scripts.provenance.fetch_sources `
  --lock third_party/native-sources.lock.json `
  --cache .cache/sources `
  --id firefox-windows-x86_64-en-us

python -m scripts.runtime.prepare_firefox_runtime `
  --installer .cache/sources/firefox-152.0.6-windows-x86_64-en-us.exe `
  --output .cache/firefox-runtime/core
```

准备脚本使用 Mozilla 安装器的 `/ExtractDir` 模式，不安装 Firefox。安装包和复制出的每个 DLL 均通过大小与 SHA-256 校验；输出目录已存在时失败，不会静默覆盖。

```powershell
$env:FOXREQ_NSS_RUNTIME_DIR = (Resolve-Path .cache/firefox-runtime/core).Path
```

## 构建 Python wheel

使用仓库本地虚拟环境，避免修改系统 Python。`abi3-py310` 表示包最低支持 Python 3.10；不能为了适配 Python 3.8/3.9 主机而降低该下限。

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install "maturin>=1,<2" "certifi>=2025.8.3,<2027" "cryptography>=41"

$env:CARGO_BUILD_JOBS = "1"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
.\.venv\Scripts\python.exe -m maturin build --release --out dist

$wheel = Get-ChildItem dist -Filter "foxreq-*.whl" |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1
.\.venv\Scripts\python.exe -m pip install --force-reinstall --no-deps $wheel.FullName
.\.venv\Scripts\python.exe -m pip check
```

中文路径下如果 maturin 的 pip 探测出现控制台编码问题，应保留 `PYTHONUTF8=1` 和 `PYTHONIOENCODING=utf-8`。本项目验证流程使用 `maturin build` 后安装 wheel，不依赖 `maturin develop`。

`cryptography` 只用于生成短期本地测试 CA 和服务器证书，列在 `project.optional-dependencies.test` 中，不属于 foxreq 发请求时的运行时依赖。

## Native stub 与 C ABI

stub 后端只用于 ABI、所有权和错误路径测试，不打开 socket、不执行 TLS，也不产生 Firefox 指纹。

```powershell
cmake -S native/nss-shim -B build/nss-shim-fake -G Ninja `
  -DFOXREQ_NSS_STUB=ON -DBUILD_TESTING=ON
cmake --build build/nss-shim-fake --parallel 1
ctest --test-dir build/nss-shim-fake --output-on-failure
```

不得把 stub 通过解释为真实请求后端通过。

## 串行测试

真实测试只连接本机回环服务，短期证书只生成到忽略的 `artifacts/fixtures/certs`。验证期间保持 `CARGO_BUILD_JOBS=1`，不同时运行 Cargo、CMake、Firefox 或多个 Python 测试进程。

建议使用统一入口：

```powershell
$env:FOXREQ_NSS_RUNTIME_DIR = (Resolve-Path .cache/firefox-runtime/core).Path
$env:CARGO_BUILD_JOBS = "1"
.\scripts\verify_python.ps1
```

统一入口会先检查 Python 3.10+ 与可用物理内存；低于 4096 MiB 时在重任务前退出。它依次执行：

1. Rust 格式与 Clippy；
2. `foxreq-core` 非默认特性测试和 `foxreq-py` 单元测试；
3. native stub 配置、单作业构建与 CTest；
4. 真实 Firefox NSS TLS/HTTP/1.1 回环编排；
5. Python 单元、真实 API、示例和文档测试；
6. pip 依赖、Git 差异与已跟踪文件敏感标记检查。

如需单独复核真实后端：

```powershell
$env:FOXREQ_NSS_RUNTIME_DIR = (Resolve-Path .cache/firefox-runtime/core).Path
$env:CARGO_BUILD_JOBS = "1"
.\.venv\Scripts\python.exe -m scripts.runtime.test_real_tls `
  --runtime .cache/firefox-runtime/core `
  --python-api .venv/Scripts/python.exe
```

该编排器为每个场景启动有限次数的回环 server/client 对并逐一等待结束，不执行并发压测。

## 内存与产物管理

抓取和统一验证入口使用 4096 MiB 可用物理内存门槛。不要在共享工作站上降低门槛；先关闭由本项目启动且已确认无用的测试进程，而不是操作用户应用。

以下内容必须保持在忽略路径中：

- `.cache/` 下的官方安装包、Firefox 运行时和源缓存；
- `artifacts/` 下的短期证书、私钥、抓包、浏览器 profile 和测试输出；
- `target/`、`build/`、`dist/`、`.venv/`；
- TLS key log、真实 Cookie、Authorization 值与用户流量。

## Firefox 指纹范围

Firefox 152 档案按 Firefox 顺序声明 zlib、Brotli、Zstandard TLS 证书压缩算法。解码输出受 NSS 提供缓冲区约束，C 到 Rust 回调会捕获错误和 panic。纯 Rust 解码依赖固定在 `Cargo.lock` 中。

当前 Windows 少量冷连接/恢复连接样本只属于部分证据。正式比较需要 100 个冷连接 Firefox 样本、至少 2 个恢复连接 Firefox 样本，以及每种 foxreq 模式 5 个样本；不能用合成 fixture 或少量烟雾测试替代。详见 `docs/fingerprint-evidence.md` 与 `profiles/firefox_152/README.md`。

## Linux 基线与当前状态

目标基线是 Linux x86-64、glibc 2.17、Python 3.10+、Rust 1.88.0、C11 编译器、CMake 3.24+、Ninja，以及经来源验证的 NSS/NSPR 构建输入。工具链只读检查入口为：

```sh
./scripts/check_toolchain.sh
```

但当前真实 NSS shim 直接使用 Windows DLL 加载、WinSock 与系统库，尚未实现 POSIX 后端，也尚未生成或验证 manylinux_2_17 wheel。因此 Linux 只能标记为“目标/未验证”，不能标记为支持。

2026-07-15 对授权 CentOS 7 主机的只读审计显示：glibc 2.17、Python 3.9.13、约 3.77 GiB 物理内存，未检测到 Rust/CMake。该环境低于 Python 和内存门槛，本阶段不安装依赖、不构建 NSS、不运行原生测试或压力测试。

## 当前原生边界

`FOXREQ_NSS_STUB=ON` 产生确定性 fake backend。Rust `nss` 特性用于测试 runtime、connection、session cache、byte buffer、partial I/O、错误复制和关闭语义。

`nss-real` 只从显式目录加载哈希锁定的 Firefox 运行时。Windows 上的生命周期、ALPN、证书、deadline、HTTPS/1.1 与 Python API 本地 fixture 测试已通过；Linux 原生后端未通过。低样本量线级烟雾比较与 100 次 Firefox 黄金门槛相互独立，前者不能将后者标记为完成。
