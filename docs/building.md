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

Windows 真实后端支持两个相互隔离的 Runtime：Firefox 140.12.0esr（NSS 3.112.5 / NSPR 4.36.2）和 Firefox 152.0.6（NSS 3.124 / NSPR 4.39）。`third_party/firefox-windows-firefox_140_esr.lock.json` 与 `third_party/firefox-windows-runtime.lock.json` 固定官方来源、Firefox build ID、NSS/NSPR 版本及最小 DLL 集；两个目录不能交叉复用。

```powershell
python -m scripts.runtime.prepare_firefox_runtime `
  --profile firefox_140_esr `
  --platform windows-x86_64 `
  --artifact path\to\Firefox_Setup_140.12.0esr.exe `
  --lock third_party/firefox-windows-firefox_140_esr.lock.json `
  --output .cache/firefox-runtime/firefox_140_esr/core

python -m scripts.runtime.prepare_firefox_runtime `
  --profile firefox_152 `
  --platform windows-x86_64 `
  --artifact path\to\Firefox_Setup_152.0.6.exe `
  --lock third_party/firefox-windows-runtime.lock.json `
  --output .cache/firefox-runtime/core
```

准备脚本使用 Mozilla 安装器的 `/ExtractDir` 模式，不安装 Firefox。安装包和复制出的每个 DLL 均通过大小与 SHA-256 校验；输出目录已存在时失败，不会静默覆盖。

```powershell
$env:FOXREQ_NSS_RUNTIME_DIR = (Resolve-Path .cache/firefox-runtime/core).Path
$env:FOXREQ_RUNTIME_FIREFOX_140_ESR = `
  (Resolve-Path .cache/firefox-runtime/firefox_140_esr/core).Path
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
- `target/`、`build/`、`dist/`、`.venv/`、`.venv312/`；
- TLS key log、真实 Cookie、Authorization 值与用户流量。

## Firefox 指纹范围

Firefox 140 ESR 与 152 档案都按各自浏览器证据配置 TLS 参数，并按 Firefox 顺序声明 zlib、Brotli、Zstandard TLS 证书压缩算法。解码输出受 NSS 提供缓冲区约束，C 到 Rust 回调会捕获错误和 panic。纯 Rust 解码依赖固定在 `Cargo.lock` 中。

Firefox 140 ESR 的 Windows 正式比较已使用 100 个有效浏览器冷连接、2 个有效恢复连接，以及 foxreq 的 5 个冷连接和 5 个恢复连接完成，扩展顺序、稳定字段、长度、JA3 与 JA4 均无差异。Firefox 152 仍只有少量烟雾证据，正式比较同样要求上述样本门槛；不能用合成 fixture 或少量烟雾测试替代。详见 `docs/fingerprint-evidence.md` 与两个 `profiles/` 档案说明。

## Linux 基线与当前状态

目标基线是 Linux x86-64、glibc 2.17、Python 3.10+、Rust 1.88.0、C11 编译器、CMake 3.24+、Ninja，以及经来源验证的 NSS/NSPR 构建输入。工具链只读检查入口为：

```sh
./scripts/check_toolchain.sh
```

真实 NSS shim 已拆分为平台窄接口。Windows 使用安全的 DLL 加载与 WinSock；Linux 使用 `dlopen`/`dlsym`、POSIX socket、`poll`、`pthread` 和 `clock_gettime`。`third_party/firefox-linux-firefox_140_esr.lock.json` 与 `third_party/firefox-linux-firefox_152.lock.json` 固定 Mozilla 官方 Linux 归档和最小 NSS/NSPR 文件集。

授权 CentOS 7 主机上已经完成 GCC 4.8.5 的 C11 严格语法检查，以及两个 Runtime 的有限加载/版本探测烟雾测试：Firefox 140 ESR 对应 NSS 3.112.5 / NSPR 4.36.2，Firefox 152 对应 NSS 3.124 / NSPR 4.39。该主机仍只有 Python 3.9.13、约 3.77 GiB 物理内存，且未安装 Rust/CMake，不满足 Python 3.10+ 与 4096 MiB 可用内存门槛，因此没有构建或安装 manylinux wheel，也没有运行 Linux Python API 完整验证或压测。

Linux 完整入口会失败关闭，必须在符合基线的隔离环境中提供两个 Runtime、短期本地证书及待检 wheel 后串行执行：

```sh
export FOXREQ_RUNTIME_FIREFOX_140_ESR=/path/to/firefox_140_esr/core
export FOXREQ_NSS_RUNTIME_DIR=/path/to/firefox_152/core
export FOXREQ_PY_TEST_FIXTURE=/path/to/local/certificate-fixture
export FOXREQ_LINUX_WHEEL=/path/to/foxreq-cp310-abi3-manylinux_2_17_x86_64.whl
./scripts/verify_python.sh
```

在该入口完整通过前，Linux 状态只能标记为“C 后端初步兼容”，不能作为正式平台支持承诺。

## 当前原生边界

`FOXREQ_NSS_STUB=ON` 产生确定性 fake backend。Rust `nss` 特性用于测试 runtime、connection、session cache、byte buffer、partial I/O、错误复制和关闭语义。

`nss-real` 只从显式目录加载哈希锁定的 Firefox 运行时。Windows 上两个档案的生命周期、ALPN、证书、deadline、HTTP/HTTPS 1.1 与 Python API 本地 fixture 测试已通过；Linux 只通过 C 编译和 Runtime 加载/版本探测烟雾测试。低样本量线级烟雾比较、平台运行测试与正式 Firefox 黄金门槛相互独立，任何一项都不能替代另一项。
