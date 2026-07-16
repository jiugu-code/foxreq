# foxreq Multi-Profile HTTP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 foxreq 核心库和 Python API 交付跨 Windows/Linux 的原生 HTTP/1.1，以及经真实运行时和浏览器样本验证的 `firefox_140_esr` 与 `firefox_152` HTTPS 档案。

**Architecture:** 明文 HTTP 在父进程使用 Rust `TcpConnector`；HTTPS 由每个 Python `Session` 延迟启动一个档案专用子进程，以隔离不同 NSS/NSPR 版本。Python 层在保留重复请求头和顺序的同时注入缺失的档案 User-Agent；运行时文件依平台和档案做哈希锁定。

**Tech Stack:** Rust 1.88.0、C11、NSS/NSPR、PyO3 abi3-py310、Python 3.10+、CMake/Ninja/MSVC、manylinux2014/glibc 2.17、`unittest`。

## Global Constraints

- 只修改核心库、Python API、档案、运行时工具、测试和正式文档；不修改、暂存或提交 `examples/fastapi_service.py`、`tests/python/test_fastapi_service.py` 和本地修改的 `docs/fastapi-service-design.md`。
- 使用隔离 worktree/feature branch，不直接在当前脏 `master` 工作区开发。
- `firefox_152` 继续默认；新档案 ID 仅为 `firefox_140_esr`。
- `firefox_140_esr` 精确对应 Firefox 140.12.0esr；`firefox_152` 精确对应 Firefox 152.0.6、NSS 3.124、NSPR 4.39。
- 不用 Firefox 152 运行时或参数冒充 Firefox 140 ESR。
- 纯 HTTP 不要求 NSS Runtime，不做证书校验，不发出 `InsecureRequestWarning`。
- 缺失大小写不敏感的 `User-Agent` 时，按档案和平台注入默认值；已传入时不改写。
- Linux 最低边界为 x86-64、glibc 2.17 / manylinux2014；Python 保持 3.10+ 和 abi3-py310。
- Windows 和 `my-centos` 全部串行；Cargo 使用 `-j 1`，不压测，不并行启动浏览器或构建。
- 不提交 Firefox/NSS 二进制、wheel、运行时、浏览器、私钥、抓包或临时证书。
- 只有 Windows 和 Linux 真实浏览器/foxreq TLS 证据门槛均通过后才宣称支持。
- 每个任务先看到针对新行为的测试按预期失败，再写生产代码。
- Git 暂存使用精确路径；每次提交前运行 `git diff --cached --check` 和 `git diff --cached --name-only`。

---

### Task 1: 档案注册表、User-Agent 与双 scheme 规范化

**Files:**
- Create: `python/foxreq/_profiles.py`
- Create: `tests/python/test_profiles.py`
- Modify: `python/foxreq/_normalize.py`
- Modify: `tests/python/test_normalize.py`
- Modify: `crates/foxreq-core/src/http1/client/url.rs`
- Modify: `crates/foxreq-core/src/http1/client.rs`
- Modify: `crates/foxreq-core/src/transport.rs`
- Modify: `crates/foxreq-core/tests/http1_client.rs`

**Interfaces:**
- Produces: `ProfileSpec` and `get_profile(profile_id, platform=None) -> ProfileSpec`.
- Produces: `Scheme::{Http,Https}` and `ParsedUrl.scheme` for later transports.
- Produces: `NormalizedRequest.scheme: str` and default User-Agent injection.

- [ ] **Step 1: Write failing Python tests**

Create `tests/python/test_profiles.py`:

```python
import unittest

from foxreq._exceptions import InvalidRequestError
from foxreq._profiles import get_profile


class ProfileTests(unittest.TestCase):
    def test_exact_profiles_and_platform_user_agents(self):
        windows = get_profile("firefox_140_esr", platform="win32")
        linux = get_profile("firefox_152", platform="linux")
        self.assertEqual(windows.firefox_version, "140.12.0esr")
        self.assertIn("Windows NT 10.0; Win64; x64", windows.user_agent)
        self.assertTrue(windows.user_agent.endswith("Firefox/140.0"))
        self.assertIn("X11; Linux x86_64", linux.user_agent)
        self.assertTrue(linux.user_agent.endswith("Firefox/152.0"))

    def test_rejects_unknown_profile_and_platform(self):
        with self.assertRaises(InvalidRequestError):
            get_profile("firefox_latest", platform="win32")
        with self.assertRaises(InvalidRequestError):
            get_profile("firefox_152", platform="darwin")
```

Add to `tests/python/test_normalize.py`:

```python
def test_http_and_default_user_agent(self):
    automatic = normalize_request(
        "GET", "http://example.test/path", None, None, None, None, 1,
        "firefox_140_esr",
    )
    self.assertEqual(automatic.scheme, "http")
    self.assertEqual(automatic.headers[0][0], b"User-Agent")
    self.assertIn(b"Firefox/140.0", automatic.headers[0][1])

    supplied = normalize_request(
        "GET", "https://example.test/", None,
        (("uSeR-aGeNt", "custom"), ("X-Order", "first")),
        None, None, 1, "firefox_152",
    )
    self.assertEqual(
        supplied.headers,
        ((b"uSeR-aGeNt", b"custom"), (b"X-Order", b"first")),
    )
```

- [ ] **Step 2: Verify Python red state**

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.python.test_profiles tests.python.test_normalize -v
```

Expected: import failure for `foxreq._profiles` and current HTTP rejection.

- [ ] **Step 3: Implement Python profiles and normalization**

Create `_profiles.py` with this complete registry shape:

```python
from dataclasses import dataclass
import sys

from ._exceptions import InvalidRequestError


@dataclass(frozen=True, slots=True)
class ProfileSpec:
    profile_id: str
    firefox_version: str
    major_version: int
    user_agent: str


_VERSIONS = {
    "firefox_140_esr": ("140.12.0esr", 140),
    "firefox_152": ("152.0.6", 152),
}


def get_profile(profile_id, platform=None):
    try:
        firefox_version, major = _VERSIONS[profile_id]
    except (KeyError, TypeError) as error:
        raise InvalidRequestError("unsupported Firefox profile") from error
    selected = sys.platform if platform is None else platform
    if selected == "win32":
        token = "Windows NT 10.0; Win64; x64"
    elif selected.startswith("linux"):
        token = "X11; Linux x86_64"
    else:
        raise InvalidRequestError("unsupported profile platform")
    ua = "Mozilla/5.0 ({}; rv:{}.0) Gecko/20100101 Firefox/{}.0".format(
        token, major, major
    )
    return ProfileSpec(profile_id, firefox_version, major, ua)
```

Make `normalize_profile()` call `get_profile()`. Make URL normalization accept only `http` and `https`, preserve the normalized scheme, and add `scheme` to `NormalizedRequest`. Prepend the encoded profile User-Agent only if no normalized header name folds to `b"user-agent"`.

- [ ] **Step 4: Run Python tests to green**

Run the Step 2 command. Expected: all selected tests pass.

- [ ] **Step 5: Write and run failing Rust scheme tests**

Record `ConnectTarget` values in the scripted connector, then assert HTTP maps to `Scheme::Http`/80 and HTTPS maps to `Scheme::Https`/443. Run:

```powershell
cargo test -p foxreq-core --test http1_client parses_http_and_https_with_distinct_schemes_and_ports -j 1
```

Expected: compile failure because `Scheme` and `ConnectTarget.scheme` do not exist.

- [ ] **Step 6: Implement Rust scheme parsing**

Add:

```rust
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Scheme {
    Http,
    Https,
}
```

Add `scheme` to `ConnectTarget` and `Origin`. Replace `parse_https_url()` with `parse_url()` accepting exact ASCII `http://`/`https://`, applying ports 80/443, and preserving all current authority, percent-encoding, userinfo and fragment checks. Accept exactly the two profile IDs before connecting.

- [ ] **Step 7: Verify and commit Task 1**

```powershell
cargo fmt --all -- --check
cargo test -p foxreq-core --tests -j 1
.\.venv\Scripts\python.exe -m unittest tests.python.test_profiles tests.python.test_normalize -v
git add -- python/foxreq/_profiles.py python/foxreq/_normalize.py tests/python/test_profiles.py tests/python/test_normalize.py crates/foxreq-core/src/http1/client/url.rs crates/foxreq-core/src/http1/client.rs crates/foxreq-core/src/transport.rs crates/foxreq-core/tests/http1_client.rs
git diff --cached --check
git diff --cached --name-only
git commit -m "feat: add Firefox profiles and dual-scheme URLs"
```

---

### Task 2: Cross-platform Rust TCP transport and native HTTP session

**Files:**
- Create: `crates/foxreq-core/src/tcp.rs`
- Create: `crates/foxreq-core/tests/http_plain.rs`
- Modify: `crates/foxreq-core/src/lib.rs`
- Modify: `crates/foxreq-core/src/transport.rs`
- Modify: `crates/foxreq-py/src/worker.rs`
- Modify: `crates/foxreq-py/src/lib.rs`

**Interfaces:**
- Produces: `TcpConnector::new()` implementing `Connector` for `Scheme::Http` only.
- Produces: `_foxreq.NativeHttpSession(profile_id)` with native response and close contracts matching `NativeSession`.

- [ ] **Step 1: Write a failing Rust loopback test**

Create a `TcpListener` test that asserts `GET /plain HTTP/1.1`, exact Host, two ordered `X-Order` headers, then returns duplicate `Set-Cookie` and `OK`. Client construction must use:

```rust
let mut client = Http1Client::new(TcpConnector::new());
let response = client.execute(ClientRequest {
    method: b"GET".to_vec(),
    url: format!("http://127.0.0.1:{port}/plain"),
    headers: vec![
        OwnedHeader::new(b"X-Order", b"first"),
        OwnedHeader::new(b"X-Order", b"second"),
    ],
    body: Vec::new(),
    timeout: Duration::from_secs(2),
    verification: VerificationMode::Default,
    profile_id: "firefox_152".to_owned(),
})?;
assert_eq!(response.body, b"OK");
```

Run `cargo test -p foxreq-core --test http_plain -j 1`. Expected: missing `TcpConnector` compile failure.

- [ ] **Step 2: Implement `TcpConnector` and `TcpTransport`**

Use `std::net::{Shutdown, TcpStream, ToSocketAddrs}`. Subtract DNS elapsed time before `connect_timeout`; map `TimedOut`/`WouldBlock` to `Timeout`, other I/O to `Io`; set `TCP_NODELAY`; apply read/write timeouts per call; treat `NotConnected` during shutdown as success. Reject `Scheme::Https` before DNS. Export `pub mod tcp;` and keep `#![deny(unsafe_code)]`.

- [ ] **Step 3: Write failing PyO3 tests and implement the plain backend**

Add tests that construct `NativeHttpSession("firefox_140_esr")` and reject `firefox_latest`. Add `PlainBackend { client: Http1Client<TcpConnector> }`, `WorkerHandle::spawn_plain()`, and:

```rust
#[pyclass(module = "foxreq._foxreq")]
struct NativeHttpSession {
    worker: WorkerHandle,
    profile_id: String,
}
```

Its request always sets `insecure: false`. Export it from `_foxreq()`.

- [ ] **Step 4: Verify and commit Task 2**

```powershell
cargo fmt --all -- --check
cargo test --workspace -j 1
cargo clippy --workspace --all-targets -- -D warnings
git add -- crates/foxreq-core/src/tcp.rs crates/foxreq-core/tests/http_plain.rs crates/foxreq-core/src/lib.rs crates/foxreq-core/src/transport.rs crates/foxreq-py/src/worker.rs crates/foxreq-py/src/lib.rs
git diff --cached --check
git diff --cached --name-only
git commit -m "feat: add native cross-platform HTTP transport"
```

---

### Task 3: Python HTTP routing and real HTTP integration

**Files:**
- Modify: `python/foxreq/_api.py`
- Modify: `tests/python/test_api.py`
- Create: `tests/python/test_real_http.py`
- Modify: `tests/fixtures/http1_scenarios.py`

**Interfaces:**
- Consumes: `_foxreq.NativeHttpSession(profile_id)`.
- Produces: lazy `Session._http` and `Session._https` paths while preserving public signatures.

- [ ] **Step 1: Write failing Python routing tests**

Add a fake HTTP native session and this contract:

```python
def test_http_needs_no_runtime_or_insecure_warning(self):
    with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
        api._foxreq, "NativeHttpSession", FakeNativeHttpSession
    ), mock.patch.object(api._foxreq, "NativeSession", FakeNativeSession):
        with api.Session(impersonate="firefox_140_esr") as session:
            response = session.get("http://example.test/plain", verify=False)
    self.assertEqual(response.status_code, 200)
    self.assertEqual(FakeNativeHttpSession.created, 1)
    self.assertEqual(FakeNativeSession.created, 0)
```

Also assert two HTTP calls reuse one native HTTP session, HTTPS resolves runtime/CA lazily, and closed sessions reject both schemes. Run `python -m unittest tests.python.test_api -v`; expected: eager runtime resolution or wrong native backend failure.

- [ ] **Step 2: Implement scheme routing and lazy TLS policy**

Store raw runtime/verify inputs in `Session.__init__`, plus `_http = None` and `_https = None`. Normalize before routing:

```python
if normalized.scheme == "http":
    native = self._http_session()
    insecure = False
else:
    native, policy = self._https_session()
    insecure = self._resolve_request_verify(verify, policy).insecure
```

Construct each backend once and close each exactly once. Emit `InsecureRequestWarning` only for HTTPS.

- [ ] **Step 3: Add real plain fixture mode and integration test**

Add `--plain` to `tests.fixtures.http1_scenarios`; skip `SSLContext` only in that mode and reuse the existing parser/response loop. Create `test_real_http.py` that runs with all Runtime variables absent, sends GET and JSON POST, verifies ordered duplicates, duplicate response headers, body, timeout mapping and keep-alive reuse.

- [ ] **Step 4: Verify and commit Task 3**

```powershell
.\.venv\Scripts\python.exe -W error::ResourceWarning -m unittest tests.python.test_api tests.python.test_real_http -v
.\.venv\Scripts\python.exe -W error::ResourceWarning -m unittest discover -s tests\python -t . -v
git add -- python/foxreq/_api.py tests/python/test_api.py tests/python/test_real_http.py tests/fixtures/http1_scenarios.py
git diff --cached --check
git diff --cached --name-only
git commit -m "feat: expose HTTP through the Python API"
```

---

### Task 4: Length-bounded HTTPS profile worker

**Files:**
- Create: `python/foxreq/_ipc.py`
- Create: `python/foxreq/_profile_worker.py`
- Create: `python/foxreq/_worker_session.py`
- Create: `tests/python/test_ipc.py`
- Create: `tests/python/test_worker_session.py`
- Modify: `python/foxreq/_api.py`
- Modify: `python/foxreq/_exceptions.py`
- Modify: `python/foxreq/__init__.py`
- Modify: `tests/python/test_exceptions.py`

**Interfaces:**
- Produces: `ProfileWorkerSession(runtime_dir, anchors, profile_id)` with `request(...)` and `close()` matching the native session contract.
- Produces: `WorkerError(FoxreqError)`.
- Produces: `write_frame(stream, metadata, body)` and `read_frame(stream, max_metadata, max_body)`.

- [ ] **Step 1: Write failing IPC tests**

Create `tests/python/test_ipc.py` using `io.BytesIO` and a wrapper returning at most three bytes per read. Test round-trip metadata/raw body, metadata above 1 MiB, body above 16 MiB, truncation and invalid UTF-8/JSON:

```python
buffer = io.BytesIO()
write_frame(buffer, {"kind": "request", "id": 7}, b"\x00body")
buffer.seek(0)
metadata, body = read_frame(buffer, 1024 * 1024, 16 * 1024 * 1024)
self.assertEqual(metadata, {"kind": "request", "id": 7})
self.assertEqual(body, b"\x00body")
```

Run `python -m unittest tests.python.test_ipc -v`. Expected: import failure for `_ipc` and `WorkerError`.

- [ ] **Step 2: Implement framing and stable exception**

Use an 8-byte network-order metadata length, canonical UTF-8 JSON metadata, an 8-byte network-order body length and exact loops. Validate lengths before allocation, require dict metadata and reject truncation. Add and export:

```python
class WorkerError(FoxreqError):
    """The isolated Firefox profile worker failed safely."""
```

- [ ] **Step 3: Write failing worker lifecycle tests**

Patch `subprocess.Popen` with a deterministic fake. Assert command prefix `sys.executable, "-I", "-m", "foxreq._profile_worker"`; Windows `CREATE_NO_WINDOW`; Linux child-only library path; ordered headers; idempotent close; truncated response/nonzero exit/timeout mapping; and termination of only the owned PID.

- [ ] **Step 4: Implement parent and child worker modules**

`ProfileWorkerSession` starts one child lazily using `stdin=PIPE`, `stdout=PIPE`, `stderr=DEVNULL`, `close_fds=True`, no shell and no `pickle`. Request metadata contains method, URL, ordered byte headers, timeout, insecure and profile; body is raw. The child creates one `_foxreq.NativeSession`, returns response frames or stable native error kind/message, and closes on an explicit close frame. Linux constructs the runtime library path before `exec`; Windows uses `CREATE_NO_WINDOW`.

- [ ] **Step 5: Route HTTPS through the worker and verify real Firefox 152**

Replace direct `_foxreq.NativeSession` use in `_api.py` with `ProfileWorkerSession`; keep `NativeHttpSession` in-process. Then run:

```powershell
$env:FOXREQ_RUNTIME_FIREFOX_152 = (Resolve-Path .cache\firefox-runtime\core).Path
$env:FOXREQ_PY_TEST_FIXTURE = (Resolve-Path artifacts\fixtures\certs\installed-smoke-20260716).Path
.\.venv\Scripts\python.exe -W error::ResourceWarning -m unittest tests.python.test_ipc tests.python.test_worker_session tests.python.test_real_api -v
.\.venv\Scripts\python.exe -W error::ResourceWarning -m unittest discover -s tests\python -t . -v
```

Expected: real HTTPS crosses a child process, all tests pass, and cleanup observes no owned worker.

- [ ] **Step 6: Commit Task 4**

```powershell
git add -- python/foxreq/_ipc.py python/foxreq/_profile_worker.py python/foxreq/_worker_session.py python/foxreq/_api.py python/foxreq/_exceptions.py python/foxreq/__init__.py tests/python/test_ipc.py tests/python/test_worker_session.py tests/python/test_exceptions.py
git diff --cached --check
git diff --cached --name-only
git commit -m "feat: isolate Firefox profile workers"
```

---

### Task 5: Profile/platform runtime manifests and safe preparation

**Files:**
- Create: `profiles/firefox_140_esr/profile.json`
- Create: `profiles/firefox_140_esr/README.md`
- Create: `python/foxreq/_runtime_manifest.py`
- Create: `python/foxreq/_runtime_locks.py`
- Create: `scripts/runtime/lock_firefox_release.py`
- Create: `tests/runtime/test_lock_firefox_release.py`
- Create: `tests/python/test_runtime_manifest.py`
- Modify: `scripts/runtime/prepare_firefox_runtime.py`
- Modify: `scripts/runtime/prepare_firefox_browser.py`
- Modify: `tests/runtime/test_prepare_firefox_runtime.py`
- Modify: `tests/runtime/test_prepare_firefox_browser.py`
- Modify: `python/foxreq/_worker_session.py`
- Modify: `crates/foxreq-core/build.rs`
- Modify: `native/nss-shim/CMakeLists.txt`
- Modify: `native/nss-shim/include/foxreq_nss.h`
- Modify: `native/nss-shim/src/runtime.c`
- Modify: `crates/foxreq-core/src/tls/mod.rs`
- Modify: `native/nss-shim/tests/test_abi.c`

**Interfaces:**
- Produces: schema-2 per-profile/platform locks and `validate_runtime(profile_id, runtime_dir, platform=None)`.
- Produces: C ABI runtime options containing `profile_id`; builds no longer require a local Runtime.

- [ ] **Step 1: Write failing manifest/extraction tests**

Test four identities (two profiles crossed with Windows/Linux), exact version matching, regular-file/hash enforcement and legacy Firefox 152 Windows lock compatibility. Construct Linux tar members for `../escape`, absolute path, symlink, hardlink and device; every unsafe member must fail before output creation. A safe tar copies only lock-listed files.

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.runtime.test_lock_firefox_release tests.runtime.test_prepare_firefox_runtime tests.runtime.test_prepare_firefox_browser tests.python.test_runtime_manifest -v
```

Expected: missing schema/modules and current Windows-only guards fail.

- [ ] **Step 2: Implement schema 2 and cross-platform preparation**

Schema fields are exactly:

```python
REQUIRED = (
    "schema_version", "profile", "platform", "source_id", "source_url",
    "source_size", "source_sha256", "source_sha512", "firefox_version",
    "firefox_build_id", "nss_version", "nspr_version", "files",
)
```

`files` is sorted `{filename,size,sha256}`. `lock_firefox_release.py` verifies Mozilla `SHA512SUMS`, extracts under ignored temporary storage, reads `application.ini`, probes NSS/NSPR and emits canonical JSON. It also deterministically regenerates `python/foxreq/_runtime_locks.py` from every tracked Firefox lock; `_runtime_manifest.py` reads only that embedded module at runtime, so an installed wheel never depends on the source-tree `third_party` directory. Tests compare each embedded record with its canonical JSON lock. Both preparation scripts select Windows installer or Linux tar handling, enforce cache-root containment and re-hash copied files.

- [ ] **Step 3: Remove build-time Runtime dependence and extend ABI**

Remove the `FOXREQ_NSS_RUNTIME_DIR` build assertion and `FindPinnedNSS.cmake` dependency. Validate embedded Python manifests before worker launch. Pass `profile_id` through `RuntimeConfig` and C runtime options; C verifies the exact loaded NSS/NSPR versions selected by that profile. Increment the C ABI version and update all size/layout/static assertions and C/Rust ABI tests.

- [ ] **Step 4: Verify and commit Task 5**

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests\runtime -t . -v
.\.venv\Scripts\python.exe -m unittest tests.python.test_runtime_manifest -v
cargo test -p foxreq-core --test nss_abi -j 1
cargo test --workspace -j 1
git add -- profiles/firefox_140_esr/profile.json profiles/firefox_140_esr/README.md python/foxreq/_runtime_manifest.py python/foxreq/_runtime_locks.py scripts/runtime/lock_firefox_release.py scripts/runtime/prepare_firefox_runtime.py scripts/runtime/prepare_firefox_browser.py tests/runtime/test_prepare_firefox_runtime.py tests/runtime/test_prepare_firefox_browser.py tests/runtime/test_lock_firefox_release.py tests/python/test_runtime_manifest.py python/foxreq/_worker_session.py crates/foxreq-core/build.rs native/nss-shim/CMakeLists.txt native/nss-shim/include/foxreq_nss.h native/nss-shim/src/runtime.c crates/foxreq-core/src/tls/mod.rs native/nss-shim/tests/test_abi.c
git diff --cached --check
git diff --cached --name-only
git commit -m "feat: add profile-specific runtime manifests"
```

---

### Task 6: Windows Firefox 140 ESR Runtime, TLS profile and evidence

**Files:**
- Create: `third_party/firefox-windows-firefox_140_esr.lock.json`
- Create: `profiles/firefox_140_esr/golden/schema.json`
- Modify: `python/foxreq/_runtime_locks.py`
- Modify: `profiles/firefox_140_esr/profile.json`
- Modify: `profiles/firefox_140_esr/README.md`
- Modify: `native/nss-shim/src/profile.c`
- Modify: `native/nss-shim/tests/test_profile.c`
- Modify: `tests/provenance/test_lock.py`
- Modify: `tests/wire/test_compare_profile.py`
- Modify: `tests/python/test_real_api.py`

**Interfaces:**
- Produces: exact Windows lock and C profile selected by `options->profile_id`.
- Produces: Windows evidence status consumed by final documentation.

- [ ] **Step 1: Download and lock the official artifact**

Download only the following to `.cache/firefox-downloads/firefox_140_esr/windows/`:

```text
https://archive.mozilla.org/pub/firefox/releases/140.12.0esr/win64/en-US/Firefox%20Setup%20140.12.0esr.exe
https://archive.mozilla.org/pub/firefox/releases/140.12.0esr/SHA512SUMS
```

Run `lock_firefox_release.py --profile firefox_140_esr --platform windows-x86_64`; the script must verify Mozilla SHA-512 before creating the lock. Never type artifact hashes manually.

- [ ] **Step 2: Prepare ignored Runtime/browser and prove identities**

```powershell
.\.venv\Scripts\python.exe -m scripts.runtime.prepare_firefox_runtime --profile firefox_140_esr --platform windows-x86_64 --artifact .cache\firefox-downloads\firefox_140_esr\windows\Firefox_Setup_140.12.0esr.exe --output .cache\firefox-runtime\firefox_140_esr\core
.\.venv\Scripts\python.exe -m scripts.runtime.prepare_firefox_browser --profile firefox_140_esr --platform windows-x86_64 --artifact .cache\firefox-downloads\firefox_140_esr\windows\Firefox_Setup_140.12.0esr.exe --output .cache\firefox-browser\firefox_140_esr\windows
```

Expected JSON: Firefox `140.12.0esr`, exact BuildID, NSS/NSPR matching the generated lock, and all copied hashes pass.

- [ ] **Step 3: Write failing profile/real API tests**

Add C tests for both IDs and unknown-ID rejection. Add a Python real test creating `Session(impersonate="firefox_140_esr", runtime_dir=runtime140)` and making one verified loopback HTTPS request. Run before the C branch; expected: invalid profile/TLS failure.

- [ ] **Step 4: Capture browser evidence and implement exact profile**

Capture the profile-declared sample count serially with the prepared browser into `artifacts/captures/firefox_140_esr/windows/browser/`. Configure only observed cipher order, signature schemes, groups, key shares, compression, ECH GREASE and NSS options in the `firefox_140_esr` C branch. Capture equal foxreq samples and run `tools.fingerprint.compare` plus `scripts.capture.compare_profile`.

Gate: version/ciphers/extensions/groups/key shares/signatures/ALPN/compression/GREASE rules all pass. If a required NSS API is absent, stop and keep the profile unsupported; never fall back to Firefox 152 behavior.

- [ ] **Step 5: Build the Windows wheel and run both profiles serially**

```powershell
$env:CARGO_BUILD_JOBS = '1'
.\.venv\Scripts\python.exe -m maturin build --release --out dist
.\.venv\Scripts\python.exe -m pip install --force-reinstall --no-deps (Get-ChildItem dist\foxreq-0.1.0-cp310-abi3-win_amd64.whl).FullName
$env:FOXREQ_RUNTIME_FIREFOX_140_ESR = (Resolve-Path .cache\firefox-runtime\firefox_140_esr\core).Path
$env:FOXREQ_RUNTIME_FIREFOX_152 = (Resolve-Path .cache\firefox-runtime\core).Path
$env:FOXREQ_PY_TEST_FIXTURE = (Resolve-Path artifacts\fixtures\certs\installed-smoke-20260716).Path
.\.venv\Scripts\python.exe -W error::ResourceWarning -m unittest tests.python.test_real_api -v
```

Expected: both profiles pass and no worker/browser/fixture remains.

- [ ] **Step 6: Commit Task 6**

```powershell
git add -- third_party/firefox-windows-firefox_140_esr.lock.json python/foxreq/_runtime_locks.py profiles/firefox_140_esr/golden/schema.json profiles/firefox_140_esr/profile.json profiles/firefox_140_esr/README.md native/nss-shim/src/profile.c native/nss-shim/tests/test_profile.c tests/provenance/test_lock.py tests/wire/test_compare_profile.py tests/python/test_real_api.py
git diff --cached --check
git diff --cached --name-only
git commit -m "feat: add verified Firefox 140 ESR profile on Windows"
```

---

### Task 7: Linux NSS port and manylinux wheel

**Files:**
- Create: `native/nss-shim/src/platform_runtime.h`
- Create: `native/nss-shim/src/platform_windows.c`
- Create: `native/nss-shim/src/platform_posix.c`
- Create: `native/nss-shim/src/platform_socket.h`
- Create: `native/nss-shim/src/socket_windows.c`
- Create: `native/nss-shim/src/socket_posix.c`
- Modify: `native/nss-shim/src/runtime.c`
- Modify: `native/nss-shim/src/connection.c`
- Modify: `native/nss-shim/src/foxreq_nss_real_internal.h`
- Modify: `native/nss-shim/CMakeLists.txt`
- Modify: `cmake/ToolchainPolicy.cmake`
- Modify: `crates/foxreq-core/build.rs`
- Create: `third_party/firefox-linux-firefox_140_esr.lock.json`
- Create: `third_party/firefox-linux-firefox_152.lock.json`
- Modify: `python/foxreq/_runtime_locks.py`
- Create: `scripts/verify_python.sh`
- Create: `tests/python/test_linux_contract.py`
- Modify: `tests/provenance/test_lock.py`
- Modify: `docs/building.md`

**Interfaces:**
- Produces: identical public C ABI on `_WIN32` and `__linux__`.
- Produces: x86_64 manylinux_2_17 abi3 wheel without bundled NSS.

- [ ] **Step 1: Write failing platform/wheel contract tests**

Add CMake tests proving Windows selects BCrypt/Winsock adapters and Linux selects `dl`/`pthread`/POSIX adapters. Create `test_linux_contract.py` that opens the wheel ZIP and asserts a `manylinux_2_17_x86_64` tag, no bundled NSS/NSPR `.so`, inclusion of `_profile_worker.py`, and both Linux manifest records in `_runtime_locks.py`.

- [ ] **Step 2: Inventory `my-centos` and verify current Linux red state**

Run read-only commands:

```bash
uname -a
getconf GNU_LIBC_VERSION
python3 --version
free -m
```

Then run `cargo check -p foxreq-core --features nss-real -j 1`. Expected: the current Windows-only build assertion and headers/libraries fail. Do not install or change system packages during this step.

- [ ] **Step 3: Split common C logic from platform adapters**

Keep trust installation, NSS symbol table, profile configuration and public ABI common. Move module loading, symbol lookup, mutex and path/file operations behind `platform_runtime.h`; move socket create/connect/close behind `platform_socket.h`. Linux uses `dlopen` with `RTLD_NOW | RTLD_LOCAL`, `dlsym`, `pthread_mutex`, `socket/connect/fcntl/poll/close`. Windows preserves `LoadLibraryExW`, BCrypt and Winsock. Both adapters return existing stable result categories and exclude host/path values from errors.

- [ ] **Step 4: Enable Linux Rust/C build**

Allow `x86_64-unknown-linux-gnu` in `build.rs`, select Ninja, link `dl` and `pthread`, and keep Windows libraries conditional. Apply `-std=c11 -Wall -Wextra -Wpedantic -Werror` on Linux. Build must not require a Runtime directory.

- [ ] **Step 5: Generate official Linux locks**

Download to ignored cache and verify using release `SHA512SUMS`:

```text
https://archive.mozilla.org/pub/firefox/releases/140.12.0esr/linux-x86_64/en-US/firefox-140.12.0esr.tar.xz
https://archive.mozilla.org/pub/firefox/releases/152.0.6/linux-x86_64/en-US/firefox-152.0.6.tar.xz
```

Run `lock_firefox_release.py` for `linux-x86_64`; commit only canonical lock JSON. Prepare both Runtime/browser directories below `.cache/` and verify BuildID/NSS/NSPR.

- [ ] **Step 6: Build manylinux serially without changing system Python**

Require an existing Python 3.10+ and Rust toolchain from the read-only inventory. If either is absent, stop, report the exact missing prerequisite and request authorization before installing anything. With prerequisites present, create an isolated environment at `/root/foxreq-env`; do not replace `/usr/bin/python`, yum ownership or alternatives. Run:

```bash
export CARGO_BUILD_JOBS=1
python -m maturin build --release --compatibility manylinux2014 --out dist
python -m pip install --force-reinstall --no-deps dist/foxreq-0.1.0-cp310-abi3-manylinux_2_17_x86_64.whl
python -m pip check
```

- [ ] **Step 7: Run Linux HTTP and both HTTPS profiles serially**

Set the two profile Runtime variables and local CA fixture. Run:

```bash
python -W error::ResourceWarning -m unittest tests.python.test_real_http -v
python -W error::ResourceWarning -m unittest tests.python.test_real_api -v
python -W error::ResourceWarning -m unittest discover -s tests/python -t . -v
```

Capture/compare both Firefox and foxreq profiles one browser at a time. Verify no command line contains `foxreq._profile_worker`, `firefox` or `tests.fixtures` afterward; record peak RSS for parent plus one worker. Do not run load tests.

- [ ] **Step 8: Verify and commit Task 7**

```powershell
git add -- native/nss-shim/src/platform_runtime.h native/nss-shim/src/platform_windows.c native/nss-shim/src/platform_posix.c native/nss-shim/src/platform_socket.h native/nss-shim/src/socket_windows.c native/nss-shim/src/socket_posix.c native/nss-shim/src/runtime.c native/nss-shim/src/connection.c native/nss-shim/src/foxreq_nss_real_internal.h native/nss-shim/CMakeLists.txt cmake/ToolchainPolicy.cmake crates/foxreq-core/build.rs third_party/firefox-linux-firefox_140_esr.lock.json third_party/firefox-linux-firefox_152.lock.json python/foxreq/_runtime_locks.py scripts/verify_python.sh tests/python/test_linux_contract.py tests/provenance/test_lock.py docs/building.md
git diff --cached --check
git diff --cached --name-only
git commit -m "feat: support Firefox NSS runtimes on Linux"
```

---

### Task 8: Documentation, examples and final cross-platform gate

**Files:**
- Modify: `README.md`
- Modify: `docs/fingerprint-evidence.md`
- Modify: `docs/building.md`
- Modify: `examples/python_basic.py`
- Modify: `examples/python_session.py`
- Modify: `tests/python/test_documentation.py`
- Modify: `tests/python/test_examples.py`
- Modify: `scripts/verify_python.ps1`
- Modify: `scripts/verify_python.sh`

**Interfaces:**
- Documents: exact profile matrix, HTTP/TLS distinction, Runtime variables and both platforms.
- Produces: serial Windows and Linux verification entrypoints.

- [ ] **Step 1: Write failing documentation/example tests**

Require README to contain both profile IDs and exact Firefox versions, HTTP/HTTPS examples, both profile Runtime variables, manylinux_2_17 status, default User-Agent behavior, and the statement that HTTP has no TLS fingerprint. Require examples to accept exact `--impersonate` choices and authorized HTTP while retaining loopback/explicit-authorization guards.

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.python.test_documentation tests.python.test_examples -v
```

Expected: missing profile/Linux/HTTP documentation and CLI choices fail.

- [ ] **Step 2: Update formal Chinese docs and examples**

Document only claims proven by Tasks 6–7. Include direct HTTP, Firefox 140 ESR HTTPS and Firefox 152 HTTPS examples. Explain custom User-Agent preservation and Session reuse. Keep successful example URLs loopback-only unless `--authorized-non-loopback` is explicit.

- [ ] **Step 3: Run the complete Windows gate from a fresh wheel**

```powershell
$env:CARGO_BUILD_JOBS = '1'
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -j 1
.\scripts\verify_python.ps1
.\.venv\Scripts\python.exe -m pip check
git diff --check
```

Expected: all exit 0, both real profiles included, no ResourceWarning and no owned residual process.

- [ ] **Step 4: Run the complete Linux gate**

Run `scripts/verify_python.sh` on `my-centos` with `CARGO_BUILD_JOBS=1`, followed by `python -m pip check`, wheel content contract and process/RSS checks. Expected: all exit 0 on glibc 2.17 with both real profiles.

- [ ] **Step 5: Check repository and sensitive-data boundaries**

```powershell
git status --short
git diff --check
git ls-files | rg "(\.dll|\.so|\.whl|\.pcap|server\.key|firefox\.exe)$"
git grep -n -I -E "BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY|Authorization:[[:space:]]+[^*<]"
```

Expected: no tracked binary/private material; the original master may still show only pre-existing local FastAPI files/modification, none staged by the feature branch.

- [ ] **Step 6: Commit Task 8**

```powershell
git add -- README.md docs/fingerprint-evidence.md docs/building.md examples/python_basic.py examples/python_session.py tests/python/test_documentation.py tests/python/test_examples.py scripts/verify_python.ps1 scripts/verify_python.sh
git diff --cached --check
git diff --cached --name-only
git commit -m "docs: document HTTP and verified Firefox profiles"
```

- [ ] **Step 7: Final review and integration handoff**

Review `git diff master...HEAD`, repeat Windows and Linux verification with fresh output, then use `superpowers:finishing-a-development-branch`. Merge locally only after the user selects it. Push `master` only after merged verification; never add or push local FastAPI files.
