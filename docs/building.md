# Building foxreq

foxreq uses a pinned Rust toolchain and a native C build. Dependency downloads
are development/build operations only; importing the eventual Python package
will never download or execute tooling.

## Windows developer baseline

- Windows x86-64
- Rust `1.88.0-x86_64-pc-windows-msvc` with `rustfmt` and `clippy`
- Visual Studio 2022 Build Tools with the x64 C++ toolset and Windows SDK
- CMake 3.24 or newer
- Ninja 1.11 or newer
- Python 3.10 or newer for the eventual public package

The first verified development machine used Visual Studio Build Tools 17.14.35,
CMake 4.4.0, and Ninja 1.11.1. These are build-environment observations, not
runtime dependencies.

Run the fail-closed check from a normal PowerShell process:

```powershell
& .\scripts\check_toolchain.ps1
```

The native stub can be configured before the pinned Firefox runtime is
prepared:

```powershell
cmake -S native/nss-shim -B build/nss-shim-smoke -G Ninja -DFOXREQ_NSS_STUB=ON
cmake --build build/nss-shim-smoke
```

### Pinned Firefox NSS runtime

The Windows real backend uses the NSS/NSPR DLLs shipped by the exact locked
Firefox installer. This keeps the TLS implementation aligned with the browser
build under comparison and avoids silently substituting system NSS. The
installer and every copied DLL are checked by size and SHA-256.

After fetching the locked installer into `.cache/sources`, prepare the minimal
four-file runtime without installing Firefox:

```powershell
python -m scripts.runtime.prepare_firefox_runtime `
  --installer .cache/sources/firefox-152.0.6-windows-x86_64-en-us.exe `
  --output .cache/firefox-runtime/core
```

The script uses Mozilla's documented
[`/ExtractDir` mode](https://firefox-source-docs.mozilla.org/browser/installer/windows/installer/FullConfig.html),
copies only the files listed in
`third_party/firefox-windows-runtime.lock.json`, and fails rather than
overwriting an existing output directory.

Run real-backend tests serially:

```powershell
$env:FOXREQ_NSS_RUNTIME_DIR = (Resolve-Path .cache/firefox-runtime/core).Path
$env:CARGO_BUILD_JOBS = "1"
cargo test -p foxreq-core --features nss-real
python -m scripts.runtime.test_real_tls --runtime .cache/firefox-runtime/core
```

The second command is the required loopback orchestrator for the ignored real
TLS cases. It generates short-lived certificate material only below the
ignored `artifacts/fixtures/certs` directory and runs each server/test pair one
at a time.

The capture orchestrators also run Cargo with one build job. Their CLI default
refuses to start when less than 4096 MiB of physical memory is available. Raw
captures, private fixture keys, and temporary Firefox profiles remain below
ignored `artifacts` paths. Do not lower the threshold on a shared workstation
without checking the other applications already running.

The Firefox 152 profile advertises certificate decompression algorithms in the
same order as Firefox: zlib, Brotli, and Zstandard. Decoding stays bounded by
the NSS-provided output buffer and C-to-Rust callbacks catch errors and panics.
The optional pure-Rust dependencies are pinned in `Cargo.lock`:

- `flate2` 1.1.9 (`MIT OR Apache-2.0`), using its Rust backend;
- `brotli-decompressor` 5.0.3 (`BSD-3-Clause/MIT`);
- `ruzstd` 0.8.3 (`MIT`).

Their transitive dependencies are likewise permissively licensed. Package
manifests in the downloaded Cargo registry remain the authority for license
metadata; packaging work must generate the final third-party notices from the
locked dependency graph.

## Linux developer baseline

- Linux x86-64 with glibc 2.17 compatibility for the final wheel target
- Rust 1.88.0 with `rustfmt` and `clippy`
- a C11 compiler, CMake 3.24 or newer, Ninja, and the pinned NSS/NSPR build
  prerequisites introduced by the provenance task
- Python 3.10 or newer for the eventual public package

Run:

```sh
./scripts/check_toolchain.sh
```

CentOS 7 is an authorized runtime-compatibility target. It must not be used as
an excuse to install unverified packages or to disable certificate checking.

## Current native boundary

`FOXREQ_NSS_STUB=ON` builds a deterministic fake backend for ABI and ownership
tests. The Rust `nss` feature links this fake backend and exercises
runtime, connection, session-cache, byte-buffer, partial-I/O, error-copy, and
close semantics. The `tls::testing` hooks exist only for this development stage.

The fake backend does not open sockets, perform TLS, or reproduce a Firefox
fingerprint, and must never be presented as a working request transport. The
`nss-real` feature loads only the hash-pinned Firefox runtime from an explicit
directory. Windows lifecycle, ALPN, certificate, deadline, and HTTPS/1.1 local
fixture tests pass. Low-count cold and resumed wire smoke comparisons are kept
separate from the required 100-handshake Firefox golden gate; they do not mark
that gate as passed.
