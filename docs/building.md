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

The native stub can be configured before pinned NSS sources are acquired:

```powershell
cmake -S native/nss-shim -B build/nss-shim-smoke -G Ninja -DFOXREQ_NSS_STUB=ON
cmake --build build/nss-shim-smoke
```

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
tests. The Rust `nss` feature currently links this fake backend and exercises
runtime, connection, session-cache, byte-buffer, partial-I/O, error-copy, and
close semantics. The `tls::testing` hooks exist only for this development stage.

The fake backend does not open sockets, perform TLS, or reproduce a Firefox
fingerprint, and must never be presented as a working request transport. The
real pinned NSS backend is enabled only after the lifecycle, local-fixture, and
wire-evidence gates pass.
