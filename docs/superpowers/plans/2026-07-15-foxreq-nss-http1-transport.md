# foxreq NSS/HTTP/1.1 Transport Implementation Plan

> Status: ready for execution after the wire-evidence foundation was merged to
> `master` at commit `528c610`.

**Goal:** Build and prove a pinned NSS/NSPR TLS transport whose observable
ClientHello behavior can be compared with the Firefox 152.0.6 baseline, then
carry deterministic HTTP/1.1 requests and responses over that transport.

**Architecture:** A Rust workspace owns bounded HTTP/1.1 codecs, deadlines,
socket state, and stable error categories. A narrow C ABI owns NSS/NSPR global
initialization, TLS configuration, handshake I/O, ALPN, certificate results,
and session resumption. Development capture tools feed raw wire evidence into
the already-merged `tools.fingerprint` parser; synthetic tests and browser
golden captures remain clearly separated. This is Plan 2 of four: wire
evidence, NSS/HTTP/1.1 transport, nghttp2/Python API, packaging/endurance.

**Implementation method:** Test-driven development. Each behavior begins with
a focused failing test, the smallest implementation needed to pass, then a
fresh focused and aggregate verification. Do not patch NSS unless the exported
API/configuration path has been exhausted and repeatable wire evidence proves
the need.

**Authorized scope:** Local fixtures, official Mozilla artifacts and source,
public fingerprint diagnostics that explicitly permit automated access, and
the user-provided authorized Linux host. Do not test third-party anti-bot
targets in this plan. Never commit credentials, cookies, packet captures from
real user traffic, TLS key logs, private keys, or temporary NSS databases.

---

## Stage gates

The work advances only after each gate has machine-readable evidence:

1. **G0 — Toolchain:** pinned Rust and native build tools run on Windows; the
   same Rust channel and compatible C toolchain run on the authorized Linux
   host.
2. **G1 — Provenance:** Firefox, NSS, and NSPR source identities, source archive
   hashes, compiler identities, build flags, and patch-set hash are recorded.
3. **G2 — HTTP/1.1 codec:** deterministic request serialization and bounded
   response parsing pass unit/property-style boundary tests without networking.
4. **G3 — NSS lifecycle:** the shim passes initialization, handshake, ALPN,
   verification, error mapping, and repeated teardown tests against local
   fixtures.
5. **G4 — Firefox baseline:** 100 authorized cold Firefox handshakes and the
   resumed-handshake set are captured, normalized, and summarized without
   secrets.
6. **G5 — Wire match:** foxreq satisfies the normalized cold/resumed Firefox
   profile policy. A mismatch produces field-level JSON evidence and blocks the
   stage.
7. **G6 — HTTPS/1.1:** the Rust transport passes local functional, malformed
   input, timeout, and connection-reuse tests over NSS.
8. **G7 — Cross-platform:** Windows and the authorized Linux host reproduce the
   stage results, with platform differences recorded explicitly.

Passing JA3 or JA4 alone never satisfies G5.

---

## Task 1: Bootstrap the pinned native workspace and build contract

**Files:**

- Create: `rust-toolchain.toml`
- Create: `Cargo.toml`
- Create: `crates/foxreq-core/Cargo.toml`
- Create: `crates/foxreq-core/src/lib.rs`
- Create: `crates/foxreq-core/tests/workspace_contract.rs`
- Create: `native/nss-shim/CMakeLists.txt`
- Create: `native/nss-shim/include/foxreq_nss.h`
- Create: `native/nss-shim/src/foxreq_nss.c`
- Create: `cmake/ToolchainPolicy.cmake`
- Create: `scripts/check_toolchain.ps1`
- Create: `scripts/check_toolchain.sh`
- Modify: `.gitignore`
- Create: `docs/building.md`

**Step 1: Freeze the supported developer toolchain.**

Pin one Rust stable release in `rust-toolchain.toml`; record the exact Windows
compiler, CMake, Ninja, and Python requirements in `docs/building.md`. Use the
same Rust channel on Linux. The initial Rust crate must build without NSS so
codec work is never blocked by native dependency acquisition.

**Step 2: Write a failing workspace-contract test.**

The test asserts that the core crate exposes `build_contract()` with the Rust
package version, target triple, enabled backend feature, and profile schema
version. The values must not include timestamps or host paths.

Run: `cargo test -p foxreq-core --test workspace_contract -- --nocapture`

Expected: FAIL because the API does not exist.

**Step 3: Add the minimal workspace and deterministic build metadata.**

Use Cargo resolver 2, deny unsafe code in the pure Rust codec modules, and
isolate all native FFI under a feature named `nss`. Do not add networking or
HTTP dependencies in this task.

**Step 4: Verify G0 locally.**

Run:

```text
cargo fmt --all -- --check
cargo test -p foxreq-core --test workspace_contract -- --nocapture
cargo clippy -p foxreq-core --all-targets -- -D warnings
cmake -S native/nss-shim -B build/nss-shim-smoke -G Ninja -DFOXREQ_NSS_STUB=ON
cmake --build build/nss-shim-smoke
```

Expected: all exit 0. The stub build proves the C ABI project is wired without
pretending that a real NSS handshake exists.

**Step 5: Commit.**

`chore: bootstrap pinned native workspace`

---

## Task 2: Freeze Firefox/NSS/NSPR provenance and acquisition

**Files:**

- Create: `profiles/firefox_152/profile.json`
- Create: `profiles/firefox_152/provenance.lock.json`
- Create: `profiles/firefox_152/README.md`
- Create: `third_party/native-sources.lock.json`
- Create: `third_party/patches/nss/README.md`
- Create: `scripts/provenance/fetch_sources.py`
- Create: `scripts/provenance/verify_sources.py`
- Create: `tests/provenance/test_lock.py`
- Modify: `.gitignore`

**Step 1: Write failing provenance-schema tests.**

Require:

- Firefox product version and channel;
- official Windows and Linux artifact URLs and SHA-256 values;
- official release-source identity;
- exact NSS and NSPR tree identities derived from that release source;
- standalone NSS/NSPR source archive hashes when separate archives are used;
- compiler identities and normalized build flags per platform;
- all applied patch paths and SHA-256 values, initially an empty array;
- capture OS, preferences, capture-tool versions, and profile schema version.

Reject unknown keys, missing fields, non-HTTPS source URLs, mutable labels such
as `latest`, malformed hashes, and a nonempty patch list with missing files.

Run: `python -m unittest tests.provenance.test_lock -v`

Expected: FAIL because the lock and verifier do not exist.

**Step 2: Resolve identities from official Mozilla sources.**

Do not guess the NSS version from a user-agent string. Start from the official
Firefox 152.0.6 release artifact and matching official release source, then
derive the included `security/nss` and NSPR identities. Record URLs and hashes
only after downloading and hashing the exact bytes. Save downloads under the
ignored `.cache/sources/` directory.

**Step 3: Implement fail-closed acquisition.**

`fetch_sources.py` downloads only lock-listed URLs, writes to a temporary file,
checks size and SHA-256, and atomically promotes the file into `.cache/sources`.
It must refuse redirects to non-HTTPS origins and never execute downloaded
content. `verify_sources.py` performs offline verification.

**Step 4: Verify G1.**

Run:

```text
python -m unittest tests.provenance.test_lock -v
python scripts/provenance/verify_sources.py --lock third_party/native-sources.lock.json
git diff --check
```

Expected: all exit 0, with no credentials, binaries, source archives, or private
captures tracked by Git.

**Step 5: Commit.**

`build: freeze Firefox NSS and NSPR provenance`

---

## Task 3: Implement deterministic HTTP/1.1 request serialization

**Files:**

- Create: `crates/foxreq-core/src/http1/mod.rs`
- Create: `crates/foxreq-core/src/http1/request.rs`
- Create: `crates/foxreq-core/src/http1/error.rs`
- Create: `crates/foxreq-core/tests/http1_request.rs`

**Step 1: Write failing request-vector tests.**

Cover exact bytes for:

- origin-form request targets, query strings, and empty paths;
- preserved header casing and insertion order;
- fixed-length empty and nonempty bodies;
- deterministic chunked framing;
- user-supplied `Host` replacement in place;
- rejection of CR/LF, NUL, invalid method tokens, invalid header names, duplicate
  `Host`, conflicting `Content-Length`, simultaneous length/chunked framing, and
  HTTP/2 pseudo-headers;
- refusal to emit proxy absolute-form or CONNECT in this stage.

Run: `cargo test -p foxreq-core --test http1_request -- --nocapture`

Expected: FAIL because no serializer exists.

**Step 2: Implement the smallest ordered serializer.**

Use owned byte strings at the transport boundary. Do not normalize user header
casing or sort headers. Calculate framing centrally so the caller cannot create
ambiguous requests. Enforce configurable aggregate header and body limits.

**Step 3: Add boundary cases.**

Test zero-length names/values, maximum accepted lengths, one-byte-over-limit,
Unicode rejected at the byte-token layer, and chunk sizes across hexadecimal
digit boundaries.

**Step 4: Verify the request half of G2.**

Run:

```text
cargo test -p foxreq-core --test http1_request -- --nocapture
cargo clippy -p foxreq-core --all-targets -- -D warnings
```

**Step 5: Commit.**

`feat: serialize deterministic HTTP1 requests`

---

## Task 4: Implement bounded HTTP/1.1 response parsing

**Files:**

- Create: `crates/foxreq-core/src/http1/response.rs`
- Create: `crates/foxreq-core/src/http1/chunked.rs`
- Create: `crates/foxreq-core/tests/http1_response.rs`
- Create: `crates/foxreq-core/tests/http1_malformed.rs`

**Step 1: Write failing incremental-parser tests.**

Feed every valid vector at every possible byte split. Cover status line,
ordered headers, duplicate non-framing headers, 1xx responses, no-body status
codes, fixed length, close-delimited bodies, chunked bodies, chunk extensions,
trailers, and bytes belonging to a subsequent response.

**Step 2: Write failing malformed-input tests.**

Reject bare LF, obsolete folding, invalid status codes, oversized status/header
lines, too many headers, conflicting/invalid content lengths, unsupported
transfer codings, length plus transfer encoding, invalid chunks, forbidden
trailers, premature EOF, and integer overflow. Errors must include a stable
category and byte offset but not response-body content.

**Step 3: Implement an explicit incremental state machine.**

Do not read until EOF when framing is known. Preserve ordered header pairs and
return unconsumed bytes. Bound every accumulation buffer before extending it.

**Step 4: Verify all of G2.**

Run:

```text
cargo test -p foxreq-core http1 -- --nocapture
cargo test -p foxreq-core --test http1_malformed -- --nocapture
cargo fmt --all -- --check
cargo clippy -p foxreq-core --all-targets -- -D warnings
```

Expected: all exit 0 under debug and release test profiles.

**Step 5: Commit.**

`feat: parse bounded HTTP1 responses`

---

## Task 5: Define the NSS C ABI and prove ownership with a fake backend

**Files:**

- Modify: `native/nss-shim/include/foxreq_nss.h`
- Modify: `native/nss-shim/src/foxreq_nss.c`
- Create: `native/nss-shim/src/foxreq_nss_internal.h`
- Create: `native/nss-shim/tests/test_abi.c`
- Create: `crates/foxreq-core/src/tls/mod.rs`
- Create: `crates/foxreq-core/src/tls/ffi.rs`
- Create: `crates/foxreq-core/src/tls/error.rs`
- Create: `crates/foxreq-core/tests/nss_abi.rs`

**Step 1: Write failing ABI ownership tests.**

The ABI must expose opaque runtime, connection, and byte-buffer handles plus
explicit free functions. Test null arguments, double-close prevention at the
Rust wrapper, zero-length reads/writes, partial I/O, deterministic injected
errors, and that error strings are copied into caller-owned buffers.

**Step 2: Define stable ABI types.**

Use fixed-width integers, explicit struct-size/version fields, and an enum of
foxreq-owned result categories. NSS/NSPR numeric codes are auxiliary fields,
not the public category. No C allocation may be released by Rust's allocator or
vice versa.

Required operations for this stage:

- runtime create/free;
- TCP+TLS connect with host, port, deadline, profile, ALPN, and verification
  policy;
- negotiated ALPN and certificate-verification result query;
- read, write, orderly close, and last-error extraction;
- opt-in session cache handle for resumption tests.

**Step 3: Implement a deterministic fake backend.**

The fake backend is test-only and supports scripted partial I/O/errors. It lets
the Rust state machine and ownership model pass before real NSS is linked.

**Step 4: Verify.**

Run:

```text
cmake -S native/nss-shim -B build/nss-shim-fake -G Ninja -DFOXREQ_NSS_STUB=ON -DBUILD_TESTING=ON
cmake --build build/nss-shim-fake
ctest --test-dir build/nss-shim-fake --output-on-failure
cargo test -p foxreq-core --features nss --test nss_abi -- --nocapture
```

**Step 5: Commit.**

`feat: define owned NSS transport ABI`

---

## Task 6: Build local TLS/capture fixtures and golden-data schema

**Files:**

- Create: `tests/fixtures/tls_server.py`
- Create: `tests/fixtures/capture_server.py`
- Create: `tests/fixtures/certs/README.md`
- Create: `scripts/capture/capture_firefox.py`
- Create: `scripts/capture/summarize_capture.py`
- Create: `profiles/firefox_152/golden/schema.json`
- Create: `tests/capture/test_capture_server.py`
- Create: `tests/capture/test_summarize.py`
- Modify: `.gitignore`

**Step 1: Write failing capture tests with synthetic ClientHellos.**

Test fragmented TLS records, multiple records in one TCP read, early close,
timeouts, size limits, connection IDs, and JSONL output. The capture server
must stop after the complete ClientHello and never log application data.

**Step 2: Implement a loopback-only fixture.**

Default bind is `127.0.0.1`; non-loopback bind requires an explicit flag. Write
raw captures only under ignored `artifacts/captures/`. The tracked golden form
contains normalized evidence, profile metadata, counts, and hashes—not raw
session material.

**Step 3: Implement Firefox capture orchestration.**

Create a fresh temporary Firefox profile per cold handshake, apply only recorded
preferences, launch the exact hashed Firefox binary, navigate only to the local
fixture, enforce a deadline, and delete the temporary profile. Resumption uses
one isolated profile/session and a separately labeled sequence. The script
must refuse an unverified Firefox binary hash.

**Step 4: Summarize through the existing parser.**

Reuse `tools.fingerprint.tls`, normalization, comparison, JA3, and JA4. Record
the extension-order multiset, fixed positions, movable set, all stable fields,
and structural length distributions across 100 cold samples.

**Step 5: Verify the fixture, not the real baseline yet.**

Run:

```text
python -m unittest discover -s tests/capture -v
python -m tools.fingerprint --help
git status --short
```

Expected: tests pass and no raw capture, browser profile, key, or certificate
private material is tracked.

**Step 6: Commit.**

`test: add isolated Firefox TLS capture harness`

---

## Task 7: Implement the real NSS/NSPR lifecycle and TLS connection

**Files:**

- Create: `native/nss-shim/cmake/FindPinnedNSS.cmake`
- Create: `native/nss-shim/src/runtime.c`
- Create: `native/nss-shim/src/connection.c`
- Create: `native/nss-shim/src/profile.c`
- Create: `native/nss-shim/src/verify.c`
- Create: `native/nss-shim/src/error.c`
- Create: `native/nss-shim/tests/test_runtime.c`
- Create: `native/nss-shim/tests/test_local_tls.c`
- Create: `crates/foxreq-core/tests/nss_local_tls.rs`
- Modify: `native/nss-shim/CMakeLists.txt`
- Modify: `crates/foxreq-core/build.rs`

**Step 1: Write failing real-backend integration tests.**

Against the local TLS fixture, test:

- repeated and concurrent runtime acquisition/release;
- SNI and `http/1.1` ALPN;
- successful trusted local certificate and explicit failures for untrusted,
  expired, and hostname-mismatched certificates;
- connect and read deadlines;
- partial read/write and peer close;
- session-cache enabled/disabled behavior;
- stable foxreq category plus NSS and NSPR numeric evidence.

**Step 2: Link only the verified pinned build.**

`FindPinnedNSS.cmake` must compare discovered headers/libraries and the recorded
build receipt to the provenance lock. It must fail on system NSS, unknown paths,
or hash mismatches. Use origin-private dynamic loading rules later during wheel
packaging; do not solve packaging in this task.

**Step 3: Implement exported-API configuration.**

Use NSS/NSPR public APIs for initialization, TCP socket import, SNI, protocol
range, ciphers, supported groups/signatures where exported controls exist,
ALPN, verification hooks, session cache, handshake, and I/O. Store all global
state behind a process-safe reference-counted runtime. Do not call NSS shutdown
while a connection exists.

**Step 4: Map errors and redact context.**

Expose host and operation names only when safe. Never include request headers,
cookies, auth values, certificate private material, or body bytes in error or
debug output.

**Step 5: Verify G3.**

Run the C and Rust integration suites repeatedly, including a 1,000-iteration
runtime/connect/close loop. Check handle counts before and after on Windows and
file-descriptor counts on Linux.

**Step 6: Commit.**

`feat: connect with pinned NSS and NSPR`

---

## Task 8: Capture Firefox goldens and close the TLS wire gap

**Files:**

- Create: `profiles/firefox_152/golden/windows-cold.json`
- Create: `profiles/firefox_152/golden/windows-resumed.json`
- Create: `profiles/firefox_152/golden/linux-cold.json`
- Create: `profiles/firefox_152/golden/linux-resumed.json`
- Create: `scripts/capture/capture_foxreq.py`
- Create: `scripts/capture/compare_profile.py`
- Create: `tests/wire/test_firefox_152_goldens.py`
- Modify: `profiles/firefox_152/profile.json`
- Modify: `profiles/firefox_152/README.md`

**Step 1: Capture and freeze the browser baseline.**

Run 100 cold handshakes per supported platform plus the documented resumption
sequence. Keep raw evidence outside Git; commit only normalized golden data and
metadata. Re-run the summarizer from raw evidence twice and require byte-identical
tracked JSON output.

**Step 2: Write the failing foxreq comparison test.**

Capture five foxreq cold and five resumed handshakes. Compare strict fields and
the learned permutation policy. Print a machine-readable path/value diff for
every failure.

Expected: the first real run may fail. Treat the diff as diagnostic evidence,
not as permission to weaken comparison rules.

**Step 3: Attribute each mismatch.**

For every field, record its owner: NSS default, NSS exported configuration,
Firefox embedder configuration, build option, or truly internal NSS behavior.
Change exported configuration first. Any proposed NSS patch requires a separate
review note containing the repeated normalized diff, lack of a public control,
minimal patch, regression test, and updated provenance hash.

**Step 4: Verify G4 and G5.**

Run:

```text
python scripts/capture/compare_profile.py --profile firefox_152 --platform windows
python scripts/capture/compare_profile.py --profile firefox_152 --platform linux
python -m unittest tests.wire.test_firefox_152_goldens -v
```

Expected: every stable field matches; ordering satisfies the frozen exact or
permutation policy; cold/resumed samples are labeled and pass independently.

**Step 5: Commit.**

`test: prove Firefox 152 TLS wire profile`

---

## Task 9: Carry deterministic HTTP/1.1 over NSS

**Files:**

- Create: `crates/foxreq-core/src/deadline.rs`
- Create: `crates/foxreq-core/src/transport.rs`
- Create: `crates/foxreq-core/src/http1/client.rs`
- Create: `crates/foxreq-core/examples/https_get.rs`
- Create: `crates/foxreq-core/tests/https_http1.rs`
- Create: `tests/fixtures/http1_scenarios.py`

**Step 1: Write failing end-to-end tests.**

Cover GET/HEAD/POST, fixed and chunked bodies, 100 Continue, ordered duplicate
headers, fixed/chunked/close-delimited responses, trailers, connection reuse,
server-requested close, early close, connect/write/read deadlines, and all
malformed cases from Task 4 over a real NSS socket.

**Step 2: Implement one-request-at-a-time connection state.**

This phase may reuse an idle HTTP/1.1 connection but does not yet expose a
general pool or Python API. A connection becomes reusable only after the body
and trailers are fully consumed and both protocol framing and NSS state are
clean. On ambiguity or cancellation, close it.

**Step 3: Propagate one absolute deadline.**

Convert the caller duration once, then pass remaining time through DNS/TCP,
handshake, write, headers, and body reads. Do not restart the clock per syscall.

**Step 4: Add a diagnostic example.**

`https_get` targets only an explicit URL, verifies certificates by default,
prints status/HTTP version/body length, and redacts URL userinfo and sensitive
headers. It is a development probe, not the public Python API.

**Step 5: Verify G6.**

Run all unit/integration suites and a 10,000-request local keep-alive loop.
Assert bounded memory and stable handle/file-descriptor counts.

**Step 6: Commit.**

`feat: send HTTP1 requests over NSS`

---

## Task 10: Cross-platform verification and stage handoff

**Files:**

- Create: `scripts/verify_stage2.ps1`
- Create: `scripts/verify_stage2.sh`
- Create: `docs/verification/nss-http1-stage.md`
- Modify: `docs/building.md`

**Step 1: Encode the complete verification sequence.**

The scripts run provenance checks, Python wire tests, Rust formatting/lints and
tests, C tests, golden comparisons, local HTTPS/1.1 integration, and credential
scans. They print tool versions and Git commit but no environment variables.

**Step 2: Run on clean Windows state.**

Delete only generated build directories after resolving and confirming they
are inside the repository. Rebuild from the lock, run `verify_stage2.ps1`, and
record commands, versions, exit codes, test counts, and known limitations.

**Step 3: Run on the authorized Linux host.**

Use an ephemeral SSH key installed by the user or another non-recorded secure
authentication method. Never place a password in a command, script, repository,
shell history, CI variable shown in logs, or process argument. Copy only the
repository and verified source cache; run `verify_stage2.sh`; retrieve only the
redacted verification report and normalized authorized captures.

CentOS 7 compatibility is a target constraint, not permission to disable TLS
verification or use unverified package mirrors. If the host cannot build the
pinned toolchain safely, build in a controlled manylinux-compatible environment
and use the host only for artifact/runtime validation.

**Step 4: Review the complete diff.**

Run:

```text
git diff master...HEAD --check
git status --short
python -m unittest discover -s tests -v
cargo test --workspace --all-features
```

Confirm that no raw captures, credentials, binaries, source archives, private
keys, TLS key logs, temporary NSS databases, or user traffic are tracked.

**Step 5: Commit.**

`docs: record NSS HTTP1 verification evidence`

---

## Stage completion criteria

This plan is complete only when G0 through G7 pass. If toolchain installation,
official source acquisition, browser automation, or secure Linux authentication
is unavailable, report the precise blocked gate and keep unverified claims out
of documentation. Do not label synthetic fixtures as Firefox goldens.

The next plan, `foxreq-nghttp2-python-api`, begins only after this stage is
green. It will add the profiled HTTP/2 prefix through nghttp2, PyO3 bindings,
the initial Requests-like Python surface, sessions/pooling, cookies, redirects,
proxy CONNECT, streaming, and content decoding.

## Scope note: Windows-local continuation

On 2026-07-15 the user explicitly deferred Linux-host testing and accepted
Windows-local verification for the current development continuation. G7 and
Linux portions of G1/G4/G5 remain open; they must not be reported as passing.
Tasks that are platform-independent or verified on Windows may continue, while
Linux wheel/release claims remain blocked until those gates are resumed.
