# foxreq v0.1 Design

Status: approved in conversation on 2026-07-15

## 1. Summary

`foxreq` is a synchronous Python HTTP client with a Requests-like API and a
Firefox-compatible network fingerprint. Version 0.1 targets Firefox 152.0.6 on
Windows and Linux. It reproduces the observable TLS ClientHello and HTTP/2
connection behavior by using Mozilla NSS/NSPR for TLS and nghttp2 for the
HTTP/2 wire protocol.

The runtime does not start or embed a browser. Browser binaries and packet
capture are development-time reference tools only. The library is intended for
authorized CTF, interoperability, regression testing, and owned-system security
assessment.

The primary reference that motivated this design is the supplied article
"Akamai对抗的隐秘战线——TLS指纹" (local source SHA-256
`61a80c833c2eb23ef8384bbb52759f814f92bd5347fbc66caeb49f562923a15a`).
The article's bypass claim is not treated as independent evidence or as a
product acceptance criterion.

## 2. Goals

Version 0.1 SHALL:

- expose a small, predictable Requests-like synchronous Python API;
- ship binary wheels for CPython 3.10 through 3.14 on Windows x86-64 and
  manylinux x86-64;
- run in a headless Linux container without X11, Firefox, or other GUI runtime;
- provide named, immutable network profiles, initially `firefox_152`;
- make `firefox_current` an alias for `firefox_152` for the whole 0.1 release
  line, never a network-fetched or silently changing value;
- reproduce the selected Firefox TLS ClientHello, including its stable extension
  order or its extension-permutation policy, using a pinned Firefox NSS and NSPR
  source revision plus explicit embedder configuration;
- reproduce the selected Firefox HTTP/2 connection preface, SETTINGS order and
  values, connection flow control, pseudo-header order, normal-header order,
  and applicable priority behavior;
- support HTTP/1.1 and HTTP/2 selected through ALPN;
- support sessions, connection reuse, cookies, redirects, timeouts, streaming,
  HTTP proxies, and HTTPS tunneling with CONNECT;
- verify server certificates by default;
- provide capture and comparison tooling that explains field-level differences
  rather than reporting only JA3 or JA4 hashes;
- keep credentials and cookies out of normal and debug logs.

## 3. Non-goals

Version 0.1 SHALL NOT:

- emulate JavaScript-visible properties such as Canvas, WebGL, fonts, screen,
  WebRTC, `navigator`, or browser storage;
- implement Chrome/BoringSSL profiles;
- implement HTTP/3 or QUIC;
- emulate DNS-over-HTTPS, operating-system TCP/IP fingerprints, or IP
  reputation;
- promise generic bot-control or Akamai bypass;
- execute JavaScript, solve challenges, or manage browser-generated clearance
  cookies;
- provide an asynchronous Python API;
- support SOCKS proxies, PAC files, client certificates, 0-RTT, or automatic
  ECH discovery through HTTPS DNS records;
- expose arbitrary low-level ClientHello mutation in the public Python API.

These exclusions keep v0.1 measurable. Later profiles or features require a
new specification and new reference captures.

## 4. Baseline and profile identity

The first profile is `firefox_152`, based on the official Firefox 152.0.6
desktop x86-64 release. The profile manifest SHALL record:

- Firefox product version and each Windows/Linux reference-binary download
  SHA-256;
- exact NSS and NSPR repository revisions;
- NSS build options and compiler identity;
- foxreq's NSS patch-set revision and patch hashes;
- capture operating system, browser preferences, test URL, and capture-tool
  versions;
- ordered TLS and HTTP/2 observations used as golden data;
- the observed ClientHello extension-permutation policy and its invariant
  positions, based on 100 fresh-profile cold handshakes;
- the default User-Agent and browser-style header templates.

`firefox_current` resolves locally to the profile shipped in the wheel. A future
Firefox profile is added under a new explicit name, such as `firefox_153`; an
existing name is never repointed after release.

The manifest is a build input and is bundled read-only. Profile selection is
part of the connection-pool key, so a socket can never be reused across two
different profiles.

## 5. Public Python API

The package exports module-level helpers and a reusable `Session`:

```python
import foxreq

response = foxreq.get(
    "https://example.com/",
    impersonate="firefox_current",
    timeout=30.0,
)

with foxreq.Session(impersonate="firefox_152") as session:
    response = session.post(
        "https://example.com/api",
        json={"hello": "world"},
    )
```

The public request surface consists of:

- `request(method, url, **options)` and method helpers;
- `Session.request(...)` and method helpers;
- `headers`, `params`, `data`, `json`, and raw byte or iterator bodies; mapping
  `data` is form encoded and string `data` is encoded as UTF-8;
- `cookies`, HTTP Basic `auth`, `proxy`, `timeout`, `allow_redirects`, `verify`, and
  `stream`;
- `impersonate`, `default_headers`, and `header_profile`.

`proxy` accepts an `http://` proxy URL; TLS-to-proxy (`https://`) and SOCKS are
not part of v0.1. `timeout` accepts one float or a `(connect, read)` pair. There
are no implicit retries in v0.1. Redirects default to a maximum of 20 hops. A
301 or 302 rewrites POST to GET, 303 rewrites every method except HEAD to GET,
and 307 or 308 preserves method and body. A preserving redirect fails with
`RedirectError` when its body is not replayable. Sensitive headers are removed
on cross-origin redirects.

`Response` exposes `status_code`, `reason`, `url`, ordered `headers`, `cookies`,
`history`, `http_version`, `content`, `text`, `json()`, `iter_bytes()`, and
`close()`. A streamed response owns its connection until consumed or closed.

Header insertion order is preserved. With `default_headers=True`, foxreq
applies the selected Firefox template first, then applies user replacements in
place and appends genuinely new headers in user order. `header_profile` is
either `navigation` or `minimal`; it defaults to `navigation`. HTTP/2
pseudo-headers are owned by the transport and cannot be supplied directly.

The API is intentionally familiar but is not advertised as a complete drop-in
replacement for `requests`.

## 6. Architecture

### 6.1 Python package

`python/foxreq` owns URL and option normalization, the public API, cookie policy,
response convenience methods, exception translation, and native-library
loading. It contains no TLS construction logic.

The native extension uses PyO3 with the CPython stable ABI targeting Python
3.10. Blocking network work releases the GIL. Python callback execution is not
allowed from NSS or nghttp2 native callbacks.

### 6.2 Rust core

`crates/foxreq-core` owns request state machines, DNS resolution, TCP sockets,
deadline propagation, proxy CONNECT, connection pooling, redirects, body
streaming, content decoding, and the boundary between the Python objects and
the native TLS/HTTP codecs.

The connection-pool key contains:

```text
scheme + host + port + proxy + profile + ALPN policy + verification policy
```

Connections are not coalesced across origins in v0.1, even if an HTTP/2
certificate covers multiple hosts. This avoids hidden changes in observable
connection behavior.

### 6.3 NSS/NSPR shim

`native/nss-shim` is a narrow C ABI over pinned NSS/NSPR. It owns process-safe
initialization, TLS socket creation, SNI, ALPN, cipher and protocol preferences,
session caching, handshake driving, certificate-chain extraction, NSS error
translation, and clean shutdown.

The shim uses exported NSS APIs wherever they can produce the golden capture.
An NSS source patch is allowed only when all of the following are true:

1. normalized captures prove a repeatable field or permutation-policy mismatch;
2. no exported NSS API or Firefox embedder option controls the field;
3. the patch is narrowly scoped and covered by a wire-level regression test;
4. the patch and its upstream source revision are recorded in the profile
   manifest and notices.

NSS/NSPR shared libraries and required softoken/freebl modules are bundled in
the wheel. Linux uses an origin-relative runtime search path. Windows loads only
from the package's private native directory using a restricted DLL search path.

### 6.4 Certificate verification

Certificate validation is enabled by default. The wheel contains a pinned CA
bundle for reproducible verification. `verify=True` selects that bundle;
`verify="path.pem"` uses the supplied trust anchors for that request policy;
`verify=False` is supported explicitly and emits an
`InsecureRequestWarning` once per process.

Custom roots are applied by the verifier associated with the connection-pool
key and SHALL NOT be added to a process-global trust set that could affect
other sessions. Hostname validation, validity periods, key usage, and chain
building are mandatory when verification is enabled.

### 6.5 HTTP/1.1

The Rust core serializes HTTP/1.1 requests directly so header casing, ordering,
and whitespace are deterministic. It supports fixed-length and chunked bodies,
interim responses, keep-alive, trailers on receive, and bounded header parsing.
It rejects response splitting, invalid content lengths, and conflicting framing
headers.

### 6.6 HTTP/2

nghttp2 is statically linked into the native extension behind a small Rust FFI
adapter. The adapter exposes explicit ordered SETTINGS entries, connection and
stream windows, header arrays, priority behavior, and serialized frame bytes.
It does not rely on a library's default SETTINGS.

The profile controls:

- client connection preface and ordered SETTINGS;
- initial connection WINDOW_UPDATE behavior;
- maximum frame and header-table settings when observed;
- pseudo-header order and regular-header order;
- Firefox-observed priority headers or PRIORITY_UPDATE frames;
- HPACK-sensitive inputs that are under application control.

Server-driven dynamic behavior is validated semantically rather than compared
byte-for-byte. The golden comparison covers the deterministic client prefix up
to and including the first request header block and any immediately associated
control frames.

### 6.7 Content decoding

gzip and deflate are built in. Brotli and Zstandard decoders are bundled and
their availability matches the profile's default `Accept-Encoding`. Decoding
is incremental for streamed responses and enforces decoded-size and ratio
limits configurable by the caller.

## 7. Request data flow

1. Python normalizes the request and resolves the immutable profile.
2. The Rust core calculates an absolute deadline and a connection-pool key.
3. A reusable eligible connection is selected, or DNS and TCP connection begin.
4. For an HTTPS destination reached through the configured HTTP proxy, the core
   establishes a CONNECT tunnel before TLS.
5. The NSS shim configures the profile, performs the handshake, validates the
   certificate, and reports negotiated ALPN and session status.
6. The core dispatches to deterministic HTTP/1.1 serialization or the profiled
   nghttp2 session.
7. Response framing and decompression are streamed into bounded buffers or the
   Python iterator.
8. A fully consumed healthy connection returns to the matching pool; otherwise
   it is closed.

Every phase receives the same monotonic deadline. A timeout cannot restart with
a fresh full duration at a deeper layer.

## 8. Errors and diagnostics

All public exceptions inherit from `FoxreqError`:

- `InvalidRequestError`
- `ProfileError`
- `DnsError`
- `ConnectError`
- `ProxyError`
- `TlsError`
- `CertificateError`
- `Http1Error`
- `Http2Error`
- `TimeoutError`
- `RedirectError`
- `DecodeError`

Native errors carry a stable foxreq category plus the original NSS, NSPR,
nghttp2, or OS error code when available. Error strings do not include request
bodies, cookies, Authorization, Proxy-Authorization, or URL user information.

Optional structured tracing reports timings, connection reuse, ALPN, TLS
version, cipher, profile name, and HTTP version. TLS secrets are never logged by
default; an explicit development-only key-log option is permitted and must name
a file path.

## 9. Fingerprint evidence and comparison

The repository includes development tools that capture and normalize reference
traffic from the pinned Firefox binary and traffic from foxreq. The normalizer
parses TLS records and ClientHello into an ordered typed representation.

Comparison ignores only intrinsically dynamic payloads:

- ClientHello random;
- session identifiers;
- key-share public key bytes while preserving group, length, count, and order;
- GREASE numeric values while preserving their category and positions;
- ticket, binder, and other per-session cryptographic payloads while preserving
  extension presence, placement, and structural lengths where stable.

It strictly compares protocol versions, cipher order, extension order,
extension structure, supported groups, signature algorithms, ALPN, key-share
shape, padding policy, GREASE positions, and all stable values. JA3 and JA4 are
reported as secondary diagnostics only.

If the pinned Firefox profile has ClientHello extension permutation enabled,
the comparison treats the observed permutable subrange as a policy rather than
pretending that one raw order is canonical. It still compares every extension
and every non-permutable position, then verifies across 100 cold handshakes that
foxreq uses the same movable set, fixed-position constraints, and NSS
permutation implementation. If Firefox's 100-handshake baseline is stable, the
order comparison remains exact on every handshake.

HTTP/2 comparison parses frames and HPACK blocks. It compares the deterministic
client frame sequence, SETTINGS order and values, window updates, priority
signals, pseudo-header order, regular-header order, and decoded header values.

Golden captures contain no authentication material and target only a local
fixture or a public fingerprint diagnostic service whose terms permit such use.
Tests against a CTF or other external target require that target to be supplied
and explicitly authorized by the user; they are never part of default CI.

## 10. Testing strategy

Development follows test-driven implementation. The suites are:

### 10.1 Unit tests

- profile schema, aliases, and immutable resolution;
- ordered header merge rules;
- timeout and redirect calculations;
- pool-key separation;
- URL, proxy, and body normalization;
- exception mapping and log redaction;
- TLS and HTTP/2 normalization and diff reporting.

### 10.2 Native protocol tests

- NSS initialization and teardown under concurrency;
- cold ClientHello against golden Firefox captures;
- resumed ClientHello after a session ticket;
- ALPN selection for HTTP/2 and HTTP/1.1-only servers;
- valid, expired, hostname-mismatched, untrusted, and custom-root certificates;
- malformed TLS peer behavior and deterministic error mapping;
- HTTP/2 SETTINGS, WINDOW_UPDATE, header order, and connection reuse;
- fragmented, malformed, and oversized HTTP/1.1 and HTTP/2 inputs.

### 10.3 Python integration tests

- every method helper and request-body form;
- sessions, cookies, redirects, proxies, and streaming;
- gzip, deflate, Brotli, and Zstandard decoding;
- early response close and pool eviction;
- connect/read timeouts and cancellation during blocking native work;
- certificate verification defaults and warnings.

### 10.4 Packaging and endurance tests

- build and install wheels in clean Windows and manylinux environments;
- import without NSS/NSPR present on the host;
- verify that packaged libraries load only from the wheel;
- verify no X11 or browser dependency in a clean Linux container;
- run a 24-hour mixed HTTP/1.1 and HTTP/2 loop with connection reuse, bounded
  memory growth, and zero leaked native handles;
- run dependency license and checksum verification.

## 11. Acceptance criteria

Version 0.1 is complete only when all of the following are true:

1. Five independent cold handshakes from foxreq match the normalized Firefox
   152.0.6 golden ClientHello on both supported operating systems when the
   baseline order is stable. If the baseline enables extension permutation, 100
   cold handshakes satisfy the permutation-policy comparison defined in section
   9, and every handshake matches all non-permuted fields.
2. Five resumed handshakes match the corresponding normalized Firefox session
   resumption shape, or resumption is disabled in both the reference capture and
   profile with the limitation documented. Silent mismatch is not acceptable.
3. HTTP/2 deterministic client frames through the first request match the
   Firefox golden observations field-for-field on both platforms.
4. JA3 and JA4 diagnostics agree where those algorithms are applicable, but
   their agreement alone does not satisfy criteria 1 through 3.
5. HTTP/1.1 and HTTP/2 functional, proxy, redirect, cookie, streaming, timeout,
   decoding, and certificate tests pass.
6. Clean Windows and Linux wheel installation tests pass without a system NSS,
   browser, or GUI dependency.
7. The 24-hour Linux endurance test completes without crashes, leaked file
   descriptors/native handles, or unbounded memory growth.
8. Final dependency notices identify NSS/NSPR under MPL 2.0 and the licenses of
   all other bundled native components.

Success against a particular anti-bot vendor is explicitly outside these
acceptance criteria. If an authorized target still rejects a request after the
network prefix matches, the result is reported as evidence of another signal,
not hidden by changing unrelated fields.

## 12. Build, supply chain, and repository layout

All native dependencies are pinned by source revision and archive checksum.
Builds produce an SBOM and third-party notices. Release artifacts are built in
clean CI images; downloading dependencies at package import time is forbidden.

```text
foxreq/
├── Cargo.toml
├── pyproject.toml
├── python/foxreq/
├── crates/foxreq-core/
├── crates/foxreq-py/
├── native/nss-shim/
├── native/nghttp2/
├── profiles/firefox_152/
├── tools/fingerprint/
├── tests/unit/
├── tests/integration/
├── tests/wire/
├── docs/superpowers/specs/
└── third_party/
```

The NSS patch set stays separate from vendored upstream source. Generated
binaries, packet captures containing user traffic, NSS key logs, and temporary
certificate databases are excluded from version control.

## 13. Chosen approach and rejected alternatives

The selected design combines Rust/PyO3 orchestration, a narrow C NSS/NSPR shim,
and nghttp2. It gives TLS behavior to the implementation Firefox uses while
retaining explicit control over HTTP/2 and a maintainable Python API.

A hand-built TLS implementation was rejected because reproducing arbitrary
ClientHello bytes is not equivalent to maintaining a correct, secure TLS state
machine and verifier. A libcurl/curl-impersonate wrapper was rejected because it
would recreate curl_cffi's architecture, limit Firefox-specific control, and
make field-level ownership less clear. A pure Rust HTTP/2 implementation using
library defaults was rejected because deterministic browser frame ordering is a
first-class acceptance requirement.

## 14. Implementation sequence boundary

The implementation plan SHALL order work by evidence:

1. freeze provenance and build the capture/normalization harness;
2. prove the pinned NSS shim can match the cold and resumed TLS baselines;
3. implement deterministic HTTP/1.1 and the minimal Python request path;
4. prove the nghttp2 wire prefix against the HTTP/2 baseline;
5. add sessions, pooling, redirects, cookies, proxies, streaming, and decoding;
6. produce wheels, supply-chain notices, and endurance verification.

No anti-bot target testing is required to advance between these stages. Each
stage must pass its local or public diagnostic evidence gate before the next
layer is treated as correct.

## 15. References

- Mozilla NSS overview and license:
  <https://firefox-source-docs.mozilla.org/security/nss/>
- Mozilla NSS build and test documentation:
  <https://firefox-source-docs.mozilla.org/security/nss/build.html>
- NSS public SSL header:
  <https://searchfox.org/firefox-main/source/security/nss/lib/ssl/ssl.h>
- nghttp2 programming guide:
  <https://nghttp2.org/documentation/programmers-guide.html>
- nghttp2 SETTINGS API:
  <https://nghttp2.org/documentation/nghttp2_submit_settings.html>
- Mozilla advisory confirming Firefox 152.0.6:
  <https://www.mozilla.org/en-US/security/advisories/mfsa2026-67/>
