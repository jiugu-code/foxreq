# Foxreq Wire Evidence Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a dependency-free Python development tool that parses, normalizes, fingerprints, and compares TLS ClientHello and deterministic HTTP/2 client-prefix evidence before any NSS request transport is implemented.

**Architecture:** The evidence tool lives under `tools/fingerprint` and consumes raw TLS records or raw HTTP/2 bytes. Small parser modules produce immutable typed models; normalization removes only cryptographically dynamic payloads; comparison and JA3/JA4 reporting operate on those models. This is Plan 1 of four sequential foxreq v0.1 plans: wire evidence, NSS/HTTP/1.1 transport, nghttp2/Python API, and packaging/endurance.

**Tech Stack:** Python standard library, `unittest`, JSON, TLS record/handshake parsing, HTTP/2 frame parsing, JA3, and the BSD-3-Clause JA4 TLS algorithm documented by FoxIO.

## Global Constraints

- Runtime implementation target remains CPython 3.10 through 3.14, Windows x86-64, and manylinux x86-64.
- This development tool must run on the currently available Python 3.8.1 so foundation work is independently verifiable before the native toolchain is installed.
- No third-party Python dependency is allowed in this plan.
- `firefox_current` resolves locally to `firefox_152`; profile names never change meaning after release.
- Dynamic TLS values may be normalized only as listed in design section 9; field presence, order, type, and stable lengths remain comparable.
- JA3 and JA4 are diagnostics, never substitutes for field-level comparison.
- No supplied or captured authentication material is committed.
- Tests use synthetic fixtures clearly labeled as synthetic; they must never be represented as Firefox 152 golden captures.
- All parsing is bounded and malformed input produces a typed error containing a byte offset.
- Implementation is test-driven: observe the focused test fail before adding each behavior.

---

## File map

- `tools/__init__.py`: marks repository development tools as importable.
- `tools/fingerprint/__init__.py`: stable evidence-tool exports.
- `tools/fingerprint/errors.py`: typed parse/profile errors with offsets and paths.
- `tools/fingerprint/binary.py`: bounded network-byte-order reader.
- `tools/fingerprint/model.py`: immutable TLS, normalized evidence, diff, policy, and HTTP/2 data types.
- `tools/fingerprint/profile.py`: immutable profile-manifest validation and alias resolution.
- `tools/fingerprint/tls.py`: TLS record reassembly and ClientHello parser.
- `tools/fingerprint/normalize.py`: field-aware ClientHello normalization.
- `tools/fingerprint/compare.py`: recursive evidence diff and permutation-policy checks.
- `tools/fingerprint/fingerprints.py`: JA3 and JA4 TLS calculations.
- `tools/fingerprint/h2.py`: bounded HTTP/2 client preface and frame parser.
- `tools/fingerprint/cli.py`: JSON command-line interface for inspect and compare.
- `tools/fingerprint/__main__.py`: `python -m tools.fingerprint` entry point.
- `tests/wire/helpers.py`: synthetic TLS and HTTP/2 byte builders.
- `tests/wire/test_profile.py`: profile schema and aliases.
- `tests/wire/test_binary.py`: bounded-reader tests.
- `tests/wire/test_tls.py`: record reassembly and ClientHello parser tests.
- `tests/wire/test_normalize.py`: dynamic-field and GREASE normalization tests.
- `tests/wire/test_compare.py`: exact diff and permutation-policy tests.
- `tests/wire/test_fingerprints.py`: JA3/JA4 official-shape test vectors.
- `tests/wire/test_h2.py`: HTTP/2 frame and SETTINGS-order tests.
- `tests/wire/test_cli.py`: end-to-end CLI JSON tests.
- `third_party/NOTICE-JA4.md`: JA4 attribution and BSD-3-Clause source reference.

---

### Task 1: Repository test harness and immutable profile model

**Files:**

- Create: `.gitignore`
- Create: `tools/__init__.py`
- Create: `tools/fingerprint/__init__.py`
- Create: `tools/fingerprint/errors.py`
- Create: `tools/fingerprint/profile.py`
- Create: `tests/__init__.py`
- Create: `tests/wire/__init__.py`
- Create: `tests/wire/test_profile.py`

**Interfaces:**

- Consumes: JSON-compatible dictionaries supplied by later capture tooling.
- Produces: `ProfileError`, `ProfileManifest.from_dict(data)`, `resolve_profile(name, manifests)`, and immutable `ProfileManifest` fields `name`, `firefox_version`, `aliases`, `nss_revision`, `nspr_revision`, `capture_count`, and `extension_permutation`.

- [ ] **Step 1: Write the failing profile tests**

```python
import unittest

from tools.fingerprint.profile import ProfileManifest, resolve_profile
from tools.fingerprint.errors import ProfileError


VALID = {
    "schema_version": 1,
    "name": "firefox_152",
    "firefox_version": "152.0.6",
    "aliases": ["firefox_current"],
    "nss_revision": "NSS_REVISION_TEST",
    "nspr_revision": "NSPR_REVISION_TEST",
    "capture_count": 100,
    "extension_permutation": "stable",
}


class ProfileManifestTests(unittest.TestCase):
    def test_manifest_is_immutable_and_alias_resolves(self):
        manifest = ProfileManifest.from_dict(VALID)
        self.assertEqual("firefox_152", resolve_profile("firefox_current", [manifest]).name)
        with self.assertRaises(AttributeError):
            manifest.name = "changed"

    def test_unknown_keys_are_rejected(self):
        data = dict(VALID, unexpected=True)
        with self.assertRaisesRegex(ProfileError, "unexpected"):
            ProfileManifest.from_dict(data)

    def test_duplicate_alias_is_rejected(self):
        other = dict(VALID, name="firefox_153", aliases=["firefox_current"])
        with self.assertRaisesRegex(ProfileError, "duplicate alias"):
            resolve_profile("firefox_current", [
                ProfileManifest.from_dict(VALID),
                ProfileManifest.from_dict(other),
            ])
```

- [ ] **Step 2: Run the focused tests and observe the missing-module failure**

Run: `python -m unittest tests.wire.test_profile -v`

Expected: FAIL with `ModuleNotFoundError: No module named 'tools.fingerprint.profile'`.

- [ ] **Step 3: Implement the minimal immutable model and resolver**

```python
# tools/fingerprint/errors.py
class FingerprintError(Exception):
    pass


class ProfileError(FingerprintError):
    pass
```

```python
# tools/fingerprint/profile.py
from dataclasses import dataclass
from typing import Iterable, Mapping, Tuple

from .errors import ProfileError


_FIELDS = {
    "schema_version", "name", "firefox_version", "aliases",
    "nss_revision", "nspr_revision", "capture_count",
    "extension_permutation",
}


@dataclass(frozen=True)
class ProfileManifest:
    schema_version: int
    name: str
    firefox_version: str
    aliases: Tuple[str, ...]
    nss_revision: str
    nspr_revision: str
    capture_count: int
    extension_permutation: str

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "ProfileManifest":
        unknown = set(data) - _FIELDS
        missing = _FIELDS - set(data)
        if unknown:
            raise ProfileError("unexpected fields: " + ", ".join(sorted(unknown)))
        if missing:
            raise ProfileError("missing fields: " + ", ".join(sorted(missing)))
        if data["schema_version"] != 1:
            raise ProfileError("schema_version must be 1")
        if data["extension_permutation"] not in ("stable", "nss"):
            raise ProfileError("extension_permutation must be stable or nss")
        if not isinstance(data["capture_count"], int) or data["capture_count"] < 1:
            raise ProfileError("capture_count must be a positive integer")
        return cls(
            schema_version=1,
            name=str(data["name"]),
            firefox_version=str(data["firefox_version"]),
            aliases=tuple(str(value) for value in data["aliases"]),
            nss_revision=str(data["nss_revision"]),
            nspr_revision=str(data["nspr_revision"]),
            capture_count=int(data["capture_count"]),
            extension_permutation=str(data["extension_permutation"]),
        )


def resolve_profile(name: str, manifests: Iterable[ProfileManifest]) -> ProfileManifest:
    index = {}
    for manifest in manifests:
        for candidate in (manifest.name,) + manifest.aliases:
            if candidate in index:
                raise ProfileError("duplicate alias or profile name: " + candidate)
            index[candidate] = manifest
    try:
        return index[name]
    except KeyError:
        raise ProfileError("unknown profile: " + name)
```

```gitignore
# .gitignore
__pycache__/
*.py[cod]
.coverage
.pytest_cache/
target/
dist/
*.pcap
*.pcapng
*.keylog
*.pem
*.key
```

```python
# tools/fingerprint/__init__.py
from .errors import FingerprintError, ProfileError
from .profile import ProfileManifest, resolve_profile

__all__ = ["FingerprintError", "ProfileError", "ProfileManifest", "resolve_profile"]
```

`tools/__init__.py`, `tests/__init__.py`, and `tests/wire/__init__.py` are empty
package markers.

- [ ] **Step 4: Run the focused tests**

Run: `python -m unittest tests.wire.test_profile -v`

Expected: 3 tests, all `ok`.

- [ ] **Step 5: Run discovery and commit**

Run: `python -m unittest discover -s tests -v`

Expected: 3 tests pass.

Commit:

```bash
git add .gitignore tools tests
git commit -m "feat: add immutable fingerprint profiles"
```

---

### Task 2: Bounded binary reader

**Files:**

- Create: `tools/fingerprint/binary.py`
- Modify: `tools/fingerprint/errors.py`
- Create: `tests/wire/test_binary.py`

**Interfaces:**

- Consumes: a `bytes` buffer and optional absolute base offset.
- Produces: `ParseError(message, offset, path)`, `Reader.u8()`, `u16()`, `u24()`, `take(size)`, `vector_u8()`, `vector_u16()`, `subreader(size, path)`, `remaining`, and `finish()`.

- [ ] **Step 1: Write failing bounds and offset tests**

```python
import unittest

from tools.fingerprint.binary import Reader
from tools.fingerprint.errors import ParseError


class ReaderTests(unittest.TestCase):
    def test_reads_network_order_and_vectors(self):
        reader = Reader(bytes.fromhex("01 0203 000004 aabbccdd"), path="fixture")
        self.assertEqual(1, reader.u8())
        self.assertEqual(0x0203, reader.u16())
        self.assertEqual(4, reader.u24())
        self.assertEqual(bytes.fromhex("aabbccdd"), reader.take(4))
        reader.finish()

    def test_truncation_reports_absolute_offset_and_path(self):
        reader = Reader(b"\x00", base_offset=40, path="client_hello.extensions")
        with self.assertRaises(ParseError) as caught:
            reader.u16()
        self.assertEqual(40, caught.exception.offset)
        self.assertEqual("client_hello.extensions", caught.exception.path)
```

- [ ] **Step 2: Run and observe failure**

Run: `python -m unittest tests.wire.test_binary -v`

Expected: FAIL because `tools.fingerprint.binary` does not exist.

- [ ] **Step 3: Implement the reader with one checked slicing primitive**

```python
class Reader:
    def __init__(self, data, base_offset=0, path="input"):
        self._data = memoryview(data)
        self._cursor = 0
        self._base_offset = base_offset
        self.path = path

    @property
    def remaining(self):
        return len(self._data) - self._cursor

    def take(self, size):
        if size < 0 or size > self.remaining:
            raise ParseError("truncated input", self._base_offset + self._cursor, self.path)
        start = self._cursor
        self._cursor += size
        return bytes(self._data[start:self._cursor])

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return int.from_bytes(self.take(2), "big")

    def u24(self):
        return int.from_bytes(self.take(3), "big")

    def vector_u8(self, path=None):
        size = self.u8()
        return self.take(size)

    def vector_u16(self, path=None):
        size = self.u16()
        return self.take(size)

    def subreader(self, size, path):
        start = self._cursor
        data = self.take(size)
        return Reader(data, self._base_offset + start, path)

    def finish(self):
        if self.remaining:
            raise ParseError("trailing bytes", self._base_offset + self._cursor, self.path)
```

```python
# tools/fingerprint/errors.py addition
class ParseError(FingerprintError):
    def __init__(self, message, offset, path):
        super().__init__("{} at byte {} ({})".format(message, offset, path))
        self.message = message
        self.offset = offset
        self.path = path
```

- [ ] **Step 4: Run reader and full discovery tests**

Run: `python -m unittest tests.wire.test_binary tests.wire.test_profile -v`

Expected: 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add tools/fingerprint/binary.py tools/fingerprint/errors.py tests/wire/test_binary.py
git commit -m "feat: add bounded wire reader"
```

---

### Task 3: TLS record reassembly and ClientHello parser

**Files:**

- Create: `tools/fingerprint/model.py`
- Create: `tools/fingerprint/tls.py`
- Create: `tests/wire/helpers.py`
- Create: `tests/wire/test_tls.py`

**Interfaces:**

- Consumes: one or more complete TLS records as `bytes`.
- Produces: immutable `TlsExtension(type_id, data)`, `ClientHello(legacy_version, random, session_id, cipher_suites, compression_methods, extensions)`, and `parse_client_hello_records(data) -> ClientHello`.

- [ ] **Step 1: Add a synthetic builder and failing parser tests**

```python
def extension(type_id, body=b""):
    return type_id.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body


def synthetic_client_hello(extensions, split_at=None, ciphers=(0x1301, 0x1302)):
    cipher_bytes = b"".join(value.to_bytes(2, "big") for value in ciphers)
    body = (
        b"\x03\x03" + bytes(range(32)) + b"\x00" +
        len(cipher_bytes).to_bytes(2, "big") + cipher_bytes + b"\x01\x00" +
        len(extensions).to_bytes(2, "big") + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    chunks = [handshake] if split_at is None else [handshake[:split_at], handshake[split_at:]]
    return b"".join(b"\x16\x03\x01" + len(chunk).to_bytes(2, "big") + chunk for chunk in chunks)
```

```python
class ClientHelloTests(unittest.TestCase):
    def test_parses_ordered_ciphers_and_extensions_across_records(self):
        wire = synthetic_client_hello(extension(43, b"\x02\x03\x04") + extension(16, b"\x00\x03\x02h2"), split_at=19)
        hello = parse_client_hello_records(wire)
        self.assertEqual((0x1301, 0x1302), hello.cipher_suites)
        self.assertEqual((43, 16), tuple(item.type_id for item in hello.extensions))

    def test_rejects_non_handshake_record(self):
        with self.assertRaisesRegex(ParseError, "content type"):
            parse_client_hello_records(b"\x17\x03\x03\x00\x00")

    def test_rejects_duplicate_extensions(self):
        wire = synthetic_client_hello(extension(43) + extension(43))
        with self.assertRaisesRegex(ParseError, "duplicate extension"):
            parse_client_hello_records(wire)
```

- [ ] **Step 2: Run and observe missing parser failure**

Run: `python -m unittest tests.wire.test_tls -v`

Expected: FAIL because `tools.fingerprint.tls` does not exist.

- [ ] **Step 3: Implement immutable models and record reassembly**

```python
@dataclass(frozen=True)
class TlsExtension:
    type_id: int
    data: bytes


@dataclass(frozen=True)
class ClientHello:
    legacy_version: int
    random: bytes
    session_id: bytes
    cipher_suites: Tuple[int, ...]
    compression_methods: Tuple[int, ...]
    extensions: Tuple[TlsExtension, ...]
```

`parse_client_hello_records` SHALL read every five-byte TLS record header,
require content type 22, enforce a 65535-byte record limit, concatenate record
payloads, require handshake type 1, and parse exactly the u24 handshake length.
The ClientHello parser SHALL require a 32-byte random, even cipher vector length,
nonempty compression vector, exact extension-vector consumption, and unique
extension IDs.

Use this concrete implementation shape:

```python
def _u16_values(data, path):
    if len(data) % 2:
        raise ParseError("u16 vector has odd length", 0, path)
    reader = Reader(data, path=path)
    values = []
    while reader.remaining:
        values.append(reader.u16())
    return tuple(values)


def _parse_client_hello(body):
    reader = Reader(body, path="client_hello")
    legacy_version = reader.u16()
    random = reader.take(32)
    session_id = reader.vector_u8()
    cipher_suites = _u16_values(reader.vector_u16(), "client_hello.cipher_suites")
    if not cipher_suites:
        raise ParseError("empty cipher suite vector", 0, "client_hello.cipher_suites")
    compression_methods = tuple(reader.vector_u8())
    if not compression_methods:
        raise ParseError("empty compression method vector", 0, "client_hello.compression_methods")
    extensions = []
    seen = set()
    if reader.remaining:
        extension_reader = reader.subreader(reader.u16(), "client_hello.extensions")
        while extension_reader.remaining:
            type_id = extension_reader.u16()
            payload = extension_reader.take(extension_reader.u16())
            if type_id in seen:
                raise ParseError("duplicate extension {}".format(type_id), 0, "client_hello.extensions")
            seen.add(type_id)
            extensions.append(TlsExtension(type_id, payload))
        extension_reader.finish()
    reader.finish()
    return ClientHello(
        legacy_version, random, session_id, cipher_suites,
        compression_methods, tuple(extensions),
    )


def parse_client_hello_records(data):
    records = Reader(data, path="tls.records")
    payloads = []
    while records.remaining:
        content_type = records.u8()
        records.u16()  # legacy record version is evidence but not ClientHello body
        size = records.u16()
        if content_type != 22:
            raise ParseError("unexpected TLS content type {}".format(content_type), 0, "tls.records")
        payloads.append(records.take(size))
    records.finish()
    handshake = Reader(b"".join(payloads), path="tls.handshake")
    if handshake.u8() != 1:
        raise ParseError("first handshake is not ClientHello", 0, "tls.handshake")
    body = handshake.take(handshake.u24())
    handshake.finish()
    return _parse_client_hello(body)
```

- [ ] **Step 4: Run parser tests and discovery**

Run: `python -m unittest tests.wire.test_tls -v`

Expected: 3 tests pass.

Run: `python -m unittest discover -s tests -v`

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add tools/fingerprint/model.py tools/fingerprint/tls.py tests/wire/helpers.py tests/wire/test_tls.py
git commit -m "feat: parse TLS ClientHello records"
```

---

### Task 4: Field-aware ClientHello normalization

**Files:**

- Modify: `tools/fingerprint/model.py`
- Create: `tools/fingerprint/normalize.py`
- Create: `tests/wire/test_normalize.py`

**Interfaces:**

- Consumes: `ClientHello`.
- Produces: `is_grease(value)`, `normalize_client_hello(hello) -> dict`, with stable JSON-compatible ordered lists.

- [ ] **Step 1: Write failing normalization tests**

```python
class NormalizeTests(unittest.TestCase):
    def test_dynamic_values_are_removed_but_shape_and_order_remain(self):
        extensions = (
            extension(0x0A0A),
            extension(51, b"\x00\x06\x00\x1d\x00\x02\xaa\xbb"),
            extension(16, b"\x00\x03\x02h2"),
        )
        hello = parse_client_hello_records(synthetic_client_hello(b"".join(extensions)))
        value = normalize_client_hello(hello)
        self.assertEqual("dynamic:32", value["random"])
        self.assertEqual(["GREASE", 51, 16], [item["type"] for item in value["extensions"]])
        self.assertEqual({"group": 29, "key_length": 2}, value["extensions"][1]["key_shares"][0])

    def test_grease_requires_the_rfc8701_pattern(self):
        self.assertTrue(is_grease(0x0A0A))
        self.assertTrue(is_grease(0xFAFA))
        self.assertFalse(is_grease(0x0A1A))
```

- [ ] **Step 2: Run and observe failure**

Run: `python -m unittest tests.wire.test_normalize -v`

Expected: FAIL because `tools.fingerprint.normalize` does not exist.

- [ ] **Step 3: Implement extension-specific decoders**

Normalize cipher IDs, extension IDs, supported groups, and supported versions
with GREASE values replaced by the string `GREASE`. Decode these extensions:

```text
0 server_name: name types and lengths, with hostname retained
10 supported_groups: ordered u16 vector
11 ec_point_formats: ordered u8 vector
13 signature_algorithms: ordered u16 vector
16 ALPN: ordered protocol strings
21 padding: length only
43 supported_versions: ordered u16 vector
45 psk_key_exchange_modes: ordered u8 vector
51 key_share: ordered group and key lengths, never key bytes
```

For unknown extensions retain exact lowercase hex. For pre_shared_key extension
41 retain identity and binder counts and lengths but remove ticket and binder
bytes. Raise `ParseError` on malformed known-extension payloads rather than
falling back to opaque hex.

Use these concrete helpers and output shape:

```python
def is_grease(value):
    return (
        value & 0x0F0F == 0x0A0A and
        value >> 8 == value & 0xFF
    )


def _identifier(value):
    return "GREASE" if is_grease(value) else value


def _u16_vector(data, path):
    reader = Reader(data, path=path)
    payload = Reader(reader.vector_u16(), path=path)
    values = []
    while payload.remaining:
        values.append(_identifier(payload.u16()))
    payload.finish()
    reader.finish()
    return values


def _alpn(data):
    reader = Reader(data, path="extension.alpn")
    payload = Reader(reader.vector_u16(), path="extension.alpn.protocols")
    protocols = []
    while payload.remaining:
        protocols.append(payload.vector_u8().decode("ascii"))
    payload.finish()
    reader.finish()
    return protocols


def _key_shares(data):
    reader = Reader(data, path="extension.key_share")
    payload = Reader(reader.vector_u16(), path="extension.key_share.entries")
    shares = []
    while payload.remaining:
        group = _identifier(payload.u16())
        key = payload.vector_u16()
        shares.append({"group": group, "key_length": len(key)})
    payload.finish()
    reader.finish()
    return shares


def _psk_shape(data):
    reader = Reader(data, path="extension.pre_shared_key")
    identities = Reader(reader.vector_u16(), path="extension.pre_shared_key.identities")
    identity_lengths = []
    while identities.remaining:
        identity_lengths.append(len(identities.vector_u16()))
        identities.take(4)  # obfuscated_ticket_age is dynamic
    identities.finish()
    binders = Reader(reader.vector_u16(), path="extension.pre_shared_key.binders")
    binder_lengths = []
    while binders.remaining:
        binder_lengths.append(len(binders.vector_u8()))
    binders.finish()
    reader.finish()
    return {"identity_lengths": identity_lengths, "binder_lengths": binder_lengths}


def _normalize_extension(item):
    value = {"type": _identifier(item.type_id), "length": len(item.data)}
    if is_grease(item.type_id):
        return value
    if item.type_id in (10, 13):
        value["values"] = _u16_vector(item.data, "extension.{}".format(item.type_id))
    elif item.type_id in (11, 45):
        reader = Reader(item.data, path="extension.{}".format(item.type_id))
        value["values"] = list(reader.vector_u8())
        reader.finish()
    elif item.type_id == 16:
        value["protocols"] = _alpn(item.data)
    elif item.type_id == 21:
        value["padding_length"] = len(item.data)
    elif item.type_id == 43:
        reader = Reader(item.data, path="extension.supported_versions")
        versions = Reader(reader.vector_u8(), path="extension.supported_versions.values")
        values = []
        while versions.remaining:
            values.append(_identifier(versions.u16()))
        versions.finish()
        reader.finish()
        value["versions"] = values
    elif item.type_id == 51:
        value["key_shares"] = _key_shares(item.data)
    elif item.type_id == 41:
        value["pre_shared_key"] = _psk_shape(item.data)
    else:
        value["data_hex"] = item.data.hex()
    return value


def normalize_client_hello(hello):
    return {
        "legacy_version": hello.legacy_version,
        "random": "dynamic:{}".format(len(hello.random)),
        "session_id": "dynamic:{}".format(len(hello.session_id)),
        "cipher_suites": [_identifier(value) for value in hello.cipher_suites],
        "compression_methods": list(hello.compression_methods),
        "extensions": [_normalize_extension(item) for item in hello.extensions],
    }
```

Add this SNI decoder and the `item.type_id == 0` branch before the generic
unknown-extension branch:

```python
def _server_names(data):
    reader = Reader(data, path="extension.server_name")
    payload = Reader(reader.vector_u16(), path="extension.server_name.names")
    names = []
    while payload.remaining:
        name_type = payload.u8()
        name = payload.vector_u16().decode("ascii")
        names.append({"name_type": name_type, "name": name})
    payload.finish()
    reader.finish()
    return names

# in _normalize_extension, immediately before the final else
    elif item.type_id == 0:
        value["server_names"] = _server_names(item.data)
```

- [ ] **Step 4: Run normalization and full tests**

Run: `python -m unittest tests.wire.test_normalize tests.wire.test_tls -v`

Expected: all normalization and parser tests pass.

- [ ] **Step 5: Commit**

```bash
git add tools/fingerprint/model.py tools/fingerprint/normalize.py tests/wire/test_normalize.py
git commit -m "feat: normalize ClientHello evidence"
```

---

### Task 5: Evidence diff and extension-permutation policy

**Files:**

- Modify: `tools/fingerprint/model.py`
- Create: `tools/fingerprint/compare.py`
- Create: `tests/wire/test_compare.py`

**Interfaces:**

- Consumes: normalized JSON-compatible evidence dictionaries.
- Produces: immutable `Difference(path, expected, actual)`, `compare_evidence(expected, actual)`, `PermutationPolicy.from_samples(samples)`, and `policy.compare(candidate)`.

- [ ] **Step 1: Write failing path and permutation tests**

```python
class CompareTests(unittest.TestCase):
    def test_diff_reports_precise_ordered_path(self):
        expected = {"cipher_suites": [4865, 4866]}
        actual = {"cipher_suites": [4866, 4865]}
        self.assertEqual("$.cipher_suites[0]", compare_evidence(expected, actual)[0].path)

    def test_policy_separates_fixed_and_movable_extensions(self):
        samples = [
            {"extensions": [{"type": 0}, {"type": 10}, {"type": 16}, {"type": 43}]},
            {"extensions": [{"type": 0}, {"type": 16}, {"type": 10}, {"type": 43}]},
        ]
        policy = PermutationPolicy.from_samples(samples)
        self.assertEqual({0: 0, 3: 43}, policy.fixed_positions)
        self.assertEqual((10, 16), policy.movable_types)
        self.assertEqual([], policy.compare(samples[1]))
```

- [ ] **Step 2: Run and observe failure**

Run: `python -m unittest tests.wire.test_compare -v`

Expected: FAIL because `tools.fingerprint.compare` does not exist.

- [ ] **Step 3: Implement recursive comparison and policy inference**

`compare_evidence` SHALL compare dict keys in sorted order and list entries by
index, returning every mismatch. `PermutationPolicy.from_samples` SHALL first
require equal extension multisets and no duplicate type IDs. An index is fixed
only when every sample has the same type at that index. All remaining types are
the sorted movable set. `policy.compare` SHALL reject length/multiset changes
and violations of fixed positions while allowing any permutation of movable
types.

Use this exact recursive behavior and immutable policy shape:

```python
@dataclass(frozen=True)
class Difference:
    path: str
    expected: object
    actual: object


def compare_evidence(expected, actual, path="$"):
    if type(expected) is not type(actual):
        return [Difference(path, expected, actual)]
    if isinstance(expected, dict):
        differences = []
        for key in sorted(set(expected) | set(actual)):
            child = "{}.{}".format(path, key)
            if key not in expected or key not in actual:
                differences.append(Difference(child, expected.get(key), actual.get(key)))
            else:
                differences.extend(compare_evidence(expected[key], actual[key], child))
        return differences
    if isinstance(expected, list):
        differences = []
        common = min(len(expected), len(actual))
        for index in range(common):
            differences.extend(compare_evidence(
                expected[index], actual[index], "{}[{}]".format(path, index)
            ))
        for index in range(common, max(len(expected), len(actual))):
            left = expected[index] if index < len(expected) else None
            right = actual[index] if index < len(actual) else None
            differences.append(Difference("{}[{}]".format(path, index), left, right))
        return differences
    return [] if expected == actual else [Difference(path, expected, actual)]


@dataclass(frozen=True)
class PermutationPolicy:
    fixed_positions: Mapping[int, object]
    movable_types: Tuple[object, ...]
    extension_count: int

    @classmethod
    def from_samples(cls, samples):
        if len(samples) < 2:
            raise ProfileError("permutation policy requires at least two samples")
        orders = [tuple(item["type"] for item in sample["extensions"]) for sample in samples]
        if any(len(order) != len(set(order)) for order in orders):
            raise ProfileError("duplicate extension type in sample")
        expected = sorted(orders[0], key=str)
        if any(sorted(order, key=str) != expected for order in orders[1:]):
            raise ProfileError("extension multisets differ")
        fixed = {
            index: orders[0][index]
            for index in range(len(orders[0]))
            if all(order[index] == orders[0][index] for order in orders[1:])
        }
        movable = tuple(value for value in expected if value not in fixed.values())
        return cls(fixed, movable, len(orders[0]))

    def compare(self, candidate):
        order = tuple(item["type"] for item in candidate["extensions"])
        differences = []
        if len(order) != self.extension_count:
            differences.append(Difference("$.extensions.length", self.extension_count, len(order)))
            return differences
        actual_movable = sorted(
            (value for index, value in enumerate(order) if index not in self.fixed_positions),
            key=str,
        )
        if tuple(actual_movable) != self.movable_types:
            differences.append(Difference("$.extensions.movable", self.movable_types, tuple(actual_movable)))
        for index, expected in self.fixed_positions.items():
            if order[index] != expected:
                differences.append(Difference("$.extensions[{}].type".format(index), expected, order[index]))
        return differences
```

- [ ] **Step 4: Run compare and full tests**

Run: `python -m unittest tests.wire.test_compare -v`

Expected: both tests pass.

- [ ] **Step 5: Commit**

```bash
git add tools/fingerprint/model.py tools/fingerprint/compare.py tests/wire/test_compare.py
git commit -m "feat: compare fingerprint evidence"
```

---

### Task 6: JA3 and JA4 TLS diagnostics

**Files:**

- Create: `tools/fingerprint/fingerprints.py`
- Create: `tests/wire/test_fingerprints.py`
- Create: `third_party/NOTICE-JA4.md`

**Interfaces:**

- Consumes: parsed `ClientHello` plus transport marker `t` for TCP.
- Produces: `ja3(hello) -> Fingerprint(raw, digest)` and `ja4(hello) -> Fingerprint(raw, digest)`, where JA4's `digest` is its complete `a_b_c` representation.

- [ ] **Step 1: Add failing synthetic and official-shape tests**

```python
class FingerprintTests(unittest.TestCase):
    def test_ja3_filters_grease_and_preserves_order(self):
        hello = ClientHello(
            0x0303, b"\x00" * 32, b"", (0x0A0A, 0x1301, 0x1302), (0,),
            (
                TlsExtension(43, b"\x02\x03\x04"),
                TlsExtension(10, b"\x00\x04\x00\x1d\x00\x17"),
                TlsExtension(11, b"\x01\x00"),
            ),
        )
        value = ja3(hello)
        self.assertTrue(value.raw.startswith("771,4865-4866,43-10-11,"))
        self.assertEqual(32, len(value.digest))

    def test_ja4_has_three_locality_preserving_sections(self):
        ciphers = tuple(int(value, 16) for value in "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9".split(","))
        extension_ids = tuple(int(value, 16) for value in "0000,0005,000a,000b,000d,0010,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01".split(","))
        signatures = tuple(int(value, 16) for value in "0403,0804,0401,0503,0805,0501,0806,0601".split(","))
        host = b"clientservices.googleapis.com"
        bodies = {
            0: (len(host) + 3).to_bytes(2, "big") + b"\x00" + len(host).to_bytes(2, "big") + host,
            13: (len(signatures) * 2).to_bytes(2, "big") + b"".join(value.to_bytes(2, "big") for value in signatures),
            16: b"\x00\x03\x02h2",
            43: b"\x02\x03\x04",
        }
        hello = ClientHello(
            0x0303, b"\x00" * 32, b"", ciphers, (0,),
            tuple(TlsExtension(type_id, bodies.get(type_id, b"")) for type_id in extension_ids),
        )
        self.assertEqual(
            "t13d1516h2_8daaf6152771_e5627efa2ab1",
            ja4(hello).digest,
        )
```

- [ ] **Step 2: Run and observe failure**

Run: `python -m unittest tests.wire.test_fingerprints -v`

Expected: FAIL because the fingerprint module does not exist.

- [ ] **Step 3: Implement JA3 and JA4 from their primary specifications**

JA3 SHALL filter GREASE from ciphers, extensions, groups, and point formats,
preserve remaining order, join the five decimal fields, and MD5 the raw string.
JA4 SHALL follow FoxIO's BSD-3-Clause JA4 TLS definition: choose the highest
non-GREASE supported version; encode TCP, version, SNI domain/IP marker, two
digit non-GREASE cipher and extension counts, and ALPN marker in section `a`;
sort lowercase four-hex-digit cipher IDs for section `b`; sort extension IDs
excluding SNI and ALPN and append ordered signature algorithms for section `c`;
SHA-256 and truncate `b` and `c` to 12 hex characters. Copy the exact official
test vector above from the official Python README example at repository revision
`f7bf03a`, then record `https://github.com/FoxIO-LLC/ja4`, that revision, and
BSD-3-Clause JA4 attribution in `third_party/NOTICE-JA4.md`.

Implement with these concrete functions; extraction helpers parse the same
wire vectors as Task 4 and raise `ParseError` on malformed input:

```python
@dataclass(frozen=True)
class Fingerprint:
    raw: str
    digest: str


def _extension(hello, type_id):
    return next((item for item in hello.extensions if item.type_id == type_id), None)


def _supported_versions(hello):
    item = _extension(hello, 43)
    if item is None:
        return [hello.legacy_version]
    reader = Reader(item.data, path="extension.supported_versions")
    values = Reader(reader.vector_u8(), path="extension.supported_versions.values")
    result = []
    while values.remaining:
        result.append(values.u16())
    values.finish()
    reader.finish()
    return result


def _signature_algorithms(hello):
    item = _extension(hello, 13)
    if item is None:
        return []
    reader = Reader(item.data, path="extension.signature_algorithms")
    values = Reader(reader.vector_u16(), path="extension.signature_algorithms.values")
    result = []
    while values.remaining:
        result.append(values.u16())
    values.finish()
    reader.finish()
    return result


def _alpn_protocols(hello):
    item = _extension(hello, 16)
    return [] if item is None else _alpn(item.data)


def _raw_u16_vector(data):
    reader = Reader(data, path="fingerprint.u16_vector")
    payload = Reader(reader.vector_u16(), path="fingerprint.u16_vector.values")
    values = []
    while payload.remaining:
        values.append(payload.u16())
    payload.finish()
    reader.finish()
    return values


def _raw_u8_vector(data):
    reader = Reader(data, path="fingerprint.u8_vector")
    values = reader.vector_u8()
    reader.finish()
    return values


def ja3(hello):
    groups_item = _extension(hello, 10)
    formats_item = _extension(hello, 11)
    groups = [] if groups_item is None else [
        value for value in _raw_u16_vector(groups_item.data) if not is_grease(value)
    ]
    formats = [] if formats_item is None else list(_raw_u8_vector(formats_item.data))
    fields = (
        str(hello.legacy_version),
        "-".join(str(value) for value in hello.cipher_suites if not is_grease(value)),
        "-".join(str(item.type_id) for item in hello.extensions if not is_grease(item.type_id)),
        "-".join(str(value) for value in groups),
        "-".join(str(value) for value in formats),
    )
    raw = ",".join(fields)
    return Fingerprint(raw, hashlib.md5(raw.encode("ascii")).hexdigest())


def ja4(hello):
    versions = [value for value in _supported_versions(hello) if not is_grease(value)]
    version = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10"}[max(versions)]
    ciphers = sorted(value for value in hello.cipher_suites if not is_grease(value))
    extensions = sorted(item.type_id for item in hello.extensions if not is_grease(item.type_id))
    signatures = [value for value in _signature_algorithms(hello) if not is_grease(value)]
    alpn = _alpn_protocols(hello)
    alpn_marker = "00" if not alpn or not alpn[0] else alpn[0][0] + alpn[0][-1]
    sni_marker = "d" if _extension(hello, 0) is not None else "i"
    a = "t{}{}{:02d}{:02d}{}".format(
        version, sni_marker, min(len(ciphers), 99), min(len(extensions), 99), alpn_marker
    )
    b_raw = ",".join("{:04x}".format(value) for value in ciphers)
    c_extensions = [value for value in extensions if value not in (0, 16)]
    c_raw = "{}_{}".format(
        ",".join("{:04x}".format(value) for value in c_extensions),
        ",".join("{:04x}".format(value) for value in signatures),
    )
    b = hashlib.sha256(b_raw.encode("ascii")).hexdigest()[:12]
    c = hashlib.sha256(c_raw.encode("ascii")).hexdigest()[:12]
    return Fingerprint("{}_{}_{}".format(a, b_raw, c_raw), "{}_{}_{}".format(a, b, c))
```

- [ ] **Step 4: Run local and official-vector tests**

Run: `python -m unittest tests.wire.test_fingerprints -v`

Expected: all tests pass and the official vector matches exactly.

- [ ] **Step 5: Commit**

```bash
git add tools/fingerprint/fingerprints.py tests/wire/test_fingerprints.py third_party/NOTICE-JA4.md
git commit -m "feat: report JA3 and JA4 diagnostics"
```

---

### Task 7: Deterministic HTTP/2 prefix parser

**Files:**

- Modify: `tools/fingerprint/model.py`
- Create: `tools/fingerprint/h2.py`
- Create: `tests/wire/test_h2.py`

**Interfaces:**

- Consumes: HTTP/2 client preface followed by complete frames.
- Produces: immutable `H2Frame(length, type_id, flags, stream_id, payload)`, `Setting(identifier, value)`, `parse_client_prefix(data)`, and `decode_settings(frame)`.

- [ ] **Step 1: Write failing preface, order, and bounds tests**

```python
class H2Tests(unittest.TestCase):
    def test_preserves_settings_order_and_window_update(self):
        wire = CLIENT_PREFACE + frame(4, settings((1, 65536), (4, 131072))) + frame(8, (983041).to_bytes(4, "big"))
        frames = parse_client_prefix(wire)
        self.assertEqual([(1, 65536), (4, 131072)], [(s.identifier, s.value) for s in decode_settings(frames[0])])
        self.assertEqual((4, 8), (frames[0].type_id, frames[1].type_id))

    def test_rejects_reserved_stream_bit_and_truncation(self):
        with self.assertRaises(ParseError):
            parse_client_prefix(CLIENT_PREFACE + b"\x00\x00\x01\x04\x00\x80\x00\x00\x00")
```

- [ ] **Step 2: Run and observe failure**

Run: `python -m unittest tests.wire.test_h2 -v`

Expected: FAIL because `tools.fingerprint.h2` does not exist.

- [ ] **Step 3: Implement bounded frame parsing**

Require the exact 24-byte client preface. Parse the 24-bit length, type, flags,
reserved bit, 31-bit stream ID, and exact payload. Reject frames over 16 MiB.
SETTINGS must use stream 0 and a payload divisible by six; preserve entry order
and reject duplicate identifiers. WINDOW_UPDATE must have length four and a
nonzero 31-bit increment. Retain unknown frame payload bytes for later diffs.

Use this implementation shape:

```python
CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


@dataclass(frozen=True)
class H2Frame:
    length: int
    type_id: int
    flags: int
    stream_id: int
    payload: bytes


@dataclass(frozen=True)
class Setting:
    identifier: int
    value: int


def parse_client_prefix(data):
    reader = Reader(data, path="http2.client_prefix")
    if reader.take(len(CLIENT_PREFACE)) != CLIENT_PREFACE:
        raise ParseError("invalid HTTP/2 client preface", 0, "http2.client_prefix")
    frames = []
    while reader.remaining:
        length = reader.u24()
        if length > 16 * 1024 * 1024:
            raise ParseError("HTTP/2 frame too large", 0, "http2.frame")
        type_id = reader.u8()
        flags = reader.u8()
        raw_stream_id = int.from_bytes(reader.take(4), "big")
        if raw_stream_id & 0x80000000:
            raise ParseError("reserved stream bit is set", 0, "http2.frame.stream_id")
        frames.append(H2Frame(length, type_id, flags, raw_stream_id, reader.take(length)))
    reader.finish()
    return tuple(frames)


def decode_settings(frame):
    if frame.type_id != 4 or frame.stream_id != 0 or frame.length % 6:
        raise ParseError("invalid SETTINGS frame", 0, "http2.settings")
    reader = Reader(frame.payload, path="http2.settings")
    values = []
    seen = set()
    while reader.remaining:
        identifier = reader.u16()
        value = int.from_bytes(reader.take(4), "big")
        if identifier in seen:
            raise ParseError("duplicate SETTINGS identifier", 0, "http2.settings")
        seen.add(identifier)
        values.append(Setting(identifier, value))
    reader.finish()
    return tuple(values)


def decode_window_update(frame):
    if frame.type_id != 8 or frame.length != 4:
        raise ParseError("invalid WINDOW_UPDATE frame", 0, "http2.window_update")
    raw = int.from_bytes(frame.payload, "big")
    increment = raw & 0x7FFFFFFF
    if raw & 0x80000000 or increment == 0:
        raise ParseError("invalid WINDOW_UPDATE increment", 0, "http2.window_update")
    return increment
```

- [ ] **Step 4: Run HTTP/2 and full tests**

Run: `python -m unittest tests.wire.test_h2 -v`

Expected: all HTTP/2 tests pass.

- [ ] **Step 5: Commit**

```bash
git add tools/fingerprint/model.py tools/fingerprint/h2.py tests/wire/test_h2.py
git commit -m "feat: parse HTTP2 client prefixes"
```

---

### Task 8: JSON CLI and foundation acceptance run

**Files:**

- Modify: `tools/fingerprint/__init__.py`
- Create: `tools/fingerprint/cli.py`
- Create: `tools/fingerprint/__main__.py`
- Create: `tests/wire/test_cli.py`
- Create: `docs/fingerprint-evidence.md`

**Interfaces:**

- Consumes: raw binary or whitespace-tolerant hexadecimal files.
- Produces: `python -m tools.fingerprint tls inspect`, `tls compare`, `tls policy`, and `h2 inspect`; JSON goes to stdout, diagnostics to stderr, exit 0 for match/success, 1 for mismatch, and 2 for invalid input or usage.

- [ ] **Step 1: Write failing subprocess CLI tests**

```python
class CliTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.directory.cleanup()

    def write_hex(self, name, wire):
        path = os.path.join(self.directory.name, name)
        with open(path, "w") as handle:
            handle.write(wire.hex())
        return path

    def run_cli(self, *arguments):
        return subprocess.run(
            [sys.executable, "-m", "tools.fingerprint"] + list(arguments),
            text=True, capture_output=True,
        )

    def test_tls_inspect_emits_stable_json(self):
        path = self.write_hex("hello.hex", synthetic_client_hello(extension(43, b"\x02\x03\x04")))
        result = self.run_cli("tls", "inspect", "--hex", path)
        self.assertEqual(0, result.returncode, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(771, output["client_hello"]["legacy_version"])
        self.assertIn("ja3", output)
        self.assertIn("ja4", output)

    def test_compare_returns_one_and_machine_readable_diffs(self):
        left_wire = synthetic_client_hello(extension(43, b"\x02\x03\x04"), ciphers=(0x1301, 0x1302))
        right_wire = synthetic_client_hello(extension(43, b"\x02\x03\x04"), ciphers=(0x1302, 0x1301))
        left = self.write_hex("left.hex", left_wire)
        right = self.write_hex("right.hex", right_wire)
        result = self.run_cli("tls", "compare", "--hex", left, right)
        self.assertEqual(1, result.returncode)
        self.assertEqual("$.cipher_suites[0]", json.loads(result.stdout)["differences"][0]["path"])
```

- [ ] **Step 2: Run and observe failure**

Run: `python -m unittest tests.wire.test_cli -v`

Expected: FAIL because `tools.fingerprint.__main__` does not exist.

- [ ] **Step 3: Implement argparse commands and deterministic JSON**

Use `argparse`, `json.dumps(value, sort_keys=True, indent=2)`, and
`bytes.fromhex` for hex input. `tls policy` requires at least two samples and
prints fixed positions and movable types. Never catch `KeyboardInterrupt`.
Catch `FingerprintError`, print `{"error": ..., "offset": ..., "path": ...}`
to stderr, and return 2.

Use this command dispatch boundary so exit codes remain testable without a
subprocess:

```python
def _read(path, is_hex):
    mode = "r" if is_hex else "rb"
    with open(path, mode) as handle:
        value = handle.read()
    return bytes.fromhex(value) if is_hex else value


def _tls_evidence(path, is_hex):
    hello = parse_client_hello_records(_read(path, is_hex))
    return {
        "client_hello": normalize_client_hello(hello),
        "ja3": asdict(ja3(hello)),
        "ja4": asdict(ja4(hello)),
    }


def _handle_tls_inspect(arguments):
    return _tls_evidence(arguments.source, arguments.hex), 0


def _handle_tls_compare(arguments):
    left = _tls_evidence(arguments.left, arguments.hex)["client_hello"]
    right = _tls_evidence(arguments.right, arguments.hex)["client_hello"]
    differences = [asdict(value) for value in compare_evidence(left, right)]
    return {"differences": differences, "match": not differences}, 1 if differences else 0


def _handle_tls_policy(arguments):
    samples = [
        _tls_evidence(source, arguments.hex)["client_hello"]
        for source in arguments.sources
    ]
    policy = PermutationPolicy.from_samples(samples)
    return {
        "extension_count": policy.extension_count,
        "fixed_positions": {str(key): value for key, value in policy.fixed_positions.items()},
        "movable_types": list(policy.movable_types),
    }, 0


def _handle_h2_inspect(arguments):
    frames = []
    for frame in parse_client_prefix(_read(arguments.source, arguments.hex)):
        value = asdict(frame)
        value["payload"] = frame.payload.hex()
        if frame.type_id == 4:
            value["settings"] = [asdict(setting) for setting in decode_settings(frame)]
        if frame.type_id == 8:
            value["window_increment"] = decode_window_update(frame)
        frames.append(value)
    return {"frames": frames}, 0


def build_parser():
    parser = argparse.ArgumentParser(prog="python -m tools.fingerprint")
    protocols = parser.add_subparsers(dest="protocol", required=True)

    tls = protocols.add_parser("tls")
    tls_commands = tls.add_subparsers(dest="tls_command", required=True)
    inspect = tls_commands.add_parser("inspect")
    inspect.add_argument("source")
    inspect.add_argument("--hex", action="store_true")
    inspect.set_defaults(handler=_handle_tls_inspect)
    compare = tls_commands.add_parser("compare")
    compare.add_argument("left")
    compare.add_argument("right")
    compare.add_argument("--hex", action="store_true")
    compare.set_defaults(handler=_handle_tls_compare)
    policy = tls_commands.add_parser("policy")
    policy.add_argument("sources", nargs="+")
    policy.add_argument("--hex", action="store_true")
    policy.set_defaults(handler=_handle_tls_policy)

    h2 = protocols.add_parser("h2")
    h2_commands = h2.add_subparsers(dest="h2_command", required=True)
    h2_inspect = h2_commands.add_parser("inspect")
    h2_inspect.add_argument("source")
    h2_inspect.add_argument("--hex", action="store_true")
    h2_inspect.set_defaults(handler=_handle_h2_inspect)
    return parser


def main(argv=None):
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        output, return_code = arguments.handler(arguments)
    except FingerprintError as error:
        payload = {"error": str(error)}
        if isinstance(error, ParseError):
            payload.update({"offset": error.offset, "path": error.path})
        print(json.dumps(payload, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(output, sort_keys=True, indent=2))
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Document evidence workflow**

`docs/fingerprint-evidence.md` SHALL show exact inspect/compare/policy commands,
state that test fixtures are synthetic, explain dynamic normalization and
permutation policy, and state that a Firefox golden may only be named after its
binary hash and capture manifest are recorded.

```markdown
# Fingerprint evidence workflow

Inspect a synthetic or captured TLS flight:

    python -m tools.fingerprint tls inspect --hex path/to/clienthello.hex

Compare two flights field by field:

    python -m tools.fingerprint tls compare --hex expected.hex actual.hex

Infer extension permutation constraints from at least two cold handshakes:

    python -m tools.fingerprint tls policy --hex sample1.hex sample2.hex

Inspect an HTTP/2 client prefix:

    python -m tools.fingerprint h2 inspect --hex path/to/http2-prefix.hex

Repository unit fixtures are synthetic and are not Firefox golden captures.
Normalization removes random bytes, session identifiers, key material, tickets,
and binders while preserving their positions, types, counts, and stable lengths.
A permutation policy preserves fixed positions and the complete movable
extension set; it does not discard extension order globally.

A capture may be named as a Firefox golden only after its manifest records the
official browser version, browser binary SHA-256, NSS/NSPR revisions, operating
system, relevant preferences, test endpoint, and capture-tool versions. Never
commit cookies, Authorization headers, key logs, or user traffic captures.
```

- [ ] **Step 5: Run complete foundation verification**

Run: `python -m unittest discover -s tests -v`

Expected: every test passes with zero errors or failures.

Run: `python -m compileall -q tools tests`

Expected: exit 0.

Run: `python -m tools.fingerprint --help`

Expected: exit 0 and help lists `tls` and `h2`.

Run: `git diff --check`

Expected: exit 0 with no output.

- [ ] **Step 6: Commit**

```bash
git add tools/fingerprint docs/fingerprint-evidence.md tests/wire/test_cli.py
git commit -m "feat: add fingerprint evidence CLI"
```

---

## Completion boundary and next plans

This plan is complete when Task 8 verification passes and the CLI can explain
field-level differences for synthetic TLS and HTTP/2 fixtures. It deliberately
does not claim a Firefox match because no official browser capture has yet been
recorded in the repository.

After this plan, write and execute these separate plans in order:

1. `foxreq-nss-http1-transport`: install/pin the Rust and C toolchains; freeze
   Firefox 152.0.6, NSS, and NSPR provenance; capture the 100-handshake baseline;
   build the NSS shim; match cold/resumed TLS; implement verified HTTP/1.1.
2. `foxreq-nghttp2-python-api`: pin nghttp2; match the deterministic HTTP/2
   prefix; add PyO3, Session, pooling, cookies, redirects, proxy CONNECT,
   streaming, and decoding.
3. `foxreq-packaging-endurance`: build Windows/manylinux wheels, private native
   loading, SBOM/notices, clean-container tests, and the 24-hour endurance run.

Each later plan begins only from evidence produced by the previous plan and
must repeat the same red-green-verify-commit task structure.
