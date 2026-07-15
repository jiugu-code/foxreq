# Fingerprint evidence workflow

Inspect a synthetic or captured TLS flight:

```console
python -m tools.fingerprint tls inspect --hex path/to/clienthello.hex
```

Compare two flights field by field:

```console
python -m tools.fingerprint tls compare --hex expected.hex actual.hex
```

Infer extension permutation constraints from at least two cold handshakes:

```console
python -m tools.fingerprint tls policy --hex sample1.hex sample2.hex
```

Inspect an HTTP/2 client prefix:

```console
python -m tools.fingerprint h2 inspect --hex path/to/http2-prefix.hex
```

Repository unit fixtures are synthetic and are not Firefox golden captures.
Normalization removes random bytes, session identifiers, key material, tickets,
and binders while preserving their positions, types, counts, and stable lengths.
A permutation policy preserves fixed positions and the complete movable
extension set; it does not discard extension order globally.

A capture may be named as a Firefox golden only after its manifest records the
official browser version, browser binary SHA-256, NSS/NSPR revisions, operating
system, relevant preferences, test endpoint, and capture-tool versions. Never
commit cookies, Authorization headers, key logs, or user traffic captures.
