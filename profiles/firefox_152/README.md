# Firefox 152 profile

This profile targets the official Firefox 152.0.6 release, locale `en-US`, on
Windows x86-64 and Linux x86-64.

The immutable Firefox release revision is
`68dfbca029f49cab85d965451998997141758306`. Its vendored component markers are
`NSS_3_124_RTM` and `NSPR_4_39_RTM`. The corresponding standalone source
revisions, read from the official archives' `.hg_archival.txt`, are
`089afe88dd219cf4b1516fd04f3b1c1fda3b7b61` and
`54e7c1b0803d151e142e30dc0d05f12e1ec67a13`. Official release archives and
their SHA-256 values are pinned in `third_party/native-sources.lock.json`.

## Evidence status

- Official archive identities: locked; local byte verification is required by
  `scripts/provenance/verify_sources.py`.
- Windows compiler identity: verified during native workspace bootstrap.
- Windows Firefox runtime: the four required NSS modules were extracted from
  the locked Firefox 152.0.6 installer, hash-verified, and exercised through
  repeated initialization and local TLS tests. This is a Windows G3 result,
  not wire-match evidence.
- Linux compiler and runtime verification: explicitly deferred by the user for
  the current Windows-local phase; this is not a Linux pass result.
- Windows Firefox smoke evidence: two cold ClientHellos and two resumed
  ClientHellos were captured from the hash-verified Firefox 152.0.6 binary.
  Their stable extension order was fixed in these samples. This sample size is
  intentionally insufficient for the golden gate.
- Windows foxreq smoke evidence: one cold ClientHello and one resumed
  ClientHello were compared with the browser smoke summaries. Record shape,
  JA3/JA4, cipher suites, extension ordering, supported groups, signature
  schemes, ALPN, key-share shapes, certificate-compression algorithms, and ECH
  length matched. Raw evidence stays under ignored `artifacts/captures`.
- Firefox cold/resumed golden captures: the required 100 cold handshakes and
  full resumption baseline are not complete. The tracked Windows golden files
  therefore do not exist, and the formal comparison command fails closed.
- NSS extension permutation: remains configured as the conservative profile
  target until the 100-handshake evidence gate determines whether the policy
  can be frozen as fully stable.

Run the formal comparison only after creating the required normalized goldens
and five-sample foxreq summaries:

```text
python scripts/capture/compare_profile.py --profile firefox_152 --platform windows
```

The command prints deterministic JSON path/value differences and returns a
nonzero status for missing inputs, insufficient counts, or mismatches. Formal
mode requires 100 cold browser samples, at least two resumed browser samples,
and five foxreq samples for each compared mode. Development evidence must pass
`--allow-partial`; its output is explicitly labeled
`"evidence_level": "partial"` and cannot satisfy G4/G5. Capture commands
default to a 4096 MiB available-memory floor and run Cargo serially.

No synthetic fixture may be labeled as a Firefox golden capture.
