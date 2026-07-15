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
- Linux compiler and runtime verification: explicitly deferred by the user for
  the current Windows-local phase; this is not a Linux pass result.
- Firefox cold/resumed golden captures: not captured yet.
- NSS extension permutation: configured as the profile target but not accepted
  as matched until the 100-handshake evidence gate passes.

No synthetic fixture may be labeled as a Firefox golden capture.
