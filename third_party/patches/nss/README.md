# NSS patch set

The Firefox 152 profile currently applies no NSS source patches. Exported NSS
configuration is always attempted and compared at the wire level before a
patch may be proposed.

Any future patch must be stored in this directory and recorded by relative path
and SHA-256 in `profiles/firefox_152/provenance.lock.json`. The review evidence
must include the repeated normalized mismatch, the missing public control, and
a focused regression test.
