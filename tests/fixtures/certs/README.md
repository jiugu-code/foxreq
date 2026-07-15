# Local TLS fixture certificates

Task 7 provisions short-lived development certificates under
`artifacts/fixtures/certs/`, which is ignored by Git. No certificate private
key, NSS database, browser profile, or TLS key log belongs in this directory or
in repository history.

The fixture set will contain separate roles for a locally trusted loopback
certificate, an untrusted issuer, an expired certificate, and a hostname
mismatch. Tests install only the generated local CA into an ephemeral trust
store; they do not disable verification globally and do not alter the operating
system or user's Firefox trust stores.

The tracked test code accepts explicit certificate/key paths. It never creates
or downloads certificate material during package import.
