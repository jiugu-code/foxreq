"""Generate short-lived local TLS fixture certificates under ignored artifacts."""

import argparse
import datetime
import ipaddress
import os
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class CertificateFixtureError(Exception):
    pass


CERTIFICATE_VARIANTS = ("valid", "expired", "hostname-mismatch")


def generate_fixture(
    output: Path, repository: Optional[Path] = None, variant: str = "valid"
) -> None:
    if variant not in CERTIFICATE_VARIANTS:
        raise CertificateFixtureError("unknown certificate fixture variant")
    repository = (repository or Path(__file__).parents[2]).resolve()
    root = (repository / "artifacts" / "fixtures" / "certs").resolve()
    if not output.is_absolute():
        output = Path.cwd() / output
    output = output.resolve()
    try:
        common = Path(os.path.commonpath((str(root), str(output))))
    except ValueError:
        raise CertificateFixtureError("certificate output must be under artifacts/fixtures/certs")
    if common != root:
        raise CertificateFixtureError("certificate output must be under artifacts/fixtures/certs")
    output.mkdir(parents=True, exist_ok=True)

    now = datetime.datetime.utcnow()
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "foxreq local test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expected_name = (
        "wrong.example.test" if variant == "hostname-mismatch" else "localhost"
    )
    server_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, expected_name)]
    )
    if variant == "expired":
        server_not_before = now - datetime.timedelta(days=2)
        server_not_after = now - datetime.timedelta(days=1)
    else:
        server_not_before = now - datetime.timedelta(minutes=5)
        server_not_after = now + datetime.timedelta(days=1)
    if variant == "hostname-mismatch":
        subject_alternative_names = [x509.DNSName(expected_name)]
    else:
        subject_alternative_names = [
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            x509.IPAddress(ipaddress.ip_address("::1")),
        ]
    server = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(server_not_before)
        .not_valid_after(server_not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(subject_alternative_names),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    _write(output / "ca.der", ca.public_bytes(serialization.Encoding.DER))
    _write(output / "ca.pem", ca.public_bytes(serialization.Encoding.PEM))
    _write(
        output / "server.pem",
        server.public_bytes(serialization.Encoding.PEM),
    )
    _write(
        output / "server.key",
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def _write(path: Path, data: bytes) -> None:
    with path.open("xb") as output:
        output.write(data)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--variant", choices=CERTIFICATE_VARIANTS, default="valid")
    args = parser.parse_args(argv)
    generate_fixture(args.output, variant=args.variant)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
