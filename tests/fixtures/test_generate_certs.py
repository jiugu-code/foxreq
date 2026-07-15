import datetime
import tempfile
import unittest
from pathlib import Path

from cryptography import x509

from tests.fixtures.generate_certs import generate_fixture


class GenerateCertificatesTests(unittest.TestCase):
    def test_generates_expired_and_hostname_mismatch_variants(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            root = repository / "artifacts" / "fixtures" / "certs"

            expired = root / "expired"
            generate_fixture(expired, repository=repository, variant="expired")
            expired_certificate = x509.load_pem_x509_certificate(
                (expired / "server.pem").read_bytes()
            )
            self.assertLess(expired_certificate.not_valid_after, datetime.datetime.utcnow())

            mismatch = root / "hostname-mismatch"
            generate_fixture(
                mismatch, repository=repository, variant="hostname-mismatch"
            )
            mismatch_certificate = x509.load_pem_x509_certificate(
                (mismatch / "server.pem").read_bytes()
            )
            names = mismatch_certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            self.assertNotIn("localhost", names.get_values_for_type(x509.DNSName))
            self.assertEqual(
                ["wrong.example.test"], names.get_values_for_type(x509.DNSName)
            )


if __name__ == "__main__":
    unittest.main()
