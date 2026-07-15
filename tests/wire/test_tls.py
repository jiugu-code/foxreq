import unittest

from tools.fingerprint.errors import ParseError
from tools.fingerprint.tls import parse_client_hello_records

from .helpers import extension, synthetic_client_hello


class ClientHelloTests(unittest.TestCase):
    def test_parses_ordered_ciphers_and_extensions_across_records(self):
        wire = synthetic_client_hello(
            extension(43, b"\x02\x03\x04")
            + extension(16, b"\x00\x03\x02h2"),
            split_at=19,
        )

        hello = parse_client_hello_records(wire)

        self.assertEqual(0x0303, hello.legacy_version)
        self.assertEqual(bytes(range(32)), hello.random)
        self.assertEqual(b"", hello.session_id)
        self.assertEqual((0x1301, 0x1302), hello.cipher_suites)
        self.assertEqual((0,), hello.compression_methods)
        self.assertEqual((43, 16), tuple(item.type_id for item in hello.extensions))
        self.assertEqual(b"\x02\x03\x04", hello.extensions[0].data)

    def test_rejects_non_handshake_record(self):
        with self.assertRaisesRegex(ParseError, "content type"):
            parse_client_hello_records(b"\x17\x03\x03\x00\x00")

    def test_rejects_non_client_hello_handshake(self):
        wire = synthetic_client_hello(handshake_type=2)

        with self.assertRaisesRegex(ParseError, "ClientHello"):
            parse_client_hello_records(wire)

    def test_rejects_duplicate_extensions(self):
        wire = synthetic_client_hello(extension(43) + extension(43))

        with self.assertRaisesRegex(ParseError, "duplicate extension"):
            parse_client_hello_records(wire)

    def test_rejects_odd_cipher_vector_length(self):
        wire = synthetic_client_hello(cipher_bytes=b"\x13")

        with self.assertRaisesRegex(ParseError, "odd length"):
            parse_client_hello_records(wire)

    def test_rejects_truncated_tls_record(self):
        wire = synthetic_client_hello()[:-1]

        with self.assertRaisesRegex(ParseError, "truncated"):
            parse_client_hello_records(wire)

    def test_rejects_truncated_extension_payload(self):
        malformed = b"\x00\x2b\x00\x04\x02\x03"
        wire = synthetic_client_hello(malformed)

        with self.assertRaisesRegex(ParseError, "truncated"):
            parse_client_hello_records(wire)

    def test_rejects_trailing_handshake_bytes(self):
        wire = synthetic_client_hello()
        extra = b"\x00"
        declared = int.from_bytes(wire[3:5], "big") + len(extra)
        wire = wire[:3] + declared.to_bytes(2, "big") + wire[5:] + extra

        with self.assertRaisesRegex(ParseError, "trailing bytes"):
            parse_client_hello_records(wire)


if __name__ == "__main__":
    unittest.main()
