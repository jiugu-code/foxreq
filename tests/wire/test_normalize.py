import unittest

from tools.fingerprint.errors import ParseError
from tools.fingerprint.normalize import is_grease, normalize_client_hello
from tools.fingerprint.tls import parse_client_hello_records

from .helpers import extension, synthetic_client_hello


def _u16_vector(*values):
    body = b"".join(value.to_bytes(2, "big") for value in values)
    return len(body).to_bytes(2, "big") + body


def _sni(host):
    encoded = host.encode("ascii")
    entry = b"\x00" + len(encoded).to_bytes(2, "big") + encoded
    return len(entry).to_bytes(2, "big") + entry


class NormalizeTests(unittest.TestCase):
    def test_dynamic_values_are_removed_but_shape_and_order_remain(self):
        extensions = b"".join(
            (
                extension(0x0A0A, b"\xaa"),
                extension(51, bytes.fromhex("0006 001d 0002 aabb")),
                extension(16, b"\x00\x03\x02h2"),
            )
        )
        hello = parse_client_hello_records(
            synthetic_client_hello(extensions, ciphers=(0x0A0A, 0x1301))
        )

        value = normalize_client_hello(hello)

        self.assertEqual("dynamic:32", value["random"])
        self.assertEqual("dynamic:0", value["session_id"])
        self.assertEqual(["GREASE", 0x1301], value["cipher_suites"])
        self.assertEqual(
            ["GREASE", 51, 16],
            [item["type"] for item in value["extensions"]],
        )
        self.assertEqual(
            {"group": 29, "key_length": 2},
            value["extensions"][1]["key_shares"][0],
        )
        self.assertEqual(["h2"], value["extensions"][2]["protocols"])

    def test_known_extensions_are_decoded_without_losing_order(self):
        extensions = b"".join(
            (
                extension(0, _sni("example.com")),
                extension(10, _u16_vector(29, 23)),
                extension(11, b"\x02\x00\x01"),
                extension(13, _u16_vector(0x0403, 0x0804)),
                extension(21, b"\x00\x00\x00"),
                extension(43, b"\x04\x03\x04\x03\x03"),
                extension(45, b"\x01\x01"),
            )
        )
        hello = parse_client_hello_records(synthetic_client_hello(extensions))

        values = normalize_client_hello(hello)["extensions"]

        self.assertEqual(
            [{"name_type": 0, "name": "example.com"}],
            values[0]["server_names"],
        )
        self.assertEqual([29, 23], values[1]["values"])
        self.assertEqual([0, 1], values[2]["values"])
        self.assertEqual([0x0403, 0x0804], values[3]["values"])
        self.assertEqual(3, values[4]["padding_length"])
        self.assertEqual([0x0304, 0x0303], values[5]["versions"])
        self.assertEqual([1], values[6]["values"])

    def test_pre_shared_key_keeps_lengths_not_secret_bytes(self):
        identity = b"abc"
        identities = (
            len(identity).to_bytes(2, "big")
            + identity
            + bytes.fromhex("01020304")
        )
        binder = b"\x55" * 32
        binders = bytes((len(binder),)) + binder
        body = (
            len(identities).to_bytes(2, "big")
            + identities
            + len(binders).to_bytes(2, "big")
            + binders
        )
        hello = parse_client_hello_records(
            synthetic_client_hello(extension(41, body))
        )

        value = normalize_client_hello(hello)["extensions"][0]

        self.assertEqual([3], value["pre_shared_key"]["identity_lengths"])
        self.assertEqual([32], value["pre_shared_key"]["binder_lengths"])
        self.assertNotIn(identity.hex(), str(value))
        self.assertNotIn(binder.hex(), str(value))

    def test_unknown_extension_retains_exact_hex(self):
        hello = parse_client_hello_records(
            synthetic_client_hello(extension(65037, b"\x01\x02\xff"))
        )

        value = normalize_client_hello(hello)["extensions"][0]

        self.assertEqual("0102ff", value["data_hex"])

    def test_malformed_known_extension_is_rejected(self):
        hello = parse_client_hello_records(
            synthetic_client_hello(extension(51, b"\x00\x06\x00"))
        )

        with self.assertRaises(ParseError):
            normalize_client_hello(hello)

    def test_grease_requires_the_rfc8701_pattern(self):
        self.assertTrue(is_grease(0x0A0A))
        self.assertTrue(is_grease(0xFAFA))
        self.assertFalse(is_grease(0x0A1A))
        self.assertFalse(is_grease(0xAAAA ^ 1))


if __name__ == "__main__":
    unittest.main()
