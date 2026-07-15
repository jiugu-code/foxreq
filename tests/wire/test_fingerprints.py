import unittest

from tools.fingerprint.fingerprints import ja3, ja4
from tools.fingerprint.model import ClientHello, TlsExtension


def _u16_vector(values):
    body = b"".join(value.to_bytes(2, "big") for value in values)
    return len(body).to_bytes(2, "big") + body


def _official_ja4_example(extension_ids=None):
    ciphers = tuple(
        int(value, 16)
        for value in (
            "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,"
            "c02c,c02f,c030,cca8,cca9"
        ).split(",")
    )
    if extension_ids is None:
        extension_ids = tuple(
            int(value, 16)
            for value in (
                "0000,0005,000a,000b,000d,0010,0012,0015,0017,001b,"
                "0023,002b,002d,0033,4469,ff01"
            ).split(",")
        )
    signatures = tuple(
        int(value, 16)
        for value in "0403,0804,0401,0503,0805,0501,0806,0601".split(",")
    )
    host = b"clientservices.googleapis.com"
    sni_entry = b"\x00" + len(host).to_bytes(2, "big") + host
    bodies = {
        0: len(sni_entry).to_bytes(2, "big") + sni_entry,
        10: _u16_vector((29, 23)),
        11: b"\x01\x00",
        13: _u16_vector(signatures),
        16: b"\x00\x03\x02h2",
        43: b"\x02\x03\x04",
    }
    return ClientHello(
        legacy_version=0x0303,
        random=b"\x00" * 32,
        session_id=b"",
        cipher_suites=ciphers,
        compression_methods=(0,),
        extensions=tuple(
            TlsExtension(type_id, bodies.get(type_id, b""))
            for type_id in extension_ids
        ),
    )


class FingerprintTests(unittest.TestCase):
    def test_ja3_filters_grease_and_preserves_order(self):
        hello = ClientHello(
            legacy_version=0x0303,
            random=b"\x00" * 32,
            session_id=b"",
            cipher_suites=(0x0A0A, 0x1301, 0x1302),
            compression_methods=(0,),
            extensions=(
                TlsExtension(43, b"\x02\x03\x04"),
                TlsExtension(10, _u16_vector((29, 23))),
                TlsExtension(11, b"\x02\x00\x01"),
            ),
        )

        value = ja3(hello)

        self.assertEqual("771,4865-4866,43-10-11,29-23,0-1", value.raw)
        self.assertEqual("1cfacea804dbaeb3c7c98da7a3943049", value.digest)

    def test_ja4_matches_official_python_readme_example(self):
        value = ja4(_official_ja4_example())

        self.assertEqual(
            "t13d1516h2_8daaf6152771_e5627efa2ab1",
            value.digest,
        )
        self.assertIn(
            "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9",
            value.raw,
        )

    def test_ja4_is_stable_when_extension_order_changes(self):
        original = _official_ja4_example()
        reversed_extensions = tuple(reversed(original.extensions))
        permuted = ClientHello(
            original.legacy_version,
            original.random,
            original.session_id,
            tuple(reversed(original.cipher_suites)),
            original.compression_methods,
            reversed_extensions,
        )

        self.assertEqual(ja4(original).digest, ja4(permuted).digest)
        self.assertNotEqual(ja3(original).digest, ja3(permuted).digest)

    def test_ja4_filters_grease_from_counts_and_hashes(self):
        original = _official_ja4_example()
        with_grease = ClientHello(
            original.legacy_version,
            original.random,
            original.session_id,
            (0x0A0A,) + original.cipher_suites,
            original.compression_methods,
            (TlsExtension(0x1A1A, b""),) + original.extensions,
        )

        self.assertEqual(ja4(original).digest, ja4(with_grease).digest)

    def test_ja4_uses_legacy_version_and_empty_markers_when_extensions_absent(self):
        hello = ClientHello(
            0x0303,
            b"\x00" * 32,
            b"",
            (0x1301,),
            (0,),
            (),
        )

        self.assertTrue(ja4(hello).digest.startswith("t12i010000_"))


if __name__ == "__main__":
    unittest.main()
