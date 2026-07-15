import unittest

from tools.fingerprint.binary import Reader
from tools.fingerprint.errors import ParseError


class ReaderTests(unittest.TestCase):
    def test_reads_network_order_values(self):
        reader = Reader(
            bytes.fromhex("01 0203 000004 aabbccdd"),
            path="fixture",
        )

        self.assertEqual(1, reader.u8())
        self.assertEqual(0x0203, reader.u16())
        self.assertEqual(4, reader.u24())
        self.assertEqual(bytes.fromhex("aabbccdd"), reader.take(4))
        self.assertEqual(0, reader.remaining)
        reader.finish()

    def test_reads_length_prefixed_vectors(self):
        reader = Reader(bytes.fromhex("02 aabb 0003 010203"), path="vectors")

        self.assertEqual(bytes.fromhex("aabb"), reader.vector_u8())
        self.assertEqual(bytes.fromhex("010203"), reader.vector_u16())
        reader.finish()

    def test_subreader_reports_absolute_offset_and_its_path(self):
        reader = Reader(bytes.fromhex("0002 aabb"), base_offset=40, path="parent")
        size = reader.u16()
        child = reader.subreader(size, "child")

        self.assertEqual(b"\xaa", child.take(1))
        with self.assertRaises(ParseError) as caught:
            child.u16()

        self.assertEqual(43, caught.exception.offset)
        self.assertEqual("child", caught.exception.path)

    def test_truncation_reports_absolute_offset_and_path(self):
        reader = Reader(b"\x00", base_offset=40, path="client_hello.extensions")

        with self.assertRaises(ParseError) as caught:
            reader.u16()

        self.assertEqual(40, caught.exception.offset)
        self.assertEqual("client_hello.extensions", caught.exception.path)

    def test_finish_rejects_trailing_bytes_at_cursor(self):
        reader = Reader(b"\x01\x02", base_offset=10, path="message")
        reader.u8()

        with self.assertRaisesRegex(ParseError, "trailing bytes") as caught:
            reader.finish()

        self.assertEqual(11, caught.exception.offset)

    def test_negative_take_is_rejected_without_moving_cursor(self):
        reader = Reader(b"\x01", path="message")

        with self.assertRaisesRegex(ParseError, "negative size"):
            reader.take(-1)

        self.assertEqual(1, reader.remaining)


if __name__ == "__main__":
    unittest.main()
