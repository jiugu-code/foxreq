import unittest

from tools.fingerprint.errors import ParseError
from tools.fingerprint.h2 import (
    CLIENT_PREFACE,
    decode_settings,
    decode_window_update,
    parse_client_prefix,
)

from .helpers import h2_frame, h2_settings


class H2Tests(unittest.TestCase):
    def test_preserves_settings_order_and_window_update(self):
        wire = (
            CLIENT_PREFACE
            + h2_frame(4, h2_settings((1, 65536), (4, 131072)))
            + h2_frame(8, (983041).to_bytes(4, "big"))
        )

        frames = parse_client_prefix(wire)

        self.assertEqual(
            [(1, 65536), (4, 131072)],
            [
                (setting.identifier, setting.value)
                for setting in decode_settings(frames[0])
            ],
        )
        self.assertEqual((4, 8), (frames[0].type_id, frames[1].type_id))
        self.assertEqual(983041, decode_window_update(frames[1]))

    def test_retains_unknown_frame_payload(self):
        wire = CLIENT_PREFACE + h2_frame(0xF0, b"\x01\x02", stream_id=3)

        frame = parse_client_prefix(wire)[0]

        self.assertEqual((0xF0, 3, b"\x01\x02"), (frame.type_id, frame.stream_id, frame.payload))

    def test_rejects_invalid_preface(self):
        with self.assertRaisesRegex(ParseError, "preface"):
            parse_client_prefix(b"not-http2")

    def test_rejects_reserved_stream_bit(self):
        wire = CLIENT_PREFACE + h2_frame(4, b"", reserved=True)

        with self.assertRaisesRegex(ParseError, "reserved stream bit"):
            parse_client_prefix(wire)

    def test_rejects_truncated_frame_payload(self):
        wire = CLIENT_PREFACE + h2_frame(4, b"\x00")[:-1]

        with self.assertRaisesRegex(ParseError, "truncated"):
            parse_client_prefix(wire)

    def test_rejects_invalid_settings_shape_and_duplicates(self):
        nonzero_stream = parse_client_prefix(
            CLIENT_PREFACE + h2_frame(4, b"", stream_id=1)
        )[0]
        with self.assertRaisesRegex(ParseError, "SETTINGS"):
            decode_settings(nonzero_stream)

        wrong_length = parse_client_prefix(
            CLIENT_PREFACE + h2_frame(4, b"\x00")
        )[0]
        with self.assertRaisesRegex(ParseError, "SETTINGS"):
            decode_settings(wrong_length)

        duplicates = parse_client_prefix(
            CLIENT_PREFACE
            + h2_frame(4, h2_settings((1, 1), (1, 2)))
        )[0]
        with self.assertRaisesRegex(ParseError, "duplicate SETTINGS"):
            decode_settings(duplicates)

    def test_rejects_invalid_window_update_increment(self):
        zero = parse_client_prefix(
            CLIENT_PREFACE + h2_frame(8, b"\x00\x00\x00\x00")
        )[0]
        with self.assertRaisesRegex(ParseError, "WINDOW_UPDATE"):
            decode_window_update(zero)

        reserved = parse_client_prefix(
            CLIENT_PREFACE + h2_frame(8, b"\x80\x00\x00\x01")
        )[0]
        with self.assertRaisesRegex(ParseError, "WINDOW_UPDATE"):
            decode_window_update(reserved)


if __name__ == "__main__":
    unittest.main()
