import io
import json
import unittest

from foxreq import WorkerError
from foxreq._ipc import read_frame, write_frame


MEBIBYTE = 1024 * 1024


class ShortReader:
    def __init__(self, data):
        self._buffer = io.BytesIO(data)

    def read(self, amount):
        return self._buffer.read(min(amount, 3))


class ShortWriter:
    def __init__(self):
        self.buffer = bytearray()

    def write(self, data):
        amount = min(len(data), 3)
        self.buffer.extend(data[:amount])
        return amount

    def flush(self):
        return None


class IpcFrameTests(unittest.TestCase):
    def test_round_trip_uses_canonical_json_and_raw_body(self):
        writer = ShortWriter()
        write_frame(writer, {"kind": "request", "id": 7}, b"\x00body")

        encoded = bytes(writer.buffer)
        metadata_length = int.from_bytes(encoded[:8], "big")
        metadata = encoded[8 : 8 + metadata_length]
        self.assertEqual(
            metadata,
            json.dumps(
                {"id": 7, "kind": "request"},
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8"),
        )
        self.assertTrue(encoded.endswith(b"\x00body"))

        decoded, body = read_frame(ShortReader(encoded), MEBIBYTE, 16 * MEBIBYTE)
        self.assertEqual(decoded, {"kind": "request", "id": 7})
        self.assertEqual(body, b"\x00body")

    def test_rejects_lengths_before_allocating_payloads(self):
        oversized_metadata = (MEBIBYTE + 1).to_bytes(8, "big")
        with self.assertRaises(WorkerError):
            read_frame(io.BytesIO(oversized_metadata), MEBIBYTE, 16 * MEBIBYTE)

        metadata = b"{}"
        oversized_body = (
            len(metadata).to_bytes(8, "big")
            + metadata
            + (16 * MEBIBYTE + 1).to_bytes(8, "big")
        )
        with self.assertRaises(WorkerError):
            read_frame(io.BytesIO(oversized_body), MEBIBYTE, 16 * MEBIBYTE)

    def test_rejects_truncation_invalid_utf8_json_and_metadata_type(self):
        cases = (
            b"\x00" * 7,
            (4).to_bytes(8, "big") + b"{}",
            (1).to_bytes(8, "big") + b"\xff" + (0).to_bytes(8, "big"),
            (1).to_bytes(8, "big") + b"{" + (0).to_bytes(8, "big"),
            (2).to_bytes(8, "big") + b"[]" + (0).to_bytes(8, "big"),
        )
        for frame in cases:
            with self.subTest(frame=frame), self.assertRaises(WorkerError):
                read_frame(io.BytesIO(frame), MEBIBYTE, 16 * MEBIBYTE)

    def test_write_rejects_non_dict_or_non_json_metadata(self):
        for metadata in ([], {"bad": object()}, {"nan": float("nan")}):
            with self.subTest(metadata=metadata), self.assertRaises(WorkerError):
                write_frame(io.BytesIO(), metadata, b"")

    def test_write_accepts_only_bytes_like_bodies(self):
        for body in (3, [1, 2, 3], "body", object()):
            with self.subTest(body=body), self.assertRaises(WorkerError):
                write_frame(io.BytesIO(), {"kind": "test"}, body)

        buffer = io.BytesIO()
        write_frame(buffer, {"kind": "test"}, memoryview(b"body"))
        buffer.seek(0)
        _metadata, body = read_frame(buffer, MEBIBYTE, 16 * MEBIBYTE)
        self.assertEqual(body, b"body")


if __name__ == "__main__":
    unittest.main()
