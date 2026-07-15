import hashlib
import io
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from scripts.capture.capture_firefox import (
    FirefoxCaptureError,
    render_user_js,
    validate_capture_url,
    validate_manifest_output,
    verify_firefox_binary,
)

from tests.fixtures.capture_server import (
    CaptureError,
    CaptureIdSequence,
    ClientHelloAccumulator,
    capture_socket,
    make_capture_record,
    validate_bind_host,
    validate_capture_output,
    write_jsonl_record,
)
from tests.wire.helpers import synthetic_client_hello


class CaptureServerTests(unittest.TestCase):
    def test_reassembles_records_and_arbitrary_recv_fragments(self):
        wire = synthetic_client_hello(split_at=19)

        for split in range(len(wire) + 1):
            accumulator = ClientHelloAccumulator()
            first_complete = accumulator.feed(wire[:split])
            self.assertEqual(split == len(wire), first_complete)
            if not first_complete:
                self.assertTrue(accumulator.feed(wire[split:]))
            self.assertEqual(wire, accumulator.result())

    def test_stops_before_application_records_in_the_same_recv(self):
        wire = synthetic_client_hello(split_at=17)
        application = b"\x17\x03\x03\x00\x06secret"
        accumulator = ClientHelloAccumulator()

        self.assertTrue(accumulator.feed(wire + application))

        self.assertEqual(wire, accumulator.result())
        self.assertNotIn(b"secret", accumulator.result())

        one_record = synthetic_client_hello()
        declared = int.from_bytes(one_record[3:5], "big")
        mixed_record = (
            one_record[:3]
            + (declared + 6).to_bytes(2, "big")
            + one_record[5:]
            + b"secret"
        )
        accumulator = ClientHelloAccumulator()
        self.assertTrue(accumulator.feed(mixed_record))
        self.assertEqual(one_record, accumulator.result())
        self.assertNotIn(b"secret", accumulator.result())

    def test_socket_capture_reports_early_close_and_timeout(self):
        client, server = socket.socketpair()
        try:
            client.sendall(synthetic_client_hello()[:11])
            client.close()
            with self.assertRaisesRegex(CaptureError, "closed") as closed:
                capture_socket(server, timeout=0.2)
            self.assertEqual("early_close", closed.exception.kind)
        finally:
            client.close()
            server.close()

        client, server = socket.socketpair()
        try:
            with self.assertRaisesRegex(CaptureError, "timed out") as timeout:
                capture_socket(server, timeout=0.01)
            self.assertEqual("timeout", timeout.exception.kind)
        finally:
            client.close()
            server.close()

    def test_socket_capture_accepts_fragmented_sends(self):
        wire = synthetic_client_hello(split_at=23)
        client, server = socket.socketpair()

        def send():
            for offset in range(0, len(wire), 3):
                client.sendall(wire[offset : offset + 3])
            client.close()

        thread = threading.Thread(target=send)
        thread.start()
        try:
            self.assertEqual(wire, capture_socket(server, timeout=1.0, recv_size=7))
        finally:
            server.close()
            thread.join(timeout=1.0)

    def test_rejects_record_and_aggregate_size_overruns(self):
        wire = synthetic_client_hello()
        accumulator = ClientHelloAccumulator(max_capture_bytes=len(wire) - 1)
        with self.assertRaisesRegex(CaptureError, "limit") as aggregate:
            accumulator.feed(wire)
        self.assertEqual("size_limit", aggregate.exception.kind)

        oversized_header = b"\x16\x03\x01\xff\xff"
        accumulator = ClientHelloAccumulator(max_record_bytes=1024)
        with self.assertRaisesRegex(CaptureError, "record") as record:
            accumulator.feed(oversized_header)
        self.assertEqual("record_limit", record.exception.kind)

    def test_connection_ids_and_jsonl_are_deterministic(self):
        sequence = CaptureIdSequence()
        self.assertEqual("capture-000001", sequence.next())
        self.assertEqual("capture-000002", sequence.next())

        wire = synthetic_client_hello()
        record = make_capture_record("capture-000001", "cold", wire)
        output = io.StringIO()
        write_jsonl_record(output, record)
        decoded = json.loads(output.getvalue())

        self.assertEqual(1, decoded["schema_version"])
        self.assertEqual("capture-000001", decoded["connection_id"])
        self.assertEqual("cold", decoded["label"])
        self.assertEqual(wire.hex(), decoded["record_hex"])
        self.assertEqual(len(wire), decoded["length"])
        self.assertEqual(hashlib.sha256(wire).hexdigest(), decoded["sha256"])
        self.assertEqual(output.getvalue().count("\n"), 1)

    def test_non_loopback_bind_requires_explicit_authorization(self):
        self.assertEqual("127.0.0.1", validate_bind_host("127.0.0.1", False))
        self.assertEqual("::1", validate_bind_host("::1", False))
        with self.assertRaisesRegex(ValueError, "non-loopback"):
            validate_bind_host("0.0.0.0", False)
        self.assertEqual("0.0.0.0", validate_bind_host("0.0.0.0", True))

    def test_firefox_binary_hash_and_loopback_url_are_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "firefox-test.bin"
            binary.write_bytes(b"pinned firefox binary")
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            self.assertEqual(digest, verify_firefox_binary(binary, digest))
            with self.assertRaisesRegex(FirefoxCaptureError, "hash"):
                verify_firefox_binary(binary, "0" * 64)

        self.assertEqual(
            "https://127.0.0.1:8443/",
            validate_capture_url("https://127.0.0.1:8443/"),
        )
        with self.assertRaisesRegex(FirefoxCaptureError, "loopback"):
            validate_capture_url("https://example.test/")
        with self.assertRaisesRegex(FirefoxCaptureError, "HTTPS"):
            validate_capture_url("http://127.0.0.1:8443/")

    def test_firefox_preferences_are_sorted_and_type_bounded(self):
        rendered = render_user_js({"z.enabled": False, "a.mode": 5})
        self.assertEqual(
            'user_pref("a.mode", 5);\nuser_pref("z.enabled", false);\n',
            rendered,
        )
        with self.assertRaisesRegex(FirefoxCaptureError, "preference"):
            render_user_js({"bad": ["not allowed"]})

    def test_raw_capture_and_manifest_outputs_are_confined_to_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            inside = repository / "artifacts" / "captures" / "capture.jsonl"
            outside = repository / "capture.jsonl"

            self.assertEqual(
                inside.resolve(),
                validate_capture_output(inside, repository=repository),
            )
            self.assertEqual(
                inside.resolve(),
                validate_manifest_output(inside, repository=repository),
            )
            with self.assertRaisesRegex(ValueError, "artifacts/captures"):
                validate_capture_output(outside, repository=repository)
            with self.assertRaisesRegex(FirefoxCaptureError, "artifacts/captures"):
                validate_manifest_output(outside, repository=repository)


if __name__ == "__main__":
    unittest.main()
