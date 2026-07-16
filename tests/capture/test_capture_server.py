import hashlib
import io
import json
import socket
import ssl
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from scripts.capture.capture_firefox import (
    FirefoxCaptureError,
    _launch,
    _print_capture_progress,
    _require_available_memory,
    capture_with_local_server,
    orchestrate_capture,
    render_certificate_override,
    render_user_js,
    validate_capture_url,
    validate_manifest_output,
    verify_firefox_binary,
)
from tests.fixtures.tls_capture_server import (
    browser_sequence_response,
    capture_tls_connection,
    capture_label,
    peek_client_hello,
)
from tests.fixtures.generate_certs import generate_fixture

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
    def test_memory_gate_waits_for_bounded_recovery_before_launch(self):
        with mock.patch(
            "scripts.capture.capture_firefox._available_physical_memory",
            side_effect=[512, 2048],
        ), mock.patch("scripts.capture.capture_firefox.time.sleep") as sleep:
            available = _require_available_memory(1024, wait_timeout=1.0)

        self.assertEqual(2048, available)
        sleep.assert_called_once()

    def test_capture_progress_is_one_bounded_json_event(self):
        output = io.StringIO()
        with mock.patch("sys.stderr", output):
            _print_capture_progress({"mode": "cold", "completed": 1, "total": 1})

        event = json.loads(output.getvalue())
        self.assertEqual("firefox_capture_progress", event["event"])
        self.assertEqual(1, event["completed"])

    def test_headless_launch_always_requests_a_screenshot_navigation(self):
        class Process:
            def terminate(self):
                pass

            def kill(self):
                pass

            def wait(self, timeout):
                self.timeout = timeout
                return 0

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "firefox.exe"
            binary.write_bytes(b"pinned firefox")
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            profile = root / "profile"
            profile.mkdir()
            process = Process()
            with mock.patch(
                "scripts.capture.capture_firefox.subprocess.Popen",
                return_value=process,
            ) as popen:
                result = _launch(
                    binary=binary,
                    expected_sha256=digest,
                    profile=profile,
                    urls=["https://127.0.0.1:8443/"],
                    timeout=2.0,
                    sequence_start=1,
                    expected_connections=1,
                    capture_waiter=lambda _count, _timeout: True,
                )

            command = popen.call_args.args[0]
            self.assertIn("--no-remote", command)
            self.assertNotIn("--new-instance", command)
            self.assertIn("--screenshot", command)
            self.assertIn(str((profile / "capture.png").resolve()), command)
            self.assertTrue(result["terminated_after_capture"])

    def test_peeks_a_client_hello_without_consuming_tls_bytes(self):
        wire = synthetic_client_hello(split_at=23)
        client, server = socket.socketpair()
        try:
            client.sendall(wire)

            self.assertEqual(wire, peek_client_hello(server, timeout=1.0))
            self.assertEqual(wire, server.recv(len(wire)))
        finally:
            client.close()
            server.close()

    def test_peek_waits_for_fragmented_client_hello_bytes(self):
        wire = synthetic_client_hello(split_at=19)
        client, server = socket.socketpair()

        def send():
            client.sendall(wire[:11])
            threading.Event().wait(0.02)
            client.sendall(wire[11:])

        thread = threading.Thread(target=send)
        thread.start()
        try:
            self.assertEqual(wire, peek_client_hello(server, timeout=1.0))
            self.assertEqual(wire, server.recv(len(wire)))
        finally:
            client.close()
            server.close()
            thread.join(timeout=1.0)

    def test_browser_sequence_responses_force_ordered_new_connections(self):
        first = browser_sequence_response(1, 3)
        second = browser_sequence_response(2, 3)
        final = browser_sequence_response(3, 3)

        self.assertIn(b'/.well-known/foxreq-capture/2.js', first)
        self.assertIn(b'/.well-known/foxreq-capture/3.js', second)
        self.assertNotIn(b'/.well-known/foxreq-capture/4.js', final)
        for response in (first, second, final):
            self.assertIn(b'Connection: close\r\n', response)

    def test_resumption_sequence_labels_only_the_bootstrap_as_cold(self):
        self.assertEqual("cold", capture_label("cold", 1))
        self.assertEqual("cold", capture_label("cold", 9))
        self.assertEqual("cold", capture_label("resumed", 1))
        self.assertEqual("resumed", capture_label("resumed", 2))

    def test_captures_then_completes_a_real_local_tls_exchange(self):
        repository = Path(__file__).parents[2]
        fixture_root = repository / "artifacts" / "fixtures" / "certs"
        fixture_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="tls-capture-test-", dir=str(fixture_root)
        ) as directory:
            fixture = Path(directory) / "material"
            generate_fixture(fixture, repository=repository)
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.set_alpn_protocols(["http/1.1"])
            server_context.load_cert_chain(
                fixture / "server.pem", fixture / "server.key"
            )
            client_context = ssl._create_unverified_context()
            client_context.set_alpn_protocols(["http/1.1"])
            client, server = socket.socketpair()
            output = io.StringIO()
            failure = []

            def serve():
                try:
                    capture_tls_connection(
                        server,
                        server_context,
                        output,
                        sequence=1,
                        count=1,
                        mode="cold",
                        timeout=2.0,
                    )
                except Exception as error:  # pragma: no cover - surfaced below
                    failure.append(error)

            thread = threading.Thread(target=serve)
            thread.start()
            try:
                with client_context.wrap_socket(
                    client, server_hostname="127.0.0.1"
                ) as tls:
                    tls.sendall(
                        b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
                    )
                    response = bytearray()
                    while True:
                        chunk = tls.recv(4096)
                        if not chunk:
                            break
                        response.extend(chunk)
            finally:
                client.close()
                thread.join(timeout=3.0)
                server.close()

            self.assertFalse(thread.is_alive())
            self.assertEqual([], failure)
            self.assertIn(b"HTTP/1.1 200 OK", response)
            record = json.loads(output.getvalue())
            self.assertEqual("cold", record["label"])
            self.assertEqual("capture-000001", record["connection_id"])
            self.assertTrue(record["record_hex"].startswith("16"))

    def test_certificate_override_is_profile_local_and_deterministic(self):
        certificate_der = b"ephemeral local certificate DER"
        digest = hashlib.sha256(certificate_der).hexdigest().upper()
        fingerprint = ":".join(
            digest[offset : offset + 2] for offset in range(0, len(digest), 2)
        )

        rendered = render_certificate_override(
            "127.0.0.1", 8443, certificate_der
        )

        self.assertIn("PSM Certificate Override Settings file", rendered)
        self.assertIn(
            "127.0.0.1:8443\tOID.2.16.840.1.101.3.4.2.1\t{}\t\n".format(
                fingerprint
            ),
            rendered,
        )

    def test_resumed_firefox_capture_uses_one_profile_and_one_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "firefox.exe"
            binary.write_bytes(b"pinned firefox")
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            profiles = []

            def launch(
                _binary,
                _expected_sha256,
                profile,
                urls,
                _timeout,
                sequence_start,
                expected_connections,
                _capture_waiter,
            ):
                profiles.append(profile)
                self.assertEqual(["https://127.0.0.1:8443/"], urls)
                self.assertTrue((profile / "user.js").is_file())
                self.assertTrue((profile / "cert_override.txt").is_file())
                self.assertEqual(1, sequence_start)
                self.assertEqual(3, expected_connections)
                return {
                    "sequence_start": 1,
                    "expected_connections": 3,
                    "timed_out": False,
                    "exit_code": 0,
                }

            with mock.patch(
                "scripts.capture.capture_firefox._launch", side_effect=launch
            ) as patched:
                manifest = orchestrate_capture(
                    binary=binary,
                    expected_sha256=digest,
                    url="https://127.0.0.1:8443/",
                    preferences={"network.trr.mode": 5},
                    mode="resumed",
                    count=3,
                    timeout=2.0,
                    certificate_der=b"server certificate DER",
                )

            self.assertEqual(1, patched.call_count)
            self.assertEqual(1, len(profiles))
            self.assertEqual(3, manifest["count"])

    def test_firefox_capture_stops_before_launch_when_memory_is_low(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "firefox.exe"
            binary.write_bytes(b"pinned firefox")
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            with mock.patch(
                "scripts.capture.capture_firefox._available_physical_memory",
                return_value=512 * 1024 * 1024,
            ), mock.patch("scripts.capture.capture_firefox._launch") as launch:
                with self.assertRaisesRegex(FirefoxCaptureError, "memory"):
                    orchestrate_capture(
                        binary=binary,
                        expected_sha256=digest,
                        url="https://127.0.0.1:8443/",
                        preferences={},
                        mode="cold",
                        count=1,
                        timeout=2.0,
                        minimum_available_memory=1024 * 1024 * 1024,
                    )
            launch.assert_not_called()

    def test_cold_capture_retries_one_failed_browser_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "firefox.exe"
            binary.write_bytes(b"pinned firefox")
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            failed = {
                "sequence_start": 1,
                "expected_connections": 1,
                "timed_out": True,
                "terminated_after_capture": False,
                "exit_code": 1,
                "stderr_tail": "transient child launch failure",
            }
            succeeded = {
                "sequence_start": 1,
                "expected_connections": 1,
                "timed_out": False,
                "terminated_after_capture": True,
                "exit_code": 0,
            }
            with mock.patch(
                "scripts.capture.capture_firefox._launch",
                side_effect=[failed, succeeded],
            ) as launch:
                manifest = orchestrate_capture(
                    binary=binary,
                    expected_sha256=digest,
                    url="https://127.0.0.1:8443/",
                    preferences={},
                    mode="cold",
                    count=1,
                    timeout=2.0,
                    launch_attempts=2,
                )

            self.assertEqual(2, launch.call_count)
            self.assertEqual(2, len(manifest["launches"]))
            self.assertTrue(manifest["launches"][-1]["terminated_after_capture"])

    def test_local_capture_orchestrator_collects_a_resumption_sequence(self):
        repository = Path(__file__).parents[2]
        fixture_root = repository / "artifacts" / "fixtures" / "certs"
        capture_root = repository / "artifacts" / "captures"
        fixture_root.mkdir(parents=True, exist_ok=True)
        capture_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="firefox-suite-cert-", dir=str(fixture_root)
        ) as certificate_directory, tempfile.TemporaryDirectory(
            prefix="firefox-suite-raw-", dir=str(capture_root)
        ) as capture_directory:
            fixture = Path(certificate_directory) / "material"
            generate_fixture(fixture, repository=repository)
            binary = Path(capture_directory) / "firefox.exe"
            binary.write_bytes(b"pinned firefox")
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]

            def launch(
                _binary,
                _expected_sha256,
                _profile,
                _urls,
                _timeout,
                _sequence_start,
                expected_connections,
                _capture_waiter,
            ):
                context = ssl._create_unverified_context()
                context.set_alpn_protocols(["http/1.1"])
                for _ in range(expected_connections):
                    with socket.create_connection(
                        ("127.0.0.1", port), timeout=2.0
                    ) as connection, context.wrap_socket(
                        connection, server_hostname="127.0.0.1"
                    ) as tls:
                        tls.sendall(
                            b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                            b"Connection: close\r\n\r\n"
                        )
                        while tls.recv(4096):
                            pass
                return {
                    "sequence_start": 1,
                    "expected_connections": expected_connections,
                    "timed_out": False,
                    "exit_code": 0,
                }

            raw_output = Path(capture_directory) / "resumed.jsonl"
            with mock.patch(
                "scripts.capture.capture_firefox._launch", side_effect=launch
            ):
                manifest = capture_with_local_server(
                    binary=binary,
                    expected_sha256=digest,
                    url="https://127.0.0.1:{}/".format(port),
                    preferences={"network.trr.mode": 5},
                    mode="resumed",
                    count=3,
                    timeout=2.0,
                    certificate=fixture / "server.pem",
                    private_key=fixture / "server.key",
                    certificate_der=(fixture / "server.der").read_bytes(),
                    raw_output=raw_output,
                )

            records = [json.loads(line) for line in raw_output.read_text().splitlines()]
            self.assertEqual(3, manifest["count"])
            self.assertEqual(["cold", "resumed", "resumed"], [item["label"] for item in records])

    def test_local_capture_reports_server_failure_before_launch_timeout(self):
        repository = Path(__file__).parents[2]
        capture_root = repository / "artifacts" / "captures"
        capture_root.mkdir(parents=True, exist_ok=True)

        class FailingServer:
            instance = None

            def __init__(self, host, port, **_kwargs):
                self.host = host
                self.port = port
                self.bound_port = port
                self.ready = threading.Event()
                self.release = threading.Event()
                FailingServer.instance = self

            def serve(self, _count):
                self.ready.set()
                self.release.wait(timeout=1.0)
                raise RuntimeError("server root cause")

            def wait_for_completed(self, _count, _timeout):
                return False

        def fail_launch(**_kwargs):
            FailingServer.instance.release.set()
            threading.Event().wait(0.02)
            raise FirefoxCaptureError("generic launch timeout")

        with tempfile.TemporaryDirectory(
            prefix="firefox-failure-", dir=str(capture_root)
        ) as directory, mock.patch(
            "scripts.capture.capture_firefox.TlsCaptureServer", FailingServer
        ), mock.patch(
            "scripts.capture.capture_firefox.orchestrate_capture",
            side_effect=fail_launch,
        ):
            output = Path(directory) / "failure.jsonl"
            with self.assertRaisesRegex(
                FirefoxCaptureError, "local TLS capture server failed"
            ) as raised:
                capture_with_local_server(
                    binary=Path(directory) / "firefox.exe",
                    expected_sha256="0" * 64,
                    url="https://127.0.0.1:8443/",
                    preferences={},
                    mode="cold",
                    count=1,
                    timeout=1.0,
                    certificate=Path(directory) / "server.pem",
                    private_key=Path(directory) / "server.key",
                    certificate_der=b"certificate",
                    raw_output=output,
                )

            self.assertIsInstance(raised.exception.__cause__, RuntimeError)
            self.assertEqual("server root cause", str(raised.exception.__cause__))

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
