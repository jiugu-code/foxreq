import json
import socket
import ssl
import tempfile
import unittest
from pathlib import Path

from scripts.capture.capture_foxreq import FoxreqCaptureError, capture_foxreq
from tests.fixtures.generate_certs import generate_fixture


class CaptureFoxreqTests(unittest.TestCase):
    def test_runs_one_serial_resumption_process_against_loopback(self):
        repository = Path(__file__).parents[2]
        fixture_root = repository / "artifacts" / "fixtures" / "certs"
        capture_root = repository / "artifacts" / "captures"
        fixture_root.mkdir(parents=True, exist_ok=True)
        capture_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="foxreq-capture-cert-", dir=str(fixture_root)
        ) as certificate_directory, tempfile.TemporaryDirectory(
            prefix="foxreq-capture-raw-", dir=str(capture_root)
        ) as capture_directory:
            fixture = Path(certificate_directory) / "material"
            generate_fixture(fixture, repository=repository)
            runtime = Path(capture_directory) / "runtime"
            runtime.mkdir()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            calls = []

            def runner(command, cwd, env, timeout):
                calls.append((command, cwd, env, timeout))
                context = ssl._create_unverified_context()
                context.set_alpn_protocols(["http/1.1"])
                for _ in range(3):
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

                class Completed:
                    returncode = 0

                return Completed()

            output = Path(capture_directory) / "foxreq-resumed.jsonl"
            manifest = capture_foxreq(
                repository=repository,
                runtime=runtime,
                ca_der=fixture / "ca.der",
                certificate=fixture / "server.pem",
                private_key=fixture / "server.key",
                raw_output=output,
                host="127.0.0.1",
                port=port,
                mode="resumed",
                count=3,
                timeout=3.0,
                cargo="cargo-test",
                minimum_available_memory=1024,
                memory_reader=lambda: 2048,
                runner=runner,
            )

            self.assertEqual(1, len(calls))
            command, cwd, environment, timeout = calls[0]
            self.assertEqual(str(repository), cwd)
            self.assertEqual("1", environment["CARGO_BUILD_JOBS"])
            self.assertEqual(str(runtime.resolve()), environment["FOXREQ_NSS_RUNTIME_DIR"])
            self.assertIn("capture_tls", command)
            self.assertEqual(3.0, timeout)
            records = [json.loads(line) for line in output.read_text().splitlines()]
            self.assertEqual(["cold", "resumed", "resumed"], [item["label"] for item in records])
            self.assertEqual("resumed", manifest["mode"])
            self.assertEqual(3, manifest["count"])
            self.assertEqual(2048, manifest["available_memory_before_bytes"])
            self.assertEqual(1024, manifest["minimum_available_memory_bytes"])

            blocked_output = Path(capture_directory) / "blocked.jsonl"
            with self.assertRaisesRegex(
                FoxreqCaptureError,
                "available physical memory is below the capture limit",
            ):
                capture_foxreq(
                    repository=repository,
                    runtime=runtime,
                    ca_der=fixture / "ca.der",
                    certificate=fixture / "server.pem",
                    private_key=fixture / "server.key",
                    raw_output=blocked_output,
                    host="127.0.0.1",
                    port=port,
                    mode="cold",
                    count=1,
                    timeout=3.0,
                    cargo="cargo-test",
                    minimum_available_memory=4096,
                    memory_reader=lambda: 2048,
                    runner=runner,
                )
            self.assertFalse(blocked_output.exists())


if __name__ == "__main__":
    unittest.main()
