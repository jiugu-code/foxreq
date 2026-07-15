import os
import socket
import subprocess
import sys
import time
import unittest
from contextlib import contextmanager
from pathlib import Path

import foxreq


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class RealApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runtime = os.environ.get("FOXREQ_NSS_RUNTIME_DIR")
        fixture = os.environ.get("FOXREQ_PY_TEST_FIXTURE")
        if not runtime or not fixture:
            raise unittest.SkipTest("real Python API fixture environment is absent")
        cls.runtime = Path(runtime).resolve()
        cls.fixture = Path(fixture).resolve()
        required = ("ca.pem", "server.pem", "server.key")
        if not cls.runtime.is_dir() or not all(
            (cls.fixture / name).is_file() for name in required
        ):
            raise unittest.SkipTest("real Python API fixture files are absent")

    @contextmanager
    def scenario(
        self,
        scenario,
        count,
        methods,
        targets,
        bodies,
        expected_headers=(),
    ):
        port = _free_port()
        command = [
            sys.executable,
            "-m",
            "tests.fixtures.http1_scenarios",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--certificate",
            str(self.fixture / "server.pem"),
            "--private-key",
            str(self.fixture / "server.key"),
            "--scenario",
            scenario,
            "--count",
            str(count),
            "--timeout",
            "8",
            "--stall-seconds",
            "1",
        ]
        for method in methods:
            command.extend(("--expect-method", method))
        for target in targets:
            command.extend(("--expect-target", target))
        for body in bodies:
            command.extend(("--expect-body-hex", body.hex()))
        for header in expected_headers:
            command.extend(("--expect-header", header))
        process = subprocess.Popen(
            command,
            cwd=str(Path(__file__).resolve().parents[2]),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            time.sleep(0.4)
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                self.fail("scenario fixture exited early: {}{}".format(stdout, stderr))
            yield "https://127.0.0.1:{}".format(port)
            try:
                stdout, stderr = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                self.fail("scenario fixture did not finish")
            self.assertEqual(
                process.returncode,
                0,
                "scenario fixture failed: {}{}".format(stdout, stderr),
            )
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()

    @contextmanager
    def handshake_server(self):
        port = _free_port()
        command = [
            sys.executable,
            "-m",
            "tests.fixtures.tls_server",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--certificate",
            str(self.fixture / "server.pem"),
            "--private-key",
            str(self.fixture / "server.key"),
            "--count",
            "1",
            "--timeout",
            "8",
        ]
        process = subprocess.Popen(
            command,
            cwd=str(Path(__file__).resolve().parents[2]),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            time.sleep(0.4)
            yield "https://127.0.0.1:{}".format(port)
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(
                process.returncode,
                0,
                "TLS fixture failed: {}{}".format(stdout, stderr),
            )
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()

    def test_top_level_get_returns_the_public_response_model(self):
        with self.scenario(
            "fixed",
            1,
            ("GET",),
            ("/fixed?existing=1&x=one&x=two",),
            (b"",),
            ("X-Order:first", "X-Order:second"),
        ) as origin:
            response = foxreq.get(
                origin + "/fixed?existing=1",
                params=(("x", "one"), ("x", "two")),
                headers=(("X-Order", "first"), ("X-Order", "second")),
                runtime_dir=self.runtime,
                verify=self.fixture / "ca.pem",
            )

        self.assertIsInstance(response, foxreq.Response)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.reason, "OK")
        self.assertEqual(response.http_version, "HTTP/1.1")
        self.assertEqual(response.content, b"OK")
        self.assertEqual(response.headers.get_all("set-cookie"), ("a=1", "b=2"))

    def test_json_post_crosses_the_native_worker(self):
        body = '{"message":"中文"}'.encode("utf-8")
        with self.scenario(
            "informational",
            1,
            ("POST",),
            ("/submit",),
            (body,),
            ("X-Order:first", "X-Order:second"),
        ) as origin:
            response = foxreq.post(
                origin + "/submit",
                headers=(("X-Order", "first"), ("X-Order", "second")),
                json={"message": "中文"},
                runtime_dir=self.runtime,
                verify=self.fixture / "ca.pem",
            )
        self.assertEqual(response.content, b"OK")

    def test_session_reuses_one_tls_connection(self):
        with self.scenario(
            "keepalive-two",
            2,
            ("GET", "GET"),
            ("/one", "/two"),
            (b"", b""),
        ) as origin:
            with foxreq.Session(
                runtime_dir=self.runtime,
                verify=self.fixture / "ca.pem",
            ) as session:
                first = session.get(origin + "/one")
                second = session.get(origin + "/two")
        self.assertEqual(first.content, b"one")
        self.assertEqual(second.content, b"two")

    def test_chunked_response_and_timeout_mapping(self):
        with self.scenario(
            "chunked", 1, ("GET",), ("/chunked",), (b"",)
        ) as origin:
            response = foxreq.get(
                origin + "/chunked",
                runtime_dir=self.runtime,
                verify=self.fixture / "ca.pem",
            )
        self.assertEqual(response.content, b"OK")

        with self.scenario(
            "stall-read", 1, ("GET",), ("/stall",), (b"",)
        ) as origin:
            with self.assertRaises(foxreq.Timeout):
                foxreq.get(
                    origin + "/stall",
                    runtime_dir=self.runtime,
                    verify=self.fixture / "ca.pem",
                    timeout=0.15,
                )

    def test_untrusted_certificate_maps_to_certificate_error(self):
        with self.handshake_server() as origin:
            with self.assertRaises(foxreq.CertificateError):
                foxreq.get(
                    origin + "/untrusted",
                    runtime_dir=self.runtime,
                    verify=True,
                    timeout=2,
                )


if __name__ == "__main__":
    unittest.main()
