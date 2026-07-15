import os
import socket
import subprocess
import sys
import time
import unittest
from contextlib import contextmanager
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class ExampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runtime = os.environ.get("FOXREQ_NSS_RUNTIME_DIR")
        fixture = os.environ.get("FOXREQ_PY_TEST_FIXTURE")
        if not runtime or not fixture:
            raise unittest.SkipTest("real example fixture environment is absent")
        cls.runtime = Path(runtime).resolve()
        cls.fixture = Path(fixture).resolve()

    @contextmanager
    def scenario(self, scenario, methods, targets, bodies, headers=()):
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
            str(len(methods)),
            "--timeout",
            "8",
        ]
        for method in methods:
            command.extend(("--expect-method", method))
        for target in targets:
            command.extend(("--expect-target", target))
        for body in bodies:
            command.extend(("--expect-body-hex", body.hex()))
        for header in headers:
            command.extend(("--expect-header", header))
        process = subprocess.Popen(
            command,
            cwd=str(REPOSITORY),
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
                "example fixture failed: {}{}".format(stdout, stderr),
            )
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()

    def test_basic_example_runs_get_and_json_post(self):
        body = b'{"ok":true}'
        with self.scenario(
            "fixed",
            ("GET", "POST"),
            ("/basic", "/basic"),
            (b"", body),
            ("X-Order:first", "X-Order:second"),
        ) as origin:
            completed = subprocess.run(
                [
                    sys.executable,
                    "examples/python_basic.py",
                    "--url",
                    origin + "/basic",
                    "--runtime",
                    str(self.runtime),
                    "--ca-pem",
                    str(self.fixture / "ca.pem"),
                ],
                cwd=str(REPOSITORY),
                capture_output=True,
                text=True,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.count("status_code=200"), 2)
        self.assertEqual(completed.stdout.count("http_version=HTTP/1.1"), 2)
        self.assertEqual(completed.stdout.count("body_length=2"), 2)
        self.assertNotIn("Set-Cookie", completed.stdout)

    def test_session_example_reuses_one_connection(self):
        with self.scenario(
            "keepalive-two",
            ("GET", "GET"),
            ("/one", "/two"),
            (b"", b""),
        ) as origin:
            completed = subprocess.run(
                [
                    sys.executable,
                    "examples/python_session.py",
                    "--origin",
                    origin,
                    "--runtime",
                    str(self.runtime),
                    "--ca-pem",
                    str(self.fixture / "ca.pem"),
                ],
                cwd=str(REPOSITORY),
                capture_output=True,
                text=True,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("body_length=3", completed.stdout)

    def test_examples_reject_non_loopback_without_explicit_authorization(self):
        completed = subprocess.run(
            [
                sys.executable,
                "examples/python_basic.py",
                "--url",
                "https://example.com/",
                "--runtime",
                str(self.runtime),
                "--ca-pem",
                str(self.fixture / "ca.pem"),
            ],
            cwd=str(REPOSITORY),
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("explicit authorization flag", completed.stderr)


if __name__ == "__main__":
    unittest.main()
