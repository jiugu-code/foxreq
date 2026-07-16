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


@contextmanager
def _without_runtime_environment():
    names = (
        "FOXREQ_NSS_RUNTIME_DIR",
        "FOXREQ_RUNTIME_FIREFOX_140_ESR",
        "FOXREQ_RUNTIME_FIREFOX_152",
    )
    saved = {name: os.environ[name] for name in names if name in os.environ}
    for name in names:
        os.environ.pop(name, None)
    try:
        yield
    finally:
        for name in names:
            os.environ.pop(name, None)
        os.environ.update(saved)


class RealHttpTests(unittest.TestCase):
    @contextmanager
    def scenario(
        self,
        scenario,
        count,
        methods,
        targets,
        bodies,
        expected_headers=(),
        stall_seconds="0.5",
    ):
        port = _free_port()
        command = [
            sys.executable,
            "-m",
            "tests.fixtures.http1_scenarios",
            "--plain",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--scenario",
            scenario,
            "--count",
            str(count),
            "--timeout",
            "5",
            "--stall-seconds",
            stall_seconds,
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
            time.sleep(0.2)
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                self.fail("plain fixture exited early: {}{}".format(stdout, stderr))
            yield "http://127.0.0.1:{}".format(port)
            stdout, stderr = process.communicate(timeout=8)
            self.assertEqual(
                process.returncode,
                0,
                "plain fixture failed: {}{}".format(stdout, stderr),
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

    def test_get_json_post_duplicates_and_keepalive_reuse(self):
        body = '{"message":"中文"}'.encode("utf-8")
        with _without_runtime_environment(), self.scenario(
            "keepalive-two",
            2,
            ("GET", "POST"),
            ("/one", "/two"),
            (b"", body),
            ("X-Order:first", "X-Order:second"),
        ) as origin:
            with foxreq.Session(
                impersonate="firefox_140_esr",
                verify=False,
            ) as session:
                first = session.get(
                    origin + "/one",
                    headers=(("X-Order", "first"), ("X-Order", "second")),
                )
                second = session.post(
                    origin + "/two",
                    headers=(("X-Order", "first"), ("X-Order", "second")),
                    json={"message": "中文"},
                )

        self.assertEqual(first.content, b"one")
        self.assertEqual(second.content, b"two")
        self.assertEqual(first.headers.get_all("set-cookie"), ("a=1", "b=2"))

    def test_stalled_plain_response_maps_to_timeout(self):
        with _without_runtime_environment(), self.scenario(
            "stall-read",
            1,
            ("GET",),
            ("/stall",),
            (b"",),
        ) as origin:
            with self.assertRaises(foxreq.Timeout):
                foxreq.get(origin + "/stall", timeout=0.05, verify=False)


if __name__ == "__main__":
    unittest.main()
