import io
import os
import subprocess
import sys
import unittest
from unittest import mock

from foxreq import ClosedSessionError, ConfigurationError, Timeout, WorkerError
from foxreq._ipc import read_frame, write_frame
from foxreq._worker_session import ProfileWorkerSession


MEBIBYTE = 1024 * 1024


def _frame(metadata, body=b""):
    buffer = io.BytesIO()
    write_frame(buffer, metadata, body)
    return buffer.getvalue()


def _success_output(url="https://example.test/data"):
    return b"".join(
        (
            _frame({"kind": "ready"}),
            _frame(
                {
                    "kind": "response",
                    "id": 1,
                    "status": 200,
                    "reason": "OK",
                    "url": url,
                    "version": "HTTP/1.1",
                    "headers": [["Set-Cookie", "a=1"], ["Set-Cookie", "b=2"]],
                },
                b"OK",
            ),
            _frame({"kind": "closed"}),
        )
    )


class MemoryPipe:
    def __init__(self, data=b""):
        self._data = bytearray(data)
        self._position = 0
        self.closed = False

    def read(self, amount):
        if self.closed:
            return b""
        end = min(self._position + amount, len(self._data))
        chunk = bytes(self._data[self._position : end])
        self._position = end
        return chunk

    def write(self, data):
        if self.closed:
            raise BrokenPipeError("pipe is closed")
        self._data.extend(data)
        return len(data)

    def flush(self):
        return None

    def close(self):
        self.closed = True

    def bytes(self):
        return bytes(self._data)


class FakeProcess:
    def __init__(self, output=b"", returncode=None, pid=4321):
        self.stdin = MemoryPipe()
        self.stdout = MemoryPipe(output)
        self.returncode = returncode
        self.pid = pid
        self.terminated = 0
        self.killed = 0
        self.waited = 0

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.waited += 1
        if self.returncode is None:
            self.returncode = 0
        return self.returncode

    def terminate(self):
        self.terminated += 1
        self.returncode = -15

    def kill(self):
        self.killed += 1
        self.returncode = -9


class WorkerSessionTests(unittest.TestCase):
    def setUp(self):
        self.validate_runtime = mock.patch(
            "foxreq._worker_session.validate_runtime"
        ).start()
        self.addCleanup(mock.patch.stopall)

    def test_child_worker_initializes_requests_and_closes_one_native_session(self):
        from foxreq import _profile_worker

        anchors = (1).to_bytes(4, "big") + (6).to_bytes(4, "big") + b"anchor"
        input_bytes = b"".join(
            (
                _frame(
                    {
                        "kind": "init",
                        "runtime_dir": "C:/runtime/firefox_152",
                        "profile": "firefox_152",
                    },
                    anchors,
                ),
                _frame(
                    {
                        "kind": "request",
                        "id": 1,
                        "method": "POST",
                        "url": "https://example.test/data",
                        "headers": [["X-Order", "first"], ["X-Order", "second"]],
                        "timeout": 1.0,
                        "insecure": True,
                        "profile": "firefox_152",
                    },
                    b"\x00body",
                ),
                _frame({"kind": "close"}),
            )
        )

        class NativeResponse:
            status = 201
            reason = b"Created"
            url = "https://example.test/data"
            version = "HTTP/1.1"
            headers = [(b"Set-Cookie", b"a=1"), (b"Set-Cookie", b"b=2")]
            body = b"response"

        class NativeSession:
            created = []
            requests = []
            closed = 0

            def __init__(self, runtime_dir, trust_anchors, profile):
                type(self).created.append((runtime_dir, tuple(trust_anchors), profile))

            def request(self, method, url, headers, body, timeout, insecure):
                type(self).requests.append(
                    (method, url, tuple(headers), body, timeout, insecure)
                )
                return NativeResponse()

            def close(self):
                type(self).closed += 1

        output = io.BytesIO()
        with mock.patch.object(_profile_worker._foxreq, "NativeSession", NativeSession):
            exit_code = _profile_worker.run(io.BytesIO(input_bytes), output)

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            NativeSession.created,
            [("C:/runtime/firefox_152", (b"anchor",), "firefox_152")],
        )
        self.assertEqual(
            NativeSession.requests[0][2],
            ((b"X-Order", b"first"), (b"X-Order", b"second")),
        )
        self.assertEqual(NativeSession.requests[0][3], b"\x00body")
        self.assertTrue(NativeSession.requests[0][-1])
        self.assertEqual(NativeSession.closed, 1)

        output.seek(0)
        ready, ready_body = read_frame(output, MEBIBYTE, 16 * MEBIBYTE)
        response, response_body = read_frame(output, MEBIBYTE, 16 * MEBIBYTE)
        closed, closed_body = read_frame(output, MEBIBYTE, 16 * MEBIBYTE)
        self.assertEqual(ready, {"kind": "ready"})
        self.assertEqual(ready_body, b"")
        self.assertEqual(response["kind"], "response")
        self.assertEqual(response["status"], 201)
        self.assertEqual(response_body, b"response")
        self.assertEqual(closed, {"kind": "closed"})
        self.assertEqual(closed_body, b"")

    def test_windows_command_frames_order_and_idempotent_close(self):
        process = FakeProcess(_success_output())
        with mock.patch.object(
            sys, "platform", "win32"
        ), mock.patch.object(
            subprocess, "CREATE_NO_WINDOW", 0x08000000, create=True
        ), mock.patch(
            "foxreq._worker_session.subprocess.Popen", return_value=process
        ) as popen:
            session = ProfileWorkerSession(
                "C:/runtime/firefox_152",
                (b"anchor-one", b"anchor-two"),
                "firefox_152",
            )
            response = session.request(
                b"POST",
                "https://example.test/data",
                ((b"X-Order", b"first"), (b"X-Order", b"second")),
                b"\x00body",
                0.5,
                True,
            )
            session.close()
            session.close()

        command = popen.call_args.args[0]
        options = popen.call_args.kwargs
        self.assertEqual(
            command[:4],
            [sys.executable, "-I", "-m", "foxreq._profile_worker"],
        )
        self.assertEqual(options["creationflags"], 0x08000000)
        self.assertIs(options["stderr"], subprocess.DEVNULL)
        self.assertTrue(options["close_fds"])
        self.assertFalse(options["shell"])
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body, b"OK")
        self.assertEqual(
            response.headers,
            ((b"Set-Cookie", b"a=1"), (b"Set-Cookie", b"b=2")),
        )

        frames = io.BytesIO(process.stdin.bytes())
        init_metadata, init_body = read_frame(frames, MEBIBYTE, 16 * MEBIBYTE)
        request_metadata, request_body = read_frame(frames, MEBIBYTE, 16 * MEBIBYTE)
        close_metadata, close_body = read_frame(frames, MEBIBYTE, 16 * MEBIBYTE)
        self.assertEqual(init_metadata["kind"], "init")
        self.assertEqual(init_metadata["profile"], "firefox_152")
        self.assertIn(b"anchor-one", init_body)
        self.assertEqual(request_metadata["kind"], "request")
        self.assertEqual(
            request_metadata["headers"],
            [["X-Order", "first"], ["X-Order", "second"]],
        )
        self.assertTrue(request_metadata["insecure"])
        self.assertEqual(request_body, b"\x00body")
        self.assertEqual(close_metadata, {"kind": "close"})
        self.assertEqual(close_body, b"")
        self.assertEqual(process.terminated, 0)
        self.assertEqual(process.killed, 0)

    def test_runtime_is_validated_before_worker_process_starts(self):
        self.validate_runtime.side_effect = ConfigurationError(
            "Firefox runtime file does not match lock: nss3.dll"
        )
        session = ProfileWorkerSession(
            "C:/runtime/firefox_152",
            (),
            "firefox_152",
        )

        with mock.patch("foxreq._worker_session.subprocess.Popen") as popen:
            with self.assertRaisesRegex(ConfigurationError, "does not match"):
                session.request(
                    b"GET",
                    "https://example.test/",
                    (),
                    b"",
                    1.0,
                )

        self.validate_runtime.assert_called_once_with(
            "firefox_152", "C:/runtime/firefox_152"
        )
        popen.assert_not_called()

    def test_linux_library_path_is_child_only(self):
        process = FakeProcess(_success_output())
        original = os.environ.get("LD_LIBRARY_PATH")
        os.environ["LD_LIBRARY_PATH"] = "parent-library-path"
        try:
            with mock.patch.object(sys, "platform", "linux"), mock.patch(
                "foxreq._worker_session.subprocess.Popen", return_value=process
            ) as popen:
                session = ProfileWorkerSession(
                    "/opt/foxreq/runtime",
                    (),
                    "firefox_152",
                )
                session.request(
                    b"GET",
                    "https://example.test/data",
                    (),
                    b"",
                    1.0,
                    False,
                )
                session.close()

            child_path = popen.call_args.kwargs["env"]["LD_LIBRARY_PATH"]
            self.assertEqual(
                child_path,
                "/opt/foxreq/runtime" + os.pathsep + "parent-library-path",
            )
            self.assertEqual(os.environ["LD_LIBRARY_PATH"], "parent-library-path")
            self.assertNotIn("creationflags", popen.call_args.kwargs)
        finally:
            if original is None:
                os.environ.pop("LD_LIBRARY_PATH", None)
            else:
                os.environ["LD_LIBRARY_PATH"] = original

    def test_remote_timeout_is_translated_and_close_remains_available(self):
        output = b"".join(
            (
                _frame({"kind": "ready"}),
                _frame(
                    {
                        "kind": "error",
                        "id": 1,
                        "error_kind": "timeout",
                        "message": "request deadline elapsed",
                    }
                ),
                _frame({"kind": "closed"}),
            )
        )
        process = FakeProcess(output)
        with mock.patch(
            "foxreq._worker_session.subprocess.Popen", return_value=process
        ):
            session = ProfileWorkerSession("runtime", (), "firefox_152")
            with self.assertRaisesRegex(Timeout, "deadline elapsed"):
                session.request(
                    b"GET", "https://example.test/", (), b"", 1.0, False
                )
            session.close()
        self.assertEqual(process.terminated, 0)

    def test_truncation_terminates_only_the_owned_process(self):
        process = FakeProcess(_frame({"kind": "ready"}) + b"\x00" * 7, pid=9876)
        with mock.patch(
            "foxreq._worker_session.subprocess.Popen", return_value=process
        ):
            session = ProfileWorkerSession("runtime", (), "firefox_152")
            with self.assertRaises(WorkerError):
                session.request(
                    b"GET", "https://example.test/", (), b"", 1.0, False
                )
        self.assertEqual(process.pid, 9876)
        self.assertEqual(process.terminated, 1)
        self.assertEqual(process.killed, 0)

    def test_process_exit_race_does_not_mask_the_worker_error(self):
        class RacedProcess(FakeProcess):
            def terminate(self):
                self.returncode = 9
                raise ProcessLookupError("process already exited")

        process = RacedProcess(_frame({"kind": "ready"}) + b"\x00" * 7)
        with mock.patch(
            "foxreq._worker_session.subprocess.Popen", return_value=process
        ):
            session = ProfileWorkerSession("runtime", (), "firefox_152")
            with self.assertRaises(WorkerError):
                session.request(
                    b"GET", "https://example.test/", (), b"", 1.0, False
                )

    def test_nonzero_exit_and_closed_session_fail_stably(self):
        exited = FakeProcess(returncode=7)
        with mock.patch(
            "foxreq._worker_session.subprocess.Popen", return_value=exited
        ):
            session = ProfileWorkerSession("runtime", (), "firefox_152")
            with self.assertRaises(WorkerError):
                session.request(
                    b"GET", "https://example.test/", (), b"", 1.0, False
                )
        self.assertEqual(exited.terminated, 0)

        closed = ProfileWorkerSession("runtime", (), "firefox_152")
        closed.close()
        with self.assertRaises(ClosedSessionError):
            closed.request(b"GET", "https://example.test/", (), b"", 1.0, False)


if __name__ == "__main__":
    unittest.main()
