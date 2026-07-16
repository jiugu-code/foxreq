"""Parent-side lifecycle for one isolated Firefox HTTPS profile worker."""

import os
import queue
import subprocess
import sys
import threading
from dataclasses import dataclass

from ._exceptions import (
    ClosedSessionError,
    FoxreqError,
    WorkerError,
    translate_native_error,
)
from ._ipc import read_frame, write_frame


_MAX_METADATA = 1024 * 1024
_MAX_BODY = 16 * 1024 * 1024
_START_TIMEOUT = 10.0
_IPC_GRACE_SECONDS = 2.0
_CLOSE_TIMEOUT = 3.0
_MAX_ANCHORS = 4096


@dataclass(frozen=True, slots=True)
class WorkerResponse:
    status: int
    reason: bytes
    url: str
    version: str
    headers: tuple
    body: bytes


class ProfileWorkerSession:
    def __init__(self, runtime_dir, anchors, profile_id):
        try:
            self._runtime_dir = os.fsdecode(os.fspath(runtime_dir))
            self._anchors = tuple(bytes(anchor) for anchor in anchors)
        except (TypeError, ValueError, OSError) as error:
            raise WorkerError("worker initialization input is invalid") from error
        if not self._runtime_dir or not isinstance(profile_id, str) or not profile_id:
            raise WorkerError("worker initialization input is invalid")
        self._profile_id = profile_id
        self._process = None
        self._closed = False
        self._next_request_id = 1
        self._lock = threading.Lock()

    def request(self, method, url, headers, body, timeout_seconds, insecure=False):
        with self._lock:
            if self._closed:
                raise ClosedSessionError("isolated Firefox profile worker is closed")
            process = self._start()
            request_id = self._next_request_id
            self._next_request_id += 1
            try:
                metadata = {
                    "kind": "request",
                    "id": request_id,
                    "method": bytes(method).decode("ascii"),
                    "url": url,
                    "headers": [
                        [bytes(name).decode("ascii"), bytes(value).decode("latin-1")]
                        for name, value in headers
                    ],
                    "timeout": float(timeout_seconds),
                    "insecure": bool(insecure),
                    "profile": self._profile_id,
                }
                write_frame(process.stdin, metadata, body)
                response_metadata, response_body = _read_frame_with_timeout(
                    process.stdout,
                    float(timeout_seconds) + _IPC_GRACE_SECONDS,
                )
                return self._decode_response(
                    response_metadata,
                    response_body,
                    request_id,
                )
            except (UnicodeError, TypeError, ValueError, OverflowError) as error:
                self._abort_process()
                raise WorkerError("worker request could not be encoded safely") from error
            except WorkerError:
                self._abort_process()
                raise

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            process = self._process
            if process is None:
                return
            try:
                if process.poll() is not None:
                    raise WorkerError("isolated Firefox profile worker exited unexpectedly")
                write_frame(process.stdin, {"kind": "close"}, b"")
                metadata, body = _read_frame_with_timeout(
                    process.stdout,
                    _CLOSE_TIMEOUT,
                )
                if body or metadata.get("kind") != "closed":
                    if metadata.get("kind") == "error":
                        raise _remote_exception(metadata)
                    raise WorkerError("worker close response is invalid")
                self._finish_process(process)
                self._process = None
            except WorkerError:
                self._abort_process()
                raise
            except FoxreqError:
                self._abort_process()
                raise

    def _start(self):
        if self._process is not None:
            if self._process.poll() is not None:
                self._finish_process(self._process)
                self._process = None
                raise WorkerError("isolated Firefox profile worker exited unexpectedly")
            return self._process

        command = [sys.executable, "-I", "-m", "foxreq._profile_worker"]
        options = {
            "stdin": subprocess.PIPE,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.DEVNULL,
            "close_fds": True,
            "shell": False,
            "bufsize": 0,
        }
        if sys.platform == "win32":
            options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        elif sys.platform.startswith("linux"):
            options["env"] = _linux_child_environment(self._runtime_dir)
        try:
            process = subprocess.Popen(command, **options)
        except (OSError, ValueError) as error:
            raise WorkerError("isolated Firefox profile worker could not start") from error
        self._process = process
        try:
            if process.stdin is None or process.stdout is None or process.poll() is not None:
                raise WorkerError("isolated Firefox profile worker exited during startup")
            write_frame(
                process.stdin,
                {
                    "kind": "init",
                    "runtime_dir": self._runtime_dir,
                    "profile": self._profile_id,
                },
                _encode_anchors(self._anchors),
            )
            metadata, body = _read_frame_with_timeout(process.stdout, _START_TIMEOUT)
            if body or metadata.get("kind") != "ready":
                if metadata.get("kind") == "error":
                    raise _remote_exception(metadata)
                raise WorkerError("isolated Firefox profile worker startup failed")
            return process
        except WorkerError:
            self._abort_process()
            raise
        except FoxreqError:
            self._abort_process()
            raise

    def _decode_response(self, metadata, body, request_id):
        if metadata.get("id") != request_id:
            raise WorkerError("worker response id is invalid")
        if metadata.get("kind") == "error":
            raise _remote_exception(metadata)
        if metadata.get("kind") != "response":
            raise WorkerError("worker response kind is invalid")
        try:
            status = metadata["status"]
            reason = metadata["reason"].encode("latin-1")
            url = metadata["url"]
            version = metadata["version"]
            raw_headers = metadata["headers"]
            if (
                isinstance(status, bool)
                or not isinstance(status, int)
                or not 100 <= status <= 999
                or not isinstance(url, str)
                or version not in ("HTTP/1.0", "HTTP/1.1")
                or not isinstance(raw_headers, list)
            ):
                raise ValueError("invalid response metadata")
            headers = []
            for item in raw_headers:
                if not isinstance(item, list) or len(item) != 2:
                    raise ValueError("invalid response header")
                name, value = item
                headers.append((name.encode("ascii"), value.encode("latin-1")))
        except (KeyError, AttributeError, TypeError, UnicodeError, ValueError) as error:
            raise WorkerError("worker response metadata is invalid") from error
        return WorkerResponse(
            status=status,
            reason=reason,
            url=url,
            version=version,
            headers=tuple(headers),
            body=body,
        )

    def _abort_process(self):
        process = self._process
        self._process = None
        if process is None:
            return
        try:
            if process.poll() is None:
                try:
                    process.terminate()
                except OSError:
                    if process.poll() is None:
                        try:
                            process.kill()
                        except OSError:
                            pass
                try:
                    process.wait(timeout=_CLOSE_TIMEOUT)
                except subprocess.TimeoutExpired:
                    try:
                        process.kill()
                        process.wait(timeout=_CLOSE_TIMEOUT)
                    except (OSError, subprocess.TimeoutExpired):
                        pass
                except OSError:
                    pass
        finally:
            _close_pipes(process)

    @staticmethod
    def _finish_process(process):
        _close_input(process)
        try:
            returncode = process.wait(timeout=_CLOSE_TIMEOUT)
        except subprocess.TimeoutExpired as error:
            raise WorkerError("isolated Firefox profile worker did not exit") from error
        finally:
            _close_output(process)
        if returncode != 0:
            raise WorkerError("isolated Firefox profile worker exited unexpectedly")


def _read_frame_with_timeout(stream, timeout):
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        raise WorkerError("worker response timeout is invalid")
    result = queue.Queue(maxsize=1)

    def read_one():
        try:
            result.put((True, read_frame(stream, _MAX_METADATA, _MAX_BODY)))
        except Exception as error:
            result.put((False, error))

    reader = threading.Thread(
        target=read_one,
        name="foxreq-profile-worker-reader",
        daemon=True,
    )
    reader.start()
    try:
        succeeded, value = result.get(timeout=timeout)
    except queue.Empty as error:
        raise WorkerError("isolated Firefox profile worker response timed out") from error
    if succeeded:
        return value
    if isinstance(value, WorkerError):
        raise value
    raise WorkerError("isolated Firefox profile worker response failed") from value


def _encode_anchors(anchors):
    if len(anchors) > _MAX_ANCHORS:
        raise WorkerError("worker trust anchor count exceeds the limit")
    encoded = bytearray(len(anchors).to_bytes(4, "big"))
    for anchor in anchors:
        if len(anchor) > 0xFFFFFFFF:
            raise WorkerError("worker trust anchor is too large")
        encoded.extend(len(anchor).to_bytes(4, "big"))
        encoded.extend(anchor)
        if len(encoded) > _MAX_BODY:
            raise WorkerError("worker trust anchors exceed the limit")
    return bytes(encoded)


def _linux_child_environment(runtime_dir):
    names = (
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "PYTHONIOENCODING",
        "PYTHONUTF8",
        "TMPDIR",
    )
    environment = {name: os.environ[name] for name in names if name in os.environ}
    inherited = os.environ.get("LD_LIBRARY_PATH")
    environment["LD_LIBRARY_PATH"] = (
        runtime_dir + os.pathsep + inherited if inherited else runtime_dir
    )
    return environment


def _remote_exception(metadata):
    kind = metadata.get("error_kind")
    message = metadata.get("message")
    if not isinstance(kind, str) or not isinstance(message, str) or not message:
        return WorkerError("isolated Firefox profile worker returned an invalid error")

    class RemoteNativeError:
        pass

    error = RemoteNativeError()
    error.kind = kind
    error.message = message
    return translate_native_error(error)


def _close_input(process):
    if process.stdin is not None:
        try:
            process.stdin.close()
        except OSError:
            pass


def _close_output(process):
    if process.stdout is not None:
        try:
            process.stdout.close()
        except OSError:
            pass


def _close_pipes(process):
    _close_input(process)
    _close_output(process)
