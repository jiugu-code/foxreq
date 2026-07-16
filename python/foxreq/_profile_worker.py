"""Isolated child process for one Firefox HTTPS profile."""

import math
import sys

from . import _foxreq
from ._exceptions import WorkerError
from ._ipc import read_frame, write_frame


_MAX_METADATA = 1024 * 1024
_MAX_BODY = 16 * 1024 * 1024
_MAX_ANCHORS = 4096


def run(input_stream, output_stream):
    native = None
    try:
        metadata, anchor_body = read_frame(input_stream, _MAX_METADATA, _MAX_BODY)
        runtime_dir, profile_id = _decode_init(metadata)
        anchors = _decode_anchors(anchor_body)
        try:
            native = _foxreq.NativeSession(runtime_dir, list(anchors), profile_id)
        except _foxreq.NativeError as error:
            _write_native_error(output_stream, error)
            return 1
        write_frame(output_stream, {"kind": "ready"}, b"")

        while True:
            metadata, body = read_frame(input_stream, _MAX_METADATA, _MAX_BODY)
            kind = metadata.get("kind")
            if kind == "close":
                if body or set(metadata) != {"kind"}:
                    raise WorkerError("worker close frame is invalid")
                try:
                    native.close()
                except _foxreq.NativeError as error:
                    _write_native_error(output_stream, error)
                    native = None
                    return 1
                native = None
                write_frame(output_stream, {"kind": "closed"}, b"")
                return 0
            if kind != "request":
                raise WorkerError("worker request frame kind is invalid")
            request_id, request = _decode_request(metadata, body, profile_id)
            try:
                response = native.request(*request)
            except _foxreq.NativeError as error:
                _write_native_error(output_stream, error, request_id)
                continue
            except Exception:
                write_frame(
                    output_stream,
                    {"kind": "worker_error", "id": request_id},
                    b"",
                )
                return 3
            _write_response(output_stream, response, request_id)
    except WorkerError:
        return 2
    except Exception:
        return 3
    finally:
        if native is not None:
            try:
                native.close()
            except Exception:
                pass


def _decode_init(metadata):
    if set(metadata) != {"kind", "profile", "runtime_dir"}:
        raise WorkerError("worker init frame is invalid")
    runtime_dir = metadata.get("runtime_dir")
    profile_id = metadata.get("profile")
    if (
        metadata.get("kind") != "init"
        or not isinstance(runtime_dir, str)
        or not runtime_dir
        or not isinstance(profile_id, str)
        or not profile_id
    ):
        raise WorkerError("worker init frame is invalid")
    return runtime_dir, profile_id


def _decode_anchors(data):
    if len(data) < 4:
        raise WorkerError("worker trust anchor frame is truncated")
    count = int.from_bytes(data[:4], "big")
    if count > _MAX_ANCHORS:
        raise WorkerError("worker trust anchor count exceeds the limit")
    position = 4
    anchors = []
    for _ in range(count):
        if position + 4 > len(data):
            raise WorkerError("worker trust anchor frame is truncated")
        length = int.from_bytes(data[position : position + 4], "big")
        position += 4
        end = position + length
        if end > len(data):
            raise WorkerError("worker trust anchor frame is truncated")
        anchors.append(data[position:end])
        position = end
    if position != len(data):
        raise WorkerError("worker trust anchor frame has trailing data")
    return tuple(anchors)


def _decode_request(metadata, body, profile_id):
    expected = {
        "headers",
        "id",
        "insecure",
        "kind",
        "method",
        "profile",
        "timeout",
        "url",
    }
    if set(metadata) != expected:
        raise WorkerError("worker request metadata is invalid")
    request_id = metadata.get("id")
    method = metadata.get("method")
    url = metadata.get("url")
    headers = metadata.get("headers")
    timeout = metadata.get("timeout")
    insecure = metadata.get("insecure")
    if (
        isinstance(request_id, bool)
        or not isinstance(request_id, int)
        or request_id < 1
        or not isinstance(method, str)
        or not method
        or not isinstance(url, str)
        or not url
        or not isinstance(headers, list)
        or isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
        or not isinstance(insecure, bool)
        or metadata.get("profile") != profile_id
    ):
        raise WorkerError("worker request metadata is invalid")
    try:
        encoded_headers = []
        for item in headers:
            if not isinstance(item, list) or len(item) != 2:
                raise ValueError("invalid header")
            name, value = item
            encoded_headers.append((name.encode("ascii"), value.encode("latin-1")))
        request = (
            method.encode("ascii"),
            url,
            tuple(encoded_headers),
            body,
            float(timeout),
            insecure,
        )
    except (AttributeError, TypeError, UnicodeError, ValueError) as error:
        raise WorkerError("worker request metadata is invalid") from error
    return request_id, request


def _write_response(output_stream, response, request_id):
    try:
        metadata = {
            "kind": "response",
            "id": request_id,
            "status": response.status,
            "reason": bytes(response.reason).decode("latin-1"),
            "url": response.url,
            "version": response.version,
            "headers": [
                [bytes(name).decode("ascii"), bytes(value).decode("latin-1")]
                for name, value in response.headers
            ],
        }
        body = bytes(response.body)
    except (AttributeError, TypeError, UnicodeError, ValueError) as error:
        raise WorkerError("native response could not be encoded safely") from error
    write_frame(output_stream, metadata, body)


def _write_native_error(output_stream, error, request_id=None):
    kind = getattr(error, "kind", "internal")
    message = getattr(error, "message", "foxreq native request failed")
    if not isinstance(kind, str) or not kind:
        kind = "internal"
    if not isinstance(message, str) or not message:
        message = "foxreq native request failed"
    metadata = {
        "kind": "error",
        "error_kind": kind[:64],
        "message": message[:1024],
    }
    if request_id is not None:
        metadata["id"] = request_id
    write_frame(output_stream, metadata, b"")


def main():
    return run(sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    raise SystemExit(main())
