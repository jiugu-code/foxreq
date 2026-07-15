"""Loopback-only server that captures exactly one TLS ClientHello per socket."""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import socket
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, IO, Mapping, Optional


TLS_HANDSHAKE = 22
CLIENT_HELLO = 1
CAPTURE_SCHEMA_VERSION = 1
_CAPTURE_ID = re.compile(r"^capture-[0-9]{6}$")
_LABELS = frozenset(("cold", "resumed", "synthetic"))


class CaptureError(Exception):
    """A bounded, content-free error from ClientHello collection."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


class ClientHelloAccumulator:
    """Incrementally retain TLS records only through the first ClientHello."""

    def __init__(
        self,
        max_capture_bytes: int = 256 * 1024,
        max_record_bytes: int = 18 * 1024,
        max_client_hello_bytes: int = 192 * 1024,
    ):
        for name, value in (
            ("max_capture_bytes", max_capture_bytes),
            ("max_record_bytes", max_record_bytes),
            ("max_client_hello_bytes", max_client_hello_bytes),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 5:
                raise ValueError("{} must be an integer of at least 5".format(name))
        self._max_capture_bytes = max_capture_bytes
        self._max_record_bytes = max_record_bytes
        self._max_client_hello_bytes = max_client_hello_bytes
        self._pending = bytearray()
        self._records = []
        self._current_header = None
        self._current_declared = 0
        self._current_payload = bytearray()
        self._handshake_prefix = bytearray()
        self._handshake_seen = 0
        self._handshake_total = None
        self._complete = False

    def feed(self, data: bytes) -> bool:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("capture input must be bytes-like")
        if self._complete:
            return True

        data = bytes(data)
        available = self._max_capture_bytes - self._raw_bytes_held()
        accepted = min(len(data), max(available, 0))
        self._pending.extend(data[:accepted])
        dropped = accepted != len(data)
        self._process()
        if self._complete:
            self._pending.clear()
            return True
        if dropped:
            raise CaptureError("size_limit", "ClientHello capture limit exceeded")
        return False

    def finish(self) -> bytes:
        if not self._complete:
            raise CaptureError(
                "early_close",
                "peer closed before a complete ClientHello",
            )
        return self.result()

    def result(self) -> bytes:
        if not self._complete:
            raise CaptureError("incomplete", "ClientHello is not complete")
        return b"".join(self._records)

    def _raw_bytes_held(self) -> int:
        completed = sum(len(record) for record in self._records)
        current = 0
        if self._current_header is not None:
            current = len(self._current_header) + len(self._current_payload)
        return completed + current + len(self._pending)

    def _process(self) -> None:
        while not self._complete:
            if self._current_header is None:
                if len(self._pending) < 5:
                    return
                header = bytes(self._pending[:5])
                del self._pending[:5]
                if header[0] != TLS_HANDSHAKE:
                    raise CaptureError(
                        "content_type",
                        "non-handshake TLS record before ClientHello completion",
                    )
                declared = int.from_bytes(header[3:5], "big")
                if declared > self._max_record_bytes:
                    raise CaptureError("record_limit", "TLS record exceeds capture limit")
                self._current_header = header
                self._current_declared = declared
                self._current_payload = bytearray()

            record_remaining = self._current_declared - len(self._current_payload)
            if record_remaining == 0:
                self._finish_record()
                continue
            if not self._pending:
                return

            handshake_remaining = self._handshake_remaining()
            amount = min(record_remaining, len(self._pending), handshake_remaining)
            chunk = bytes(self._pending[:amount])
            del self._pending[:amount]
            self._current_payload.extend(chunk)
            self._observe_handshake(chunk)

            if self._handshake_total == self._handshake_seen:
                self._finish_record(truncated=True)
                self._complete = True
                return
            if len(self._current_payload) == self._current_declared:
                self._finish_record()

    def _handshake_remaining(self) -> int:
        if self._handshake_total is None:
            return 4 - len(self._handshake_prefix)
        return self._handshake_total - self._handshake_seen

    def _observe_handshake(self, chunk: bytes) -> None:
        if self._handshake_total is None:
            self._handshake_prefix.extend(chunk)
            if len(self._handshake_prefix) == 4:
                if self._handshake_prefix[0] != CLIENT_HELLO:
                    raise CaptureError(
                        "handshake_type",
                        "first TLS handshake message is not ClientHello",
                    )
                body_length = int.from_bytes(self._handshake_prefix[1:4], "big")
                total = 4 + body_length
                if total > self._max_client_hello_bytes:
                    raise CaptureError(
                        "size_limit",
                        "ClientHello handshake exceeds capture limit",
                    )
                self._handshake_total = total
        self._handshake_seen += len(chunk)

    def _finish_record(self, truncated: bool = False) -> None:
        payload = bytes(self._current_payload)
        header = self._current_header
        if truncated or len(payload) != self._current_declared:
            header = header[:3] + len(payload).to_bytes(2, "big")
        self._records.append(header + payload)
        self._current_header = None
        self._current_declared = 0
        self._current_payload = bytearray()


def capture_socket(
    connection: socket.socket,
    timeout: float,
    recv_size: int = 16 * 1024,
    accumulator: Optional[ClientHelloAccumulator] = None,
) -> bytes:
    """Read one complete ClientHello or raise a bounded CaptureError."""

    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if recv_size < 1:
        raise ValueError("recv_size must be positive")
    accumulator = accumulator or ClientHelloAccumulator()
    connection.settimeout(timeout)
    while True:
        try:
            data = connection.recv(recv_size)
        except socket.timeout:
            raise CaptureError("timeout", "ClientHello capture timed out")
        except OSError as error:
            raise CaptureError("socket", "ClientHello socket read failed") from error
        if not data:
            return accumulator.finish()
        if accumulator.feed(data):
            return accumulator.result()


class CaptureIdSequence:
    def __init__(self):
        self._value = 0
        self._lock = threading.Lock()

    def next(self) -> str:
        with self._lock:
            self._value += 1
            return "capture-{:06d}".format(self._value)


def make_capture_record(connection_id: str, label: str, wire: bytes) -> Dict[str, object]:
    if not _CAPTURE_ID.fullmatch(connection_id):
        raise ValueError("invalid capture connection ID")
    if label not in _LABELS:
        raise ValueError("invalid capture label")
    if not isinstance(wire, bytes) or not wire:
        raise ValueError("wire capture must be non-empty bytes")
    return {
        "schema_version": CAPTURE_SCHEMA_VERSION,
        "connection_id": connection_id,
        "label": label,
        "length": len(wire),
        "sha256": hashlib.sha256(wire).hexdigest(),
        "record_hex": wire.hex(),
    }


def write_jsonl_record(output: IO[str], record: Mapping[str, object]) -> None:
    output.write(json.dumps(dict(record), sort_keys=True, separators=(",", ":")))
    output.write("\n")
    output.flush()


def validate_bind_host(host: str, allow_non_loopback: bool) -> str:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError("bind host must be an explicit IP address")
    if not address.is_loopback and not allow_non_loopback:
        raise ValueError("non-loopback bind requires --allow-non-loopback")
    return host


def validate_capture_output(path: Path, repository: Optional[Path] = None) -> Path:
    repository = (repository or Path(__file__).parents[2]).resolve()
    root = (repository / "artifacts" / "captures").resolve()
    resolved = path.resolve()
    try:
        common = Path(os.path.commonpath((str(root), str(resolved))))
    except ValueError:
        raise ValueError("capture output must be under artifacts/captures")
    if common != root:
        raise ValueError("capture output must be under artifacts/captures")
    return resolved


@dataclass
class CaptureServer:
    host: str
    port: int
    output: IO[str]
    label: str = "cold"
    allow_non_loopback: bool = False
    timeout: float = 5.0

    def serve(self, count: int) -> None:
        if count < 1:
            raise ValueError("count must be positive")
        host = validate_bind_host(self.host, self.allow_non_loopback)
        if self.label not in _LABELS:
            raise ValueError("invalid capture label")
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        sequence = CaptureIdSequence()
        with socket.socket(family, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((host, self.port))
            listener.listen(16)
            for _ in range(count):
                connection, _peer = listener.accept()
                with connection:
                    wire = capture_socket(connection, timeout=self.timeout)
                write_jsonl_record(
                    self.output,
                    make_capture_record(sequence.next(), self.label, wire),
                )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--label", choices=sorted(_LABELS), default="cold")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--allow-non-loopback", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    output_path = validate_capture_output(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("x", encoding="utf-8", newline="\n") as output:
        CaptureServer(
            host=args.host,
            port=args.port,
            output=output,
            label=args.label,
            allow_non_loopback=args.allow_non_loopback,
            timeout=args.timeout,
        ).serve(args.count)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
