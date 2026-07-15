"""Loopback TLS fixture that peeks ClientHello bytes before completing TLS."""

import argparse
import select
import socket
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path
from threading import Condition, Event
from typing import IO, Optional

from tests.fixtures.capture_server import (
    CaptureError,
    ClientHelloAccumulator,
    make_capture_record,
    write_jsonl_record,
)


def peek_client_hello(
    connection: socket.socket,
    timeout: float,
    peek_capacity: int = 256 * 1024,
    accumulator: Optional[ClientHelloAccumulator] = None,
) -> bytes:
    """Capture one ClientHello with MSG_PEEK so SSL can consume it afterward."""

    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if peek_capacity < 5:
        raise ValueError("peek_capacity must be at least 5")
    accumulator = accumulator or ClientHelloAccumulator(
        max_capture_bytes=peek_capacity
    )
    deadline = time.monotonic() + timeout
    observed = 0
    original_timeout = connection.gettimeout()
    connection.setblocking(False)
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CaptureError("timeout", "ClientHello capture timed out")
            try:
                pending = connection.recv(peek_capacity, socket.MSG_PEEK)
            except BlockingIOError:
                readable, _writable, _exceptional = select.select(
                    [connection], [], [], remaining
                )
                if not readable:
                    raise CaptureError("timeout", "ClientHello capture timed out")
                continue
            except OSError as error:
                raise CaptureError(
                    "socket", "ClientHello socket peek failed"
                ) from error
            if not pending:
                raise CaptureError(
                    "early_close", "peer closed before a complete ClientHello"
                )
            if len(pending) > observed:
                if accumulator.feed(pending[observed:]):
                    return accumulator.result()
                observed = len(pending)
                if observed >= peek_capacity:
                    raise CaptureError(
                        "size_limit", "ClientHello capture limit exceeded"
                    )
            time.sleep(min(0.002, max(remaining, 0.0)))
    finally:
        connection.settimeout(original_timeout)


def browser_sequence_response(sequence: int, count: int) -> bytes:
    """Return a parser-blocking response chain that forces sequential sockets."""

    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or isinstance(count, bool)
        or not isinstance(count, int)
        or sequence < 1
        or count < 1
        or sequence > count
    ):
        raise ValueError("sequence must be within the positive capture count")
    if sequence == 1:
        if count == 1:
            body = b"<!doctype html><meta charset=utf-8><title>complete</title>"
        else:
            body = (
                b"<!doctype html><meta charset=utf-8>"
                b'<script src="/.well-known/foxreq-capture/2.js"></script>'
            )
        content_type = b"text/html; charset=utf-8"
    else:
        if sequence == count:
            body = b"window.__foxreqCaptureComplete = true;"
        else:
            next_path = "/.well-known/foxreq-capture/{}.js".format(
                sequence + 1
            )
            body = (
                "document.write('<script src=\"{}\"></script>');".format(
                    next_path
                ).encode("ascii")
            )
        content_type = b"application/javascript; charset=utf-8"
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: "
        + content_type
        + b"\r\nContent-Length: "
        + str(len(body)).encode("ascii")
        + b"\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
        + body
    )


def capture_label(mode: str, sequence: int) -> str:
    if mode not in ("cold", "resumed"):
        raise ValueError("capture mode must be cold or resumed")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise ValueError("capture sequence must be positive")
    if mode == "resumed" and sequence > 1:
        return "resumed"
    return "cold"


def capture_tls_connection(
    connection: socket.socket,
    context: ssl.SSLContext,
    output: IO[str],
    sequence: int,
    count: int,
    mode: str,
    timeout: float,
    max_request_bytes: int = 64 * 1024,
) -> None:
    """Record ClientHello, complete TLS, and force the next browser socket."""

    browser_sequence_response(sequence, count)
    label = capture_label(mode, sequence)
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if max_request_bytes < 4:
        raise ValueError("max_request_bytes must be at least 4")
    wire = peek_client_hello(connection, timeout=timeout)
    connection.settimeout(timeout)
    with context.wrap_socket(connection, server_side=True) as tls:
        request = bytearray()
        while b"\r\n\r\n" not in request:
            remaining = max_request_bytes - len(request)
            if remaining <= 0:
                raise CaptureError("request_limit", "TLS request exceeds limit")
            try:
                chunk = tls.recv(min(4096, remaining))
            except socket.timeout as error:
                raise CaptureError("timeout", "TLS request timed out") from error
            if not chunk:
                raise CaptureError("early_close", "peer closed before HTTP request")
            request.extend(chunk)
        write_jsonl_record(
            output,
            make_capture_record("capture-{:06d}".format(sequence), label, wire),
        )
        response_sequence = sequence if mode == "resumed" else 1
        response_count = count if mode == "resumed" else 1
        tls.sendall(browser_sequence_response(response_sequence, response_count))


@dataclass
class TlsCaptureServer:
    host: str
    port: int
    certificate: Path
    private_key: Path
    output: IO[str]
    mode: str = "cold"
    allow_non_loopback: bool = False
    timeout: float = 10.0
    ready: Event = field(default_factory=Event, init=False)
    bound_port: Optional[int] = field(default=None, init=False)
    _completion: Condition = field(default_factory=Condition, init=False)
    _completed: int = field(default=0, init=False)

    def wait_for_completed(self, count: int, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        with self._completion:
            while self._completed < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._completion.wait(remaining)
            return True

    def _mark_completed(self, sequence: int) -> None:
        with self._completion:
            if sequence > self._completed:
                self._completed = sequence
            self._completion.notify_all()

    def serve(self, count: int) -> None:
        from tests.fixtures.capture_server import validate_bind_host

        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise ValueError("count must be positive")
        capture_label(self.mode, 1)
        host = validate_bind_host(self.host, self.allow_non_loopback)
        if not self.certificate.is_file() or not self.private_key.is_file():
            raise ValueError("certificate and private key files are required")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(["http/1.1"])
        context.load_cert_chain(self.certificate, self.private_key)
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((host, self.port))
            listener.listen(8)
            listener.settimeout(self.timeout)
            self.bound_port = listener.getsockname()[1]
            self.ready.set()
            sequence = 1
            while sequence <= count:
                connection, _peer = listener.accept()
                with connection:
                    try:
                        capture_tls_connection(
                            connection,
                            context,
                            self.output,
                            sequence=sequence,
                            count=count,
                            mode=self.mode,
                            timeout=self.timeout,
                        )
                    except CaptureError as error:
                        if error.kind != "early_close":
                            raise
                        continue
                self._mark_completed(sequence)
                sequence += 1


def main(argv=None) -> int:
    from tests.fixtures.capture_server import validate_capture_output

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--mode", choices=("cold", "resumed"), required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--allow-non-loopback", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    output_path = validate_capture_output(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("x", encoding="utf-8", newline="\n") as output:
        TlsCaptureServer(
            host=args.host,
            port=args.port,
            certificate=args.certificate,
            private_key=args.private_key,
            output=output,
            mode=args.mode,
            allow_non_loopback=args.allow_non_loopback,
            timeout=args.timeout,
        ).serve(args.count)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
