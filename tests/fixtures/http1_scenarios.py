"""Deterministic loopback-only HTTPS/1.1 scenarios for foxreq tests."""

import argparse
import socket
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from tests.fixtures.capture_server import validate_bind_host


MAX_REQUEST_HEAD = 64 * 1024
SCENARIOS = (
    "fixed",
    "chunked",
    "informational",
    "close",
    "keepalive-two",
    "server-close",
    "early-close",
    "malformed-length",
    "stall-read",
)


class ScenarioError(ValueError):
    """Raised when fixture input violates the deterministic protocol contract."""


@dataclass(frozen=True)
class ParsedRequest:
    method: bytes
    target: bytes
    version: bytes
    headers: Tuple[Tuple[bytes, bytes], ...]
    body: bytes


def build_response(scenario: str, request_index: int) -> Optional[bytes]:
    """Return the exact response bytes for a named scenario."""
    if request_index < 0:
        raise ScenarioError("request index must be non-negative")
    if scenario == "fixed":
        return (
            b"HTTP/1.1 200 OK\r\n"
            b"Set-Cookie: a=1\r\n"
            b"Set-Cookie: b=2\r\n"
            b"Content-Length: 2\r\n\r\nOK"
        )
    if scenario == "chunked":
        return (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"2\r\nOK\r\n0\r\nX-End: yes\r\n\r\n"
        )
    if scenario == "informational":
        return (
            b"HTTP/1.1 100 Continue\r\n\r\n"
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
        )
    if scenario == "close":
        return b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nOK"
    if scenario == "keepalive-two":
        body = b"one" if request_index == 0 else b"two"
        return b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n" + body
    if scenario == "server-close":
        return (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 2\r\nConnection: close\r\n\r\nOK"
        )
    if scenario == "early-close":
        return b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nOK"
    if scenario == "malformed-length":
        return (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 2\r\nContent-Length: 3\r\n\r\nOK"
        )
    if scenario == "stall-read":
        return None
    raise ScenarioError("unknown HTTP/1.1 fixture scenario")


def _parse_head(data: bytes, max_head_bytes: int):
    if max_head_bytes < 1:
        raise ScenarioError("request head limit must be positive")
    marker = data.find(b"\r\n\r\n")
    if marker < 0:
        raise ScenarioError("incomplete request head")
    head_end = marker + 4
    if head_end > max_head_bytes:
        raise ScenarioError("fixture request head exceeds limit")
    lines = data[:marker].split(b"\r\n")
    if not lines or len(lines[0].split(b" ")) != 3:
        raise ScenarioError("invalid request line")
    method, target, version = lines[0].split(b" ")
    if not method or not target or version not in (b"HTTP/1.0", b"HTTP/1.1"):
        raise ScenarioError("invalid request line")
    headers = []
    content_lengths = []
    for line in lines[1:]:
        if not line or b":" not in line:
            raise ScenarioError("invalid request header")
        name, value = line.split(b":", 1)
        if not name or name[-1:] in (b" ", b"\t"):
            raise ScenarioError("invalid request header")
        value = value.strip(b" \t")
        headers.append((name, value))
        if name.lower() == b"content-length":
            content_lengths.append(value)
    if len(content_lengths) > 1:
        raise ScenarioError("ambiguous request content length")
    body_length = 0
    if content_lengths:
        if not content_lengths[0].isdigit():
            raise ScenarioError("invalid request content length")
        body_length = int(content_lengths[0])
    return method, target, version, tuple(headers), head_end, body_length


def parse_request(data: bytes, max_head_bytes: int = MAX_REQUEST_HEAD) -> ParsedRequest:
    """Parse one complete request without logging request values."""
    method, target, version, headers, head_end, body_length = _parse_head(
        data, max_head_bytes
    )
    if len(data) - head_end < body_length:
        raise ScenarioError("incomplete request body")
    return ParsedRequest(
        method=method,
        target=target,
        version=version,
        headers=headers,
        body=data[head_end : head_end + body_length],
    )


def _request_size(data: bytearray, max_head_bytes: int) -> Optional[int]:
    marker = data.find(b"\r\n\r\n")
    if marker < 0:
        if len(data) >= max_head_bytes:
            raise ScenarioError("fixture request head exceeds limit")
        return None
    head_end = marker + 4
    if head_end > max_head_bytes:
        raise ScenarioError("fixture request head exceeds limit")
    _method, _target, _version, _headers, _head_end, body_length = _parse_head(
        bytes(data[:head_end]), max_head_bytes
    )
    return head_end + body_length


def _read_request(connection: ssl.SSLSocket, max_head_bytes: int) -> Optional[ParsedRequest]:
    data = bytearray()
    while True:
        expected = _request_size(data, max_head_bytes)
        if expected is not None and len(data) >= expected:
            return parse_request(bytes(data[:expected]), max_head_bytes)
        chunk = connection.recv(4096)
        if not chunk:
            if not data:
                return None
            raise ScenarioError("request ended before it was complete")
        data.extend(chunk)


@dataclass
class Http1ScenarioServer:
    host: str
    port: int
    certificate: Path
    private_key: Path
    scenario: str
    timeout: float = 5.0
    stall_seconds: float = 1.0
    max_request_bytes: int = MAX_REQUEST_HEAD
    allow_non_loopback: bool = False
    expected_methods: Tuple[bytes, ...] = ()
    expected_targets: Tuple[bytes, ...] = ()
    expected_bodies: Tuple[bytes, ...] = ()
    expected_headers: Tuple[Tuple[bytes, bytes], ...] = ()

    def serve(self, count: int) -> None:
        if count < 1:
            raise ScenarioError("count must be positive")
        if self.scenario not in SCENARIOS:
            raise ScenarioError("unknown HTTP/1.1 fixture scenario")
        if self.timeout <= 0 or self.stall_seconds < 0:
            raise ScenarioError("fixture timeouts are invalid")
        host = validate_bind_host(self.host, self.allow_non_loopback)
        if not self.certificate.is_file() or not self.private_key.is_file():
            raise ScenarioError("certificate and private key files are required")

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(["http/1.1"])
        context.load_cert_chain(self.certificate, self.private_key)
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        served = 0
        with socket.socket(family, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((host, self.port))
            listener.listen(4)
            while served < count:
                connection, _peer = listener.accept()
                with connection:
                    connection.settimeout(self.timeout)
                    try:
                        with context.wrap_socket(connection, server_side=True) as tls:
                            while served < count:
                                request = _read_request(tls, self.max_request_bytes)
                                if request is None:
                                    break
                                self.validate_request(request, served, count)
                                if self.scenario == "stall-read":
                                    time.sleep(self.stall_seconds)
                                    served += 1
                                    break
                                response = self._response_for(request, served)
                                tls.sendall(response)
                                served += 1
                                if self.scenario in (
                                    "close",
                                    "server-close",
                                    "early-close",
                                    "malformed-length",
                                ) or request.method == b"HEAD":
                                    break
                    except (ConnectionError, OSError, ssl.SSLError):
                        # Negative TLS and timeout cases intentionally close early.
                        continue
                if self.scenario == "keepalive-two" and served < count:
                    raise ScenarioError("keepalive scenario requires one TLS connection")

    def validate_request(
        self, request: ParsedRequest, request_index: int, request_count: int
    ) -> None:
        expected_method = _expected_at(
            self.expected_methods, request_index, request_count, "method"
        )
        expected_target = _expected_at(
            self.expected_targets, request_index, request_count, "target"
        )
        expected_body = _expected_at(
            self.expected_bodies, request_index, request_count, "body"
        )
        if expected_method is not None and request.method != expected_method:
            raise ScenarioError("request method did not match expectation")
        if expected_target is not None and request.target != expected_target:
            raise ScenarioError("request target did not match expectation")
        if expected_body is not None and request.body != expected_body:
            raise ScenarioError("request body did not match expectation")
        header_index = 0
        for expected in self.expected_headers:
            while header_index < len(request.headers):
                actual = request.headers[header_index]
                header_index += 1
                if actual == expected:
                    break
            else:
                raise ScenarioError("ordered request headers did not match expectation")

    def _response_for(self, request: ParsedRequest, request_index: int) -> bytes:
        if request.method == b"HEAD":
            return (
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                b"Connection: close\r\n\r\n"
            )
        response = build_response(self.scenario, request_index)
        if response is None:
            raise ScenarioError("stall scenario has no response bytes")
        return response


def _expected_at(values, request_index, request_count, label):
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    if len(values) != request_count:
        raise ScenarioError(label + " expectation count is invalid")
    return values[request_index]


def _ascii_bytes(value):
    try:
        return value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise argparse.ArgumentTypeError("expectation must be ASCII") from exc


def _hex_bytes(value):
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("body expectation must be hexadecimal") from exc


def _header_pair(value):
    if ":" not in value:
        raise argparse.ArgumentTypeError("header expectation requires name:value")
    name, header_value = value.split(":", 1)
    try:
        encoded_name = name.encode("ascii")
        encoded_value = header_value.encode("latin-1")
    except UnicodeEncodeError as exc:
        raise argparse.ArgumentTypeError("header expectation encoding is invalid") from exc
    if not encoded_name:
        raise argparse.ArgumentTypeError("header expectation name is empty")
    return encoded_name, encoded_value


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--scenario", choices=SCENARIOS, required=True)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--stall-seconds", type=float, default=1.0)
    parser.add_argument("--allow-non-loopback", action="store_true")
    parser.add_argument("--expect-method", action="append", type=_ascii_bytes, default=[])
    parser.add_argument("--expect-target", action="append", type=_ascii_bytes, default=[])
    parser.add_argument("--expect-body-hex", action="append", type=_hex_bytes, default=[])
    parser.add_argument("--expect-header", action="append", type=_header_pair, default=[])
    args = parser.parse_args(argv)
    Http1ScenarioServer(
        host=args.host,
        port=args.port,
        certificate=args.certificate,
        private_key=args.private_key,
        scenario=args.scenario,
        timeout=args.timeout,
        stall_seconds=args.stall_seconds,
        allow_non_loopback=args.allow_non_loopback,
        expected_methods=tuple(args.expect_method),
        expected_targets=tuple(args.expect_target),
        expected_bodies=tuple(args.expect_body_hex),
        expected_headers=tuple(args.expect_header),
    ).serve(args.count)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
