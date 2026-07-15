"""Small loopback-only TLS/HTTP fixture for later real-NSS integration tests."""

import argparse
import socket
import ssl
import time
from dataclasses import dataclass
from pathlib import Path

from tests.fixtures.capture_server import validate_bind_host


@dataclass
class TlsFixtureServer:
    host: str
    port: int
    certificate: Path
    private_key: Path
    allow_non_loopback: bool = False
    timeout: float = 5.0
    max_request_bytes: int = 64 * 1024
    stall_before_tls: float = 0.0

    def serve(self, count: int) -> None:
        if count < 1:
            raise ValueError("count must be positive")
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
            listener.listen(16)
            for _ in range(count):
                connection, _peer = listener.accept()
                with connection:
                    connection.settimeout(self.timeout)
                    if self.stall_before_tls > 0:
                        time.sleep(self.stall_before_tls)
                        continue
                    try:
                        with context.wrap_socket(connection, server_side=True) as tls:
                            self._serve_http(tls)
                    except (ssl.SSLError, OSError):
                        # Certificate-rejection tests intentionally abort the handshake;
                        # Windows may surface the peer alert as ConnectionResetError.
                        continue

    def _serve_http(self, connection: ssl.SSLSocket) -> None:
        request = bytearray()
        while b"\r\n\r\n" not in request:
            remaining = self.max_request_bytes - len(request)
            if remaining <= 0:
                raise ValueError("fixture request header exceeds limit")
            chunk = connection.recv(min(4096, remaining))
            if not chunk:
                return
            request.extend(chunk)
        connection.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 2\r\n"
            b"Connection: close\r\n\r\nOK"
        )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--stall-before-tls", type=float, default=0.0)
    parser.add_argument("--allow-non-loopback", action="store_true")
    args = parser.parse_args(argv)
    TlsFixtureServer(
        host=args.host,
        port=args.port,
        certificate=args.certificate,
        private_key=args.private_key,
        allow_non_loopback=args.allow_non_loopback,
        timeout=args.timeout,
        stall_before_tls=args.stall_before_tls,
    ).serve(args.count)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
