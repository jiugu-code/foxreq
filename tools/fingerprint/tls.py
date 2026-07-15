"""Strict TLS record reassembly and ClientHello parsing."""

from typing import List, Tuple

from .binary import Reader
from .errors import ParseError
from .model import ClientHello, TlsExtension


HANDSHAKE_CONTENT_TYPE = 22
CLIENT_HELLO_HANDSHAKE_TYPE = 1


def _u16_values(data: bytes, base_offset: int, path: str) -> Tuple[int, ...]:
    if len(data) % 2:
        raise ParseError("u16 vector has odd length", base_offset, path)

    reader = Reader(data, base_offset=base_offset, path=path)
    values: List[int] = []
    while reader.remaining:
        values.append(reader.u16())
    return tuple(values)


def _parse_client_hello(body: bytes, base_offset: int) -> ClientHello:
    reader = Reader(body, base_offset=base_offset, path="client_hello")
    legacy_version = reader.u16()
    random = reader.take(32)
    session_id = reader.vector_u8()

    cipher_offset = reader.offset + 2
    cipher_suites = _u16_values(
        reader.vector_u16(),
        base_offset=cipher_offset,
        path="client_hello.cipher_suites",
    )
    if not cipher_suites:
        raise ParseError(
            "empty cipher suite vector",
            cipher_offset,
            "client_hello.cipher_suites",
        )

    compression_offset = reader.offset + 1
    compression_methods = tuple(reader.vector_u8())
    if not compression_methods:
        raise ParseError(
            "empty compression method vector",
            compression_offset,
            "client_hello.compression_methods",
        )

    extensions: List[TlsExtension] = []
    seen = set()
    if reader.remaining:
        extension_size = reader.u16()
        extension_reader = reader.subreader(
            extension_size,
            "client_hello.extensions",
        )
        while extension_reader.remaining:
            type_offset = extension_reader.offset
            type_id = extension_reader.u16()
            payload = extension_reader.take(extension_reader.u16())
            if type_id in seen:
                raise ParseError(
                    "duplicate extension {}".format(type_id),
                    type_offset,
                    "client_hello.extensions",
                )
            seen.add(type_id)
            extensions.append(TlsExtension(type_id=type_id, data=payload))
        extension_reader.finish()

    reader.finish()
    return ClientHello(
        legacy_version=legacy_version,
        random=random,
        session_id=session_id,
        cipher_suites=cipher_suites,
        compression_methods=compression_methods,
        extensions=tuple(extensions),
    )


def parse_client_hello_records(data: bytes) -> ClientHello:
    """Parse one ClientHello fragmented across one or more handshake records."""

    records = Reader(data, path="tls.records")
    payloads: List[bytes] = []
    first_payload_offset = None

    while records.remaining:
        record_offset = records.offset
        content_type = records.u8()
        records.u16()
        payload_size = records.u16()
        if content_type != HANDSHAKE_CONTENT_TYPE:
            raise ParseError(
                "unexpected TLS content type {}".format(content_type),
                record_offset,
                "tls.records",
            )
        if first_payload_offset is None:
            first_payload_offset = records.offset
        payloads.append(records.take(payload_size))

    records.finish()
    handshake_offset = first_payload_offset if first_payload_offset is not None else 0
    handshake = Reader(
        b"".join(payloads),
        base_offset=handshake_offset,
        path="tls.handshake",
    )
    handshake_type_offset = handshake.offset
    handshake_type = handshake.u8()
    if handshake_type != CLIENT_HELLO_HANDSHAKE_TYPE:
        raise ParseError(
            "first handshake is not ClientHello",
            handshake_type_offset,
            "tls.handshake",
        )
    body_size = handshake.u24()
    body_offset = handshake.offset
    body = handshake.take(body_size)
    handshake.finish()
    return _parse_client_hello(body, base_offset=body_offset)
