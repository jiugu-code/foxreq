"""JA3 and JA4 TLS diagnostics derived from parsed ClientHello evidence."""

import hashlib
from typing import List, Optional

from .binary import Reader
from .errors import ParseError
from .model import ClientHello, Fingerprint, TlsExtension
from .normalize import is_grease


def _extension(hello: ClientHello, type_id: int) -> Optional[TlsExtension]:
    return next(
        (item for item in hello.extensions if item.type_id == type_id),
        None,
    )


def _raw_u16_vector(data: bytes, path: str) -> List[int]:
    reader = Reader(data, path=path)
    payload = Reader(reader.vector_u16(), path=path + ".values")
    values: List[int] = []
    while payload.remaining:
        values.append(payload.u16())
    payload.finish()
    reader.finish()
    return values


def _raw_u8_vector(data: bytes, path: str) -> List[int]:
    reader = Reader(data, path=path)
    values = list(reader.vector_u8())
    reader.finish()
    return values


def _supported_versions(hello: ClientHello) -> List[int]:
    item = _extension(hello, 43)
    if item is None:
        return [hello.legacy_version]

    reader = Reader(item.data, path="extension.supported_versions")
    payload = Reader(
        reader.vector_u8(),
        path="extension.supported_versions.values",
    )
    values: List[int] = []
    while payload.remaining:
        values.append(payload.u16())
    payload.finish()
    reader.finish()
    return values


def _signature_algorithms(hello: ClientHello) -> List[int]:
    item = _extension(hello, 13)
    if item is None:
        return []
    return _raw_u16_vector(item.data, "extension.signature_algorithms")


def _alpn_protocols(hello: ClientHello) -> List[str]:
    item = _extension(hello, 16)
    if item is None:
        return []

    reader = Reader(item.data, path="extension.alpn")
    payload = Reader(reader.vector_u16(), path="extension.alpn.protocols")
    protocols: List[str] = []
    while payload.remaining:
        protocol_offset = payload.offset + 1
        raw = payload.vector_u8()
        try:
            protocols.append(raw.decode("ascii"))
        except UnicodeDecodeError:
            raise ParseError(
                "ALPN protocol is not ASCII",
                protocol_offset,
                "extension.alpn.protocols",
            )
    payload.finish()
    reader.finish()
    return protocols


def ja3(hello: ClientHello) -> Fingerprint:
    """Calculate the order-sensitive JA3 raw value and MD5 digest."""

    groups_item = _extension(hello, 10)
    formats_item = _extension(hello, 11)
    groups = (
        []
        if groups_item is None
        else [
            value
            for value in _raw_u16_vector(
                groups_item.data,
                "extension.supported_groups",
            )
            if not is_grease(value)
        ]
    )
    formats = (
        []
        if formats_item is None
        else _raw_u8_vector(
            formats_item.data,
            "extension.ec_point_formats",
        )
    )
    fields = (
        str(hello.legacy_version),
        "-".join(
            str(value)
            for value in hello.cipher_suites
            if not is_grease(value)
        ),
        "-".join(
            str(item.type_id)
            for item in hello.extensions
            if not is_grease(item.type_id)
        ),
        "-".join(str(value) for value in groups),
        "-".join(str(value) for value in formats),
    )
    raw = ",".join(fields)
    return Fingerprint(
        raw=raw,
        digest=hashlib.md5(raw.encode("ascii")).hexdigest(),
    )


def _ja4_version(hello: ClientHello) -> str:
    versions = [
        value for value in _supported_versions(hello) if not is_grease(value)
    ]
    if not versions:
        versions = [hello.legacy_version]
    highest = max(versions)
    try:
        return {
            0x0304: "13",
            0x0303: "12",
            0x0302: "11",
            0x0301: "10",
        }[highest]
    except KeyError:
        raise ParseError(
            "unsupported TLS version 0x{:04x}".format(highest),
            0,
            "ja4.version",
        )


def ja4(hello: ClientHello) -> Fingerprint:
    """Calculate FoxIO's order-normalized JA4 TLS fingerprint."""

    ciphers = sorted(
        value for value in hello.cipher_suites if not is_grease(value)
    )
    extensions = sorted(
        item.type_id
        for item in hello.extensions
        if not is_grease(item.type_id)
    )
    signatures = [
        value
        for value in _signature_algorithms(hello)
        if not is_grease(value)
    ]
    protocols = _alpn_protocols(hello)
    first_protocol = protocols[0] if protocols else ""
    alpn_marker = (
        first_protocol[0] + first_protocol[-1]
        if first_protocol
        else "00"
    )
    sni_marker = "d" if _extension(hello, 0) is not None else "i"
    section_a = "t{}{}{:02d}{:02d}{}".format(
        _ja4_version(hello),
        sni_marker,
        min(len(ciphers), 99),
        min(len(extensions), 99),
        alpn_marker,
    )

    section_b_raw = ",".join(
        "{:04x}".format(value) for value in ciphers
    )
    c_extensions = [
        value for value in extensions if value not in (0, 16)
    ]
    section_c_raw = "{}_{}".format(
        ",".join("{:04x}".format(value) for value in c_extensions),
        ",".join("{:04x}".format(value) for value in signatures),
    )
    section_b = hashlib.sha256(
        section_b_raw.encode("ascii")
    ).hexdigest()[:12]
    section_c = hashlib.sha256(
        section_c_raw.encode("ascii")
    ).hexdigest()[:12]
    return Fingerprint(
        raw="{}_{}_{}".format(section_a, section_b_raw, section_c_raw),
        digest="{}_{}_{}".format(section_a, section_b, section_c),
    )
