"""Field-aware normalization for comparable ClientHello evidence."""

from typing import Dict, List, Union

from .binary import Reader
from .errors import ParseError
from .model import ClientHello, TlsExtension


Identifier = Union[int, str]


def is_grease(value: int) -> bool:
    """Return whether a 16-bit value is one of RFC 8701's GREASE values."""

    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def _identifier(value: int) -> Identifier:
    return "GREASE" if is_grease(value) else value


def _u16_vector(data: bytes, path: str) -> List[Identifier]:
    reader = Reader(data, path=path)
    payload = Reader(reader.vector_u16(), path=path + ".values")
    values: List[Identifier] = []
    while payload.remaining:
        values.append(_identifier(payload.u16()))
    payload.finish()
    reader.finish()
    return values


def _u8_vector(data: bytes, path: str) -> List[int]:
    reader = Reader(data, path=path)
    values = list(reader.vector_u8())
    reader.finish()
    return values


def _server_names(data: bytes) -> List[Dict[str, object]]:
    reader = Reader(data, path="extension.server_name")
    payload = Reader(
        reader.vector_u16(),
        path="extension.server_name.names",
    )
    names: List[Dict[str, object]] = []
    while payload.remaining:
        name_type = payload.u8()
        name_offset = payload.offset + 2
        raw_name = payload.vector_u16()
        try:
            name = raw_name.decode("ascii")
        except UnicodeDecodeError:
            raise ParseError(
                "server name is not ASCII",
                name_offset,
                "extension.server_name.names",
            )
        names.append({"name_type": name_type, "name": name})
    payload.finish()
    reader.finish()
    return names


def _alpn(data: bytes) -> List[str]:
    reader = Reader(data, path="extension.alpn")
    payload = Reader(reader.vector_u16(), path="extension.alpn.protocols")
    protocols: List[str] = []
    while payload.remaining:
        protocol_offset = payload.offset + 1
        raw_protocol = payload.vector_u8()
        try:
            protocols.append(raw_protocol.decode("ascii"))
        except UnicodeDecodeError:
            raise ParseError(
                "ALPN protocol is not ASCII",
                protocol_offset,
                "extension.alpn.protocols",
            )
    payload.finish()
    reader.finish()
    return protocols


def _supported_versions(data: bytes) -> List[Identifier]:
    reader = Reader(data, path="extension.supported_versions")
    payload = Reader(
        reader.vector_u8(),
        path="extension.supported_versions.values",
    )
    versions: List[Identifier] = []
    while payload.remaining:
        versions.append(_identifier(payload.u16()))
    payload.finish()
    reader.finish()
    return versions


def _key_shares(data: bytes) -> List[Dict[str, object]]:
    reader = Reader(data, path="extension.key_share")
    payload = Reader(
        reader.vector_u16(),
        path="extension.key_share.entries",
    )
    shares: List[Dict[str, object]] = []
    while payload.remaining:
        group = _identifier(payload.u16())
        key = payload.vector_u16()
        shares.append({"group": group, "key_length": len(key)})
    payload.finish()
    reader.finish()
    return shares


def _psk_shape(data: bytes) -> Dict[str, List[int]]:
    reader = Reader(data, path="extension.pre_shared_key")
    identities = Reader(
        reader.vector_u16(),
        path="extension.pre_shared_key.identities",
    )
    identity_lengths: List[int] = []
    while identities.remaining:
        identity_lengths.append(len(identities.vector_u16()))
        identities.take(4)
    identities.finish()

    binders = Reader(
        reader.vector_u16(),
        path="extension.pre_shared_key.binders",
    )
    binder_lengths: List[int] = []
    while binders.remaining:
        binder_lengths.append(len(binders.vector_u8()))
    binders.finish()
    reader.finish()
    return {
        "identity_lengths": identity_lengths,
        "binder_lengths": binder_lengths,
    }


def _normalize_extension(item: TlsExtension) -> Dict[str, object]:
    value: Dict[str, object] = {
        "type": _identifier(item.type_id),
        "length": len(item.data),
    }
    if is_grease(item.type_id):
        return value

    if item.type_id == 0:
        value["server_names"] = _server_names(item.data)
    elif item.type_id in (10, 13):
        value["values"] = _u16_vector(
            item.data,
            "extension.{}".format(item.type_id),
        )
    elif item.type_id in (11, 45):
        value["values"] = _u8_vector(
            item.data,
            "extension.{}".format(item.type_id),
        )
    elif item.type_id == 16:
        value["protocols"] = _alpn(item.data)
    elif item.type_id == 21:
        value["padding_length"] = len(item.data)
    elif item.type_id == 41:
        value["pre_shared_key"] = _psk_shape(item.data)
    elif item.type_id == 43:
        value["versions"] = _supported_versions(item.data)
    elif item.type_id == 51:
        value["key_shares"] = _key_shares(item.data)
    else:
        value["data_hex"] = item.data.hex()
    return value


def normalize_client_hello(hello: ClientHello) -> Dict[str, object]:
    """Convert a ClientHello to deterministic JSON-compatible evidence."""

    return {
        "legacy_version": hello.legacy_version,
        "random": "dynamic:{}".format(len(hello.random)),
        "session_id": "dynamic:{}".format(len(hello.session_id)),
        "cipher_suites": [_identifier(value) for value in hello.cipher_suites],
        "compression_methods": list(hello.compression_methods),
        "extensions": [_normalize_extension(item) for item in hello.extensions],
    }
