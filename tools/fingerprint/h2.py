"""Bounded HTTP/2 client-prefix and control-frame parsing."""

from typing import List, Tuple

from .binary import Reader
from .errors import ParseError
from .model import H2Frame, Setting


CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
SETTINGS_FRAME_TYPE = 4
WINDOW_UPDATE_FRAME_TYPE = 8
ACK_FLAG = 1


def parse_client_prefix(data: bytes) -> Tuple[H2Frame, ...]:
    """Parse the exact HTTP/2 client preface and all complete frames."""

    if len(data) < len(CLIENT_PREFACE) or data[: len(CLIENT_PREFACE)] != CLIENT_PREFACE:
        raise ParseError(
            "invalid HTTP/2 client preface",
            0,
            "http2.client_prefix",
        )

    reader = Reader(
        data[len(CLIENT_PREFACE) :],
        base_offset=len(CLIENT_PREFACE),
        path="http2.frames",
    )
    frames: List[H2Frame] = []
    while reader.remaining:
        frame_offset = reader.offset
        length = reader.u24()
        type_id = reader.u8()
        flags = reader.u8()
        raw_stream_id = int.from_bytes(reader.take(4), "big")
        if raw_stream_id & 0x80000000:
            raise ParseError(
                "reserved stream bit is set",
                frame_offset + 5,
                "http2.frame.stream_id",
            )
        payload = reader.take(length)
        frames.append(
            H2Frame(
                length=length,
                type_id=type_id,
                flags=flags,
                stream_id=raw_stream_id,
                payload=payload,
            )
        )
    reader.finish()
    return tuple(frames)


def decode_settings(frame: H2Frame) -> Tuple[Setting, ...]:
    """Validate and decode SETTINGS while preserving entry order."""

    if frame.type_id != SETTINGS_FRAME_TYPE or frame.stream_id != 0:
        raise ParseError("invalid SETTINGS frame", 0, "http2.settings")
    if frame.flags & ACK_FLAG:
        if frame.length:
            raise ParseError(
                "SETTINGS ACK must have an empty payload",
                0,
                "http2.settings",
            )
        return ()
    if frame.length % 6:
        raise ParseError("invalid SETTINGS payload length", 0, "http2.settings")

    reader = Reader(frame.payload, path="http2.settings")
    values: List[Setting] = []
    seen = set()
    while reader.remaining:
        identifier_offset = reader.offset
        identifier = reader.u16()
        value = int.from_bytes(reader.take(4), "big")
        if identifier in seen:
            raise ParseError(
                "duplicate SETTINGS identifier {}".format(identifier),
                identifier_offset,
                "http2.settings",
            )
        seen.add(identifier)
        values.append(Setting(identifier=identifier, value=value))
    reader.finish()
    return tuple(values)


def decode_window_update(frame: H2Frame) -> int:
    """Validate and return a WINDOW_UPDATE increment."""

    if frame.type_id != WINDOW_UPDATE_FRAME_TYPE or frame.length != 4:
        raise ParseError(
            "invalid WINDOW_UPDATE frame",
            0,
            "http2.window_update",
        )
    raw = int.from_bytes(frame.payload, "big")
    increment = raw & 0x7FFFFFFF
    if raw & 0x80000000 or increment == 0:
        raise ParseError(
            "invalid WINDOW_UPDATE increment",
            0,
            "http2.window_update",
        )
    return increment
