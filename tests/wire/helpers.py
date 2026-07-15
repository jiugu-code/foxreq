"""Synthetic wire builders used only by parser unit tests."""


def extension(type_id, body=b""):
    return type_id.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body


def synthetic_client_hello(
    extensions=b"",
    split_at=None,
    ciphers=(0x1301, 0x1302),
    cipher_bytes=None,
    handshake_type=1,
):
    if cipher_bytes is None:
        cipher_bytes = b"".join(value.to_bytes(2, "big") for value in ciphers)
    body = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"
        + len(cipher_bytes).to_bytes(2, "big")
        + cipher_bytes
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = (
        bytes((handshake_type,))
        + len(body).to_bytes(3, "big")
        + body
    )
    chunks = (
        [handshake]
        if split_at is None
        else [handshake[:split_at], handshake[split_at:]]
    )
    return b"".join(
        b"\x16\x03\x01" + len(chunk).to_bytes(2, "big") + chunk
        for chunk in chunks
    )


def h2_frame(type_id, payload=b"", flags=0, stream_id=0, reserved=False):
    raw_stream_id = stream_id | (0x80000000 if reserved else 0)
    return (
        len(payload).to_bytes(3, "big")
        + bytes((type_id, flags))
        + raw_stream_id.to_bytes(4, "big")
        + payload
    )


def h2_settings(*entries):
    return b"".join(
        identifier.to_bytes(2, "big") + value.to_bytes(4, "big")
        for identifier, value in entries
    )
