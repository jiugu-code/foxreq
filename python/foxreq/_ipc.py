"""Length-bounded JSON metadata and raw-body IPC frames."""

import json

from ._exceptions import WorkerError


_LENGTH_BYTES = 8


def write_frame(stream, metadata, body):
    if not isinstance(metadata, dict):
        raise WorkerError("worker frame metadata must be an object")
    if not isinstance(body, (bytes, bytearray, memoryview)):
        raise WorkerError("worker frame body must be bytes-like")
    try:
        encoded_metadata = json.dumps(
            metadata,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        encoded_body = bytes(body)
    except (TypeError, ValueError, OverflowError) as error:
        raise WorkerError("worker frame cannot be encoded safely") from error

    parts = (
        len(encoded_metadata).to_bytes(_LENGTH_BYTES, "big"),
        encoded_metadata,
        len(encoded_body).to_bytes(_LENGTH_BYTES, "big"),
        encoded_body,
    )
    try:
        for part in parts:
            _write_all(stream, part)
        flush = getattr(stream, "flush", None)
        if flush is not None:
            flush()
    except (OSError, TypeError, ValueError) as error:
        raise WorkerError("worker frame could not be written") from error


def read_frame(stream, max_metadata, max_body):
    _validate_limit(max_metadata, "metadata")
    _validate_limit(max_body, "body")
    metadata_length = int.from_bytes(_read_exact(stream, _LENGTH_BYTES), "big")
    if metadata_length > max_metadata:
        raise WorkerError("worker frame metadata exceeds the limit")
    encoded_metadata = _read_exact(stream, metadata_length)
    body_length = int.from_bytes(_read_exact(stream, _LENGTH_BYTES), "big")
    if body_length > max_body:
        raise WorkerError("worker frame body exceeds the limit")
    body = _read_exact(stream, body_length)
    try:
        metadata = json.loads(
            encoded_metadata.decode("utf-8"),
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as error:
        raise WorkerError("worker frame metadata is invalid") from error
    if not isinstance(metadata, dict):
        raise WorkerError("worker frame metadata must be an object")
    return metadata, body


def _validate_limit(value, label):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise WorkerError("worker frame {} limit is invalid".format(label))


def _read_exact(stream, amount):
    data = bytearray()
    try:
        while len(data) < amount:
            chunk = stream.read(amount - len(data))
            if not isinstance(chunk, (bytes, bytearray, memoryview)):
                raise WorkerError("worker frame stream returned invalid data")
            if not chunk:
                raise WorkerError("worker frame is truncated")
            if len(chunk) > amount - len(data):
                raise WorkerError("worker frame stream exceeded the requested length")
            data.extend(chunk)
    except WorkerError:
        raise
    except (OSError, TypeError, ValueError) as error:
        raise WorkerError("worker frame could not be read") from error
    return bytes(data)


def _write_all(stream, data):
    written = 0
    while written < len(data):
        amount = stream.write(data[written:])
        if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
            raise WorkerError("worker frame write made no progress")
        if amount > len(data) - written:
            raise WorkerError("worker frame stream exceeded the source length")
        written += amount


def _reject_json_constant(value):
    raise ValueError("non-finite JSON number: " + value)
