"""Immutable wire-evidence models shared by parsers and comparators."""

from dataclasses import dataclass
from typing import Any, Tuple


@dataclass(frozen=True)
class TlsExtension:
    """One ordered ClientHello extension and its exact payload bytes."""

    type_id: int
    data: bytes


@dataclass(frozen=True)
class ClientHello:
    """The stable structure of one reassembled TLS ClientHello."""

    legacy_version: int
    random: bytes
    session_id: bytes
    cipher_suites: Tuple[int, ...]
    compression_methods: Tuple[int, ...]
    extensions: Tuple[TlsExtension, ...]


@dataclass(frozen=True)
class Difference:
    """One deterministic mismatch between expected and actual evidence."""

    path: str
    expected: Any
    actual: Any


@dataclass(frozen=True)
class Fingerprint:
    """A fingerprint's inspectable raw form and rendered digest."""

    raw: str
    digest: str
