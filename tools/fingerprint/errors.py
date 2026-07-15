"""Typed errors raised by the fingerprint evidence tool."""


class FingerprintError(Exception):
    """Base error for deterministic fingerprint evidence operations."""


class ProfileError(FingerprintError):
    """A profile manifest or profile lookup is invalid."""


class ParseError(FingerprintError):
    """Bounded wire parsing failed at a known absolute byte offset."""

    def __init__(self, message: str, offset: int, path: str) -> None:
        super().__init__("{} at byte {} ({})".format(message, offset, path))
        self.message = message
        self.offset = offset
        self.path = path
