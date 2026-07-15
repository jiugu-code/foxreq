"""Typed errors raised by the fingerprint evidence tool."""


class FingerprintError(Exception):
    """Base error for deterministic fingerprint evidence operations."""


class ProfileError(FingerprintError):
    """A profile manifest or profile lookup is invalid."""
