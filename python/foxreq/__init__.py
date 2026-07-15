"""foxreq Python package."""

from ._foxreq import NativeError, NativeResponse, NativeSession, __version__
from ._exceptions import (
    CertificateError,
    ClosedSessionError,
    ConfigurationError,
    ConnectionError,
    FoxreqError,
    InsecureRequestWarning,
    InvalidRequestError,
    ProtocolError,
    Timeout,
    TlsError,
)
from ._headers import Headers
from ._models import Response

__all__ = (
    "CertificateError",
    "ClosedSessionError",
    "ConfigurationError",
    "ConnectionError",
    "FoxreqError",
    "Headers",
    "InsecureRequestWarning",
    "InvalidRequestError",
    "NativeError",
    "NativeResponse",
    "NativeSession",
    "ProtocolError",
    "Response",
    "Timeout",
    "TlsError",
    "__version__",
)
