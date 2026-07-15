"""foxreq Python package."""

from ._foxreq import __version__
from ._api import Session, get, post, request
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
    "ProtocolError",
    "Response",
    "Session",
    "Timeout",
    "TlsError",
    "__version__",
    "get",
    "post",
    "request",
)
