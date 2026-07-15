"""Public foxreq exception hierarchy and native error translation."""


class FoxreqError(Exception):
    """Base class for foxreq failures."""


class ConfigurationError(FoxreqError):
    """The local runtime or trust configuration is invalid."""


class InvalidRequestError(FoxreqError):
    """Request input is invalid."""


class ConnectionError(FoxreqError):
    """The network connection failed."""


class TlsError(FoxreqError):
    """The TLS exchange failed."""


class CertificateError(TlsError):
    """Peer certificate validation failed."""


class Timeout(FoxreqError):
    """The request deadline elapsed."""


class ProtocolError(FoxreqError):
    """The HTTP response violated the supported protocol contract."""


class ClosedSessionError(FoxreqError):
    """The request used a closed Session."""


class InsecureRequestWarning(UserWarning):
    """TLS peer verification was explicitly disabled."""


_NATIVE_ERRORS = {
    "invalid_argument": InvalidRequestError,
    "closed": ClosedSessionError,
    "timeout": Timeout,
    "connection": ConnectionError,
    "tls": TlsError,
    "certificate": CertificateError,
    "protocol": ProtocolError,
}


def translate_native_error(error):
    """Convert one structured native failure without copying request data."""
    kind = getattr(error, "kind", "internal")
    message = getattr(error, "message", None)
    if not isinstance(message, str) or not message:
        message = "foxreq native request failed"
    exception_type = _NATIVE_ERRORS.get(kind, FoxreqError)
    return exception_type(message)
