import unittest

from foxreq._exceptions import (
    CertificateError,
    ClosedSessionError,
    ConnectionError,
    FoxreqError,
    InvalidRequestError,
    ProtocolError,
    Timeout,
    TlsError,
    translate_native_error,
)


class FakeNativeError(Exception):
    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind
        self.message = message


class ExceptionMappingTests(unittest.TestCase):
    def test_maps_every_stable_native_kind(self):
        expected = {
            "invalid_argument": InvalidRequestError,
            "closed": ClosedSessionError,
            "timeout": Timeout,
            "connection": ConnectionError,
            "tls": TlsError,
            "certificate": CertificateError,
            "protocol": ProtocolError,
            "worker_panic": FoxreqError,
            "internal": FoxreqError,
        }
        for kind, exception_type in expected.items():
            with self.subTest(kind=kind):
                translated = translate_native_error(FakeNativeError(kind, "safe message"))
                self.assertIsInstance(translated, exception_type)
                self.assertEqual(str(translated), "safe message")

    def test_unknown_native_kind_falls_back_to_base_error(self):
        self.assertIsInstance(
            translate_native_error(FakeNativeError("future", "safe message")),
            FoxreqError,
        )


if __name__ == "__main__":
    unittest.main()
