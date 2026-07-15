import os
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from foxreq._exceptions import ConfigurationError, InvalidRequestError
from foxreq._normalize import (
    normalize_profile,
    normalize_request,
    normalize_timeout,
    normalize_verify,
    resolve_runtime_dir,
)


class NormalizeRequestTests(unittest.TestCase):
    def test_preserves_duplicate_headers_and_ordered_query_values(self):
        request = normalize_request(
            "get",
            "https://例子.test/path?existing=1",
            [("x", "first"), ("x", "second")],
            [("X-Order", "first"), ("X-Order", "second")],
            None,
            None,
            2.5,
            "firefox_152",
        )

        self.assertEqual(request.method, b"GET")
        self.assertEqual(
            request.url,
            "https://xn--fsqu00a.test/path?existing=1&x=first&x=second",
        )
        self.assertEqual(
            request.headers,
            ((b"X-Order", b"first"), (b"X-Order", b"second")),
        )
        self.assertEqual(request.timeout, 2.5)

    def test_json_is_compact_utf8_and_adds_content_type_once(self):
        request = normalize_request(
            "POST",
            "https://example.test/submit",
            None,
            [("content-type", "application/custom")],
            None,
            {"message": "中文"},
            1,
            "firefox_152",
        )
        self.assertEqual(request.body, '{"message":"中文"}'.encode("utf-8"))
        self.assertEqual(request.headers, ((b"content-type", b"application/custom"),))

        automatic = normalize_request(
            "POST",
            "https://example.test/submit",
            None,
            None,
            None,
            {"ok": True},
            1,
            "firefox_152",
        )
        self.assertIn((b"Content-Type", b"application/json"), automatic.headers)

    def test_rejects_conflicting_bodies_and_header_injection(self):
        with self.assertRaises(InvalidRequestError):
            normalize_request(
                "POST",
                "https://example.test/",
                None,
                None,
                b"data",
                {"json": True},
                1,
                "firefox_152",
            )
        with self.assertRaises(InvalidRequestError):
            normalize_request(
                "GET",
                "https://example.test/",
                None,
                [("X-Test", "safe\r\nInjected: yes")],
                None,
                None,
                1,
                "firefox_152",
            )

    def test_timeout_profile_and_url_are_fail_closed(self):
        for value in (0, -1, float("inf"), float("nan"), True):
            with self.subTest(value=value), self.assertRaises(InvalidRequestError):
                normalize_timeout(value)
        self.assertEqual(normalize_profile("firefox_152"), "firefox_152")
        with self.assertRaises(InvalidRequestError):
            normalize_profile("firefox_latest")
        with self.assertRaises(InvalidRequestError):
            normalize_request(
                "GET",
                "http://example.test/",
                None,
                None,
                None,
                None,
                1,
                "firefox_152",
            )
        with self.assertRaises(InvalidRequestError):
            normalize_request(
                "GET",
                "https://user@example.test/",
                None,
                None,
                None,
                None,
                1,
                "firefox_152",
            )


class VerifyPolicyTests(unittest.TestCase):
    def test_false_is_explicitly_insecure(self):
        policy = normalize_verify(False)
        self.assertTrue(policy.insecure)
        self.assertEqual(policy.anchors, ())

    def test_default_certifi_bundle_produces_multiple_anchors(self):
        policy = normalize_verify(True)
        self.assertFalse(policy.insecure)
        self.assertGreater(len(policy.anchors), 100)
        self.assertTrue(all(isinstance(anchor, bytes) and anchor for anchor in policy.anchors))

    def test_parses_a_commented_pem_bundle_and_rejects_stray_text(self):
        first = b"\x30\x03\x02\x01\x01"
        second = b"\x30\x03\x02\x01\x02"
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory, "bundle.pem")
            bundle.write_text(
                "# local test bundle\n"
                + ssl.DER_cert_to_PEM_cert(first)
                + "\n"
                + ssl.DER_cert_to_PEM_cert(second),
                encoding="ascii",
            )
            policy = normalize_verify(bundle)
            self.assertFalse(policy.insecure)
            self.assertEqual(policy.anchors, (first, second))

            bundle.write_text(
                ssl.DER_cert_to_PEM_cert(first) + "unexpected text\n",
                encoding="ascii",
            )
            with self.assertRaises(ConfigurationError):
                normalize_verify(bundle)

    def test_rejects_empty_directory_and_oversized_pem_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ConfigurationError):
                normalize_verify(directory)
            empty = Path(directory, "empty.pem")
            empty.write_bytes(b"")
            with self.assertRaises(ConfigurationError):
                normalize_verify(empty)
            oversized = Path(directory, "oversized.pem")
            with oversized.open("wb") as output:
                output.seek(4 * 1024 * 1024)
                output.write(b"x")
            with self.assertRaises(ConfigurationError):
                normalize_verify(oversized)

    def test_runtime_resolution_prefers_explicit_then_environment(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            with mock.patch.dict(os.environ, {"FOXREQ_NSS_RUNTIME_DIR": second}):
                self.assertEqual(resolve_runtime_dir(first), Path(first).resolve())
                self.assertEqual(resolve_runtime_dir(None), Path(second).resolve())
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ConfigurationError):
                resolve_runtime_dir(None)


if __name__ == "__main__":
    unittest.main()
