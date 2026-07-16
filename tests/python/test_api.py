import os
import tempfile
import unittest
import warnings
from unittest import mock

import foxreq._api as api
from foxreq import (
    ClosedSessionError,
    ConfigurationError,
    InsecureRequestWarning,
)


class FakeNativeResponse:
    status = 200
    reason = b"OK"
    url = "https://example.test/data"
    version = "HTTP/1.1"
    headers = [(b"Content-Type", b"application/json")]
    body = b'{"ok":true}'


class FakeNativeSession:
    created = 0
    requests = []
    closed = 0

    def __init__(self, runtime_dir, anchors, profile):
        type(self).created += 1
        self.runtime_dir = runtime_dir
        self.anchors = tuple(anchors)
        self.profile = profile

    def request(self, method, url, headers, body, timeout, insecure):
        type(self).requests.append(
            (method, url, tuple(headers), body, timeout, insecure)
        )
        return FakeNativeResponse()

    def close(self):
        type(self).closed += 1

    @classmethod
    def reset(cls):
        cls.created = 0
        cls.requests = []
        cls.closed = 0


class FakeNativeHttpSession:
    created = 0
    requests = []
    closed = 0

    def __init__(self, profile):
        type(self).created += 1
        self.profile = profile

    def request(self, method, url, headers, body, timeout, insecure):
        type(self).requests.append(
            (method, url, tuple(headers), body, timeout, insecure)
        )
        return FakeNativeResponse()

    def close(self):
        type(self).closed += 1

    @classmethod
    def reset(cls):
        cls.created = 0
        cls.requests = []
        cls.closed = 0


class SessionTests(unittest.TestCase):
    def setUp(self):
        FakeNativeSession.reset()
        FakeNativeHttpSession.reset()

    def test_context_manager_reuses_one_native_session(self):
        with tempfile.TemporaryDirectory() as runtime, mock.patch.object(
            api._foxreq, "NativeSession", FakeNativeSession
        ):
            with api.Session(runtime_dir=runtime, verify=True) as session:
                first = session.get("https://example.test/one")
                second = session.post("https://example.test/two", json={"ok": True})

        self.assertEqual(first.json(), {"ok": True})
        self.assertEqual(second.status_code, 200)
        self.assertEqual(FakeNativeSession.created, 1)
        self.assertEqual(len(FakeNativeSession.requests), 2)
        self.assertEqual(FakeNativeSession.closed, 1)

    def test_close_is_idempotent_and_later_requests_fail(self):
        with mock.patch.object(
            api._foxreq, "NativeHttpSession", FakeNativeHttpSession
        ), mock.patch.object(api._foxreq, "NativeSession", FakeNativeSession):
            session = api.Session(verify=False)
            session.close()
            session.close()
            for url in (
                "http://example.test/closed",
                "https://example.test/closed",
            ):
                with self.subTest(url=url), self.assertRaises(ClosedSessionError):
                    session.get(url)

        self.assertEqual(FakeNativeHttpSession.created, 0)
        self.assertEqual(FakeNativeSession.created, 0)

    def test_http_needs_no_runtime_or_insecure_warning(self):
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
            api._foxreq, "NativeHttpSession", FakeNativeHttpSession
        ), mock.patch.object(
            api._foxreq, "NativeSession", FakeNativeSession
        ), mock.patch.object(
            api, "resolve_runtime_dir", side_effect=AssertionError("runtime resolved")
        ), mock.patch.object(
            api, "normalize_verify", side_effect=AssertionError("verify normalized")
        ), warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with api.Session(impersonate="firefox_140_esr", verify=False) as session:
                first = session.get("http://example.test/one", verify=False)
                second = session.get("http://example.test/two")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(FakeNativeHttpSession.created, 1)
        self.assertEqual(len(FakeNativeHttpSession.requests), 2)
        self.assertEqual(FakeNativeHttpSession.closed, 1)
        self.assertEqual(FakeNativeSession.created, 0)
        self.assertTrue(all(not request[-1] for request in FakeNativeHttpSession.requests))
        self.assertFalse(
            any(issubclass(item.category, InsecureRequestWarning) for item in caught)
        )

    def test_mixed_session_closes_each_created_backend_once(self):
        with tempfile.TemporaryDirectory() as runtime, mock.patch.object(
            api._foxreq, "NativeHttpSession", FakeNativeHttpSession
        ), mock.patch.object(api._foxreq, "NativeSession", FakeNativeSession):
            session = api.Session(runtime_dir=runtime, verify=False)
            session.get("http://example.test/plain")
            with self.assertWarns(InsecureRequestWarning):
                session.get("https://example.test/secure")
            session.close()
            session.close()

        self.assertEqual(FakeNativeHttpSession.created, 1)
        self.assertEqual(FakeNativeHttpSession.closed, 1)
        self.assertEqual(FakeNativeSession.created, 1)
        self.assertEqual(FakeNativeSession.closed, 1)

    def test_insecure_request_warns_and_different_ca_policy_is_rejected(self):
        with tempfile.TemporaryDirectory() as runtime, mock.patch.object(
            api._foxreq, "NativeSession", FakeNativeSession
        ):
            with api.Session(runtime_dir=runtime, verify=True) as session:
                with self.assertWarns(InsecureRequestWarning):
                    session.get("https://example.test/insecure", verify=False)
                with tempfile.NamedTemporaryFile(suffix=".pem") as other:
                    with self.assertRaises(ConfigurationError):
                        session.get("https://example.test/other", verify=other.name)

        self.assertTrue(FakeNativeSession.requests[0][-1])

    def test_top_level_get_creates_and_closes_one_short_session(self):
        with tempfile.TemporaryDirectory() as runtime, mock.patch.object(
            api._foxreq, "NativeSession", FakeNativeSession
        ):
            with self.assertWarns(InsecureRequestWarning):
                response = api.get(
                    "https://example.test/top",
                    runtime_dir=runtime,
                    verify=False,
                    params=[("x", "one"), ("x", "two")],
                )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(FakeNativeSession.created, 1)
        self.assertEqual(FakeNativeSession.closed, 1)
        self.assertIn("?x=one&x=two", FakeNativeSession.requests[0][1])


if __name__ == "__main__":
    unittest.main()
