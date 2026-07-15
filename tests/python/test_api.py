import tempfile
import unittest
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


class SessionTests(unittest.TestCase):
    def setUp(self):
        FakeNativeSession.reset()

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
        with tempfile.TemporaryDirectory() as runtime, mock.patch.object(
            api._foxreq, "NativeSession", FakeNativeSession
        ):
            session = api.Session(runtime_dir=runtime, verify=False)
            session.close()
            session.close()
            with self.assertRaises(ClosedSessionError):
                session.get("https://example.test/closed")

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
