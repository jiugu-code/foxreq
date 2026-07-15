import unittest

from foxreq._headers import Headers
from foxreq._models import Response


class FakeNativeResponse:
    status = 200
    reason = b"OK"
    url = "https://example.test/data"
    version = "HTTP/1.1"
    headers = [
        (b"Set-Cookie", b"a=1"),
        (b"set-cookie", b"b=2"),
        (b"Content-Type", b"application/json; charset=utf-8"),
    ]
    body = b'{"ok":true}'


class HeadersTests(unittest.TestCase):
    def test_preserves_duplicates_and_case_insensitive_lookup(self):
        headers = Headers((('Set-Cookie', 'a=1'), ('set-cookie', 'b=2')))
        self.assertEqual(headers.get_all("SET-COOKIE"), ("a=1", "b=2"))
        self.assertEqual(headers.get("set-cookie"), "a=1")
        self.assertEqual(
            list(headers.items()),
            [("Set-Cookie", "a=1"), ("set-cookie", "b=2")],
        )
        with self.assertRaises(TypeError):
            headers["X-New"] = "value"
        with self.assertRaises(TypeError):
            Headers(["ab"])


class ResponseTests(unittest.TestCase):
    def test_copies_native_data_and_decodes_text_and_json(self):
        response = Response.from_native(FakeNativeResponse())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.reason, "OK")
        self.assertEqual(response.http_version, "HTTP/1.1")
        self.assertEqual(response.content, b'{"ok":true}')
        self.assertEqual(response.text, '{"ok":true}')
        self.assertEqual(response.json(), {"ok": True})
        self.assertEqual(response.headers.get_all("set-cookie"), ("a=1", "b=2"))

    def test_unknown_charset_falls_back_to_utf8_replacement(self):
        native = FakeNativeResponse()
        native.headers = [(b"Content-Type", b"text/plain; charset=unknown-charset")]
        native.body = b"ok\xff"
        response = Response.from_native(native)
        self.assertEqual(response.text, "ok\ufffd")


if __name__ == "__main__":
    unittest.main()
