"""Contract tests for the deterministic HTTPS/1.1 scenario fixture."""

import unittest
from pathlib import Path

from tests.fixtures.http1_scenarios import (
    SCENARIOS,
    Http1ScenarioServer,
    ScenarioError,
    build_response,
    parse_request,
)


class Http1ScenarioTests(unittest.TestCase):
    def test_chunked_scenario_is_exact(self):
        self.assertEqual(
            build_response("chunked", 0),
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"2\r\nOK\r\n0\r\nX-End: yes\r\n\r\n",
        )

    def test_all_named_scenarios_have_deterministic_responses(self):
        self.assertEqual(
            SCENARIOS,
            (
                "fixed",
                "chunked",
                "informational",
                "close",
                "keepalive-two",
                "server-close",
                "early-close",
                "malformed-length",
                "stall-read",
            ),
        )
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario):
                first = build_response(scenario, 0)
                second = build_response(scenario, 0)
                self.assertEqual(first, second)
                if scenario == "stall-read":
                    self.assertIsNone(first)
                else:
                    self.assertTrue(first.startswith(b"HTTP/1.1 "))

    def test_keepalive_scenario_changes_only_by_request_index(self):
        self.assertIn(b"Content-Length: 3\r\n", build_response("keepalive-two", 0))
        self.assertIn(b"Content-Length: 3\r\n", build_response("keepalive-two", 1))
        self.assertTrue(build_response("keepalive-two", 0).endswith(b"one"))
        self.assertTrue(build_response("keepalive-two", 1).endswith(b"two"))

    def test_unknown_scenario_is_rejected(self):
        with self.assertRaises(ScenarioError):
            build_response("unknown", 0)

    def test_request_parser_preserves_order_and_body(self):
        request = parse_request(
            b"POST /submit?x=1 HTTP/1.1\r\n"
            b"Host: example.test\r\n"
            b"X-Order: first\r\n"
            b"X-Order: second\r\n"
            b"Content-Length: 2\r\n\r\nOK"
        )
        self.assertEqual(request.method, b"POST")
        self.assertEqual(request.target, b"/submit?x=1")
        self.assertEqual(
            request.headers[1:],
            ((b"X-Order", b"first"), (b"X-Order", b"second"), (b"Content-Length", b"2")),
        )
        self.assertEqual(request.body, b"OK")

    def test_request_parser_rejects_ambiguous_or_oversized_heads(self):
        with self.assertRaises(ScenarioError):
            parse_request(
                b"POST / HTTP/1.1\r\nContent-Length: 1\r\n"
                b"Content-Length: 2\r\n\r\nxx"
            )
        with self.assertRaises(ScenarioError):
            parse_request(b"GET / HTTP/1.1\r\nX-Large: " + b"x" * (64 * 1024) + b"\r\n\r\n")

    def test_server_validates_request_values_without_logging_them(self):
        server = Http1ScenarioServer(
            host="127.0.0.1",
            port=8443,
            certificate=Path("server.pem"),
            private_key=Path("server.key"),
            scenario="fixed",
            expected_methods=(b"POST",),
            expected_targets=(b"/submit",),
            expected_bodies=(b"OK",),
            expected_headers=((b"X-Order", b"first"), (b"X-Order", b"second")),
        )
        request = parse_request(
            b"POST /submit HTTP/1.1\r\nHost: example.test\r\n"
            b"X-Order: first\r\nX-Order: second\r\n"
            b"Content-Length: 2\r\n\r\nOK"
        )
        server.validate_request(request, 0, 1)

        mismatched = parse_request(b"GET /submit HTTP/1.1\r\nHost: example.test\r\n\r\n")
        with self.assertRaisesRegex(ScenarioError, "method did not match"):
            server.validate_request(mismatched, 0, 1)


if __name__ == "__main__":
    unittest.main()
