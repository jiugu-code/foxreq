import json
import os
import subprocess
import sys
import tempfile
import unittest

from tools.fingerprint.h2 import CLIENT_PREFACE

from .helpers import (
    extension,
    h2_frame,
    h2_settings,
    synthetic_client_hello,
)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.directory.cleanup()

    def write_hex(self, name, wire):
        path = os.path.join(self.directory.name, name)
        with open(path, "w") as handle:
            handle.write(wire.hex())
        return path

    def run_cli(self, *arguments):
        return subprocess.run(
            [sys.executable, "-m", "tools.fingerprint"] + list(arguments),
            text=True,
            capture_output=True,
        )

    def test_tls_inspect_emits_stable_json(self):
        path = self.write_hex(
            "hello.hex",
            synthetic_client_hello(extension(43, b"\x02\x03\x04")),
        )

        result = self.run_cli("tls", "inspect", "--hex", path)

        self.assertEqual(0, result.returncode, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(771, output["client_hello"]["legacy_version"])
        self.assertIn("ja3", output)
        self.assertIn("ja4", output)

    def test_compare_returns_one_and_machine_readable_diffs(self):
        left = self.write_hex(
            "left.hex",
            synthetic_client_hello(ciphers=(0x1301, 0x1302)),
        )
        right = self.write_hex(
            "right.hex",
            synthetic_client_hello(ciphers=(0x1302, 0x1301)),
        )

        result = self.run_cli("tls", "compare", "--hex", left, right)

        self.assertEqual(1, result.returncode, result.stderr)
        differences = json.loads(result.stdout)["differences"]
        self.assertEqual("$.cipher_suites[0]", differences[0]["path"])

    def test_policy_reports_fixed_positions_and_movable_types(self):
        first = self.write_hex(
            "first.hex",
            synthetic_client_hello(
                extension(5) + extension(18) + extension(35) + extension(23)
            ),
        )
        second = self.write_hex(
            "second.hex",
            synthetic_client_hello(
                extension(5) + extension(35) + extension(18) + extension(23)
            ),
        )

        result = self.run_cli("tls", "policy", "--hex", first, second)

        self.assertEqual(0, result.returncode, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual({"0": 5, "3": 23}, output["fixed_positions"])
        self.assertEqual([18, 35], output["movable_types"])

    def test_h2_inspect_decodes_ordered_settings(self):
        path = self.write_hex(
            "h2.hex",
            CLIENT_PREFACE + h2_frame(4, h2_settings((1, 65536), (4, 131072))),
        )

        result = self.run_cli("h2", "inspect", "--hex", path)

        self.assertEqual(0, result.returncode, result.stderr)
        settings = json.loads(result.stdout)["frames"][0]["settings"]
        self.assertEqual([1, 4], [value["identifier"] for value in settings])

    def test_invalid_hex_returns_two_with_json_error(self):
        path = os.path.join(self.directory.name, "invalid.hex")
        with open(path, "w") as handle:
            handle.write("not-hex")

        result = self.run_cli("tls", "inspect", "--hex", path)

        self.assertEqual(2, result.returncode)
        self.assertIn("error", json.loads(result.stderr))
        self.assertEqual("", result.stdout)

    def test_help_lists_protocol_commands(self):
        result = self.run_cli("--help")

        self.assertEqual(0, result.returncode)
        self.assertIn("tls", result.stdout)
        self.assertIn("h2", result.stdout)


if __name__ == "__main__":
    unittest.main()
