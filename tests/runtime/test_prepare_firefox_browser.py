import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.runtime.prepare_firefox_browser import (
    BrowserPreparationError,
    prepare_browser,
)


class PrepareFirefoxBrowserTests(unittest.TestCase):
    def test_extracts_a_fresh_browser_from_the_hash_locked_installer(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            installer = repository / ".cache" / "sources" / "firefox.exe"
            installer.parent.mkdir(parents=True)
            installer.write_bytes(b"locked installer")
            lock = repository / "runtime.lock.json"
            lock.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "platform": "windows-x86_64",
                        "source_id": "firefox-windows-x86_64-en-us",
                        "source_size": installer.stat().st_size,
                        "source_sha256": hashlib.sha256(
                            installer.read_bytes()
                        ).hexdigest(),
                        "firefox_version": "152.0.6",
                        "firefox_build_id": "20260713164047",
                    }
                ),
                encoding="utf-8",
            )
            output = repository / ".cache" / "firefox-browser" / "windows"
            calls = []

            def runner(command, check, timeout):
                calls.append((command, check, timeout))
                extracted = Path(command[1].split("=", 1)[1]) / "core"
                extracted.mkdir(parents=True)
                (extracted / "firefox.exe").write_bytes(b"exact browser binary")
                (extracted / "xul.dll").write_bytes(b"browser dependency")
                (extracted / "application.ini").write_text(
                    "[App]\nVersion=152.0.6\nBuildID=20260713164047\n",
                    encoding="utf-8",
                )

                class Completed:
                    returncode = 0

                return Completed()

            evidence = prepare_browser(
                installer=installer,
                output=output,
                lock=lock,
                repository=repository,
                runner=runner,
            )

            self.assertEqual(1, len(calls))
            self.assertEqual(b"browser dependency", (output / "xul.dll").read_bytes())
            self.assertEqual(
                hashlib.sha256(b"exact browser binary").hexdigest(),
                evidence["firefox_binary_sha256"],
            )
            self.assertEqual(str(output / "firefox.exe"), evidence["firefox_binary"])

    def test_rejects_output_outside_the_browser_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            with self.assertRaisesRegex(BrowserPreparationError, "under"):
                prepare_browser(
                    installer=repository / "missing.exe",
                    output=repository / "outside",
                    lock=repository / "missing.json",
                    repository=repository,
                )


if __name__ == "__main__":
    unittest.main()
