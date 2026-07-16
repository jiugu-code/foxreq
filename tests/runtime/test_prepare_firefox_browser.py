import hashlib
import io
import json
import tarfile
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

    def test_extracts_linux_browser_from_schema_two_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            archive = repository / "firefox.tar.xz"
            with tarfile.open(archive, "w:xz") as tar:
                _tar_file(tar, "firefox/firefox", b"linux browser")
                _tar_file(
                    tar,
                    "firefox/application.ini",
                    b"[App]\nVersion=140.12.0\nBuildID=20260701000000\n",
                )
                _tar_file(tar, "firefox/libxul.so", b"dependency")
            artifact = archive.read_bytes()
            lock = repository / "runtime.lock.json"
            lock.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "profile": "firefox_140_esr",
                        "platform": "linux-x86_64",
                        "source_id": "fixture",
                        "source_url": "https://example.invalid/firefox.tar.xz",
                        "source_size": len(artifact),
                        "source_sha256": hashlib.sha256(artifact).hexdigest(),
                        "source_sha512": hashlib.sha512(artifact).hexdigest(),
                        "firefox_version": "140.12.0",
                        "firefox_build_id": "20260701000000",
                        "nss_version": "3.113.1",
                        "nspr_version": "4.36.1",
                        "files": [
                            {
                                "filename": "libxul.so",
                                "size": len(b"dependency"),
                                "sha256": hashlib.sha256(b"dependency").hexdigest(),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            output = repository / ".cache" / "firefox-browser" / "linux"

            evidence = prepare_browser(
                installer=archive,
                output=output,
                lock=lock,
                repository=repository,
                profile="firefox_140_esr",
                platform="linux-x86_64",
            )

            self.assertEqual(b"dependency", (output / "libxul.so").read_bytes())
            self.assertEqual(str(output / "firefox"), evidence["firefox_binary"])
            self.assertEqual("140.12.0", evidence["firefox_version"])


def _tar_file(archive, name, content):
    info = tarfile.TarInfo(name)
    info.size = len(content)
    archive.addfile(info, io.BytesIO(content))


if __name__ == "__main__":
    unittest.main()
