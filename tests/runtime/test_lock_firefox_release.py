import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from scripts.runtime.lock_firefox_release import (
    ReleaseLockError,
    lock_release,
    regenerate_embedded_locks,
)


class LockFirefoxReleaseTests(unittest.TestCase):
    def test_verifies_sha512_and_writes_canonical_schema_two_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            artifact = repository / "firefox-140.12.0.tar.xz"
            files = {
                "firefox/application.ini": (
                    b"[App]\nVersion=140.12.0\nBuildID=20260701000000\n"
                ),
                "firefox/firefox": b"browser",
                "firefox/libnspr4.so": b"nspr",
                "firefox/libnss3.so": b"nss",
            }
            _write_tar(artifact, files)
            sums = repository / "SHA512SUMS"
            sums_name = "linux-x86_64/en-US/" + artifact.name
            sums.write_text(
                "{}  {}\n".format(
                    hashlib.sha512(artifact.read_bytes()).hexdigest(),
                    sums_name,
                ),
                encoding="ascii",
            )
            output = repository / "third_party" / "firefox-140-linux.lock.json"
            embedded = repository / "python" / "foxreq" / "_runtime_locks.py"

            document = lock_release(
                artifact=artifact,
                output=output,
                profile="firefox_140_esr",
                platform="linux-x86_64",
                source_id="firefox-140.12.0-linux-x86_64-en-us",
                source_url="https://archive.mozilla.org/firefox.tar.xz",
                sha512sums=sums,
                sha512_name=sums_name,
                runtime_files=("libnss3.so", "libnspr4.so"),
                repository=repository,
                version_probe=lambda root, platform: ("3.113.1", "4.36.1"),
                embedded_output=embedded,
            )

            self.assertEqual(
                {
                    "schema_version",
                    "profile",
                    "platform",
                    "source_id",
                    "source_url",
                    "source_size",
                    "source_sha256",
                    "source_sha512",
                    "firefox_version",
                    "firefox_build_id",
                    "nss_version",
                    "nspr_version",
                    "files",
                },
                set(document),
            )
            self.assertEqual(
                ["libnspr4.so", "libnss3.so"],
                [entry["filename"] for entry in document["files"]],
            )
            self.assertEqual(document, json.loads(output.read_text(encoding="utf-8")))
            self.assertIn("firefox_140_esr", embedded.read_text(encoding="utf-8"))
            self.assertTrue(output.read_bytes().endswith(b"\n"))

    def test_rejects_artifact_missing_from_sha512sums(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            artifact = repository / "firefox.tar.xz"
            _write_tar(
                artifact,
                {
                    "firefox/application.ini": (
                        b"[App]\nVersion=140.12.0\nBuildID=20260701000000\n"
                    ),
                    "firefox/libnss3.so": b"nss",
                },
            )
            sums = repository / "SHA512SUMS"
            sums.write_text("0" * 128 + "  another.tar.xz\n", encoding="ascii")

            with self.assertRaisesRegex(ReleaseLockError, "SHA512SUMS"):
                lock_release(
                    artifact=artifact,
                    output=repository / "third_party" / "lock.json",
                    profile="firefox_140_esr",
                    platform="linux-x86_64",
                    source_id="fixture",
                    source_url="https://example.invalid/firefox.tar.xz",
                    sha512sums=sums,
                    runtime_files=("libnss3.so",),
                    repository=repository,
                    version_probe=lambda root, platform: ("3.113.1", "4.36.1"),
                )

    def test_embedded_lock_generation_is_deterministic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            locks = root / "third_party"
            locks.mkdir()
            document = _minimal_lock()
            (locks / "firefox-z.lock.json").write_text(
                json.dumps(document), encoding="utf-8"
            )
            output = root / "_runtime_locks.py"

            regenerate_embedded_locks(locks, output)
            first = output.read_bytes()
            regenerate_embedded_locks(locks, output)

            self.assertEqual(first, output.read_bytes())
            self.assertNotIn(str(root).encode(), first)


def _write_tar(path, files):
    with tarfile.open(path, "w:xz") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))


def _minimal_lock():
    payload = b"nss"
    return {
        "schema_version": 2,
        "profile": "firefox_152",
        "platform": "linux-x86_64",
        "source_id": "fixture",
        "source_url": "https://example.invalid/firefox.tar.xz",
        "source_size": 1,
        "source_sha256": "0" * 64,
        "source_sha512": "0" * 128,
        "firefox_version": "152.0.6",
        "firefox_build_id": "20260713164047",
        "nss_version": "3.124",
        "nspr_version": "4.39",
        "files": [
            {
                "filename": "libnss3.so",
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        ],
    }


if __name__ == "__main__":
    unittest.main()
