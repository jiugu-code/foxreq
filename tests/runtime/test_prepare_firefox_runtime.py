import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.runtime.prepare_firefox_runtime import (
    RuntimePreparationError,
    prepare_runtime,
)


class PrepareFirefoxRuntimeTests(unittest.TestCase):
    def test_extracts_only_files_verified_by_the_runtime_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            installer = repository / "firefox.exe"
            installer.write_bytes(b"locked installer")
            payloads = {
                "mozglue.dll": b"mozglue",
                "nss3.dll": b"nss",
                "freebl3.dll": b"freebl",
                "softokn3.dll": b"softokn",
            }
            lock = repository / "runtime.lock.json"
            lock.write_text(
                json.dumps(_lock(installer.read_bytes(), payloads)), encoding="utf-8"
            )

            def extract(command, check, timeout):
                self.assertFalse(check)
                self.assertEqual(180, timeout)
                extraction = Path(command[1].split("=", 1)[1]) / "core"
                extraction.mkdir()
                for name, content in payloads.items():
                    (extraction / name).write_bytes(content)
                (extraction / "firefox.exe").write_bytes(b"must not be copied")
                return subprocess.CompletedProcess(command, 0)

            output = repository / ".cache" / "firefox-runtime" / "prepared"
            prepared = prepare_runtime(
                installer, output, lock, repository=repository, runner=extract
            )

            self.assertEqual(output.resolve(), prepared)
            self.assertEqual(set(payloads), {path.name for path in output.iterdir()})

    def test_rejects_output_outside_the_runtime_cache(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            with self.assertRaisesRegex(RuntimePreparationError, "must be under"):
                prepare_runtime(
                    repository / "firefox.exe",
                    repository / "outside",
                    repository / "runtime.lock.json",
                    repository=repository,
                )


def _lock(installer, payloads):
    return {
        "schema_version": 1,
        "platform": "windows-x86_64",
        "source_id": "firefox-windows-x86_64-en-us",
        "source_size": len(installer),
        "source_sha256": hashlib.sha256(installer).hexdigest(),
        "files": [
            {
                "filename": name,
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            for name, content in payloads.items()
        ],
    }


if __name__ == "__main__":
    unittest.main()
