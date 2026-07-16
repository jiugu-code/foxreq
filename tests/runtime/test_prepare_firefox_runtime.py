import hashlib
import io
import json
import subprocess
import tarfile
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

    def test_linux_tar_copies_only_lock_listed_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            archive = repository / "firefox.tar.xz"
            _write_tar(
                archive,
                {
                    "firefox/libnss3.so": b"nss",
                    "firefox/libnspr4.so": b"nspr",
                    "firefox/firefox": b"must not be copied",
                },
            )
            payloads = {"libnss3.so": b"nss", "libnspr4.so": b"nspr"}
            lock = repository / "runtime.lock.json"
            lock.write_text(
                json.dumps(
                    _schema_two_lock(
                        archive.read_bytes(),
                        payloads,
                        profile="firefox_140_esr",
                        platform="linux-x86_64",
                    )
                ),
                encoding="utf-8",
            )
            output = repository / ".cache" / "firefox-runtime" / "linux"

            prepared = prepare_runtime(
                archive,
                output,
                lock,
                repository=repository,
                profile="firefox_140_esr",
                platform="linux-x86_64",
            )

            self.assertEqual(output.resolve(), prepared)
            self.assertEqual(set(payloads), {path.name for path in output.iterdir()})

    def test_linux_tar_rejects_every_unsafe_member_before_output_creation(self):
        unsafe = (
            ("../escape", "file"),
            ("/absolute", "file"),
            ("firefox/link", "symlink"),
            ("firefox/hard", "hardlink"),
            ("firefox/device", "device"),
        )
        for name, kind in unsafe:
            with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as temporary:
                repository = Path(temporary)
                archive = repository / "firefox.tar.xz"
                _write_tar(archive, {"firefox/libnss3.so": b"nss"}, (name, kind))
                lock = repository / "runtime.lock.json"
                lock.write_text(
                    json.dumps(
                        _schema_two_lock(
                            archive.read_bytes(),
                            {"libnss3.so": b"nss"},
                            profile="firefox_140_esr",
                            platform="linux-x86_64",
                        )
                    ),
                    encoding="utf-8",
                )
                output = repository / ".cache" / "firefox-runtime" / "linux"

                with self.assertRaisesRegex(RuntimePreparationError, "unsafe"):
                    prepare_runtime(
                        archive,
                        output,
                        lock,
                        repository=repository,
                        profile="firefox_140_esr",
                        platform="linux-x86_64",
                    )
                self.assertFalse(output.exists())


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


def _schema_two_lock(artifact, payloads, profile, platform):
    return {
        "schema_version": 2,
        "profile": profile,
        "platform": platform,
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
                "filename": name,
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            for name, content in sorted(payloads.items())
        ],
    }


def _write_tar(path, files, unsafe=None):
    with tarfile.open(path, "w:xz") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
        if unsafe is None:
            return
        name, kind = unsafe
        info = tarfile.TarInfo(name)
        if kind == "file":
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        elif kind == "symlink":
            info.type = tarfile.SYMTYPE
            info.linkname = "../outside"
            archive.addfile(info)
        elif kind == "hardlink":
            info.type = tarfile.LNKTYPE
            info.linkname = "firefox/libnss3.so"
            archive.addfile(info)
        elif kind == "device":
            info.type = tarfile.CHRTYPE
            archive.addfile(info)


if __name__ == "__main__":
    unittest.main()
