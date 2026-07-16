import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from foxreq import ConfigurationError
from foxreq import _runtime_locks
from foxreq._runtime_manifest import validate_runtime


class RuntimeManifestTests(unittest.TestCase):
    def test_validates_all_four_profile_platform_identities(self):
        pairs = (
            ("firefox_140_esr", "windows-x86_64", "nss3.dll"),
            ("firefox_140_esr", "linux-x86_64", "libnss3.so"),
            ("firefox_152", "windows-x86_64", "nss3.dll"),
            ("firefox_152", "linux-x86_64", "libnss3.so"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            locks = {}
            for index, (profile, platform, filename) in enumerate(pairs):
                runtime = root / str(index)
                runtime.mkdir()
                payload = "{}:{}".format(profile, platform).encode()
                (runtime / filename).write_bytes(payload)
                locks[(profile, platform)] = _schema_two_lock(
                    profile, platform, filename, payload
                )
            with mock.patch.object(_runtime_locks, "RUNTIME_LOCKS", locks):
                for index, (profile, platform, _) in enumerate(pairs):
                    with self.subTest(profile=profile, platform=platform):
                        validated = validate_runtime(
                            profile, root / str(index), platform=platform
                        )
                        self.assertEqual(profile, validated.profile_id)
                        self.assertEqual(platform, validated.platform)

    def test_validates_exact_profile_platform_files_and_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary)
            payload = b"locked runtime"
            (runtime / "nss3.dll").write_bytes(payload)
            locks = {
                ("firefox_152", "windows-x86_64"): _schema_two_lock(
                    "firefox_152", "windows-x86_64", "nss3.dll", payload
                )
            }

            with mock.patch.object(_runtime_locks, "RUNTIME_LOCKS", locks):
                validated = validate_runtime(
                    "firefox_152", runtime, platform="windows-x86_64"
                )

            self.assertEqual(runtime.resolve(), validated.path)
            self.assertEqual("firefox_152", validated.profile_id)
            self.assertEqual("windows-x86_64", validated.platform)
            self.assertEqual("3.124", validated.nss_version)
            self.assertEqual("4.39", validated.nspr_version)

    def test_rejects_unknown_profile_platform_pair(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            _runtime_locks, "RUNTIME_LOCKS", {}
        ):
            with self.assertRaisesRegex(ConfigurationError, "not available"):
                validate_runtime(
                    "firefox_140_esr",
                    temporary,
                    platform="linux-x86_64",
                )

    def test_rejects_runtime_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary)
            (runtime / "libnss3.so").write_bytes(b"tampered")
            locks = {
                ("firefox_140_esr", "linux-x86_64"): _schema_two_lock(
                    "firefox_140_esr",
                    "linux-x86_64",
                    "libnss3.so",
                    b"expected",
                )
            }
            with mock.patch.object(_runtime_locks, "RUNTIME_LOCKS", locks):
                with self.assertRaisesRegex(ConfigurationError, "does not match"):
                    validate_runtime(
                        "firefox_140_esr",
                        runtime,
                        platform="linux-x86_64",
                    )

    def test_rejects_a_profile_with_the_wrong_firefox_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary)
            payload = b"nss"
            (runtime / "nss3.dll").write_bytes(payload)
            manifest = _schema_two_lock(
                "firefox_152", "windows-x86_64", "nss3.dll", payload
            )
            manifest["firefox_version"] = "140.12.0"
            locks = {("firefox_152", "windows-x86_64"): manifest}
            with mock.patch.object(_runtime_locks, "RUNTIME_LOCKS", locks):
                with self.assertRaisesRegex(ConfigurationError, "versions"):
                    validate_runtime(
                        "firefox_152", runtime, platform="windows-x86_64"
                    )

    def test_rejects_symlinked_runtime_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            runtime.mkdir()
            target = root / "outside.dll"
            target.write_bytes(b"expected")
            link = runtime / "nss3.dll"
            try:
                link.symlink_to(target)
            except (NotImplementedError, OSError):
                self.skipTest("symlinks are not available for this account")
            locks = {
                ("firefox_152", "windows-x86_64"): _schema_two_lock(
                    "firefox_152", "windows-x86_64", "nss3.dll", b"expected"
                )
            }
            with mock.patch.object(_runtime_locks, "RUNTIME_LOCKS", locks):
                with self.assertRaisesRegex(ConfigurationError, "regular file"):
                    validate_runtime(
                        "firefox_152", runtime, platform="windows-x86_64"
                    )

    def test_accepts_the_exact_legacy_firefox_152_windows_lock(self):
        lock = _runtime_locks.RUNTIME_LOCKS[
            ("firefox_152", "windows-x86_64")
        ]
        self.assertEqual(1, lock["schema_version"])
        self.assertEqual("152.0.6", lock["firefox_version"])
        self.assertEqual("3.124", lock["nss_version"])
        self.assertEqual("4.39", lock["nspr_version"])

    def test_embedded_legacy_record_matches_the_reviewed_json_lock(self):
        repository = Path(__file__).parents[2]
        reviewed = json.loads(
            (repository / "third_party" / "firefox-windows-runtime.lock.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            reviewed,
            _runtime_locks.RUNTIME_LOCKS[("firefox_152", "windows-x86_64")],
        )


def _schema_two_lock(profile, platform, filename, payload):
    return {
        "schema_version": 2,
        "profile": profile,
        "platform": platform,
        "source_id": "fixture",
        "source_url": "https://example.invalid/firefox.tar.xz",
        "source_size": 1,
        "source_sha256": "0" * 64,
        "source_sha512": "0" * 128,
        "firefox_version": "152.0.6" if profile == "firefox_152" else "140.12.0",
        "firefox_build_id": "20260713164047",
        "nss_version": "3.124",
        "nspr_version": "4.39",
        "files": [
            {
                "filename": filename,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        ],
    }


if __name__ == "__main__":
    unittest.main()
