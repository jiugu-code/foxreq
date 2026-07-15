import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.provenance.verify_sources import (
    LockError,
    load_profile_lock,
    load_source_lock,
    verify_cached_sources,
)


def _source(source_id, filename, content=b"abc"):
    return {
        "id": source_id,
        "url": "https://archive.mozilla.org/" + filename,
        "filename": filename,
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
    }


def _source_lock():
    return {
        "schema_version": 1,
        "sources": [
            _source("firefox-source", "firefox-152.0.6.source.tar.xz"),
            _source("firefox-windows-x86_64-en-us", "firefox-setup.exe"),
            _source("firefox-linux-x86_64-en-us", "firefox.tar.xz"),
            _source("nss-source", "nss.tar.gz"),
            _source("nspr-source", "nspr.tar.gz"),
        ],
    }


def _profile_lock():
    return {
        "schema_version": 1,
        "profile": "firefox_152",
        "firefox": {
            "version": "152.0.6",
            "channel": "release",
            "build_id": "20260713164047",
            "release_revision": "1" * 40,
            "source_id": "firefox-source",
            "artifacts": {
                "windows-x86_64": "firefox-windows-x86_64-en-us",
                "linux-x86_64": "firefox-linux-x86_64-en-us",
            },
            "binary_evidence": {
                "windows-x86_64": {
                    "filename": "firefox.exe",
                    "sha256": "4" * 64,
                    "size": 1234,
                },
                "linux-x86_64": {
                    "filename": "firefox",
                    "sha256": "5" * 64,
                    "size": 2345,
                },
            },
        },
        "components": {
            "nss": {
                "repository": "https://hg.mozilla.org/projects/nss",
                "revision": "2" * 40,
                "source_id": "nss-source",
                "source_path": "security/nss",
                "version": "3.124.0",
            },
            "nspr": {
                "repository": "https://hg.mozilla.org/projects/nspr",
                "revision": "3" * 40,
                "source_id": "nspr-source",
                "source_path": "nsprpub",
                "version": "4.38.2",
            },
        },
        "builds": {
            "windows-x86_64": {
                "compiler": "MSVC 19.44.35228",
                "flags": ["opt", "x64"],
            },
            "linux-x86_64": {
                "compiler": "GCC 11.4.1",
                "flags": ["opt", "x64"],
            },
        },
        "deferred_platforms": [],
        "patches": [],
        "capture": {
            "endpoint": "https://127.0.0.1:8443/",
            "operating_systems": {
                "windows-x86_64": "Windows 11 test build",
                "linux-x86_64": "CentOS 7 test build",
            },
            "locales": {
                "windows-x86_64": "en-US",
                "linux-x86_64": "en-US",
            },
            "preferences": {},
            "tools": {"foxreq-capture": "1"},
        },
    }


class ProvenanceLockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source_path = self.root / "sources.json"
        self.profile_path = self.root / "profile.json"

    def tearDown(self):
        self.temp.cleanup()

    def _write(self, path, value):
        path.write_text(json.dumps(value), encoding="utf-8")

    def test_valid_locks_are_loaded_and_cross_referenced(self):
        self._write(self.source_path, _source_lock())
        self._write(self.profile_path, _profile_lock())

        sources = load_source_lock(self.source_path)
        profile = load_profile_lock(self.profile_path, sources, self.root)

        self.assertEqual(sources["firefox-source"]["size"], 3)
        self.assertEqual(profile["firefox"]["version"], "152.0.6")
        self.assertEqual(
            profile["firefox"]["binary_evidence"]["windows-x86_64"]["sha256"],
            "4" * 64,
        )

    def test_unknown_and_missing_keys_are_rejected(self):
        lock = _source_lock()
        lock["unexpected"] = True
        self._write(self.source_path, lock)
        with self.assertRaisesRegex(LockError, "unknown keys"):
            load_source_lock(self.source_path)

        profile = _profile_lock()
        del profile["capture"]
        self._write(self.source_path, _source_lock())
        self._write(self.profile_path, profile)
        with self.assertRaisesRegex(LockError, "missing keys"):
            load_profile_lock(
                self.profile_path, load_source_lock(self.source_path), self.root
            )

    def test_sources_require_https_exact_hash_size_and_unique_identity(self):
        cases = []

        non_https = _source_lock()
        non_https["sources"][0]["url"] = "http://archive.mozilla.org/file"
        cases.append(non_https)

        mutable = _source_lock()
        mutable["sources"][0]["url"] = "https://example.test/latest/file"
        cases.append(mutable)

        bad_hash = _source_lock()
        bad_hash["sources"][0]["sha256"] = "abc"
        cases.append(bad_hash)

        zero_size = _source_lock()
        zero_size["sources"][0]["size"] = 0
        cases.append(zero_size)

        duplicate = _source_lock()
        duplicate["sources"][1]["id"] = duplicate["sources"][0]["id"]
        cases.append(duplicate)

        for index, lock in enumerate(cases):
            with self.subTest(index=index):
                self._write(self.source_path, lock)
                with self.assertRaises(LockError):
                    load_source_lock(self.source_path)

    def test_profile_requires_exact_versions_revisions_and_source_refs(self):
        sources = _source_lock()
        self._write(self.source_path, sources)
        loaded_sources = load_source_lock(self.source_path)

        cases = []
        mutable_version = _profile_lock()
        mutable_version["firefox"]["version"] = "latest"
        cases.append(mutable_version)

        short_revision = _profile_lock()
        short_revision["components"]["nss"]["revision"] = "1234"
        cases.append(short_revision)

        missing_ref = _profile_lock()
        missing_ref["components"]["nspr"]["source_id"] = "unknown"
        cases.append(missing_ref)

        placeholder_compiler = _profile_lock()
        placeholder_compiler["builds"]["linux-x86_64"]["compiler"] = "pending"
        cases.append(placeholder_compiler)

        for index, profile in enumerate(cases):
            with self.subTest(index=index):
                self._write(self.profile_path, profile)
                with self.assertRaises(LockError):
                    load_profile_lock(self.profile_path, loaded_sources, self.root)

    def test_linux_can_be_explicitly_deferred_without_claiming_verification(self):
        self._write(self.source_path, _source_lock())
        sources = load_source_lock(self.source_path)
        profile = _profile_lock()
        profile["deferred_platforms"] = ["linux-x86_64"]
        del profile["builds"]["linux-x86_64"]
        del profile["capture"]["operating_systems"]["linux-x86_64"]
        del profile["firefox"]["binary_evidence"]["linux-x86_64"]
        self._write(self.profile_path, profile)

        loaded = load_profile_lock(self.profile_path, sources, self.root)
        self.assertEqual(loaded["deferred_platforms"], ["linux-x86_64"])

        profile["builds"]["linux-x86_64"] = {
            "compiler": "GCC 11.4.1",
            "flags": ["opt", "x64"],
        }
        self._write(self.profile_path, profile)
        with self.assertRaises(LockError):
            load_profile_lock(self.profile_path, sources, self.root)

        profile = _profile_lock()
        profile["deferred_platforms"] = list(profile["builds"])
        profile["builds"] = {}
        self._write(self.profile_path, profile)
        with self.assertRaises(LockError):
            load_profile_lock(self.profile_path, sources, self.root)

    def test_patch_must_exist_inside_repo_and_match_hash(self):
        self._write(self.source_path, _source_lock())
        sources = load_source_lock(self.source_path)
        patch_dir = self.root / "third_party" / "patches" / "nss"
        patch_dir.mkdir(parents=True)
        patch = patch_dir / "0001-test.patch"
        patch.write_bytes(b"patch")

        profile = _profile_lock()
        profile["patches"] = [
            {
                "path": "third_party/patches/nss/0001-test.patch",
                "sha256": hashlib.sha256(b"patch").hexdigest(),
            }
        ]
        self._write(self.profile_path, profile)
        load_profile_lock(self.profile_path, sources, self.root)

        profile["patches"][0]["sha256"] = "f" * 64
        self._write(self.profile_path, profile)
        with self.assertRaisesRegex(LockError, "patch hash"):
            load_profile_lock(self.profile_path, sources, self.root)

        profile["patches"][0]["path"] = "../outside.patch"
        self._write(self.profile_path, profile)
        with self.assertRaises(LockError):
            load_profile_lock(self.profile_path, sources, self.root)

    def test_offline_verification_checks_file_size_and_hash(self):
        lock = {"schema_version": 1, "sources": [_source("one", "one.bin")]}
        self._write(self.source_path, lock)
        sources = load_source_lock(self.source_path)
        cache = self.root / "cache"
        cache.mkdir()
        (cache / "one.bin").write_bytes(b"abc")

        verified = verify_cached_sources(sources, cache)
        self.assertEqual(verified, ["one"])

        (cache / "one.bin").write_bytes(b"abd")
        with self.assertRaisesRegex(LockError, "hash mismatch"):
            verify_cached_sources(sources, cache)


if __name__ == "__main__":
    unittest.main()
