import hashlib
import io
import tempfile
import unittest
from pathlib import Path

from scripts.provenance.fetch_sources import fetch_source
from scripts.provenance.verify_sources import LockError


class _Response(io.BytesIO):
    def __init__(self, content, url="https://example.test/source.bin"):
        super().__init__(content)
        self._url = url

    def geturl(self):
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


class _Opener:
    def __init__(self, content, url="https://example.test/source.bin"):
        self.content = content
        self.url = url
        self.calls = 0

    def open(self, request, timeout):
        self.calls += 1
        return _Response(self.content, self.url)


def _source(content=b"source"):
    return {
        "id": "source",
        "url": "https://example.test/source.bin",
        "filename": "source.bin",
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
    }


class FetchSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.cache = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_download_is_verified_and_reused_from_cache(self):
        opener = _Opener(b"source")

        self.assertEqual(fetch_source(_source(), self.cache, opener), "downloaded")
        self.assertEqual((self.cache / "source.bin").read_bytes(), b"source")
        self.assertEqual(fetch_source(_source(), self.cache, opener), "cached")
        self.assertEqual(opener.calls, 1)

    def test_hash_or_size_failure_leaves_no_destination_or_partial_file(self):
        cases = [b"badbad", b"source-extra"]
        for content in cases:
            with self.subTest(content=content):
                with self.assertRaises(LockError):
                    fetch_source(_source(), self.cache, _Opener(content))
                self.assertFalse((self.cache / "source.bin").exists())
                self.assertEqual(list(self.cache.glob("*.part-*")), [])

    def test_final_non_https_url_is_rejected(self):
        opener = _Opener(b"source", "http://example.test/source.bin")

        with self.assertRaisesRegex(LockError, "not HTTPS"):
            fetch_source(_source(), self.cache, opener)
        self.assertFalse((self.cache / "source.bin").exists())


if __name__ == "__main__":
    unittest.main()
