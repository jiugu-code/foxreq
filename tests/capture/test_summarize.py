import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.capture.summarize_capture import (
    SummaryError,
    summarize_records,
    validate_raw_input_path,
)
from tests.fixtures.capture_server import make_capture_record
from tests.wire.helpers import extension, synthetic_client_hello


def profile(capture_count=2):
    return {
        "schema_version": 1,
        "name": "firefox_152",
        "firefox_version": "152.0.6",
        "aliases": [],
        "nss_revision": "nss-revision",
        "nspr_revision": "nspr-revision",
        "capture_count": capture_count,
        "extension_permutation": "nss",
    }


def record(identifier, wire, label="cold"):
    return make_capture_record(identifier, label, wire)


class SummarizeCaptureTests(unittest.TestCase):
    def test_summarizes_permutations_lengths_hashes_and_fingerprints(self):
        versions = extension(43, b"\x02\x03\x04")
        alpn = extension(16, b"\x00\x03\x02h2")
        first = synthetic_client_hello(versions + alpn)
        second = synthetic_client_hello(alpn + versions)

        summary = summarize_records(
            [record("capture-000001", first), record("capture-000002", second)],
            profile(),
        )

        self.assertEqual(1, summary["schema_version"])
        self.assertEqual(2, summary["sample_count"])
        self.assertEqual({"cold": 2}, summary["labels"])
        self.assertEqual(
            sorted([hashlib.sha256(first).hexdigest(), hashlib.sha256(second).hexdigest()]),
            summary["raw_capture_sha256"],
        )
        self.assertEqual([], summary["extension_order"]["fixed_positions"])
        self.assertEqual([16, 43], summary["extension_order"]["movable_types"])
        self.assertEqual(2, len(summary["extension_order"]["orders"]))
        self.assertEqual(2, len(summary["fingerprints"]["ja3"]))
        self.assertEqual(1, len(summary["fingerprints"]["ja4"]))
        self.assertEqual(
            [{"value": len(first), "count": 2}],
            summary["length_distributions"]["record_bytes"],
        )
        self.assertIn("extensions_by_type", summary["stable_evidence"])

        encoded = json.dumps(summary, sort_keys=True)
        self.assertNotIn("record_hex", encoded)
        self.assertNotIn(first.hex(), encoded)

    def test_pre_shared_key_bytes_are_reduced_to_shape(self):
        psk = (
            b"\x00\x08\x00\x02ID\x00\x00\x00\x00"
            b"\x00\x04\x03XYZ"
        )
        wire = synthetic_client_hello(extension(41, psk))
        summary = summarize_records(
            [record("capture-000001", wire), record("capture-000002", wire)],
            profile(),
        )
        encoded = json.dumps(summary, sort_keys=True)

        self.assertNotIn("4944", encoded)
        self.assertNotIn("58595a", encoded)
        psk_shape = summary["stable_evidence"]["extensions_by_type"]["41"][
            "pre_shared_key"
        ]
        self.assertEqual([2], psk_shape["identity_lengths"])
        self.assertEqual([3], psk_shape["binder_lengths"])

    def test_rejects_hash_mismatch_duplicate_ids_and_wrong_count(self):
        wire = synthetic_client_hello()
        bad_hash = record("capture-000001", wire)
        bad_hash["sha256"] = "0" * 64
        with self.assertRaisesRegex(SummaryError, "sha256"):
            summarize_records([bad_hash, record("capture-000002", wire)], profile())

        duplicate = [
            record("capture-000001", wire),
            record("capture-000001", wire),
        ]
        with self.assertRaisesRegex(SummaryError, "duplicate"):
            summarize_records(duplicate, profile())

        with self.assertRaisesRegex(SummaryError, "capture_count"):
            summarize_records([record("capture-000001", wire)], profile())

    def test_tracked_schema_is_strict_and_describes_normalized_output(self):
        path = (
            Path(__file__).parents[2]
            / "profiles"
            / "firefox_152"
            / "golden"
            / "schema.json"
        )
        schema = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(
            "https://json-schema.org/draft/2020-12/schema",
            schema["$schema"],
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("stable_evidence", schema["required"])
        self.assertNotIn("record_hex", json.dumps(schema))

    def test_raw_summary_input_is_confined_to_ignored_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            inside = repository / "artifacts" / "captures" / "capture.jsonl"
            outside = repository / "capture.jsonl"

            self.assertEqual(
                inside.resolve(),
                validate_raw_input_path(inside, repository=repository),
            )
            with self.assertRaisesRegex(SummaryError, "artifacts/captures"):
                validate_raw_input_path(outside, repository=repository)


if __name__ == "__main__":
    unittest.main()
