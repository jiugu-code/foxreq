import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from scripts.capture.compare_profile import (
    ProfileComparisonError,
    compare_summaries,
    main,
)


def summary(sample_count=2):
    return {
        "schema_version": 1,
        "profile": {
            "name": "firefox_152",
            "firefox_version": "152.0.6",
            "nss_revision": "nss-revision",
            "nspr_revision": "nspr-revision",
            "capture_count": 100,
            "extension_permutation": "stable",
        },
        "sample_count": sample_count,
        "labels": {"cold": sample_count},
        "raw_capture_sha256": ["a" * 64],
        "normalized_sha256": ["b" * 64],
        "extension_order": {
            "extension_count": 3,
            "extension_types": [16, 27, 65037],
            "fixed_positions": [
                {"index": 0, "type": 16},
                {"index": 1, "type": 27},
                {"index": 2, "type": 65037},
            ],
            "movable_types": [],
            "orders": [
                {"types": [16, 27, 65037], "count": sample_count},
            ],
        },
        "stable_evidence": {
            "legacy_version": 771,
            "random": "dynamic:32",
            "session_id": "dynamic:32",
            "cipher_suites": [4865, 4867, 4866],
            "compression_methods": [0],
            "extensions_by_type": {
                "16": {"length": 14, "protocols": ["h2", "http/1.1"]},
                "27": {"length": 7, "data_sha256": "c" * 64},
                "65037": {"length": 281},
            },
        },
        "length_distributions": {
            "record_bytes": [{"value": 1874, "count": sample_count}],
            "session_id_bytes": [{"value": 32, "count": sample_count}],
            "cipher_suite_count": [{"value": 3, "count": sample_count}],
            "extension_count": [{"value": 3, "count": sample_count}],
            "extension_payload_bytes": {
                "16": [{"value": 14, "count": sample_count}],
                "27": [{"value": 7, "count": sample_count}],
                "65037": [{"value": 281, "count": sample_count}],
            },
        },
        "fingerprints": {
            "ja3": [{"raw": "ja3-raw", "digest": "ja3-digest", "count": sample_count}],
            "ja4": [{"raw": "ja4-raw", "digest": "ja4-digest", "count": sample_count}],
        },
    }


class CompareProfileTests(unittest.TestCase):
    def test_ignores_counts_hashes_and_candidate_values_for_dynamic_fields(self):
        baseline = summary()
        candidate = summary(sample_count=1)
        candidate["raw_capture_sha256"] = ["d" * 64]
        candidate["normalized_sha256"] = ["e" * 64]
        candidate["stable_evidence"]["extensions_by_type"]["65037"][
            "data_sha256"
        ] = "f" * 64

        self.assertEqual([], compare_summaries(baseline, candidate))

    def test_reports_precise_stable_order_length_and_fingerprint_paths(self):
        baseline = summary()
        candidate = copy.deepcopy(baseline)
        candidate["stable_evidence"]["extensions_by_type"]["16"]["protocols"] = [
            "http/1.1",
            "h2",
        ]
        candidate["extension_order"]["orders"][0]["types"] = [27, 16, 65037]
        candidate["length_distributions"]["record_bytes"] = [
            {"value": 1871, "count": 2}
        ]
        candidate["fingerprints"]["ja4"][0]["raw"] = "different-ja4"

        paths = [item.path for item in compare_summaries(baseline, candidate)]

        self.assertIn(
            "$.stable_evidence.extensions_by_type.16.protocols[0]", paths
        )
        self.assertIn("$.extension_order.orders[0].types[0]", paths)
        self.assertIn("$.length_distributions.record_bytes.values", paths)
        self.assertIn("$.fingerprints.ja4", paths)

    def test_nss_policy_accepts_only_the_frozen_movable_extension_set(self):
        baseline = summary()
        baseline["profile"]["extension_permutation"] = "nss"
        baseline["extension_order"]["fixed_positions"] = [
            {"index": 2, "type": 65037}
        ]
        baseline["extension_order"]["movable_types"] = [16, 27]
        baseline["extension_order"]["orders"] = [
            {"types": [16, 27, 65037], "count": 1},
            {"types": [27, 16, 65037], "count": 1},
        ]
        candidate = copy.deepcopy(baseline)
        candidate["extension_order"]["orders"] = [
            {"types": [27, 16, 65037], "count": 2}
        ]

        self.assertEqual([], compare_summaries(baseline, candidate))

        candidate["extension_order"]["orders"][0]["types"] = [16, 65037, 27]
        paths = [item.path for item in compare_summaries(baseline, candidate)]
        self.assertIn("$.extension_order.orders[0].types[2]", paths)

    def test_rejects_a_baseline_policy_that_does_not_cover_every_extension(self):
        baseline = summary()
        baseline["extension_order"]["fixed_positions"].pop()

        with self.assertRaisesRegex(ProfileComparisonError, "cover"):
            compare_summaries(baseline, summary())

    def test_rejects_unhashable_extension_identifiers_as_structured_input_errors(self):
        baseline = summary()
        baseline["extension_order"]["extension_types"][0] = []

        with self.assertRaisesRegex(ProfileComparisonError, "policy"):
            compare_summaries(baseline, summary())

    def test_cli_emits_machine_readable_success_and_missing_golden_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "baseline.json"
            candidate = root / "candidate.json"
            baseline.write_text(json.dumps(summary()), encoding="utf-8")
            candidate.write_text(json.dumps(summary(sample_count=1)), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                result = main(
                    [
                        "--profile",
                        "firefox_152",
                        "--platform",
                        "windows",
                        "--mode",
                        "cold",
                        "--baseline-cold",
                        str(baseline),
                        "--candidate-cold",
                        str(candidate),
                    ]
                )
            error = json.loads(output.getvalue())
            self.assertEqual(2, result)
            self.assertFalse(error["ok"])
            self.assertIn("100", error["error"]["message"])

            output = io.StringIO()
            with redirect_stdout(output):
                result = main(
                    [
                        "--profile",
                        "firefox_152",
                        "--platform",
                        "windows",
                        "--mode",
                        "cold",
                        "--allow-partial",
                        "--baseline-cold",
                        str(baseline),
                        "--candidate-cold",
                        str(candidate),
                    ]
                )
            success = json.loads(output.getvalue())
            self.assertEqual(0, result)
            self.assertTrue(success["ok"])
            self.assertEqual("partial", success["evidence_level"])

            output = io.StringIO()
            with redirect_stdout(output):
                result = main(
                    [
                        "--profile",
                        "firefox_152",
                        "--platform",
                        "windows",
                        "--mode",
                        "cold",
                        "--repository",
                        str(root),
                    ]
                )
            error = json.loads(output.getvalue())
            self.assertEqual(2, result)
            self.assertFalse(error["ok"])
            self.assertEqual("input", error["error"]["category"])


if __name__ == "__main__":
    unittest.main()
