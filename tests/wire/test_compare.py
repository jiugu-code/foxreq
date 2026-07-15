import unittest

from tools.fingerprint.compare import PermutationPolicy, compare_evidence
from tools.fingerprint.errors import ProfileError


class CompareTests(unittest.TestCase):
    def test_diff_reports_precise_ordered_path(self):
        expected = {"cipher_suites": [4865, 4866]}
        actual = {"cipher_suites": [4866, 4865]}

        differences = compare_evidence(expected, actual)

        self.assertEqual(
            ["$.cipher_suites[0]", "$.cipher_suites[1]"],
            [difference.path for difference in differences],
        )

    def test_diff_reports_missing_keys_and_list_entries(self):
        expected = {"a": 1, "values": [1, 2]}
        actual = {"b": 2, "values": [1]}

        differences = compare_evidence(expected, actual)

        self.assertEqual(
            ["$.a", "$.b", "$.values[1]"],
            [difference.path for difference in differences],
        )

    def test_diff_does_not_treat_boolean_as_integer(self):
        differences = compare_evidence({"value": 1}, {"value": True})

        self.assertEqual("$.value", differences[0].path)

    def test_policy_separates_fixed_and_movable_extensions(self):
        samples = [
            {
                "extensions": [
                    {"type": 0},
                    {"type": 10},
                    {"type": 16},
                    {"type": 43},
                ]
            },
            {
                "extensions": [
                    {"type": 0},
                    {"type": 16},
                    {"type": 10},
                    {"type": 43},
                ]
            },
        ]

        policy = PermutationPolicy.from_samples(samples)

        self.assertEqual({0: 0, 3: 43}, policy.fixed_positions)
        self.assertEqual((10, 16), policy.movable_types)
        self.assertEqual([], policy.compare(samples[1]))

    def test_policy_rejects_changed_fixed_position(self):
        samples = [
            {"extensions": [{"type": 0}, {"type": 10}, {"type": 16}]},
            {"extensions": [{"type": 0}, {"type": 16}, {"type": 10}]},
        ]
        candidate = {
            "extensions": [{"type": 10}, {"type": 0}, {"type": 16}]
        }

        differences = PermutationPolicy.from_samples(samples).compare(candidate)

        self.assertIn("$.extensions[0].type", [item.path for item in differences])

    def test_policy_requires_two_samples_with_one_unique_multiset(self):
        with self.assertRaisesRegex(ProfileError, "at least two"):
            PermutationPolicy.from_samples(
                [{"extensions": [{"type": 0}, {"type": 10}]}]
            )
        with self.assertRaisesRegex(ProfileError, "multisets differ"):
            PermutationPolicy.from_samples(
                [
                    {"extensions": [{"type": 0}, {"type": 10}]},
                    {"extensions": [{"type": 0}, {"type": 16}]},
                ]
            )

    def test_policy_rejects_duplicate_extension_types(self):
        with self.assertRaisesRegex(ProfileError, "duplicate extension"):
            PermutationPolicy.from_samples(
                [
                    {"extensions": [{"type": 0}, {"type": 0}]},
                    {"extensions": [{"type": 0}, {"type": 0}]},
                ]
            )


if __name__ == "__main__":
    unittest.main()
