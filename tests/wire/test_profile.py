import unittest

from tools.fingerprint.errors import ProfileError
from tools.fingerprint.profile import ProfileManifest, resolve_profile


VALID = {
    "schema_version": 1,
    "name": "firefox_152",
    "firefox_version": "152.0.6",
    "aliases": ["firefox_current"],
    "nss_revision": "NSS_REVISION_TEST",
    "nspr_revision": "NSPR_REVISION_TEST",
    "capture_count": 100,
    "extension_permutation": "stable",
}


class ProfileManifestTests(unittest.TestCase):
    def test_manifest_is_immutable_and_alias_resolves(self):
        manifest = ProfileManifest.from_dict(VALID)

        resolved = resolve_profile("firefox_current", [manifest])

        self.assertEqual("firefox_152", resolved.name)
        with self.assertRaises(AttributeError):
            manifest.name = "changed"

    def test_unknown_keys_are_rejected(self):
        data = dict(VALID, unexpected=True)

        with self.assertRaisesRegex(ProfileError, "unexpected"):
            ProfileManifest.from_dict(data)

    def test_duplicate_alias_is_rejected(self):
        other = dict(VALID, name="firefox_153", aliases=["firefox_current"])

        with self.assertRaisesRegex(ProfileError, "duplicate alias"):
            resolve_profile(
                "firefox_current",
                [ProfileManifest.from_dict(VALID), ProfileManifest.from_dict(other)],
            )

    def test_missing_fields_are_rejected(self):
        data = dict(VALID)
        del data["nss_revision"]

        with self.assertRaisesRegex(ProfileError, "missing"):
            ProfileManifest.from_dict(data)

    def test_schema_and_permutation_values_are_validated(self):
        with self.assertRaisesRegex(ProfileError, "schema_version"):
            ProfileManifest.from_dict(dict(VALID, schema_version=2))
        with self.assertRaisesRegex(ProfileError, "extension_permutation"):
            ProfileManifest.from_dict(dict(VALID, extension_permutation="random"))

    def test_capture_count_must_be_a_positive_integer(self):
        with self.assertRaisesRegex(ProfileError, "capture_count"):
            ProfileManifest.from_dict(dict(VALID, capture_count=0))
        with self.assertRaisesRegex(ProfileError, "capture_count"):
            ProfileManifest.from_dict(dict(VALID, capture_count=True))

    def test_unknown_profile_is_rejected(self):
        manifest = ProfileManifest.from_dict(VALID)

        with self.assertRaisesRegex(ProfileError, "unknown profile"):
            resolve_profile("firefox_999", [manifest])


if __name__ == "__main__":
    unittest.main()
