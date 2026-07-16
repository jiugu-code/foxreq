import unittest

from foxreq._exceptions import InvalidRequestError
from foxreq._profiles import get_profile


class ProfileTests(unittest.TestCase):
    def test_exact_profiles_and_platform_user_agents(self):
        windows = get_profile("firefox_140_esr", platform="win32")
        linux = get_profile("firefox_152", platform="linux")

        self.assertEqual(windows.firefox_version, "140.12.0esr")
        self.assertIn("Windows NT 10.0; Win64; x64", windows.user_agent)
        self.assertTrue(windows.user_agent.endswith("Firefox/140.0"))
        self.assertIn("X11; Linux x86_64", linux.user_agent)
        self.assertTrue(linux.user_agent.endswith("Firefox/152.0"))

    def test_rejects_unknown_profile_and_platform(self):
        with self.assertRaises(InvalidRequestError):
            get_profile("firefox_latest", platform="win32")
        with self.assertRaises(InvalidRequestError):
            get_profile("firefox_152", platform="darwin")


if __name__ == "__main__":
    unittest.main()
