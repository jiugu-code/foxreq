import re
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]


class DocumentationTests(unittest.TestCase):
    def setUp(self):
        self.readme_path = REPOSITORY / "README.md"
        self.verify_path = REPOSITORY / "scripts" / "verify_python.ps1"

    def test_readme_is_formal_and_claims_are_bounded(self):
        text = self.readme_path.read_text(encoding="utf-8")
        for required in (
            "项目状态",
            "授权使用边界",
            "能力矩阵",
            "Firefox 152",
            "NSS 3.124",
            "Python 3.10+",
            "foxreq.get(",
            "foxreq.Session(",
            "CARGO_BUILD_JOBS",
            "FOXREQ_NSS_RUNTIME_DIR",
            "Windows",
            "Linux",
            "路线图",
            "许可证",
        ):
            self.assertIn(required, text)

        for prohibited in (
            "已绕过 Akamai",
            "完整模拟 Firefox",
            "Linux 已通过",
            "已发布到 PyPI",
        ):
            self.assertNotIn(prohibited, text)

        self.assertIsNone(
            re.search(
                r"(?im)^\s*(?:password|passwd|pwd|密码)\s*[:=]\s*\S+",
                text,
            )
        )
        private_key_marker = r"BEGIN (?:RSA |OPENSSH |EC )?" + "PRIVATE KEY"
        self.assertNotRegex(text, private_key_marker)

    def test_readme_local_links_and_examples_exist(self):
        text = self.readme_path.read_text(encoding="utf-8")
        local_links = []
        for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", text):
            target = target.strip().strip("<>")
            if target.startswith(("https://", "http://", "mailto:", "#")):
                continue
            local_links.append(target.split("#", 1)[0])

        self.assertTrue(local_links, "README must link to repository documentation")
        for target in local_links:
            self.assertTrue(
                (REPOSITORY / target).exists(),
                "README local link does not exist: {}".format(target),
            )

        for example in ("examples/python_basic.py", "examples/python_session.py"):
            self.assertIn(example, text)
            self.assertTrue((REPOSITORY / example).is_file())

    def test_verification_entrypoint_is_serial_and_fail_closed(self):
        text = self.verify_path.read_text(encoding="utf-8")
        for required in (
            "_available_physical_memory",
            "4096",
            "CARGO_BUILD_JOBS",
            "cargo fmt",
            "cargo clippy",
            "cargo test",
            "cmake",
            "ctest",
            "test_real_tls",
            "unittest",
            "git diff --check",
        ):
            self.assertIn(required, text)
        self.assertNotIn("Start-Job", text)
        self.assertNotIn("ForEach-Object -Parallel", text)


if __name__ == "__main__":
    unittest.main()
