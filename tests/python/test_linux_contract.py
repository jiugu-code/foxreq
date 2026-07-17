import os
import unittest
import zipfile
from pathlib import Path

from scripts.runtime.lock_firefox_release import DEFAULT_RUNTIME_FILES


class LinuxContractTests(unittest.TestCase):
    def setUp(self):
        self.repository = Path(__file__).parents[2]

    def test_real_backend_uses_explicit_windows_and_posix_adapters(self):
        source = self.repository / "native" / "nss-shim" / "src"
        required = (
            "platform_runtime.h",
            "platform_windows.c",
            "platform_posix.c",
            "platform_socket.h",
            "socket_windows.c",
            "socket_posix.c",
        )
        for filename in required:
            self.assertTrue((source / filename).is_file(), filename)

        internal = (source / "foxreq_nss_real_internal.h").read_text()
        runtime = (source / "runtime.c").read_text()
        connection = (source / "connection.c").read_text()
        for forbidden in ("winsock2.h", "windows.h", "SRWLOCK", "HMODULE"):
            self.assertNotIn(forbidden, internal)
            self.assertNotIn(forbidden, runtime)
        self.assertNotRegex(
            connection, r"\bSOCKET\b|\bINVALID_SOCKET\b|WSAGetLastError"
        )

    def test_cmake_and_rust_select_only_supported_native_targets(self):
        cmake = (self.repository / "native" / "nss-shim" / "CMakeLists.txt").read_text()
        for expected in (
            "platform_windows.c",
            "platform_posix.c",
            "socket_windows.c",
            "socket_posix.c",
            "ws2_32",
            "bcrypt",
            "${CMAKE_DL_LIBS}",
            "pthread",
        ):
            self.assertIn(expected, cmake)

        build = (self.repository / "crates" / "foxreq-core" / "build.rs").read_text()
        self.assertIn('target == "x86_64-unknown-linux-gnu"', build)
        self.assertIn('cargo:rustc-link-lib=dl', build)
        self.assertIn('cargo:rustc-link-lib=pthread', build)

    def test_linux_runtime_lock_uses_files_present_in_official_archives(self):
        files = DEFAULT_RUNTIME_FILES["linux-x86_64"]
        self.assertNotIn("libmozglue.so", files)
        self.assertNotIn("libnssckbi.so", files)
        for required in (
            "libfreeblpriv3.so",
            "libmozsqlite3.so",
            "libnspr4.so",
            "libnss3.so",
            "libnssutil3.so",
            "libplc4.so",
            "libplds4.so",
            "libsmime3.so",
            "libsoftokn3.so",
            "libssl3.so",
        ):
            self.assertIn(required, files)

    def test_linux_verification_entrypoint_is_serial_and_fail_closed(self):
        script = self.repository / "scripts" / "verify_python.sh"
        self.assertTrue(script.is_file())
        text = script.read_text()
        for required in (
            "set -eu",
            "MemAvailable",
            "4096",
            "CARGO_BUILD_JOBS=1",
            "FOXREQ_RUNTIME_FIREFOX_140_ESR",
            "FOXREQ_NSS_RUNTIME_DIR",
            "FOXREQ_LINUX_WHEEL",
            "cargo fmt",
            "cargo clippy",
            "cmake",
            "ctest",
            "unittest",
            "pip check",
            "git diff --check",
        ):
            self.assertIn(required, text)
        self.assertNotIn("xargs -P", text)
        self.assertNotRegex(text, r"(?:^|\s)&(?:\s|$)")

    def test_manylinux_wheel_contract_when_wheel_is_supplied(self):
        value = os.environ.get("FOXREQ_LINUX_WHEEL")
        if not value:
            self.skipTest("Linux wheel path is absent")
        wheel = Path(value).resolve(strict=True)
        self.assertIn("manylinux_2_17_x86_64", wheel.name)
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist()
            self.assertTrue(any(name.endswith("foxreq/_profile_worker.py") for name in names))
            self.assertTrue(any(name.endswith("foxreq/_runtime_locks.py") for name in names))
            forbidden = (
                "libnss3.so",
                "libnspr4.so",
                "libssl3.so",
                "libsoftokn3.so",
                "libfreeblpriv3.so",
            )
            self.assertFalse(any(Path(name).name in forbidden for name in names))
            locks_name = next(
                name for name in names if name.endswith("foxreq/_runtime_locks.py")
            )
            locks = archive.read(locks_name).decode("utf-8")
            self.assertIn("('firefox_140_esr', 'linux-x86_64')", locks)
            self.assertIn("('firefox_152', 'linux-x86_64')", locks)


if __name__ == "__main__":
    unittest.main()
