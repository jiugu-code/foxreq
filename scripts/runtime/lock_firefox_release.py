"""Create reviewed Firefox runtime locks from official release artifacts."""

import argparse
import configparser
import hashlib
import json
import os
import pprint
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

from scripts.runtime.prepare_firefox_runtime import (
    SUPPORTED_PLATFORMS,
    SUPPORTED_PROFILES,
    RuntimePreparationError,
    _extract_linux_archive,
    _extract_windows,
    _load_lock,
    _safe_relative_name,
)


class ReleaseLockError(Exception):
    pass


DEFAULT_RUNTIME_FILES = {
    "windows-x86_64": (
        "freebl3.dll",
        "mozglue.dll",
        "nss3.dll",
        "softokn3.dll",
    ),
    "linux-x86_64": (
        "libfreeblpriv3.so",
        "libmozglue.so",
        "libmozsqlite3.so",
        "libnspr4.so",
        "libnss3.so",
        "libnssckbi.so",
        "libnssutil3.so",
        "libplc4.so",
        "libplds4.so",
        "libsmime3.so",
        "libsoftokn3.so",
        "libssl3.so",
    ),
}
EXPECTED_FIREFOX_VERSIONS = {
    "firefox_140_esr": "140.12.0",
    "firefox_152": "152.0.6",
}


def lock_release(
    *,
    artifact,
    output,
    profile,
    platform,
    source_id,
    source_url,
    sha512sums,
    sha512_name=None,
    runtime_files=None,
    repository=None,
    runner=None,
    version_probe=None,
    embedded_output=None,
):
    """Verify, extract and lock one exact Firefox release."""
    if profile not in SUPPORTED_PROFILES or platform not in SUPPORTED_PLATFORMS:
        raise ReleaseLockError("unsupported Firefox profile/platform")
    if not isinstance(source_id, str) or not source_id:
        raise ReleaseLockError("source identity must be non-empty")
    if not isinstance(source_url, str) or not source_url.startswith("https://"):
        raise ReleaseLockError("source URL must use HTTPS")
    artifact = Path(artifact)
    sha256, sha512, source_size = _artifact_hashes(artifact)
    artifact = artifact.resolve(strict=True)
    output = Path(output).resolve()
    repository = Path(repository or Path(__file__).parents[2]).resolve()
    if output.exists():
        raise ReleaseLockError("runtime lock output must not already exist")
    selected_sum_name = sha512_name or artifact.name
    if not _safe_relative_name(selected_sum_name):
        raise ReleaseLockError("Mozilla SHA512SUMS artifact name is invalid")
    _verify_sha512sums(selected_sum_name, sha512, sha512sums)

    selected_files = tuple(runtime_files or DEFAULT_RUNTIME_FILES[platform])
    if (
        not selected_files
        or len(set(selected_files)) != len(selected_files)
        or any(not _safe_relative_name(name) for name in selected_files)
    ):
        raise ReleaseLockError("runtime file selection is invalid")

    cache_root = repository / ".cache" / "firefox-locks"
    cache_root.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".release-", dir=str(cache_root)))
    try:
        try:
            if platform == "windows-x86_64":
                _extract_windows(artifact, temporary, runner or subprocess.run)
                source_root = temporary / "core"
            else:
                _extract_linux_archive(artifact, temporary)
                source_root = temporary / "firefox"
        except RuntimePreparationError as error:
            raise ReleaseLockError(str(error)) from error
        version, build_id = _application_identity(source_root / "application.ini")
        if version != EXPECTED_FIREFOX_VERSIONS[profile]:
            raise ReleaseLockError("Firefox release version does not match profile")
        probe = version_probe or _probe_versions
        try:
            nss_version, nspr_version = probe(source_root, platform)
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            raise ReleaseLockError("could not probe Firefox NSS/NSPR versions") from error
        if not all(isinstance(value, str) and value for value in (nss_version, nspr_version)):
            raise ReleaseLockError("Firefox NSS/NSPR versions are invalid")

        locked_files = []
        for filename in sorted(selected_files):
            path = source_root.joinpath(*PurePosixPath(filename).parts)
            if not path.is_file() or path.is_symlink():
                raise ReleaseLockError("Firefox runtime file is missing: " + filename)
            locked_files.append(
                {
                    "filename": filename,
                    "size": path.stat().st_size,
                    "sha256": _hash(path, "sha256"),
                }
            )
        document = {
            "schema_version": 2,
            "profile": profile,
            "platform": platform,
            "source_id": source_id,
            "source_url": source_url,
            "source_size": source_size,
            "source_sha256": sha256,
            "source_sha512": sha512,
            "firefox_version": version,
            "firefox_build_id": build_id,
            "nss_version": nss_version,
            "nspr_version": nspr_version,
            "files": locked_files,
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8", newline="\n") as destination:
            destination.write(_canonical_json(document))
    finally:
        shutil.rmtree(temporary, ignore_errors=True)

    if embedded_output is not None:
        regenerate_embedded_locks(output.parent, embedded_output)
    return document


def regenerate_embedded_locks(lock_directory, output):
    """Regenerate deterministic wheel data from every canonical Firefox lock."""
    lock_directory = Path(lock_directory)
    records = {}
    for path in sorted(lock_directory.glob("firefox-*.lock.json")):
        try:
            document, profile, platform = _load_lock(path)
        except RuntimePreparationError as error:
            raise ReleaseLockError("invalid Firefox lock: " + path.name) from error
        key = (profile, platform)
        if key in records:
            raise ReleaseLockError("duplicate Firefox profile/platform lock")
        records[key] = document
    rendered = (
        '"""Generated runtime lock data shipped inside the foxreq wheel.\n\n'
        "Regenerate with scripts/runtime/lock_firefox_release.py; do not edit.\n"
        '"""\n\n'
        "RUNTIME_LOCKS = "
        + pprint.pformat(records, sort_dicts=True, width=88)
        + "\n"
    )
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8", newline="\n")
    return records


def _verify_sha512sums(filename, expected, path):
    path = Path(path)
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or _is_reparse_point(info):
            raise OSError("SHA512SUMS is not a regular file")
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise ReleaseLockError("could not read Mozilla SHA512SUMS") from error
    matches = []
    for line in lines:
        match = re.fullmatch(r"([0-9A-Fa-f]{128}) [ *](.+)", line)
        if match and match.group(2) == filename:
            matches.append(match.group(1).lower())
    if matches != [expected]:
        raise ReleaseLockError("artifact does not match Mozilla SHA512SUMS")


def _application_identity(path):
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with path.open("r", encoding="utf-8") as source:
            parser.read_file(source)
        version = parser.get("App", "Version")
        build_id = parser.get("App", "BuildID")
    except (OSError, configparser.Error) as error:
        raise ReleaseLockError("invalid Firefox application.ini") from error
    if not re.fullmatch(r"[0-9]{14}", build_id):
        raise ReleaseLockError("invalid Firefox build identity")
    return version, build_id


def _probe_versions(runtime_root, platform):
    nss_name = "nss3.dll" if platform == "windows-x86_64" else "libnss3.so"
    environment = os.environ.copy()
    if platform == "linux-x86_64":
        inherited = environment.get("LD_LIBRARY_PATH")
        environment["LD_LIBRARY_PATH"] = (
            str(runtime_root) + os.pathsep + inherited
            if inherited
            else str(runtime_root)
        )
    code = (
        "import ctypes,json,os,sys;"
        "root=sys.argv[1];"
        "handle=os.add_dll_directory(root) if sys.platform=='win32' else None;"
        "lib=ctypes.CDLL(os.path.join(root,sys.argv[2]));"
        "lib.NSS_GetVersion.restype=ctypes.c_char_p;"
        "lib.PR_GetVersion.restype=ctypes.c_char_p;"
        "print(json.dumps([lib.NSS_GetVersion().decode('ascii'),"
        "lib.PR_GetVersion().decode('ascii')]))"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code, str(runtime_root), nss_name],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )
    if completed.returncode != 0:
        raise ReleaseLockError("Firefox NSS/NSPR version probe failed")
    try:
        values = json.loads(completed.stdout)
    except ValueError as error:
        raise ReleaseLockError("Firefox NSS/NSPR version probe was invalid") from error
    if not isinstance(values, list) or len(values) != 2:
        raise ReleaseLockError("Firefox NSS/NSPR version probe was invalid")
    return tuple(values)


def _hash(path, algorithm):
    digest = hashlib.new(algorithm)
    try:
        with Path(path).open("rb") as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    return digest.hexdigest()
                digest.update(chunk)
    except OSError as error:
        raise ReleaseLockError("could not hash Firefox release artifact") from error


def _artifact_hashes(path):
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    try:
        path = Path(path)
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or _is_reparse_point(before):
            raise OSError("artifact is not a regular file")
        with path.open("rb") as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                sha256.update(chunk)
                sha512.update(chunk)
        after = path.lstat()
    except OSError as error:
        raise ReleaseLockError("could not hash Firefox release artifact") from error
    identity_before = (before.st_size, before.st_mtime_ns)
    identity_after = (after.st_size, after.st_mtime_ns)
    if identity_before != identity_after:
        raise ReleaseLockError("Firefox release artifact changed while hashing")
    return sha256.hexdigest(), sha512.hexdigest(), before.st_size


def _is_reparse_point(info):
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(flag and getattr(info, "st_file_attributes", 0) & flag)


def _canonical_json(document):
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def main(argv=None):
    repository = Path(__file__).parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", choices=sorted(SUPPORTED_PROFILES), required=True)
    parser.add_argument("--platform", choices=sorted(SUPPORTED_PLATFORMS), required=True)
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--sha512sums", type=Path, required=True)
    parser.add_argument("--sha512-name")
    parser.add_argument("--runtime-file", action="append", dest="runtime_files")
    parser.add_argument(
        "--embedded-output",
        type=Path,
        default=repository / "python" / "foxreq" / "_runtime_locks.py",
    )
    args = parser.parse_args(argv)
    try:
        document = lock_release(
            artifact=args.artifact,
            output=args.output,
            profile=args.profile,
            platform=args.platform,
            source_id=args.source_id,
            source_url=args.source_url,
            sha512sums=args.sha512sums,
            sha512_name=args.sha512_name,
            runtime_files=args.runtime_files,
            embedded_output=args.embedded_output,
        )
    except ReleaseLockError as error:
        print(json.dumps({"error": str(error)}, sort_keys=True), file=sys.stderr)
        return 2
    print(_canonical_json(document), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
