"""Prepare a fresh Firefox browser from an exact hash-locked release artifact."""

import argparse
import configparser
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from scripts.runtime.prepare_firefox_runtime import (
    RuntimePreparationError,
    SUPPORTED_PLATFORMS,
    SUPPORTED_PROFILES,
    _extract_linux_archive,
    _extract_windows,
    _load_lock,
    _verify_artifact,
)


class BrowserPreparationError(Exception):
    pass


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


def _under(path, root, label):
    path = Path(path)
    if not path.is_absolute():
        path = Path.cwd() / path
    path = path.resolve()
    root = root.resolve()
    try:
        common = Path(os.path.commonpath((str(root), str(path))))
    except ValueError as error:
        raise BrowserPreparationError(label + " must be under " + str(root)) from error
    if common != root:
        raise BrowserPreparationError(label + " must be under " + str(root))
    return path


def _application_identity(path):
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with path.open("r", encoding="utf-8") as source:
            parser.read_file(source)
        return parser.get("App", "Version"), parser.get("App", "BuildID")
    except (OSError, configparser.Error) as error:
        raise BrowserPreparationError("invalid extracted application.ini") from error


def prepare_browser(
    installer,
    output,
    lock,
    repository=None,
    runner=None,
    profile=None,
    platform=None,
):
    repository = Path(repository or Path(__file__).parents[2]).resolve()
    cache_root = (repository / ".cache" / "firefox-browser").resolve()
    output = _under(output, cache_root, "browser output")
    if output.exists():
        raise BrowserPreparationError("browser output must not already exist")
    try:
        document, lock_profile, lock_platform = _load_lock(
            lock, profile=profile, platform=platform, require_files=False
        )
    except RuntimePreparationError as error:
        raise BrowserPreparationError(str(error)) from error
    selected_platform = platform or lock_platform
    artifact = Path(installer).resolve()
    if not _verify_artifact(artifact, document):
        raise BrowserPreparationError("Firefox artifact does not match the lock")

    cache_root.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".extract-", dir=str(cache_root)))
    runner = runner or subprocess.run
    created_output = False
    try:
        try:
            if selected_platform == "windows-x86_64":
                _extract_windows(artifact, temporary, runner)
                source = temporary / "core"
                binary_name = "firefox.exe"
            elif selected_platform == "linux-x86_64":
                _extract_linux_archive(artifact, temporary)
                source = temporary / "firefox"
                binary_name = "firefox"
            else:
                raise BrowserPreparationError("unsupported browser platform")
        except RuntimePreparationError as error:
            raise BrowserPreparationError(str(error)) from error

        binary = source / binary_name
        application = source / "application.ini"
        if not source.is_dir() or not binary.is_file() or binary.is_symlink():
            raise BrowserPreparationError("extracted Firefox browser is incomplete")
        if any(path.is_symlink() for path in source.rglob("*")):
            raise BrowserPreparationError("extracted Firefox browser contains a symlink")
        version, build_id = _application_identity(application)
        if (
            version != document["firefox_version"]
            or build_id != document["firefox_build_id"]
        ):
            raise BrowserPreparationError("extracted Firefox identity mismatch")
        shutil.copytree(str(source), str(output))
        created_output = True
        output_binary = output / binary_name
        if selected_platform == "linux-x86_64":
            output_binary.chmod(output_binary.stat().st_mode | stat.S_IXUSR)
        copied_version, copied_build_id = _application_identity(
            output / "application.ini"
        )
        if copied_version != version or copied_build_id != build_id:
            raise BrowserPreparationError("copied Firefox identity mismatch")
        evidence = {
            "firefox_binary": str(output_binary),
            "firefox_binary_sha256": _sha256(output_binary),
            "firefox_binary_size": output_binary.stat().st_size,
            "firefox_version": version,
            "firefox_build_id": build_id,
            "profile": profile or lock_profile,
            "platform": selected_platform,
            "artifact_sha256": document["source_sha256"],
            "installer_sha256": document["source_sha256"],
        }
    except Exception:
        if created_output:
            shutil.rmtree(str(output), ignore_errors=True)
        raise
    finally:
        shutil.rmtree(str(temporary), ignore_errors=True)
    return evidence


def main(argv=None):
    repository = Path(__file__).parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", "--installer", dest="artifact", type=Path, required=True)
    parser.add_argument("--profile", choices=sorted(SUPPORTED_PROFILES))
    parser.add_argument("--platform", choices=sorted(SUPPORTED_PLATFORMS))
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(".cache/firefox-browser/windows"),
    )
    parser.add_argument(
        "--lock",
        type=Path,
        default=repository / "third_party" / "firefox-windows-runtime.lock.json",
    )
    args = parser.parse_args(argv)
    try:
        evidence = prepare_browser(
            args.artifact,
            args.output,
            args.lock,
            profile=args.profile,
            platform=args.platform,
        )
    except BrowserPreparationError as error:
        print(json.dumps({"error": str(error)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
