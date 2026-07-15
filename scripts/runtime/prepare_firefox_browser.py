"""Extract a fresh Firefox browser from the exact hash-locked Windows installer."""

import argparse
import configparser
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


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


def _load_lock(path):
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise BrowserPreparationError("could not read Firefox runtime lock") from error
    digest = document.get("source_sha256")
    size = document.get("source_size")
    if (
        document.get("schema_version") != 1
        or document.get("platform") != "windows-x86_64"
        or document.get("source_id") != "firefox-windows-x86_64-en-us"
        or not isinstance(digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or not isinstance(document.get("firefox_version"), str)
        or not document["firefox_version"]
        or not isinstance(document.get("firefox_build_id"), str)
        or not re.fullmatch(r"[0-9]{14}", document["firefox_build_id"])
    ):
        raise BrowserPreparationError("invalid Firefox runtime lock")
    return document


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


def prepare_browser(installer, output, lock, repository=None, runner=None):
    if os.name != "nt":
        raise BrowserPreparationError("Firefox installer extraction requires Windows")
    repository = Path(repository or Path(__file__).parents[2]).resolve()
    cache_root = (repository / ".cache" / "firefox-browser").resolve()
    output = _under(output, cache_root, "browser output")
    if output.exists():
        raise BrowserPreparationError("browser output must not already exist")
    document = _load_lock(lock)
    installer = Path(installer).resolve()
    if (
        not installer.is_file()
        or installer.is_symlink()
        or installer.stat().st_size != document["source_size"]
        or _sha256(installer) != document["source_sha256"]
    ):
        raise BrowserPreparationError("Firefox installer does not match the lock")

    cache_root.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".extract-", dir=str(cache_root)))
    runner = runner or subprocess.run
    created_output = False
    try:
        try:
            completed = runner(
                [str(installer), "/ExtractDir=" + str(temporary)],
                check=False,
                timeout=180,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise BrowserPreparationError("Firefox installer extraction failed") from error
        if completed.returncode != 0:
            raise BrowserPreparationError(
                "Firefox installer extraction returned {}".format(
                    completed.returncode
                )
            )
        source = temporary / "core"
        binary = source / "firefox.exe"
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
        output_binary = output / "firefox.exe"
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
    parser.add_argument("--installer", type=Path, required=True)
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
        evidence = prepare_browser(args.installer, args.output, args.lock)
    except BrowserPreparationError as error:
        print(json.dumps({"error": str(error)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
