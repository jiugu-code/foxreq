"""Prepare an exact hash-locked Firefox NSS runtime on Windows or Linux."""

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath


class RuntimePreparationError(Exception):
    pass


SCHEMA_TWO_FIELDS = {
    "schema_version",
    "profile",
    "platform",
    "source_id",
    "source_url",
    "source_size",
    "source_sha256",
    "source_sha512",
    "firefox_version",
    "firefox_build_id",
    "nss_version",
    "nspr_version",
    "files",
}
SUPPORTED_PROFILES = {"firefox_140_esr", "firefox_152"}
SUPPORTED_PLATFORMS = {"windows-x86_64", "linux-x86_64"}
_MAX_ARCHIVE_MEMBERS = 100_000
_MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
_WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *("COM{}".format(index) for index in range(1, 10)),
    *("LPT{}".format(index) for index in range(1, 10)),
}


def _hash(path, algorithm):
    digest = hashlib.new(algorithm)
    with path.open("rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


def _sha256(path):
    return _hash(path, "sha256")


def _verify_file(path, expected_size, expected_hash):
    try:
        info = path.lstat()
        return (
            stat.S_ISREG(info.st_mode)
            and not _is_reparse_point(info)
            and info.st_size == expected_size
            and _sha256(path) == expected_hash
        )
    except OSError:
        return False


def _load_lock(path, profile=None, platform=None, require_files=True):
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise RuntimePreparationError("could not read pinned runtime lock") from error
    if not isinstance(document, dict):
        raise RuntimePreparationError("invalid pinned runtime lock")

    schema = document.get("schema_version")
    if schema == 1:
        lock_profile = "firefox_152"
        lock_platform = "windows-x86_64"
        if (
            document.get("platform") != lock_platform
            or document.get("source_id") != "firefox-windows-x86_64-en-us"
        ):
            raise RuntimePreparationError("pinned runtime source identity mismatch")
    elif schema == 2:
        if set(document) != SCHEMA_TWO_FIELDS:
            raise RuntimePreparationError("invalid schema-2 pinned runtime lock fields")
        lock_profile = document.get("profile")
        lock_platform = document.get("platform")
        if (
            lock_profile not in SUPPORTED_PROFILES
            or lock_platform not in SUPPORTED_PLATFORMS
            or not _nonempty(document.get("source_id"))
            or not _nonempty(document.get("source_url"))
            or not _positive_integer(document.get("source_size"))
            or not _hex(document.get("source_sha256"), 64)
            or not _hex(document.get("source_sha512"), 128)
        ):
            raise RuntimePreparationError("invalid pinned runtime source identity")
    else:
        raise RuntimePreparationError("unsupported pinned runtime lock schema")

    if profile is not None and profile != lock_profile:
        raise RuntimePreparationError("pinned runtime lock profile mismatch")
    if platform is not None and platform != lock_platform:
        raise RuntimePreparationError("pinned runtime lock platform mismatch")
    for key in ("firefox_version", "firefox_build_id", "nss_version", "nspr_version"):
        if schema == 2 and not _nonempty(document.get(key)):
            raise RuntimePreparationError("invalid pinned runtime version identity")

    files = document.get("files")
    if schema == 1 and not require_files and files is None:
        return document, lock_profile, lock_platform
    if not isinstance(files, list) or not files:
        raise RuntimePreparationError("pinned runtime file list is empty")
    names = []
    for entry in files:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"filename", "size", "sha256"}
            or not _safe_relative_name(entry.get("filename"))
            or entry["filename"] in names
            or not _positive_integer(entry.get("size"))
            or not _hex(entry.get("sha256"), 64)
        ):
            raise RuntimePreparationError("invalid pinned runtime file entry")
        names.append(entry["filename"])
    if schema == 2 and names != sorted(names):
        raise RuntimePreparationError("pinned runtime file list must be sorted")
    return document, lock_profile, lock_platform


def _under(path, root, label):
    path = Path(path)
    if not path.is_absolute():
        path = Path.cwd() / path
    path = path.resolve()
    root = root.resolve()
    try:
        common = Path(os.path.commonpath((str(root), str(path))))
    except ValueError as error:
        raise RuntimePreparationError(label + " must be under " + str(root)) from error
    if common != root:
        raise RuntimePreparationError(label + " must be under " + str(root))
    return path


def prepare_runtime(
    installer,
    output,
    lock,
    repository=None,
    runner=None,
    profile=None,
    platform=None,
):
    repository = Path(repository or Path(__file__).parents[2]).resolve()
    cache_root = (repository / ".cache" / "firefox-runtime").resolve()
    output = _under(output, cache_root, "runtime output")
    if output.exists():
        raise RuntimePreparationError("runtime output must not already exist")

    lock_document, lock_profile, lock_platform = _load_lock(
        Path(lock), profile=profile, platform=platform
    )
    selected_platform = platform or lock_platform
    artifact = Path(installer).resolve()
    if not _verify_artifact(artifact, lock_document):
        raise RuntimePreparationError("Firefox artifact does not match the lock")

    cache_root.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".extract-", dir=str(cache_root)))
    created_output = False
    runner = runner or subprocess.run
    try:
        if selected_platform == "windows-x86_64":
            _extract_windows(artifact, temporary, runner)
            source_root = temporary / "core"
        elif selected_platform == "linux-x86_64":
            _extract_linux_archive(artifact, temporary)
            source_root = temporary / "firefox"
        else:
            raise RuntimePreparationError("unsupported runtime platform")

        for entry in lock_document["files"]:
            if not _verify_file(
                _locked_path(source_root, entry["filename"]),
                entry["size"],
                entry["sha256"],
            ):
                raise RuntimePreparationError(
                    "extracted runtime file does not match lock: " + entry["filename"]
                )

        output.mkdir(parents=True)
        created_output = True
        for entry in lock_document["files"]:
            source = _locked_path(source_root, entry["filename"])
            destination = _locked_path(output, entry["filename"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            with source.open("rb") as input_file, destination.open("xb") as output_file:
                shutil.copyfileobj(input_file, output_file, length=1024 * 1024)
            if not _verify_file(destination, entry["size"], entry["sha256"]):
                raise RuntimePreparationError(
                    "prepared runtime file does not match lock: " + entry["filename"]
                )
    except Exception:
        if created_output:
            shutil.rmtree(str(output), ignore_errors=True)
        raise
    finally:
        shutil.rmtree(str(temporary), ignore_errors=True)

    return output


def _verify_artifact(path, document):
    if not _verify_file(path, document.get("source_size"), document.get("source_sha256")):
        return False
    expected_sha512 = document.get("source_sha512")
    return expected_sha512 is None or _hash(path, "sha512") == expected_sha512


def _extract_windows(artifact, temporary, runner):
    command = [str(artifact), "/ExtractDir=" + str(temporary)]
    try:
        completed = runner(command, check=False, timeout=180)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimePreparationError("Firefox installer extraction failed") from error
    if completed.returncode != 0:
        raise RuntimePreparationError(
            "Firefox installer extraction returned {}".format(completed.returncode)
        )


def _extract_linux_archive(artifact, destination):
    try:
        with tarfile.open(artifact, mode="r:*") as archive:
            members = _validate_archive_members(archive)
            for member in members:
                target = destination.joinpath(*PurePosixPath(member.name).parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise RuntimePreparationError("unsafe Firefox archive member")
                with source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
    except RuntimePreparationError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise RuntimePreparationError("Firefox archive extraction failed") from error


def _validate_archive_members(members):
    names = set()
    validated = []
    total_size = 0
    for member in members:
        name = member.name.rstrip("/")
        normalized = name.casefold()
        if (
            not _safe_relative_name(name)
            or normalized in names
            or not (member.isfile() or member.isdir())
            or len(validated) >= _MAX_ARCHIVE_MEMBERS
            or member.size < 0
            or member.size > _MAX_ARCHIVE_BYTES - total_size
        ):
            raise RuntimePreparationError("unsafe Firefox archive member")
        names.add(normalized)
        total_size += member.size
        validated.append(member)
    return tuple(validated)


def _locked_path(root, filename):
    return root.joinpath(*PurePosixPath(filename).parts)


def _safe_relative_name(value):
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    parts = path.parts
    if path.is_absolute() or any(part in {"", ".", ".."} for part in parts):
        return False
    for part in parts:
        stem = part.rstrip(" .").split(".", 1)[0].upper()
        if ":" in part or stem in _WINDOWS_RESERVED:
            return False
    return "/".join(parts) == value


def _positive_integer(value):
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _nonempty(value):
    return isinstance(value, str) and bool(value)


def _hex(value, length):
    return (
        isinstance(value, str)
        and re.fullmatch("[0-9a-f]{{{}}}".format(length), value) is not None
    )


def _is_reparse_point(info):
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(flag and getattr(info, "st_file_attributes", 0) & flag)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--artifact", "--installer", dest="artifact", type=Path, required=True
    )
    parser.add_argument("--profile", choices=sorted(SUPPORTED_PROFILES))
    parser.add_argument("--platform", choices=sorted(SUPPORTED_PLATFORMS))
    parser.add_argument("--output", type=Path, default=Path(".cache/firefox-runtime/core"))
    parser.add_argument(
        "--lock", type=Path, default=Path("third_party/firefox-windows-runtime.lock.json")
    )
    args = parser.parse_args(argv)
    try:
        output = prepare_runtime(
            args.artifact,
            args.output,
            args.lock,
            profile=args.profile,
            platform=args.platform,
        )
    except RuntimePreparationError as error:
        print(json.dumps({"error": str(error)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps({"runtime": str(output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
