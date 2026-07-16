"""Validate a Firefox runtime against locks embedded in the installed wheel."""

import hashlib
import os
import platform as platform_module
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from . import _runtime_locks
from ._exceptions import ConfigurationError


_HASH_CHUNK_SIZE = 1024 * 1024
_HEX_256 = re.compile(r"[0-9a-f]{64}")
_HEX_512 = re.compile(r"[0-9a-f]{128}")
_PLATFORMS = {"windows-x86_64", "linux-x86_64"}
_PROFILES = {"firefox_140_esr", "firefox_152"}
_FIREFOX_VERSIONS = {
    "firefox_140_esr": "140.12.0",
    "firefox_152": "152.0.6",
}
_WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *("COM{}".format(index) for index in range(1, 10)),
    *("LPT{}".format(index) for index in range(1, 10)),
}
_SCHEMA_TWO_FIELDS = {
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


@dataclass(frozen=True, slots=True)
class ValidatedRuntime:
    path: Path
    profile_id: str
    platform: str
    firefox_version: str
    firefox_build_id: str
    nss_version: str
    nspr_version: str


def validate_runtime(profile_id, runtime_dir, platform=None):
    """Return immutable metadata after validating every locked runtime file."""
    selected_platform = _platform_id() if platform is None else platform
    if profile_id not in _PROFILES or selected_platform not in _PLATFORMS:
        raise ConfigurationError("Firefox runtime is not available for this profile/platform")
    try:
        manifest = _runtime_locks.RUNTIME_LOCKS[(profile_id, selected_platform)]
    except (KeyError, TypeError) as error:
        raise ConfigurationError(
            "Firefox runtime is not available for this profile/platform"
        ) from error
    _validate_manifest(manifest, profile_id, selected_platform)

    try:
        requested = Path(os.fsdecode(os.fspath(runtime_dir)))
        if not requested.is_absolute():
            requested = Path.cwd() / requested
        if _has_reparse_component(requested):
            raise ConfigurationError(
                "Firefox runtime directory must be a regular directory"
            )
        runtime = requested.resolve(strict=True)
    except (OSError, TypeError, ValueError) as error:
        raise ConfigurationError("Firefox runtime directory is invalid") from error
    if not _is_plain_directory(runtime):
        raise ConfigurationError("Firefox runtime directory must be a regular directory")

    for entry in manifest["files"]:
        candidate = runtime.joinpath(*PurePosixPath(entry["filename"]).parts)
        if _has_reparse_component(candidate) or not _is_plain_file(candidate):
            raise ConfigurationError(
                "Firefox runtime file must be a regular file: " + entry["filename"]
            )
        try:
            size = candidate.stat().st_size
            digest = _sha256(candidate)
        except OSError as error:
            raise ConfigurationError(
                "Firefox runtime file could not be verified: " + entry["filename"]
            ) from error
        if size != entry["size"] or digest != entry["sha256"]:
            raise ConfigurationError(
                "Firefox runtime file does not match lock: " + entry["filename"]
            )

    return ValidatedRuntime(
        path=runtime,
        profile_id=profile_id,
        platform=selected_platform,
        firefox_version=manifest["firefox_version"],
        firefox_build_id=manifest["firefox_build_id"],
        nss_version=manifest["nss_version"],
        nspr_version=manifest["nspr_version"],
    )


def _platform_id():
    machine = platform_module.machine().lower()
    if machine not in {"amd64", "x86_64"}:
        raise ConfigurationError("Firefox runtime is not available for this architecture")
    if sys.platform == "win32":
        return "windows-x86_64"
    if sys.platform.startswith("linux"):
        return "linux-x86_64"
    raise ConfigurationError("Firefox runtime is not available for this platform")


def _validate_manifest(manifest, profile_id, selected_platform):
    if not isinstance(manifest, dict):
        raise ConfigurationError("embedded Firefox runtime lock is invalid")
    schema = manifest.get("schema_version")
    if schema == 1:
        if (
            profile_id != "firefox_152"
            or selected_platform != "windows-x86_64"
            or manifest.get("source_id") != "firefox-windows-x86_64-en-us"
            or manifest.get("firefox_version") != "152.0.6"
            or manifest.get("firefox_build_id") != "20260713164047"
            or manifest.get("nss_version") != "3.124"
            or manifest.get("nspr_version") != "4.39"
        ):
            raise ConfigurationError("legacy Firefox runtime lock identity is invalid")
    elif schema == 2:
        if (
            set(manifest) != _SCHEMA_TWO_FIELDS
            or manifest.get("profile") != profile_id
            or manifest.get("platform") != selected_platform
            or not _nonempty(manifest.get("source_id"))
            or not _nonempty(manifest.get("source_url"))
            or not _positive_integer(manifest.get("source_size"))
            or not _matches(_HEX_256, manifest.get("source_sha256"))
            or not _matches(_HEX_512, manifest.get("source_sha512"))
        ):
            raise ConfigurationError("embedded Firefox runtime lock identity is invalid")
    else:
        raise ConfigurationError("embedded Firefox runtime lock schema is unsupported")

    required_text = (
        "firefox_version",
        "firefox_build_id",
        "nss_version",
        "nspr_version",
    )
    if (
        any(not _nonempty(manifest.get(name)) for name in required_text)
        or manifest.get("firefox_version") != _FIREFOX_VERSIONS[profile_id]
        or re.fullmatch(r"[0-9]{14}", manifest.get("firefox_build_id", "")) is None
        or re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", manifest.get("nss_version", ""))
        is None
        or re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", manifest.get("nspr_version", ""))
        is None
    ):
        raise ConfigurationError("embedded Firefox runtime versions are invalid")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise ConfigurationError("embedded Firefox runtime file list is invalid")
    names = set()
    ordered_names = []
    for entry in files:
        if not isinstance(entry, dict):
            raise ConfigurationError("embedded Firefox runtime file entry is invalid")
        filename = entry.get("filename")
        normalized = filename.casefold() if isinstance(filename, str) else None
        if (
            set(entry) != {"filename", "size", "sha256"}
            or not _safe_relative_name(filename)
            or normalized in names
            or not _positive_integer(entry.get("size"))
            or not _matches(_HEX_256, entry.get("sha256"))
        ):
            raise ConfigurationError("embedded Firefox runtime file entry is invalid")
        names.add(normalized)
        ordered_names.append(filename)
    if schema == 2 and ordered_names != sorted(ordered_names):
        raise ConfigurationError("embedded Firefox runtime file list is invalid")


def _safe_relative_name(value):
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return False
    for part in path.parts:
        stem = part.rstrip(" .").split(".", 1)[0].upper()
        if ":" in part or stem in _WINDOWS_RESERVED:
            return False
    return "/".join(path.parts) == value


def _positive_integer(value):
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _nonempty(value):
    return isinstance(value, str) and bool(value)


def _matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _is_plain_directory(path):
    try:
        info = path.lstat()
    except OSError:
        return False
    return stat.S_ISDIR(info.st_mode) and not _is_reparse_point(info)


def _is_plain_file(path):
    try:
        info = path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and not _is_reparse_point(info)


def _is_reparse_point(info):
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(flag and getattr(info, "st_file_attributes", 0) & flag)


def _has_reparse_component(path):
    path = Path(path)
    current = Path(path.anchor)
    start = 1 if path.anchor else 0
    for part in path.parts[start:]:
        current /= part
        try:
            info = current.lstat()
        except OSError:
            return False
        if stat.S_ISLNK(info.st_mode) or _is_reparse_point(info):
            return True
    return False


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            chunk = source.read(_HASH_CHUNK_SIZE)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)
