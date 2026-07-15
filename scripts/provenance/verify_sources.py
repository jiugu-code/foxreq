import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit


class LockError(ValueError):
    pass


_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_FIREFOX_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_BUILD_ID_RE = re.compile(r"^[0-9]{14}$")
_COMPONENT_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+(?:\.[0-9]+)?$")
_PROFILE_RE = re.compile(r"^firefox_[0-9]+$")
_PLATFORMS = ("windows-x86_64", "linux-x86_64")


def _read_json(path):
    path = Path(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LockError("cannot read JSON lock {}: {}".format(path, exc)) from exc
    if not isinstance(value, dict):
        raise LockError("{} must contain a JSON object".format(path))
    return value


def _exact_keys(value, required, path):
    if not isinstance(value, dict):
        raise LockError("{} must be an object".format(path))
    actual = set(value)
    required = set(required)
    missing = sorted(required - actual)
    unknown = sorted(actual - required)
    if missing:
        raise LockError("{} missing keys: {}".format(path, ", ".join(missing)))
    if unknown:
        raise LockError("{} unknown keys: {}".format(path, ", ".join(unknown)))


def _validate_https_url(url, path):
    if not isinstance(url, str):
        raise LockError("{} must be a string".format(path))
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise LockError("{} must use HTTPS".format(path))
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise LockError("{} must not contain credentials, query, or fragment".format(path))
    if any(segment.lower() == "latest" for segment in parsed.path.split("/")):
        raise LockError("{} must not use a mutable latest path".format(path))


def _validate_sha256(value, path):
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise LockError("{} must be a lowercase SHA-256".format(path))


def _validate_positive_int(value, path):
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise LockError("{} must be a positive integer".format(path))


def _validate_nonempty_string(value, path):
    if not isinstance(value, str) or not value.strip():
        raise LockError("{} must be a nonempty string".format(path))


def _validate_compiler(value, path):
    _validate_nonempty_string(value, path)
    lowered = value.lower()
    if any(marker in lowered for marker in ("pending", "unverified", "unknown", "tbd")):
        raise LockError("{} must be a verified compiler identity".format(path))


def _sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def load_source_lock(path):
    root = _read_json(path)
    _exact_keys(root, {"schema_version", "sources"}, "source lock")
    if root["schema_version"] != 1:
        raise LockError("source lock schema_version must be 1")
    if not isinstance(root["sources"], list) or not root["sources"]:
        raise LockError("source lock sources must be a nonempty list")

    by_id = {}
    filenames = set()
    for index, source in enumerate(root["sources"]):
        label = "sources[{}]".format(index)
        _exact_keys(
            source,
            {"id", "url", "filename", "sha256", "size"},
            label,
        )
        source_id = source["id"]
        if not isinstance(source_id, str) or not _ID_RE.fullmatch(source_id):
            raise LockError("{}.id is invalid".format(label))
        if source_id in by_id:
            raise LockError("duplicate source id: {}".format(source_id))

        filename = source["filename"]
        if (
            not isinstance(filename, str)
            or not filename
            or Path(filename).name != filename
            or filename in {".", ".."}
        ):
            raise LockError("{}.filename must be one safe basename".format(label))
        if filename in filenames:
            raise LockError("duplicate source filename: {}".format(filename))

        _validate_https_url(source["url"], label + ".url")
        _validate_sha256(source["sha256"], label + ".sha256")
        _validate_positive_int(source["size"], label + ".size")
        by_id[source_id] = dict(source)
        filenames.add(filename)

    return by_id


def _validate_source_ref(source_id, sources, path):
    if not isinstance(source_id, str) or source_id not in sources:
        raise LockError("{} references an unknown source id".format(path))


def _validate_component(name, component, sources):
    path = "components.{}".format(name)
    _exact_keys(
        component,
        {"repository", "revision", "source_id", "source_path", "version"},
        path,
    )
    _validate_https_url(component["repository"], path + ".repository")
    if not isinstance(component["revision"], str) or not _REVISION_RE.fullmatch(
        component["revision"]
    ):
        raise LockError("{}.revision must be a 40-character revision".format(path))
    _validate_source_ref(component["source_id"], sources, path + ".source_id")
    source_path = component["source_path"]
    parsed_path = PurePosixPath(source_path) if isinstance(source_path, str) else None
    if (
        parsed_path is None
        or parsed_path.is_absolute()
        or ".." in parsed_path.parts
        or str(parsed_path) in {"", "."}
    ):
        raise LockError("{}.source_path must be repository relative".format(path))
    if not isinstance(component["version"], str) or not _COMPONENT_VERSION_RE.fullmatch(
        component["version"]
    ):
        raise LockError("{}.version must be exact".format(path))


def _validate_deferred_platforms(deferred):
    if not isinstance(deferred, list) or any(
        platform not in _PLATFORMS for platform in deferred
    ):
        raise LockError("deferred_platforms must contain known platforms")
    if len(deferred) != len(set(deferred)):
        raise LockError("deferred_platforms contains duplicates")
    if set(deferred) == set(_PLATFORMS):
        raise LockError("at least one platform build must remain verified")


def _validate_builds(builds, deferred):
    expected = set(_PLATFORMS) - set(deferred)
    _exact_keys(builds, expected, "builds")
    for platform in sorted(expected):
        build = builds[platform]
        path = "builds.{}".format(platform)
        _exact_keys(build, {"compiler", "flags"}, path)
        _validate_compiler(build["compiler"], path + ".compiler")
        flags = build["flags"]
        if not isinstance(flags, list) or any(
            not isinstance(flag, str) or not flag for flag in flags
        ):
            raise LockError("{}.flags must be a string list".format(path))
        if len(flags) != len(set(flags)):
            raise LockError("{}.flags contains duplicates".format(path))


def _resolve_repo_file(repo_root, relative, path):
    if not isinstance(relative, str):
        raise LockError("{} must be a string".format(path))
    posix = PurePosixPath(relative)
    if posix.is_absolute() or ".." in posix.parts:
        raise LockError("{} must stay inside the repository".format(path))
    if posix.parts[:3] != ("third_party", "patches", "nss"):
        raise LockError("{} must be under third_party/patches/nss".format(path))

    root = Path(repo_root).resolve()
    candidate = root.joinpath(*posix.parts).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise LockError("{} escapes the repository".format(path)) from exc
    if not candidate.is_file() or candidate.is_symlink():
        raise LockError("{} does not name a regular patch file".format(path))
    return candidate


def _validate_patches(patches, repo_root):
    if not isinstance(patches, list):
        raise LockError("patches must be a list")
    seen = set()
    for index, patch in enumerate(patches):
        path = "patches[{}]".format(index)
        _exact_keys(patch, {"path", "sha256"}, path)
        if patch["path"] in seen:
            raise LockError("duplicate patch path: {}".format(patch["path"]))
        _validate_sha256(patch["sha256"], path + ".sha256")
        patch_path = _resolve_repo_file(repo_root, patch["path"], path + ".path")
        if _sha256_file(patch_path) != patch["sha256"]:
            raise LockError("patch hash mismatch: {}".format(patch["path"]))
        seen.add(patch["path"])


def _validate_capture(capture, deferred):
    _exact_keys(
        capture,
        {"endpoint", "operating_systems", "locales", "preferences", "tools"},
        "capture",
    )
    _validate_https_url(capture["endpoint"], "capture.endpoint")
    if urlsplit(capture["endpoint"]).hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise LockError("capture.endpoint must be an HTTPS loopback URL")
    expected_systems = set(_PLATFORMS) - set(deferred)
    _exact_keys(
        capture["operating_systems"],
        expected_systems,
        "capture.operating_systems",
    )
    for platform, identity in capture["operating_systems"].items():
        _validate_nonempty_string(identity, "capture.operating_systems." + platform)
    _exact_keys(capture["locales"], set(_PLATFORMS), "capture.locales")
    for platform, locale in capture["locales"].items():
        _validate_nonempty_string(locale, "capture.locales." + platform)
    if not isinstance(capture["preferences"], dict):
        raise LockError("capture.preferences must be an object")
    if not isinstance(capture["tools"], dict) or not capture["tools"]:
        raise LockError("capture.tools must be a nonempty object")
    for name, version in capture["tools"].items():
        _validate_nonempty_string(name, "capture.tools key")
        _validate_nonempty_string(version, "capture.tools." + name)


def load_profile_lock(path, sources, repo_root):
    root = _read_json(path)
    _exact_keys(
        root,
        {
            "schema_version",
            "profile",
            "firefox",
            "components",
            "builds",
            "deferred_platforms",
            "patches",
            "capture",
        },
        "profile lock",
    )
    if root["schema_version"] != 1:
        raise LockError("profile lock schema_version must be 1")
    if not isinstance(root["profile"], str) or not _PROFILE_RE.fullmatch(root["profile"]):
        raise LockError("profile must be an immutable firefox_<major> name")

    firefox = root["firefox"]
    _exact_keys(
        firefox,
        {
            "version",
            "channel",
            "build_id",
            "release_revision",
            "source_id",
            "artifacts",
        },
        "firefox",
    )
    if not isinstance(firefox["version"], str) or not _FIREFOX_VERSION_RE.fullmatch(
        firefox["version"]
    ):
        raise LockError("firefox.version must be an exact three-part version")
    if firefox["channel"] != "release":
        raise LockError("firefox.channel must be release")
    if not isinstance(firefox["build_id"], str) or not _BUILD_ID_RE.fullmatch(
        firefox["build_id"]
    ):
        raise LockError("firefox.build_id must be a 14-digit build identifier")
    if not isinstance(firefox["release_revision"], str) or not _REVISION_RE.fullmatch(
        firefox["release_revision"]
    ):
        raise LockError("firefox.release_revision must be a 40-character revision")
    _validate_source_ref(firefox["source_id"], sources, "firefox.source_id")
    _exact_keys(firefox["artifacts"], set(_PLATFORMS), "firefox.artifacts")
    for platform, source_id in firefox["artifacts"].items():
        _validate_source_ref(source_id, sources, "firefox.artifacts." + platform)

    _exact_keys(root["components"], {"nss", "nspr"}, "components")
    _validate_component("nss", root["components"]["nss"], sources)
    _validate_component("nspr", root["components"]["nspr"], sources)
    _validate_deferred_platforms(root["deferred_platforms"])
    _validate_builds(root["builds"], root["deferred_platforms"])
    _validate_patches(root["patches"], repo_root)
    _validate_capture(root["capture"], root["deferred_platforms"])
    return root


def verify_cached_sources(sources, cache_dir):
    cache = Path(cache_dir)
    verified = []
    for source_id, source in sources.items():
        path = cache / source["filename"]
        if not path.is_file() or path.is_symlink():
            raise LockError("missing cached source: {}".format(source_id))
        actual_size = path.stat().st_size
        if actual_size != source["size"]:
            raise LockError(
                "size mismatch for {}: expected {}, received {}".format(
                    source_id, source["size"], actual_size
                )
            )
        actual_hash = _sha256_file(path)
        if actual_hash != source["sha256"]:
            raise LockError(
                "hash mismatch for {}: expected {}, received {}".format(
                    source_id, source["sha256"], actual_hash
                )
            )
        verified.append(source_id)
    return verified


def main(argv=None):
    parser = argparse.ArgumentParser(description="verify pinned foxreq source inputs")
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--cache", type=Path, default=Path(".cache/sources"))
    parser.add_argument("--profile-lock", type=Path)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)

    try:
        sources = load_source_lock(args.lock)
        if args.profile_lock:
            load_profile_lock(args.profile_lock, sources, args.repo_root)
        verified = verify_cached_sources(sources, args.cache)
    except LockError as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2

    print(json.dumps({"verified": verified}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
