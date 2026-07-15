"""Launch only a hash-verified Firefox against an explicit loopback HTTPS URL."""

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Mapping, Optional, Sequence
from urllib.parse import urlsplit


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PREFERENCE = re.compile(r"^[A-Za-z0-9._-]+$")


class FirefoxCaptureError(Exception):
    pass


def verify_firefox_binary(path: Path, expected_sha256: str) -> str:
    if not isinstance(expected_sha256, str) or not _SHA256.fullmatch(expected_sha256):
        raise FirefoxCaptureError("expected Firefox hash must be lowercase SHA-256")
    if path.is_symlink() or not path.is_file():
        raise FirefoxCaptureError("Firefox binary must be a regular non-symlink file")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    actual = digest.hexdigest()
    if not hmac.compare_digest(actual, expected_sha256):
        raise FirefoxCaptureError("Firefox binary hash mismatch")
    return actual


def validate_capture_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        address = ipaddress.ip_address(host) if host is not None else None
        parsed.port
    except (ValueError, TypeError):
        raise FirefoxCaptureError("capture URL must contain a valid loopback address")
    if parsed.scheme != "https":
        raise FirefoxCaptureError("capture URL must use HTTPS")
    if address is None or not address.is_loopback:
        raise FirefoxCaptureError("capture URL must use a loopback IP literal")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise FirefoxCaptureError("capture URL must not contain userinfo or a fragment")
    return url


def render_user_js(preferences: Mapping[str, object]) -> str:
    if not isinstance(preferences, Mapping):
        raise FirefoxCaptureError("preferences must be a mapping")
    lines = []
    for key in sorted(preferences):
        value = preferences[key]
        if not isinstance(key, str) or not _PREFERENCE.fullmatch(key):
            raise FirefoxCaptureError("invalid Firefox preference name")
        if isinstance(value, bool):
            encoded = "true" if value else "false"
        elif isinstance(value, int):
            encoded = str(value)
        elif isinstance(value, str):
            encoded = json.dumps(value, ensure_ascii=True)
        else:
            raise FirefoxCaptureError("invalid Firefox preference value")
        lines.append("user_pref({}, {});".format(json.dumps(key), encoded))
    return "\n".join(lines) + "\n"


def load_profile_lock(path: Path) -> Mapping[str, object]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        firefox = data["firefox"]
        capture = data["capture"]
        preferences = capture["preferences"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise FirefoxCaptureError("invalid profile provenance lock") from error
    if data.get("schema_version") != 1 or not isinstance(preferences, Mapping):
        raise FirefoxCaptureError("invalid profile provenance lock")
    if not all(
        isinstance(firefox.get(field), str) and firefox[field]
        for field in ("version", "build_id", "release_revision")
    ):
        raise FirefoxCaptureError("invalid Firefox provenance identity")
    render_user_js(preferences)
    return data


def orchestrate_capture(
    binary: Path,
    expected_sha256: str,
    url: str,
    preferences: Mapping[str, object],
    mode: str,
    count: int,
    timeout: float,
) -> Dict[str, object]:
    if mode not in ("cold", "resumed"):
        raise FirefoxCaptureError("capture mode must be cold or resumed")
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise FirefoxCaptureError("capture count must be positive")
    if timeout <= 0:
        raise FirefoxCaptureError("capture timeout must be positive")
    digest = verify_firefox_binary(binary, expected_sha256)
    url = validate_capture_url(url)
    user_js = render_user_js(preferences)
    preferences_hash = hashlib.sha256(user_js.encode("utf-8")).hexdigest()
    launches = []

    if mode == "cold":
        for sequence in range(1, count + 1):
            with tempfile.TemporaryDirectory(prefix="foxreq-firefox-cold-") as directory:
                profile = Path(directory)
                (profile / "user.js").write_text(user_js, encoding="utf-8")
                launches.append(
                    _launch(
                        binary,
                        expected_sha256,
                        profile,
                        [url],
                        timeout,
                        sequence,
                        1,
                    )
                )
    else:
        with tempfile.TemporaryDirectory(prefix="foxreq-firefox-resumed-") as directory:
            profile = Path(directory)
            (profile / "user.js").write_text(user_js, encoding="utf-8")
            launches.append(
                _launch(
                    binary,
                    expected_sha256,
                    profile,
                    [url] * count,
                    timeout,
                    1,
                    count,
                )
            )

    return {
        "schema_version": 1,
        "mode": mode,
        "count": count,
        "url": url,
        "firefox_binary_sha256": digest,
        "preferences_sha256": preferences_hash,
        "launches": launches,
    }


def _launch(
    binary: Path,
    expected_sha256: str,
    profile: Path,
    urls: Sequence[str],
    timeout: float,
    sequence_start: int,
    expected_connections: int,
) -> Dict[str, object]:
    verify_firefox_binary(binary, expected_sha256)
    command = [
        str(binary.resolve()),
        "-headless",
        "-no-remote",
        "-profile",
        str(profile.resolve()),
    ] + list(urls)
    environment = os.environ.copy()
    environment["MOZ_HEADLESS"] = "1"
    environment["MOZ_NO_REMOTE"] = "1"
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=environment,
    )
    timed_out = False
    try:
        exit_code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.terminate()
        try:
            exit_code = process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            process.kill()
            exit_code = process.wait(timeout=2.0)
    return {
        "sequence_start": sequence_start,
        "expected_connections": expected_connections,
        "timed_out": timed_out,
        "exit_code": exit_code,
    }


def validate_manifest_output(path: Path, repository: Optional[Path] = None) -> Path:
    repository = (repository or Path(__file__).parents[2]).resolve()
    root = (repository / "artifacts" / "captures").resolve()
    resolved = path.resolve()
    try:
        common = Path(os.path.commonpath((str(root), str(resolved))))
    except ValueError:
        raise FirefoxCaptureError("manifest must be under artifacts/captures")
    if common != root:
        raise FirefoxCaptureError("manifest must be under artifacts/captures")
    return resolved


def _parser() -> argparse.ArgumentParser:
    repository = Path(__file__).parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firefox", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument(
        "--profile-lock",
        type=Path,
        default=repository / "profiles" / "firefox_152" / "provenance.lock.json",
    )
    parser.add_argument("--url")
    parser.add_argument("--mode", choices=("cold", "resumed"), required=True)
    parser.add_argument("--count", type=int)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--allow-partial", action="store_true")
    parser.add_argument("--manifest", type=Path, required=True)
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    provenance = load_profile_lock(args.profile_lock)
    capture = provenance["capture"]
    url = args.url or capture["endpoint"]
    profile_path = args.profile_lock.parent / "profile.json"
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    expected_count = profile["capture_count"]
    count = expected_count if args.count is None else args.count
    if count != expected_count and not args.allow_partial:
        raise FirefoxCaptureError(
            "capture count differs from profile; use --allow-partial for fixture work"
        )
    manifest = orchestrate_capture(
        binary=args.firefox,
        expected_sha256=args.expected_sha256,
        url=url,
        preferences=capture["preferences"],
        mode=args.mode,
        count=count,
        timeout=args.timeout,
    )
    manifest["profile"] = provenance["profile"]
    manifest["firefox_version"] = provenance["firefox"]["version"]
    manifest["firefox_build_id"] = provenance["firefox"]["build_id"]
    manifest["firefox_release_revision"] = provenance["firefox"]["release_revision"]
    output = validate_manifest_output(args.manifest)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
