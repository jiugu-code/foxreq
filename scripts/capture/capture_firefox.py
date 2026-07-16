"""Launch only a hash-verified Firefox against an explicit loopback HTTPS URL."""

import argparse
import ctypes
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Dict, Mapping, Optional, Sequence
from urllib.parse import urlsplit

from tests.fixtures.capture_server import validate_capture_output
from tests.fixtures.tls_capture_server import TlsCaptureServer


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PREFERENCE = re.compile(r"^[A-Za-z0-9._-]+$")


class FirefoxCaptureError(Exception):
    pass


@contextmanager
def temporary_firefox_profile():
    """Yield a profile and tolerate short-lived Firefox child-process locks."""

    directory = Path(tempfile.mkdtemp(prefix="foxreq-firefox-cold-"))
    try:
        yield directory
    finally:
        for attempt in range(50):
            try:
                shutil.rmtree(directory)
                break
            except FileNotFoundError:
                break
            except PermissionError:
                if attempt == 49:
                    shutil.rmtree(directory, ignore_errors=True)
                    break
                time.sleep(0.1)


def render_certificate_override(host: str, port: int, certificate_der: bytes) -> str:
    """Render one temporary-profile SHA-256 certificate exception."""

    try:
        address = ipaddress.ip_address(host)
    except ValueError as error:
        raise FirefoxCaptureError("certificate override host must be an IP") from error
    if not address.is_loopback:
        raise FirefoxCaptureError("certificate override host must be loopback")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise FirefoxCaptureError("certificate override port is invalid")
    if not isinstance(certificate_der, bytes) or not certificate_der:
        raise FirefoxCaptureError("certificate override DER must be non-empty bytes")
    digest = hashlib.sha256(certificate_der).hexdigest().upper()
    fingerprint = ":".join(
        digest[offset : offset + 2] for offset in range(0, len(digest), 2)
    )
    host_port = "[{}]:{}".format(host, port) if address.version == 6 else "{}:{}".format(host, port)
    return (
        "# PSM Certificate Override Settings file\n"
        "# This is a generated file! Do not edit.\n"
        "{}\tOID.2.16.840.1.101.3.4.2.1\t{}\t\n".format(
            host_port, fingerprint
        )
    )


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
    certificate_der: Optional[bytes] = None,
    minimum_available_memory: int = 0,
    memory_wait_timeout: float = 0.0,
    launch_attempts: int = 1,
    progress: Optional[Callable[[Mapping[str, object]], None]] = None,
    capture_waiter: Optional[Callable[[int, float], bool]] = None,
) -> Dict[str, object]:
    if mode not in ("cold", "resumed"):
        raise FirefoxCaptureError("capture mode must be cold or resumed")
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise FirefoxCaptureError("capture count must be positive")
    if timeout <= 0:
        raise FirefoxCaptureError("capture timeout must be positive")
    if (
        isinstance(minimum_available_memory, bool)
        or not isinstance(minimum_available_memory, int)
        or minimum_available_memory < 0
    ):
        raise FirefoxCaptureError("minimum available memory must be non-negative")
    if (
        isinstance(memory_wait_timeout, bool)
        or not isinstance(memory_wait_timeout, (int, float))
        or not math.isfinite(memory_wait_timeout)
        or memory_wait_timeout < 0
    ):
        raise FirefoxCaptureError("memory wait timeout must be non-negative")
    if (
        isinstance(launch_attempts, bool)
        or not isinstance(launch_attempts, int)
        or not 1 <= launch_attempts <= 3
    ):
        raise FirefoxCaptureError("launch attempts must be between one and three")
    digest = verify_firefox_binary(binary, expected_sha256)
    url = validate_capture_url(url)
    user_js = render_user_js(preferences)
    preferences_hash = hashlib.sha256(user_js.encode("utf-8")).hexdigest()
    launches = []

    if mode == "cold":
        for sequence in range(1, count + 1):
            for attempt in range(1, launch_attempts + 1):
                with temporary_firefox_profile() as profile:
                    _write_capture_profile(profile, user_js, url, certificate_der)
                    memory_before = _require_available_memory(
                        minimum_available_memory, memory_wait_timeout
                    )
                    launch = _launch(
                        binary,
                        expected_sha256,
                        profile,
                        [url],
                        timeout,
                        sequence,
                        1,
                        capture_waiter,
                    )
                    launch["attempt"] = attempt
                    launch["available_memory_before_bytes"] = memory_before
                    launch["available_memory_after_bytes"] = (
                        _available_physical_memory()
                    )
                    launches.append(launch)
                    try:
                        _require_launch_success(launch)
                    except FirefoxCaptureError:
                        if attempt == launch_attempts:
                            raise
                        continue
                    if progress is not None:
                        progress(
                            {
                                "mode": mode,
                                "completed": sequence,
                                "total": count,
                                "available_memory_bytes": launch[
                                    "available_memory_after_bytes"
                                ],
                            }
                        )
                    break
    else:
        with temporary_firefox_profile() as profile:
            _write_capture_profile(profile, user_js, url, certificate_der)
            memory_before = _require_available_memory(
                minimum_available_memory, memory_wait_timeout
            )
            launch = _launch(
                binary,
                expected_sha256,
                profile,
                [url],
                timeout,
                1,
                count,
                capture_waiter,
            )
            _require_launch_success(launch)
            launch["available_memory_before_bytes"] = memory_before
            launch["available_memory_after_bytes"] = _available_physical_memory()
            launches.append(launch)
            if progress is not None:
                progress(
                    {
                        "mode": mode,
                        "completed": count,
                        "total": count,
                        "available_memory_bytes": launch[
                            "available_memory_after_bytes"
                        ],
                    }
                )

    return {
        "schema_version": 1,
        "mode": mode,
        "count": count,
        "url": url,
        "firefox_binary_sha256": digest,
        "preferences_sha256": preferences_hash,
        "minimum_available_memory_bytes": minimum_available_memory,
        "memory_wait_timeout_seconds": memory_wait_timeout,
        "launch_attempt_limit": launch_attempts,
        "launches": launches,
    }


def _write_capture_profile(
    profile: Path,
    user_js: str,
    url: str,
    certificate_der: Optional[bytes],
) -> None:
    (profile / "user.js").write_text(user_js, encoding="utf-8")
    if certificate_der is None:
        return
    parsed = urlsplit(url)
    host = parsed.hostname
    if host is None:
        raise FirefoxCaptureError("capture URL must contain a host")
    port = parsed.port or 443
    (profile / "cert_override.txt").write_bytes(
        render_certificate_override(host, port, certificate_der).encode("ascii")
    )


def _require_launch_success(launch: Mapping[str, object]) -> None:
    captured = launch.get("terminated_after_capture") is True
    if launch.get("timed_out") is not False or (
        not captured and launch.get("exit_code") != 0
    ):
        detail = launch.get("stderr_tail")
        suffix = ": " + detail if isinstance(detail, str) and detail else ""
        raise FirefoxCaptureError(
            "Firefox capture launch did not complete cleanly" + suffix
        )


def _available_physical_memory() -> Optional[int]:
    if os.name != "nt":
        return None

    class MemoryStatus(ctypes.Structure):
        _fields_ = [
            ("length", ctypes.c_uint32),
            ("memory_load", ctypes.c_uint32),
            ("total_physical", ctypes.c_uint64),
            ("available_physical", ctypes.c_uint64),
            ("total_page_file", ctypes.c_uint64),
            ("available_page_file", ctypes.c_uint64),
            ("total_virtual", ctypes.c_uint64),
            ("available_virtual", ctypes.c_uint64),
            ("available_extended_virtual", ctypes.c_uint64),
        ]

    status = MemoryStatus()
    status.length = ctypes.sizeof(status)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        raise FirefoxCaptureError("could not read available physical memory")
    return int(status.available_physical)


def _require_available_memory(
    minimum: int, wait_timeout: float = 0.0
) -> Optional[int]:
    deadline = time.monotonic() + wait_timeout
    while True:
        available = _available_physical_memory()
        if available is None or available >= minimum:
            return available
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FirefoxCaptureError(
                "available physical memory is below the capture limit"
            )
        time.sleep(min(1.0, remaining))


def capture_with_local_server(
    binary: Path,
    expected_sha256: str,
    url: str,
    preferences: Mapping[str, object],
    mode: str,
    count: int,
    timeout: float,
    certificate: Path,
    private_key: Path,
    certificate_der: bytes,
    raw_output: Path,
    minimum_available_memory: int = 0,
    memory_wait_timeout: float = 0.0,
    launch_attempts: int = 1,
    progress: Optional[Callable[[Mapping[str, object]], None]] = None,
) -> Dict[str, object]:
    """Run one bounded loopback capture suite with an in-process TLS fixture."""

    url = validate_capture_url(url)
    parsed = urlsplit(url)
    host = parsed.hostname
    port = parsed.port or 443
    if host is None:
        raise FirefoxCaptureError("capture URL must contain a host")
    output_path = validate_capture_output(raw_output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    failures = []
    with output_path.open("x", encoding="utf-8", newline="\n") as output:
        server = TlsCaptureServer(
            host=host,
            port=port,
            certificate=certificate,
            private_key=private_key,
            output=output,
            mode=mode,
            timeout=timeout,
            accept_timeout=(timeout + memory_wait_timeout) * launch_attempts + 1.0,
        )

        def serve():
            try:
                server.serve(count)
            except Exception as error:  # captured and surfaced on the caller thread
                failures.append(error)
            finally:
                server.ready.set()

        thread = threading.Thread(
            target=serve, name="foxreq-firefox-capture", daemon=True
        )
        thread.start()
        if not server.ready.wait(timeout=min(timeout, 5.0)):
            raise FirefoxCaptureError("local TLS capture server did not start")
        if failures:
            raise FirefoxCaptureError("local TLS capture server failed to start") from failures[0]
        if server.bound_port != port:
            raise FirefoxCaptureError("local TLS capture server bound the wrong port")
        capture_error = None
        manifest = None
        try:
            manifest = orchestrate_capture(
                binary=binary,
                expected_sha256=expected_sha256,
                url=url,
                preferences=preferences,
                mode=mode,
                count=count,
                timeout=timeout,
                certificate_der=certificate_der,
                minimum_available_memory=minimum_available_memory,
                memory_wait_timeout=memory_wait_timeout,
                launch_attempts=launch_attempts,
                progress=progress,
                capture_waiter=server.wait_for_completed,
            )
        except Exception as error:
            capture_error = error
            request_stop = getattr(server, "request_stop", None)
            if request_stop is not None:
                request_stop()
        thread.join(timeout=timeout + 1.0)
        if thread.is_alive():
            raise FirefoxCaptureError("local TLS capture server did not stop")
        if failures:
            detail = ": " + str(capture_error) if capture_error is not None else ""
            raise FirefoxCaptureError(
                "local TLS capture server failed" + detail
            ) from failures[0]
        if capture_error is not None:
            raise capture_error
    if manifest is None:
        raise FirefoxCaptureError("Firefox capture produced no manifest")
    return manifest


def _launch(
    binary: Path,
    expected_sha256: str,
    profile: Path,
    urls: Sequence[str],
    timeout: float,
    sequence_start: int,
    expected_connections: int,
    capture_waiter: Optional[Callable[[int, float], bool]] = None,
) -> Dict[str, object]:
    verify_firefox_binary(binary, expected_sha256)
    command = [
        str(binary.resolve()),
        "--headless",
        "--no-remote",
        "--profile",
        str(profile.resolve()),
    ]
    command.extend(
        ["--screenshot", str((profile / "capture.png").resolve())]
    )
    command.extend(urls)
    environment = os.environ.copy()
    environment["MOZ_HEADLESS"] = "1"
    environment["MOZ_NO_REMOTE"] = "1"
    with tempfile.TemporaryFile() as diagnostics:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=diagnostics,
            env=environment,
        )
        timed_out = False
        terminated_after_capture = False
        if capture_waiter is not None:
            target = sequence_start + expected_connections - 1
            terminated_after_capture = capture_waiter(target, timeout)
            timed_out = not terminated_after_capture
            process.terminate()
            try:
                exit_code = process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                process.kill()
                exit_code = process.wait(timeout=2.0)
        else:
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
        failed = timed_out or (not terminated_after_capture and exit_code != 0)
        stderr_tail = ""
        if failed:
            diagnostics.seek(0, os.SEEK_END)
            length = diagnostics.tell()
            diagnostics.seek(max(0, length - 4096))
            stderr_tail = diagnostics.read(4096).decode("utf-8", errors="replace")
            stderr_tail = stderr_tail.replace("\x00", "").strip()
    result = {
        "sequence_start": sequence_start,
        "expected_connections": expected_connections,
        "timed_out": timed_out,
        "terminated_after_capture": terminated_after_capture,
        "exit_code": exit_code,
    }
    if stderr_tail:
        result["stderr_tail"] = stderr_tail
    return result


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
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--certificate-der", type=Path, required=True)
    parser.add_argument("--raw-output", type=Path, required=True)
    parser.add_argument(
        "--profile-lock",
        type=Path,
        default=repository / "profiles" / "firefox_152" / "provenance.lock.json",
    )
    parser.add_argument("--url")
    parser.add_argument("--mode", choices=("cold", "resumed"), required=True)
    parser.add_argument("--count", type=int)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument(
        "--minimum-available-memory-mb", type=int, default=4096
    )
    parser.add_argument("--memory-wait-timeout", type=float, default=60.0)
    parser.add_argument("--launch-attempts", type=int, default=3)
    parser.add_argument("--allow-partial", action="store_true")
    parser.add_argument("--manifest", type=Path, required=True)
    return parser


def _print_capture_progress(event: Mapping[str, object]) -> None:
    payload = dict(event)
    payload["event"] = "firefox_capture_progress"
    print(json.dumps(payload, sort_keys=True), file=sys.stderr, flush=True)


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
    manifest = capture_with_local_server(
        binary=args.firefox,
        expected_sha256=args.expected_sha256,
        url=url,
        preferences=capture["preferences"],
        mode=args.mode,
        count=count,
        timeout=args.timeout,
        certificate=args.certificate,
        private_key=args.private_key,
        certificate_der=args.certificate_der.read_bytes(),
        raw_output=args.raw_output,
        minimum_available_memory=args.minimum_available_memory_mb * 1024 * 1024,
        memory_wait_timeout=args.memory_wait_timeout,
        launch_attempts=args.launch_attempts,
        progress=_print_capture_progress,
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
