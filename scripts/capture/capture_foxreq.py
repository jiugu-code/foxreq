"""Capture foxreq ClientHellos against the bounded loopback TLS fixture."""

import argparse
import ctypes
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

from tests.fixtures.capture_server import validate_capture_output
from tests.fixtures.tls_capture_server import TlsCaptureServer


class FoxreqCaptureError(Exception):
    pass


def _available_physical_memory():
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
        raise FoxreqCaptureError("could not read available physical memory")
    return int(status.available_physical)


def capture_foxreq(
    repository,
    runtime,
    ca_der,
    certificate,
    private_key,
    raw_output,
    host,
    port,
    mode,
    count,
    timeout,
    cargo,
    profile="firefox_152",
    minimum_available_memory=0,
    memory_reader=None,
    runner=None,
):
    repository = Path(repository).resolve()
    runtime = Path(runtime).resolve()
    ca_der = Path(ca_der).resolve()
    certificate = Path(certificate).resolve()
    private_key = Path(private_key).resolve()
    try:
        address = ipaddress.ip_address(host)
    except ValueError as error:
        raise FoxreqCaptureError("capture host must be an IP literal") from error
    if not address.is_loopback:
        raise FoxreqCaptureError("capture host must be loopback")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise FoxreqCaptureError("capture port is invalid")
    if mode not in ("cold", "resumed"):
        raise FoxreqCaptureError("capture mode must be cold or resumed")
    if profile not in ("firefox_140_esr", "firefox_152"):
        raise FoxreqCaptureError("capture profile is unsupported")
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 1000:
        raise FoxreqCaptureError("capture count must be between 1 and 1000")
    if timeout <= 0:
        raise FoxreqCaptureError("capture timeout must be positive")
    if (
        isinstance(minimum_available_memory, bool)
        or not isinstance(minimum_available_memory, int)
        or minimum_available_memory < 0
    ):
        raise FoxreqCaptureError("minimum available memory must be non-negative")
    if not runtime.is_dir():
        raise FoxreqCaptureError("pinned Firefox runtime directory is missing")
    if not ca_der.is_file() or not certificate.is_file() or not private_key.is_file():
        raise FoxreqCaptureError("local TLS certificate fixture is incomplete")
    memory_reader = memory_reader or _available_physical_memory
    available_memory = memory_reader()
    if (
        available_memory is not None
        and available_memory < minimum_available_memory
    ):
        raise FoxreqCaptureError("available physical memory is below the capture limit")
    output_path = validate_capture_output(raw_output, repository=repository)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["CARGO_BUILD_JOBS"] = "1"
    environment["FOXREQ_NSS_RUNTIME_DIR"] = str(runtime)
    base_command = [
        str(cargo),
        "run",
        "--quiet",
        "-p",
        "foxreq-core",
        "--features",
        "nss-real",
        "--example",
        "capture_tls",
        "--",
        "--runtime",
        str(runtime),
        "--ca-der",
        str(ca_der),
        "--profile",
        profile,
        "--host",
        host,
        "--port",
        str(port),
        "--mode",
        mode,
    ]
    process_counts = [1] * count if mode == "cold" else [count]
    failures = []
    runner = runner or subprocess.run
    with output_path.open("x", encoding="utf-8", newline="\n") as output:
        server = TlsCaptureServer(
            host=host,
            port=port,
            certificate=certificate,
            private_key=private_key,
            output=output,
            mode=mode,
            timeout=timeout,
        )

        def serve():
            try:
                server.serve(count)
            except Exception as error:
                failures.append(error)
            finally:
                server.ready.set()

        thread = threading.Thread(
            target=serve, name="foxreq-native-capture", daemon=True
        )
        thread.start()
        if not server.ready.wait(timeout=min(timeout, 5.0)):
            raise FoxreqCaptureError("local TLS capture server did not start")
        if failures:
            raise FoxreqCaptureError("local TLS capture server failed to start") from failures[0]
        capture_error = None
        try:
            for process_count in process_counts:
                command = base_command + ["--count", str(process_count)]
                try:
                    completed = runner(
                        command,
                        cwd=str(repository),
                        env=environment,
                        timeout=timeout,
                    )
                except (OSError, subprocess.TimeoutExpired) as error:
                    raise FoxreqCaptureError(
                        "foxreq capture process failed"
                    ) from error
                if completed.returncode != 0:
                    raise FoxreqCaptureError(
                        "foxreq capture process returned {}".format(
                            completed.returncode
                        )
                    )
        except Exception as error:
            capture_error = error
            server.request_stop()
        thread.join(timeout=timeout + 1.0)
        if thread.is_alive():
            raise FoxreqCaptureError("local TLS capture server did not stop")
        if failures:
            raise FoxreqCaptureError("local TLS capture server failed") from failures[0]
        if capture_error is not None:
            raise capture_error
    return {
        "mode": mode,
        "profile": profile,
        "count": count,
        "process_count": len(process_counts),
        "available_memory_before_bytes": available_memory,
        "minimum_available_memory_bytes": minimum_available_memory,
    }


def main(argv=None):
    repository = Path(__file__).parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--runtime", type=Path, default=Path(".cache/firefox-runtime/core")
    )
    parser.add_argument("--ca-der", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--raw-output", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--mode", choices=("cold", "resumed"), required=True)
    parser.add_argument(
        "--profile",
        choices=("firefox_140_esr", "firefox_152"),
        default="firefox_152",
    )
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument(
        "--minimum-available-memory-mb", type=int, default=4096
    )
    parser.add_argument("--cargo", default=shutil.which("cargo") or "cargo")
    args = parser.parse_args(argv)
    try:
        manifest = capture_foxreq(
            repository=repository,
            runtime=args.runtime,
            ca_der=args.ca_der,
            certificate=args.certificate,
            private_key=args.private_key,
            raw_output=args.raw_output,
            host=args.host,
            port=args.port,
            mode=args.mode,
            count=args.count,
            timeout=args.timeout,
            cargo=args.cargo,
            profile=args.profile,
            minimum_available_memory=(
                args.minimum_available_memory_mb * 1024 * 1024
            ),
        )
    except FoxreqCaptureError as error:
        print(json.dumps({"error": str(error)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
