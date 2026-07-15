"""Run real Firefox-NSS loopback TLS tests serially with ephemeral certificates."""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

from tests.fixtures.generate_certs import generate_fixture


class RealTlsTestError(Exception):
    pass


CASES = (
    ("exchanges_http_11_over_the_local_tls_fixture", "valid", False, 0.0),
    ("verifies_an_explicit_ephemeral_local_ca", "valid", True, 0.0),
    ("rejects_an_untrusted_local_ca", "valid", False, 0.0),
    ("rejects_an_expired_certificate_from_a_trusted_ca", "expired", True, 0.0),
    (
        "rejects_a_hostname_mismatch_from_a_trusted_ca",
        "hostname-mismatch",
        True,
        0.0,
    ),
    ("times_out_a_stalled_tls_handshake", "valid", False, 1.0),
    ("times_out_a_stalled_tls_read", "valid", False, 0.0),
)

RUNTIME_CASES = (
    "isolates_active_runtime_trust_anchors",
    "rejects_an_invalid_der_trust_anchor",
)


def _free_loopback_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _fixture(repository, variant):
    output = repository / "artifacts" / "fixtures" / "certs" / (
        "orchestrated-" + variant
    )
    required = ("ca.der", "ca.pem", "server.pem", "server.key")
    if not output.exists():
        generate_fixture(output, repository=repository, variant=variant)
    if not all((output / name).is_file() for name in required):
        raise RealTlsTestError("incomplete certificate fixture: " + variant)
    return output


def _run_case(repository, runtime, cargo, name, variant, use_ca, stall_before_tls):
    fixture = _fixture(repository, variant)
    port = _free_loopback_port()
    server_command = [
        sys.executable,
        "-m",
        "tests.fixtures.tls_server",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--certificate",
        str(fixture / "server.pem"),
        "--private-key",
        str(fixture / "server.key"),
        "--count",
        "1",
        "--timeout",
        "8",
    ]
    if stall_before_tls:
        server_command.extend(["--stall-before-tls", str(stall_before_tls)])
    server = subprocess.Popen(
        server_command,
        cwd=str(repository),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    try:
        time.sleep(0.4)
        if server.poll() is not None:
            stdout, stderr = server.communicate()
            raise RealTlsTestError(
                "TLS fixture failed before {}: {}{}".format(name, stdout, stderr)
            )
        environment = os.environ.copy()
        environment["FOXREQ_NSS_RUNTIME_DIR"] = str(runtime)
        environment["FOXREQ_NSS_TEST_PORT"] = str(port)
        if use_ca:
            environment["FOXREQ_NSS_TEST_CA_DER"] = str(fixture / "ca.der")
        else:
            environment.pop("FOXREQ_NSS_TEST_CA_DER", None)
        command = [
            cargo,
            "test",
            "-p",
            "foxreq-core",
            "--features",
            "nss-real",
            "--test",
            "nss_real_local_tls",
            name,
            "--",
            "--exact",
            "--ignored",
            "--nocapture",
        ]
        completed = subprocess.run(command, cwd=str(repository), env=environment)
        if completed.returncode != 0:
            raise RealTlsTestError("real TLS test failed: " + name)
        try:
            stdout, stderr = server.communicate(timeout=10)
        except subprocess.TimeoutExpired as exc:
            raise RealTlsTestError("TLS fixture did not exit after " + name) from exc
        if server.returncode != 0:
            raise RealTlsTestError(
                "TLS fixture failed during {}: {}{}".format(name, stdout, stderr)
            )
    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


def _run_runtime_case(repository, runtime, cargo, name, first_ca, second_ca):
    environment = os.environ.copy()
    environment["FOXREQ_NSS_RUNTIME_DIR"] = str(runtime)
    environment["FOXREQ_NSS_TEST_CA_DER"] = str(first_ca)
    environment["FOXREQ_NSS_TEST_OTHER_CA_DER"] = str(second_ca)
    command = [
        cargo,
        "test",
        "-p",
        "foxreq-core",
        "--features",
        "nss-real",
        "--test",
        "nss_real_local_tls",
        name,
        "--",
        "--exact",
        "--ignored",
        "--nocapture",
    ]
    completed = subprocess.run(command, cwd=str(repository), env=environment)
    if completed.returncode != 0:
        raise RealTlsTestError("real NSS runtime test failed: " + name)


def run_suite(repository, runtime, cargo):
    repository = Path(repository).resolve()
    runtime = Path(runtime).resolve()
    if not runtime.is_dir():
        raise RealTlsTestError("pinned Firefox runtime directory is missing")
    first = _fixture(repository, "valid") / "ca.der"
    second = _fixture(repository, "hostname-mismatch") / "ca.der"
    for name in RUNTIME_CASES:
        _run_runtime_case(repository, runtime, cargo, name, first, second)
    for name, variant, use_ca, stall_before_tls in CASES:
        _run_case(
            repository, runtime, cargo, name, variant, use_ca, stall_before_tls
        )
    return list(RUNTIME_CASES) + [
        name for name, _variant, _use_ca, _stall_before_tls in CASES
    ]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--runtime", type=Path, default=Path(".cache/firefox-runtime/core")
    )
    parser.add_argument("--cargo", default=shutil.which("cargo") or "cargo")
    args = parser.parse_args(argv)
    repository = Path(__file__).resolve().parents[2]
    try:
        tests = run_suite(repository, args.runtime, args.cargo)
    except RealTlsTestError as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps({"passed": tests}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
