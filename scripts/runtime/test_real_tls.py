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

HTTP1_CASES = (
    (
        "gets_a_fixed_response_with_duplicate_headers",
        "fixed",
        1,
        ("GET",),
        ("/fixed?x=1",),
        (b"",),
    ),
    (
        "sends_a_head_request_without_accepting_response_body_bytes",
        "fixed",
        1,
        ("HEAD",),
        ("/head",),
        (b"",),
    ),
    (
        "sends_a_post_and_accepts_an_informational_response",
        "informational",
        1,
        ("POST",),
        ("/submit",),
        (b"payload",),
    ),
    ("decodes_a_chunked_response", "chunked", 1, ("GET",), ("/chunked",), (b"",)),
    (
        "completes_a_close_delimited_response",
        "close",
        1,
        ("GET",),
        ("/close",),
        (b"",),
    ),
    (
        "reuses_one_keepalive_connection",
        "keepalive-two",
        2,
        ("GET", "GET"),
        ("/one", "/two"),
        (b"", b""),
    ),
    (
        "reconnects_after_an_explicit_server_close",
        "server-close",
        2,
        ("GET", "GET"),
        ("/one", "/two"),
        (b"", b""),
    ),
    (
        "rejects_an_early_response_eof",
        "early-close",
        1,
        ("GET",),
        ("/early",),
        (b"",),
    ),
    (
        "rejects_ambiguous_response_framing",
        "malformed-length",
        1,
        ("GET",),
        ("/malformed",),
        (b"",),
    ),
    (
        "times_out_a_stalled_response_read",
        "stall-read",
        1,
        ("GET",),
        ("/stall",),
        (b"",),
    ),
)

PYTHON_API_CASES = (
    "test_chunked_response_and_timeout_mapping",
    "test_json_post_crosses_the_native_worker",
    "test_session_reuses_one_tls_connection",
    "test_top_level_get_returns_the_public_response_model",
    "test_untrusted_certificate_maps_to_certificate_error",
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


def _run_http1_case(
    repository, runtime, cargo, fixture, name, scenario, count, methods, targets, bodies
):
    port = _free_loopback_port()
    server_command = [
        sys.executable,
        "-m",
        "tests.fixtures.http1_scenarios",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--certificate",
        str(fixture / "server.pem"),
        "--private-key",
        str(fixture / "server.key"),
        "--scenario",
        scenario,
        "--count",
        str(count),
        "--timeout",
        "8",
        "--stall-seconds",
        "1",
    ]
    for method in methods:
        server_command.extend(["--expect-method", method])
    for target in targets:
        server_command.extend(["--expect-target", target])
    for body in bodies:
        server_command.extend(["--expect-body-hex", body.hex()])
    server_command.extend(["--expect-header", "X-Order:first"])
    server_command.extend(["--expect-header", "X-Order:second"])
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
                "HTTP/1 fixture failed before {}: {}{}".format(name, stdout, stderr)
            )
        environment = os.environ.copy()
        environment["FOXREQ_NSS_RUNTIME_DIR"] = str(runtime)
        environment["FOXREQ_HTTP1_TEST_PORT"] = str(port)
        environment["FOXREQ_HTTP1_TEST_CA_DER"] = str(fixture / "ca.der")
        command = [
            cargo,
            "test",
            "-p",
            "foxreq-core",
            "--features",
            "nss-real",
            "--test",
            "https_http1",
            name,
            "--",
            "--exact",
            "--ignored",
            "--nocapture",
        ]
        completed = subprocess.run(command, cwd=str(repository), env=environment)
        if completed.returncode != 0:
            raise RealTlsTestError("real HTTP/1 test failed: " + name)
        try:
            stdout, stderr = server.communicate(timeout=10)
        except subprocess.TimeoutExpired as exc:
            raise RealTlsTestError("HTTP/1 fixture did not exit after " + name) from exc
        if server.returncode != 0:
            raise RealTlsTestError(
                "HTTP/1 fixture failed during {}: {}{}".format(name, stdout, stderr)
            )
    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


def _run_python_api_suite(repository, runtime, python_api):
    python_api = Path(python_api).resolve()
    runtime = Path(runtime).resolve()
    if not python_api.is_file():
        raise RealTlsTestError("Python API interpreter is missing")
    environment = os.environ.copy()
    environment["PYTHONUTF8"] = "1"
    environment["FOXREQ_NSS_RUNTIME_DIR"] = str(runtime)
    environment["FOXREQ_PY_TEST_FIXTURE"] = str(_fixture(repository, "valid"))
    command = [
        str(python_api),
        "-W",
        "error::ResourceWarning",
        "-m",
        "unittest",
        "tests.python.test_real_api",
        "-v",
    ]
    completed = subprocess.run(command, cwd=str(repository), env=environment)
    if completed.returncode != 0:
        raise RealTlsTestError("real Python API tests failed")
    return list(PYTHON_API_CASES)


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
    fixture = _fixture(repository, "valid")
    for name, scenario, count, methods, targets, bodies in HTTP1_CASES:
        _run_http1_case(
            repository,
            runtime,
            cargo,
            fixture,
            name,
            scenario,
            count,
            methods,
            targets,
            bodies,
        )
    return (
        list(RUNTIME_CASES)
        + [name for name, _variant, _use_ca, _stall_before_tls in CASES]
        + [name for name, _scenario, _count, _methods, _targets, _bodies in HTTP1_CASES]
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--runtime", type=Path, default=Path(".cache/firefox-runtime/core")
    )
    parser.add_argument("--cargo", default=shutil.which("cargo") or "cargo")
    parser.add_argument("--python-api", type=Path)
    args = parser.parse_args(argv)
    repository = Path(__file__).resolve().parents[2]
    try:
        tests = run_suite(repository, args.runtime, args.cargo)
        if args.python_api is not None:
            tests.extend(
                _run_python_api_suite(repository, args.runtime, args.python_api)
            )
    except RealTlsTestError as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps({"passed": tests}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
