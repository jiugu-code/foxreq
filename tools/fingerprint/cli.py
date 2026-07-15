"""Machine-readable command-line interface for fingerprint evidence."""

import argparse
import json
import sys
from dataclasses import asdict
from typing import List, Optional

from .compare import PermutationPolicy, compare_evidence
from .errors import FingerprintError, ParseError
from .fingerprints import ja3, ja4
from .h2 import decode_settings, decode_window_update, parse_client_prefix
from .normalize import normalize_client_hello
from .tls import parse_client_hello_records


def _read(path: str, is_hex: bool) -> bytes:
    if is_hex:
        with open(path, "r", encoding="ascii") as handle:
            return bytes.fromhex(handle.read())
    with open(path, "rb") as handle:
        return handle.read()


def _tls_evidence(path: str, is_hex: bool):
    hello = parse_client_hello_records(_read(path, is_hex))
    return {
        "client_hello": normalize_client_hello(hello),
        "ja3": asdict(ja3(hello)),
        "ja4": asdict(ja4(hello)),
    }


def _handle_tls_inspect(arguments):
    return _tls_evidence(arguments.source, arguments.hex), 0


def _handle_tls_compare(arguments):
    left = _tls_evidence(arguments.left, arguments.hex)["client_hello"]
    right = _tls_evidence(arguments.right, arguments.hex)["client_hello"]
    differences = [
        asdict(value) for value in compare_evidence(left, right)
    ]
    return {
        "differences": differences,
        "match": not differences,
    }, 1 if differences else 0


def _handle_tls_policy(arguments):
    samples = [
        _tls_evidence(source, arguments.hex)["client_hello"]
        for source in arguments.sources
    ]
    policy = PermutationPolicy.from_samples(samples)
    return {
        "extension_count": policy.extension_count,
        "fixed_positions": {
            str(index): value
            for index, value in policy.fixed_positions.items()
        },
        "movable_types": list(policy.movable_types),
    }, 0


def _handle_h2_inspect(arguments):
    frames = []
    for frame in parse_client_prefix(_read(arguments.source, arguments.hex)):
        value = asdict(frame)
        value["payload"] = frame.payload.hex()
        if frame.type_id == 4:
            value["settings"] = [
                asdict(setting) for setting in decode_settings(frame)
            ]
        elif frame.type_id == 8:
            value["window_increment"] = decode_window_update(frame)
        frames.append(value)
    return {"frames": frames}, 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m tools.fingerprint")
    protocols = parser.add_subparsers(dest="protocol", required=True)

    tls = protocols.add_parser("tls", help="inspect TLS ClientHello evidence")
    tls_commands = tls.add_subparsers(dest="tls_command", required=True)

    inspect = tls_commands.add_parser("inspect", help="inspect one ClientHello")
    inspect.add_argument("source")
    inspect.add_argument("--hex", action="store_true", help="read hexadecimal text")
    inspect.set_defaults(handler=_handle_tls_inspect)

    compare = tls_commands.add_parser("compare", help="compare two ClientHellos")
    compare.add_argument("left")
    compare.add_argument("right")
    compare.add_argument("--hex", action="store_true", help="read hexadecimal text")
    compare.set_defaults(handler=_handle_tls_compare)

    policy = tls_commands.add_parser(
        "policy",
        help="infer extension permutation constraints",
    )
    policy.add_argument("sources", nargs="+")
    policy.add_argument("--hex", action="store_true", help="read hexadecimal text")
    policy.set_defaults(handler=_handle_tls_policy)

    h2 = protocols.add_parser("h2", help="inspect HTTP/2 client evidence")
    h2_commands = h2.add_subparsers(dest="h2_command", required=True)
    h2_inspect = h2_commands.add_parser(
        "inspect",
        help="inspect one HTTP/2 client prefix",
    )
    h2_inspect.add_argument("source")
    h2_inspect.add_argument("--hex", action="store_true", help="read hexadecimal text")
    h2_inspect.set_defaults(handler=_handle_h2_inspect)
    return parser


def _error_payload(error: Exception):
    payload = {"error": str(error)}
    if isinstance(error, ParseError):
        payload.update({"offset": error.offset, "path": error.path})
    return payload


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        output, return_code = arguments.handler(arguments)
    except (FingerprintError, OSError, UnicodeError, ValueError) as error:
        print(
            json.dumps(_error_payload(error), sort_keys=True),
            file=sys.stderr,
        )
        return 2

    print(json.dumps(output, sort_keys=True, indent=2))
    return return_code
