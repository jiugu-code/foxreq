"""Convert ignored raw ClientHello JSONL into tracked, redacted evidence."""

import argparse
import copy
import hashlib
import json
import os
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from tools.fingerprint.compare import PermutationPolicy
from tools.fingerprint.errors import ParseError, ProfileError
from tools.fingerprint.fingerprints import ja3, ja4
from tools.fingerprint.normalize import normalize_client_hello
from tools.fingerprint.profile import ProfileManifest
from tools.fingerprint.tls import parse_client_hello_records


_CAPTURE_FIELDS = {
    "schema_version",
    "connection_id",
    "label",
    "length",
    "sha256",
    "record_hex",
}
_CAPTURE_ID = re.compile(r"^capture-[0-9]{6}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MISSING = object()


class SummaryError(Exception):
    pass


def summarize_records(
    records: Sequence[Mapping[str, object]],
    profile_data: Mapping[str, object],
) -> Dict[str, object]:
    """Validate raw records and return a secret-free deterministic summary."""

    try:
        manifest = ProfileManifest.from_dict(profile_data)
    except ProfileError as error:
        raise SummaryError("invalid profile: {}".format(error))
    if len(records) != manifest.capture_count:
        raise SummaryError(
            "capture_count requires {}, received {}".format(
                manifest.capture_count,
                len(records),
            )
        )
    if not records:
        raise SummaryError("capture set must not be empty")

    identifiers = set()
    labels = Counter()
    raw_hashes = []
    normalized_hashes = []
    normalized_samples = []
    canonical_samples = []
    raw_lengths = []
    session_lengths = []
    cipher_counts = []
    extension_counts = []
    extension_lengths = defaultdict(list)
    ja3_values = []
    ja4_values = []

    for index, record in enumerate(records):
        wire, connection_id, label, raw_hash = _decode_record(record, index)
        if connection_id in identifiers:
            raise SummaryError("duplicate connection_id: {}".format(connection_id))
        identifiers.add(connection_id)
        labels[label] += 1
        raw_hashes.append(raw_hash)

        try:
            hello = parse_client_hello_records(wire)
            normalized = normalize_client_hello(hello)
            ja3_value = ja3(hello)
            ja4_value = ja4(hello)
        except ParseError as error:
            raise SummaryError("invalid ClientHello at sample {}: {}".format(index, error))

        redacted = _redact_evidence(normalized)
        canonical = _canonicalize_extensions(redacted)
        normalized_samples.append(redacted)
        canonical_samples.append(canonical)
        normalized_hashes.append(_json_sha256(redacted))
        raw_lengths.append(len(wire))
        session_lengths.append(len(hello.session_id))
        cipher_counts.append(len(hello.cipher_suites))
        extension_counts.append(len(hello.extensions))
        for item in redacted["extensions"]:
            extension_lengths[_identifier_key(item["type"])].append(item["length"])
        ja3_values.append((ja3_value.raw, ja3_value.digest))
        ja4_values.append((ja4_value.raw, ja4_value.digest))

    extension_order = _extension_order_summary(normalized_samples)
    stable = _stable_projection(canonical_samples)
    if stable is _MISSING:
        stable = {}

    return {
        "schema_version": 1,
        "profile": {
            "name": manifest.name,
            "firefox_version": manifest.firefox_version,
            "nss_revision": manifest.nss_revision,
            "nspr_revision": manifest.nspr_revision,
            "capture_count": manifest.capture_count,
            "extension_permutation": manifest.extension_permutation,
        },
        "sample_count": len(records),
        "labels": dict(sorted(labels.items())),
        "raw_capture_sha256": sorted(raw_hashes),
        "normalized_sha256": sorted(normalized_hashes),
        "extension_order": extension_order,
        "stable_evidence": stable,
        "length_distributions": {
            "record_bytes": _distribution(raw_lengths),
            "session_id_bytes": _distribution(session_lengths),
            "cipher_suite_count": _distribution(cipher_counts),
            "extension_count": _distribution(extension_counts),
            "extension_payload_bytes": {
                key: _distribution(values)
                for key, values in sorted(extension_lengths.items())
            },
        },
        "fingerprints": {
            "ja3": _fingerprint_distribution(ja3_values),
            "ja4": _fingerprint_distribution(ja4_values),
        },
    }


def load_jsonl(path: Path) -> List[Mapping[str, object]]:
    records = []
    with path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise SummaryError("invalid JSONL at line {}".format(line_number)) from error
            if not isinstance(value, Mapping):
                raise SummaryError("JSONL line {} must be an object".format(line_number))
            records.append(value)
    return records


def _decode_record(
    record: Mapping[str, object], index: int
) -> Tuple[bytes, str, str, str]:
    if not isinstance(record, Mapping) or set(record) != _CAPTURE_FIELDS:
        raise SummaryError("sample {} has invalid capture fields".format(index))
    if record["schema_version"] != 1:
        raise SummaryError("sample {} has invalid schema_version".format(index))
    connection_id = record["connection_id"]
    label = record["label"]
    expected_length = record["length"]
    expected_hash = record["sha256"]
    raw_hex = record["record_hex"]
    if not isinstance(connection_id, str) or not _CAPTURE_ID.fullmatch(connection_id):
        raise SummaryError("sample {} has invalid connection_id".format(index))
    if not isinstance(label, str) or label not in ("cold", "resumed", "synthetic"):
        raise SummaryError("sample {} has invalid label".format(index))
    if (
        isinstance(expected_length, bool)
        or not isinstance(expected_length, int)
        or expected_length < 1
    ):
        raise SummaryError("sample {} has invalid length".format(index))
    if not isinstance(expected_hash, str) or not _SHA256.fullmatch(expected_hash):
        raise SummaryError("sample {} has invalid sha256".format(index))
    if not isinstance(raw_hex, str):
        raise SummaryError("sample {} has invalid record_hex".format(index))
    try:
        wire = bytes.fromhex(raw_hex)
    except ValueError as error:
        raise SummaryError("sample {} has invalid record_hex".format(index)) from error
    if len(wire) != expected_length:
        raise SummaryError("sample {} length mismatch".format(index))
    actual_hash = hashlib.sha256(wire).hexdigest()
    if actual_hash != expected_hash:
        raise SummaryError("sample {} sha256 mismatch".format(index))
    return wire, connection_id, label, actual_hash


def _redact_evidence(evidence: Mapping[str, object]) -> Dict[str, object]:
    redacted = copy.deepcopy(evidence)
    for item in redacted["extensions"]:
        raw_hex = item.pop("data_hex", None)
        if raw_hex is not None:
            item["data_sha256"] = hashlib.sha256(bytes.fromhex(raw_hex)).hexdigest()
    return redacted


def _canonicalize_extensions(evidence: Mapping[str, object]) -> Dict[str, object]:
    canonical = {key: copy.deepcopy(value) for key, value in evidence.items() if key != "extensions"}
    by_type = {}
    occurrences = Counter()
    for item in evidence["extensions"]:
        key = _identifier_key(item["type"])
        occurrences[key] += 1
        if occurrences[key] > 1:
            key = "{}#{}".format(key, occurrences[key])
        value = copy.deepcopy(item)
        value.pop("type", None)
        by_type[key] = value
    canonical["extensions_by_type"] = dict(sorted(by_type.items()))
    return canonical


def _stable_projection(values: Sequence[object]):
    first = values[0]
    if any(type(value) is not type(first) for value in values[1:]):
        return _MISSING
    if isinstance(first, dict):
        common = set(first)
        for value in values[1:]:
            common &= set(value)
        result = {}
        for key in sorted(common, key=str):
            projected = _stable_projection([value[key] for value in values])
            if projected is not _MISSING:
                result[key] = projected
        return result if result else _MISSING
    if isinstance(first, list):
        if any(len(value) != len(first) for value in values[1:]):
            return _MISSING
        projected = [
            _stable_projection([value[index] for value in values])
            for index in range(len(first))
        ]
        if all(value is not _MISSING for value in projected):
            return projected
        stable_items = {
            str(index): value
            for index, value in enumerate(projected)
            if value is not _MISSING
        }
        if stable_items:
            return {"length": len(first), "stable_items": stable_items}
        return _MISSING
    if all(value == first for value in values[1:]):
        return copy.deepcopy(first)
    return _MISSING


def _extension_order_summary(samples: Sequence[Mapping[str, object]]) -> Dict[str, object]:
    orders = [tuple(item["type"] for item in sample["extensions"]) for sample in samples]
    if len(samples) == 1:
        fixed = {index: value for index, value in enumerate(orders[0])}
        movable = ()
        extension_count = len(orders[0])
    else:
        try:
            policy = PermutationPolicy.from_samples(samples)
        except ProfileError as error:
            raise SummaryError("invalid extension permutation set: {}".format(error))
        fixed = policy.fixed_positions
        movable = policy.movable_types
        extension_count = policy.extension_count
    order_counts = Counter(orders)
    return {
        "extension_count": extension_count,
        "extension_types": sorted(orders[0], key=_identifier_sort_key),
        "fixed_positions": [
            {"index": index, "type": value}
            for index, value in sorted(fixed.items())
        ],
        "movable_types": list(movable),
        "orders": [
            {"types": list(order), "count": count}
            for order, count in sorted(
                order_counts.items(),
                key=lambda item: json.dumps(item[0], separators=(",", ":")),
            )
        ],
    }


def _distribution(values: Iterable[int]) -> List[Dict[str, int]]:
    return [
        {"value": value, "count": count}
        for value, count in sorted(Counter(values).items())
    ]


def _fingerprint_distribution(values: Iterable[Tuple[str, str]]) -> List[Dict[str, object]]:
    return [
        {"raw": raw, "digest": digest, "count": count}
        for (raw, digest), count in sorted(Counter(values).items())
    ]


def _json_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _identifier_key(value: object) -> str:
    return str(value)


def _identifier_sort_key(value: object) -> Tuple[str, str]:
    return type(value).__name__, str(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    validate_raw_input_path(args.input)
    profile_data = json.loads(args.profile.read_text(encoding="utf-8"))
    summary = summarize_records(load_jsonl(args.input), profile_data)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


def validate_raw_input_path(
    path: Path, repository: Optional[Path] = None
) -> Path:
    repository = (repository or Path(__file__).parents[2]).resolve()
    root = (repository / "artifacts" / "captures").resolve()
    resolved = path.resolve()
    try:
        common = Path(os.path.commonpath((str(root), str(resolved))))
    except ValueError:
        raise SummaryError("raw capture input must be under artifacts/captures")
    if common != root:
        raise SummaryError("raw capture input must be under artifacts/captures")
    return resolved


if __name__ == "__main__":
    raise SystemExit(main())
