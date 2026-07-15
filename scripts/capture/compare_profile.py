"""Compare normalized foxreq TLS evidence with frozen Firefox goldens."""

import argparse
import json
from pathlib import Path
from typing import List, Mapping, Sequence

from tools.fingerprint.compare import compare_evidence
from tools.fingerprint.model import Difference


class ProfileComparisonError(Exception):
    pass


def compare_summaries(
    baseline: Mapping[str, object], candidate: Mapping[str, object]
) -> List[Difference]:
    """Compare stable evidence while excluding sample-specific secrets and counts."""

    differences: List[Difference] = []
    differences.extend(
        compare_evidence(
            baseline.get("schema_version"),
            candidate.get("schema_version"),
            "$.schema_version",
        )
    )
    differences.extend(
        compare_evidence(
            baseline.get("profile"), candidate.get("profile"), "$.profile"
        )
    )
    differences.extend(_compare_label_sets(baseline, candidate))
    differences.extend(_compare_extension_order(baseline, candidate))
    differences.extend(
        _compare_projection(
            baseline.get("stable_evidence"),
            candidate.get("stable_evidence"),
            "$.stable_evidence",
        )
    )
    differences.extend(_compare_distributions(baseline, candidate))
    differences.extend(_compare_fingerprints(baseline, candidate))
    return differences


def _compare_label_sets(baseline, candidate):
    expected = sorted(_mapping(baseline, "labels").keys(), key=str)
    actual = sorted(_mapping(candidate, "labels").keys(), key=str)
    if expected == actual:
        return []
    return [Difference("$.labels.types", expected, actual)]


def _compare_extension_order(baseline, candidate):
    expected = _mapping(baseline, "extension_order")
    actual = _mapping(candidate, "extension_order")
    profile = _mapping(baseline, "profile")
    _validate_extension_policy(expected, profile.get("extension_permutation"))
    differences = []
    for field in ("extension_count", "extension_types"):
        differences.extend(
            compare_evidence(
                expected.get(field),
                actual.get(field),
                "$.extension_order.{}".format(field),
            )
        )

    expected_count = expected.get("extension_count")
    expected_types = _sorted_values(expected.get("extension_types", []))
    fixed_positions = {}
    for item in _sequence(expected, "fixed_positions"):
        if not isinstance(item, Mapping) or set(item) != {"index", "type"}:
            raise ProfileComparisonError("invalid fixed extension position")
        index = item["index"]
        if isinstance(index, bool) or not isinstance(index, int) or index < 0:
            raise ProfileComparisonError("invalid fixed extension index")
        fixed_positions[index] = item["type"]
    movable_types = _sorted_values(expected.get("movable_types", []))

    for order_index, item in enumerate(_sequence(actual, "orders")):
        if not isinstance(item, Mapping) or not isinstance(item.get("types"), list):
            raise ProfileComparisonError("invalid candidate extension order")
        order = item["types"]
        path = "$.extension_order.orders[{}].types".format(order_index)
        if len(order) != expected_count:
            differences.append(Difference(path + ".length", expected_count, len(order)))
            continue
        if _sorted_values(order) != expected_types:
            differences.append(
                Difference(path + ".set", expected_types, _sorted_values(order))
            )
        actual_movable = _sorted_values(
            [value for index, value in enumerate(order) if index not in fixed_positions]
        )
        if actual_movable != movable_types:
            differences.append(
                Difference(path + ".movable", movable_types, actual_movable)
            )
        for index, value in sorted(fixed_positions.items()):
            if index >= len(order) or order[index] != value:
                actual_value = order[index] if index < len(order) else None
                differences.append(
                    Difference("{}[{}]".format(path, index), value, actual_value)
                )
    if not _sequence(actual, "orders"):
        differences.append(Difference("$.extension_order.orders", "non-empty", []))
    return differences


def _validate_extension_policy(order, permutation):
    extension_count = order.get("extension_count")
    extension_types = order.get("extension_types")
    movable_types = order.get("movable_types")
    if (
        isinstance(extension_count, bool)
        or not isinstance(extension_count, int)
        or extension_count < 0
        or not isinstance(extension_types, list)
        or len(extension_types) != extension_count
        or not _has_unique_hashable_values(extension_types)
        or not isinstance(movable_types, list)
        or not _has_unique_hashable_values(movable_types)
    ):
        raise ProfileComparisonError("invalid extension permutation policy")

    fixed_positions = {}
    fixed_types = []
    for item in _sequence(order, "fixed_positions"):
        if not isinstance(item, Mapping) or set(item) != {"index", "type"}:
            raise ProfileComparisonError("invalid fixed extension position")
        index = item["index"]
        if (
            isinstance(index, bool)
            or not isinstance(index, int)
            or index < 0
            or index >= extension_count
            or index in fixed_positions
        ):
            raise ProfileComparisonError("invalid fixed extension index")
        fixed_positions[index] = item["type"]
        fixed_types.append(item["type"])
    covered = fixed_types + movable_types
    if not _has_unique_hashable_values(covered) or _sorted_values(
        covered
    ) != _sorted_values(extension_types):
        raise ProfileComparisonError(
            "extension permutation policy must cover every extension exactly once"
        )
    if len(fixed_positions) + len(movable_types) != extension_count:
        raise ProfileComparisonError(
            "extension permutation policy must cover every extension position"
        )
    if permutation == "stable" and movable_types:
        raise ProfileComparisonError("stable extension policy cannot contain movable types")
    if permutation not in ("stable", "nss"):
        raise ProfileComparisonError("invalid extension permutation mode")


def _compare_projection(expected, actual, path):
    """Compare only baseline-proven keys; candidate-only keys are dynamic evidence."""

    if type(expected) is not type(actual):
        return [Difference(path, expected, actual)]
    if isinstance(expected, dict):
        differences = []
        for key in sorted(expected, key=str):
            child_path = "{}.{}".format(path, key)
            if key not in actual:
                differences.append(Difference(child_path, expected[key], None))
            else:
                differences.extend(
                    _compare_projection(expected[key], actual[key], child_path)
                )
        return differences
    if isinstance(expected, list):
        differences = []
        common = min(len(expected), len(actual))
        for index in range(common):
            differences.extend(
                _compare_projection(
                    expected[index], actual[index], "{}[{}]".format(path, index)
                )
            )
        for index in range(common, max(len(expected), len(actual))):
            left = expected[index] if index < len(expected) else None
            right = actual[index] if index < len(actual) else None
            differences.append(Difference("{}[{}]".format(path, index), left, right))
        return differences
    if expected == actual:
        return []
    return [Difference(path, expected, actual)]


def _compare_distributions(baseline, candidate):
    expected = _mapping(baseline, "length_distributions")
    actual = _mapping(candidate, "length_distributions")
    differences = []
    for field in (
        "record_bytes",
        "session_id_bytes",
        "cipher_suite_count",
        "extension_count",
    ):
        differences.extend(
            _compare_distribution(
                expected.get(field),
                actual.get(field),
                "$.length_distributions.{}".format(field),
            )
        )

    expected_extensions = _mapping(expected, "extension_payload_bytes")
    actual_extensions = _mapping(actual, "extension_payload_bytes")
    differences.extend(
        compare_evidence(
            sorted(expected_extensions, key=str),
            sorted(actual_extensions, key=str),
            "$.length_distributions.extension_payload_bytes.types",
        )
    )
    for extension_type in sorted(
        set(expected_extensions) & set(actual_extensions), key=str
    ):
        differences.extend(
            _compare_distribution(
                expected_extensions[extension_type],
                actual_extensions[extension_type],
                "$.length_distributions.extension_payload_bytes.{}".format(
                    extension_type
                ),
            )
        )
    return differences


def _compare_distribution(expected, actual, path):
    expected_values = _distribution_values(expected)
    actual_values = _distribution_values(actual)
    unexpected = [value for value in actual_values if value not in expected_values]
    if actual_values and not unexpected:
        return []
    return [Difference(path + ".values", expected_values, actual_values)]


def _compare_fingerprints(baseline, candidate):
    expected = _mapping(baseline, "fingerprints")
    actual = _mapping(candidate, "fingerprints")
    differences = []
    for name in ("ja3", "ja4"):
        expected_values = _fingerprint_values(expected.get(name))
        actual_values = _fingerprint_values(actual.get(name))
        unexpected = [value for value in actual_values if value not in expected_values]
        if not actual_values or unexpected:
            differences.append(
                Difference(
                    "$.fingerprints.{}".format(name),
                    expected_values,
                    actual_values,
                )
            )
    return differences


def _distribution_values(value):
    if not isinstance(value, list):
        return []
    values = []
    for item in value:
        if not isinstance(item, Mapping) or "value" not in item:
            raise ProfileComparisonError("invalid length distribution")
        values.append(item["value"])
    return _sorted_values(set(values))


def _fingerprint_values(value):
    if not isinstance(value, list):
        return []
    values = []
    for item in value:
        if not isinstance(item, Mapping) or "raw" not in item or "digest" not in item:
            raise ProfileComparisonError("invalid fingerprint distribution")
        values.append((item["raw"], item["digest"]))
    return sorted(set(values), key=lambda item: (str(item[0]), str(item[1])))


def _mapping(value, field):
    if not isinstance(value, Mapping):
        raise ProfileComparisonError("summary must be a mapping")
    result = value.get(field)
    if not isinstance(result, Mapping):
        raise ProfileComparisonError("{} must be a mapping".format(field))
    return result


def _sequence(value, field):
    if not isinstance(value, Mapping):
        raise ProfileComparisonError("summary section must be a mapping")
    result = value.get(field)
    if not isinstance(result, list):
        raise ProfileComparisonError("{} must be a list".format(field))
    return result


def _sorted_values(values: Sequence[object]):
    return sorted(values, key=lambda value: (type(value).__name__, str(value)))


def _has_unique_hashable_values(values):
    try:
        return len(set(values)) == len(values)
    except TypeError:
        return False


def _read_summary(path: Path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProfileComparisonError("cannot read {}: {}".format(path, error))
    if not isinstance(value, Mapping):
        raise ProfileComparisonError("{} must contain a JSON object".format(path))
    return value


def _validate_evidence_counts(baseline, candidate, mode, allow_partial):
    baseline_count = _summary_count(baseline, mode, "baseline")
    candidate_count = _summary_count(candidate, mode, "candidate")
    if allow_partial:
        return
    profile = _mapping(baseline, "profile")
    capture_count = profile.get("capture_count")
    if (
        isinstance(capture_count, bool)
        or not isinstance(capture_count, int)
        or capture_count < 1
    ):
        raise ProfileComparisonError("profile capture_count must be positive")
    if mode == "cold" and baseline_count != capture_count:
        raise ProfileComparisonError(
            "cold baseline requires {} samples, received {}".format(
                capture_count, baseline_count
            )
        )
    if mode == "resumed" and baseline_count < 2:
        raise ProfileComparisonError("resumed baseline requires at least 2 samples")
    if candidate_count != 5:
        raise ProfileComparisonError(
            "foxreq {} candidate requires 5 samples, received {}".format(
                mode, candidate_count
            )
        )


def _summary_count(summary, mode, label):
    if not isinstance(summary, Mapping):
        raise ProfileComparisonError("{} summary must be a mapping".format(label))
    count = summary.get("sample_count")
    labels = _mapping(summary, "labels")
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or count < 1
        or set(labels) != {mode}
        or labels.get(mode) != count
    ):
        raise ProfileComparisonError(
            "{} {} sample count and labels are inconsistent".format(label, mode)
        )
    return count


def _path(repository, explicit, default):
    path = explicit if explicit is not None else default
    if not path.is_absolute():
        path = repository / path
    return path.resolve()


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--platform", choices=("windows", "linux"), required=True)
    parser.add_argument("--mode", choices=("all", "cold", "resumed"), default="all")
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="label an explicitly partial smoke comparison instead of enforcing gate counts",
    )
    parser.add_argument("--repository", type=Path, default=Path(__file__).parents[2])
    for mode in ("cold", "resumed"):
        parser.add_argument("--baseline-{}".format(mode), type=Path)
        parser.add_argument("--candidate-{}".format(mode), type=Path)
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    repository = args.repository.resolve()
    modes = ("cold", "resumed") if args.mode == "all" else (args.mode,)
    comparisons = []
    try:
        for mode in modes:
            baseline = _path(
                repository,
                getattr(args, "baseline_{}".format(mode)),
                Path("profiles")
                / args.profile
                / "golden"
                / "{}-{}.json".format(args.platform, mode),
            )
            candidate = _path(
                repository,
                getattr(args, "candidate_{}".format(mode)),
                Path("artifacts")
                / "captures"
                / "foxreq-{}-{}-{}-summary.json".format(
                    args.profile, args.platform, mode
                ),
            )
            baseline_summary = _read_summary(baseline)
            candidate_summary = _read_summary(candidate)
            _validate_evidence_counts(
                baseline_summary,
                candidate_summary,
                mode,
                args.allow_partial,
            )
            differences = compare_summaries(baseline_summary, candidate_summary)
            comparisons.append(
                {
                    "mode": mode,
                    "baseline": str(baseline),
                    "candidate": str(candidate),
                    "differences": [
                        {
                            "path": item.path,
                            "expected": item.expected,
                            "actual": item.actual,
                        }
                        for item in differences
                    ],
                }
            )
    except ProfileComparisonError as error:
        print(
            json.dumps(
                {
                    "ok": False,
                    "profile": args.profile,
                    "platform": args.platform,
                    "evidence_level": "partial" if args.allow_partial else "formal",
                    "error": {"category": "input", "message": str(error)},
                },
                sort_keys=True,
            )
        )
        return 2

    ok = all(not item["differences"] for item in comparisons)
    print(
        json.dumps(
            {
                "ok": ok,
                "profile": args.profile,
                "platform": args.platform,
                "evidence_level": "partial" if args.allow_partial else "formal",
                "comparisons": comparisons,
            },
            sort_keys=True,
        )
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
