"""Deterministic evidence comparison and extension-permutation policies."""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Dict, List, Mapping, Sequence, Tuple

from .errors import ProfileError
from .model import Difference


def compare_evidence(expected, actual, path: str = "$") -> List[Difference]:
    """Recursively compare JSON-compatible evidence without coercing types."""

    if type(expected) is not type(actual):
        return [Difference(path, expected, actual)]

    if isinstance(expected, dict):
        differences: List[Difference] = []
        for key in sorted(set(expected) | set(actual), key=str):
            child_path = "{}.{}".format(path, key)
            if key not in expected:
                differences.append(Difference(child_path, None, actual[key]))
            elif key not in actual:
                differences.append(Difference(child_path, expected[key], None))
            else:
                differences.extend(
                    compare_evidence(expected[key], actual[key], child_path)
                )
        return differences

    if isinstance(expected, list):
        differences = []
        common = min(len(expected), len(actual))
        for index in range(common):
            differences.extend(
                compare_evidence(
                    expected[index],
                    actual[index],
                    "{}[{}]".format(path, index),
                )
            )
        for index in range(common, max(len(expected), len(actual))):
            left = expected[index] if index < len(expected) else None
            right = actual[index] if index < len(actual) else None
            differences.append(
                Difference("{}[{}]".format(path, index), left, right)
            )
        return differences

    if expected == actual:
        return []
    return [Difference(path, expected, actual)]


def _sort_types(values: Sequence[object]) -> List[object]:
    return sorted(values, key=lambda value: (type(value).__name__, str(value)))


def _extension_order(sample: Mapping[str, object]) -> Tuple[object, ...]:
    try:
        extensions = sample["extensions"]
        return tuple(item["type"] for item in extensions)
    except (KeyError, TypeError):
        raise ProfileError("sample must contain an extensions list with types")


@dataclass(frozen=True)
class PermutationPolicy:
    """Fixed positions and the complete set of evidence-proven movable types."""

    fixed_positions: Mapping[int, object]
    movable_types: Tuple[object, ...]
    extension_count: int

    @classmethod
    def from_samples(
        cls,
        samples: Sequence[Mapping[str, object]],
    ) -> "PermutationPolicy":
        if len(samples) < 2:
            raise ProfileError("permutation policy requires at least two samples")

        orders = [_extension_order(sample) for sample in samples]
        if any(len(order) != len(set(order)) for order in orders):
            raise ProfileError("duplicate extension type in sample")

        expected_types = _sort_types(orders[0])
        if any(_sort_types(order) != expected_types for order in orders[1:]):
            raise ProfileError("extension multisets differ")

        fixed: Dict[int, object] = {
            index: orders[0][index]
            for index in range(len(orders[0]))
            if all(order[index] == orders[0][index] for order in orders[1:])
        }
        movable = tuple(
            value for value in expected_types if value not in fixed.values()
        )
        return cls(
            fixed_positions=MappingProxyType(fixed),
            movable_types=movable,
            extension_count=len(orders[0]),
        )

    def compare(self, candidate: Mapping[str, object]) -> List[Difference]:
        order = _extension_order(candidate)
        if len(order) != self.extension_count:
            return [
                Difference(
                    "$.extensions.length",
                    self.extension_count,
                    len(order),
                )
            ]

        expected_types = _sort_types(
            list(self.fixed_positions.values()) + list(self.movable_types)
        )
        actual_types = _sort_types(order)
        differences: List[Difference] = []
        if actual_types != expected_types:
            differences.append(
                Difference(
                    "$.extensions.types",
                    tuple(expected_types),
                    tuple(actual_types),
                )
            )

        actual_movable = _sort_types(
            [
                value
                for index, value in enumerate(order)
                if index not in self.fixed_positions
            ]
        )
        if tuple(actual_movable) != self.movable_types:
            differences.append(
                Difference(
                    "$.extensions.movable",
                    self.movable_types,
                    tuple(actual_movable),
                )
            )

        for index, expected in self.fixed_positions.items():
            if order[index] != expected:
                differences.append(
                    Difference(
                        "$.extensions[{}].type".format(index),
                        expected,
                        order[index],
                    )
                )
        return differences
