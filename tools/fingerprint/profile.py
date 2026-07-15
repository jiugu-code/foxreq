"""Immutable fingerprint profile manifests and local alias resolution."""

from dataclasses import dataclass
from typing import Iterable, Mapping, Tuple

from .errors import ProfileError


_FIELDS = {
    "schema_version",
    "name",
    "firefox_version",
    "aliases",
    "nss_revision",
    "nspr_revision",
    "capture_count",
    "extension_permutation",
}


def _required_text(data: Mapping[str, object], field: str) -> str:
    value = data[field]
    if not isinstance(value, str) or not value:
        raise ProfileError("{} must be a non-empty string".format(field))
    return value


@dataclass(frozen=True)
class ProfileManifest:
    """Build-time identity and evidence policy for one browser profile."""

    schema_version: int
    name: str
    firefox_version: str
    aliases: Tuple[str, ...]
    nss_revision: str
    nspr_revision: str
    capture_count: int
    extension_permutation: str

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "ProfileManifest":
        if not isinstance(data, Mapping):
            raise ProfileError("profile manifest must be a mapping")

        unknown = set(data) - _FIELDS
        missing = _FIELDS - set(data)
        if unknown:
            raise ProfileError("unexpected fields: " + ", ".join(sorted(unknown)))
        if missing:
            raise ProfileError("missing fields: " + ", ".join(sorted(missing)))
        if data["schema_version"] != 1:
            raise ProfileError("schema_version must be 1")

        aliases_value = data["aliases"]
        if not isinstance(aliases_value, (list, tuple)) or not all(
            isinstance(alias, str) and alias for alias in aliases_value
        ):
            raise ProfileError("aliases must be a list of non-empty strings")
        aliases = tuple(aliases_value)
        if len(set(aliases)) != len(aliases):
            raise ProfileError("aliases must not contain duplicates")

        capture_count = data["capture_count"]
        if (
            isinstance(capture_count, bool)
            or not isinstance(capture_count, int)
            or capture_count < 1
        ):
            raise ProfileError("capture_count must be a positive integer")

        extension_permutation = data["extension_permutation"]
        if extension_permutation not in ("stable", "nss"):
            raise ProfileError("extension_permutation must be stable or nss")

        name = _required_text(data, "name")
        if name in aliases:
            raise ProfileError("profile name must not also be an alias")

        return cls(
            schema_version=1,
            name=name,
            firefox_version=_required_text(data, "firefox_version"),
            aliases=aliases,
            nss_revision=_required_text(data, "nss_revision"),
            nspr_revision=_required_text(data, "nspr_revision"),
            capture_count=capture_count,
            extension_permutation=extension_permutation,
        )


def resolve_profile(
    name: str, manifests: Iterable[ProfileManifest]
) -> ProfileManifest:
    """Resolve an explicit profile name or immutable local alias."""

    index = {}
    for manifest in manifests:
        for candidate in (manifest.name,) + manifest.aliases:
            if candidate in index:
                raise ProfileError("duplicate alias or profile name: " + candidate)
            index[candidate] = manifest

    try:
        return index[name]
    except KeyError:
        raise ProfileError("unknown profile: " + name)
