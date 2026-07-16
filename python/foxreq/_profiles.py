"""Exact Firefox profile identities and platform User-Agent defaults."""

import sys
from dataclasses import dataclass

from ._exceptions import InvalidRequestError


@dataclass(frozen=True, slots=True)
class ProfileSpec:
    profile_id: str
    firefox_version: str
    major_version: int
    user_agent: str


_VERSIONS = {
    "firefox_140_esr": ("140.12.0esr", 140),
    "firefox_152": ("152.0.6", 152),
}


def get_profile(profile_id, platform=None):
    try:
        firefox_version, major = _VERSIONS[profile_id]
    except (KeyError, TypeError) as error:
        raise InvalidRequestError("unsupported Firefox profile") from error

    selected = sys.platform if platform is None else platform
    if selected == "win32":
        token = "Windows NT 10.0; Win64; x64"
    elif selected.startswith("linux"):
        token = "X11; Linux x86_64"
    else:
        raise InvalidRequestError("unsupported profile platform")

    user_agent = (
        "Mozilla/5.0 ({}; rv:{}.0) Gecko/20100101 Firefox/{}.0".format(
            token,
            major,
            major,
        )
    )
    return ProfileSpec(profile_id, firefox_version, major, user_agent)
