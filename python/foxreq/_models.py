"""Immutable public response model."""

import codecs
import json as _json
import re
from dataclasses import dataclass

from ._headers import Headers


_CHARSET = re.compile(r"(?:^|;)\s*charset\s*=\s*[\"']?([^;\s\"']+)", re.I)


@dataclass(frozen=True, slots=True)
class Response:
    status_code: int
    reason: str
    url: str
    http_version: str
    headers: Headers
    content: bytes

    @classmethod
    def from_native(cls, native):
        headers = Headers(
            (
                bytes(name).decode("ascii"),
                bytes(value).decode("latin-1"),
            )
            for name, value in native.headers
        )
        return cls(
            status_code=int(native.status),
            reason=bytes(native.reason).decode("latin-1"),
            url=str(native.url),
            http_version=str(native.version),
            headers=headers,
            content=bytes(native.body),
        )

    @property
    def text(self):
        encoding = "utf-8"
        content_type = self.headers.get("Content-Type", "")
        match = _CHARSET.search(content_type)
        if match:
            candidate = match.group(1)
            try:
                codecs.lookup(candidate)
            except LookupError:
                pass
            else:
                encoding = candidate
        return self.content.decode(encoding, errors="replace")

    def json(self):
        return _json.loads(self.text)
