"""Python-native request, runtime, and trust-policy normalization."""

import ipaddress
import json as _json
import math
import os
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

from ._exceptions import ConfigurationError, InvalidRequestError
from ._profiles import get_profile


_HEADER_TOKEN = frozenset(
    b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
_MAX_PEM_BYTES = 4 * 1024 * 1024
_BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----"
_END_CERTIFICATE = "-----END CERTIFICATE-----"


@dataclass(frozen=True, slots=True)
class NormalizedRequest:
    method: bytes
    url: str
    scheme: str
    headers: tuple
    body: bytes
    timeout: float
    profile: str


@dataclass(frozen=True, slots=True)
class VerifyPolicy:
    anchors: tuple
    insecure: bool


def normalize_request(
    method,
    url,
    params,
    headers,
    data,
    json_value,
    timeout,
    impersonate,
):
    normalized_method = _normalize_method(method)
    normalized_url, scheme = _normalize_url(url, params)
    normalized_headers = list(_normalize_headers(headers))
    if data is not None and json_value is not None:
        raise InvalidRequestError("data and json are mutually exclusive")
    if json_value is not None:
        try:
            body = _json.dumps(
                json_value,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise InvalidRequestError("json value is not serializable") from exc
        if not any(name.lower() == b"content-type" for name, _ in normalized_headers):
            normalized_headers.append((b"Content-Type", b"application/json"))
    else:
        body = _normalize_body(data)
    profile = get_profile(impersonate)
    if not any(name.lower() == b"user-agent" for name, _ in normalized_headers):
        normalized_headers.insert(0, (b"User-Agent", profile.user_agent.encode("ascii")))
    return NormalizedRequest(
        method=normalized_method,
        url=normalized_url,
        scheme=scheme,
        headers=tuple(normalized_headers),
        body=body,
        timeout=normalize_timeout(timeout),
        profile=profile.profile_id,
    )


def normalize_timeout(value):
    if isinstance(value, bool):
        raise InvalidRequestError("timeout must be a finite positive number")
    try:
        timeout = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise InvalidRequestError("timeout must be a finite positive number") from exc
    if not math.isfinite(timeout) or timeout <= 0:
        raise InvalidRequestError("timeout must be a finite positive number")
    return timeout


def normalize_profile(value):
    return get_profile(value).profile_id


def normalize_verify(value):
    if value is False:
        return VerifyPolicy(anchors=(), insecure=True)
    if value is True:
        try:
            import certifi
        except ImportError as exc:
            raise ConfigurationError("certifi is required for verify=True") from exc
        path = Path(certifi.where())
    else:
        try:
            path = Path(os.fsdecode(os.fspath(value)))
        except (TypeError, ValueError) as exc:
            raise ConfigurationError("verify must be bool or a PEM bundle path") from exc
    return VerifyPolicy(anchors=_read_pem_bundle(path), insecure=False)


def resolve_runtime_dir(value):
    selected = value if value is not None else os.environ.get("FOXREQ_NSS_RUNTIME_DIR")
    if selected is None:
        raise ConfigurationError(
            "runtime_dir or FOXREQ_NSS_RUNTIME_DIR is required"
        )
    try:
        path = Path(os.fsdecode(os.fspath(selected))).expanduser().resolve()
    except (TypeError, ValueError, OSError) as exc:
        raise ConfigurationError("Firefox runtime directory is invalid") from exc
    if not path.is_dir():
        raise ConfigurationError("Firefox runtime directory does not exist")
    return path


def _normalize_method(value):
    if not isinstance(value, str):
        raise InvalidRequestError("method must be a string")
    try:
        method = value.strip().upper().encode("ascii")
    except UnicodeEncodeError as exc:
        raise InvalidRequestError("method must be ASCII") from exc
    if not method or any(byte not in _HEADER_TOKEN for byte in method):
        raise InvalidRequestError("method is not a valid HTTP token")
    return method


def _normalize_url(value, params):
    if not isinstance(value, str) or not value:
        raise InvalidRequestError("url must be a non-empty string")
    if any(character in value for character in "\r\n\0") or "#" in value:
        raise InvalidRequestError("url contains a forbidden fragment or control character")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise InvalidRequestError("url authority is invalid") from exc
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https") or parsed.hostname is None:
        raise InvalidRequestError("only absolute http and https URLs are supported")
    if parsed.username is not None or parsed.password is not None:
        raise InvalidRequestError("url userinfo is not supported")
    hostname = parsed.hostname
    if ":" in hostname:
        try:
            hostname = str(ipaddress.ip_address(hostname))
        except ValueError as exc:
            raise InvalidRequestError("IPv6 host is invalid") from exc
        authority = "[{}]".format(hostname)
    else:
        try:
            authority = hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise InvalidRequestError("DNS host cannot be converted to IDNA") from exc
    if port is not None:
        authority += ":{}".format(port)
    path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parsed.query, safe="=&;%:@/?+,$-_.!~*'()")
    if params is not None:
        try:
            items = params.items() if isinstance(params, Mapping) else params
            encoded = urlencode(items, doseq=True)
        except (TypeError, ValueError) as exc:
            raise InvalidRequestError("params must be a mapping or pair sequence") from exc
        if encoded:
            query = query + ("&" if query else "") + encoded
    return urlunsplit((scheme, authority, path, query, "")), scheme


def _normalize_headers(value):
    if value is None:
        return ()
    try:
        items = value.items() if isinstance(value, Mapping) else value
        normalized = []
        for item in items:
            if isinstance(item, (str, bytes, bytearray, memoryview)):
                raise InvalidRequestError("header item must be a name/value pair")
            name, header_value = item
            name = _header_bytes(name, "name", "ascii")
            header_value = _header_bytes(header_value, "value", "latin-1")
            if not name or any(byte not in _HEADER_TOKEN for byte in name):
                raise InvalidRequestError("header name is not a valid HTTP token")
            if any(byte in (0, 10, 13) for byte in header_value):
                raise InvalidRequestError("header value contains a forbidden byte")
            normalized.append((name, header_value))
    except InvalidRequestError:
        raise
    except (TypeError, ValueError) as exc:
        raise InvalidRequestError("headers must be a mapping or pair sequence") from exc
    return tuple(normalized)


def _header_bytes(value, label, encoding):
    if isinstance(value, str):
        try:
            return value.encode(encoding)
        except UnicodeEncodeError as exc:
            raise InvalidRequestError(
                "header {} cannot be encoded as {}".format(label, encoding)
            ) from exc
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise InvalidRequestError("header {} must be str or bytes-like".format(label))


def _normalize_body(value):
    if value is None:
        return b""
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise InvalidRequestError("data must be str or bytes-like")


def _read_pem_bundle(path):
    try:
        if not path.is_file():
            raise ConfigurationError("PEM bundle path is not a file")
        with path.open("rb") as source:
            raw = source.read(_MAX_PEM_BYTES + 1)
    except ConfigurationError:
        raise
    except OSError as exc:
        raise ConfigurationError("PEM bundle cannot be read") from exc
    if len(raw) > _MAX_PEM_BYTES:
        raise ConfigurationError("PEM bundle exceeds the 4 MiB limit")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ConfigurationError("PEM bundle must be ASCII") from exc

    anchors = []
    block = None
    for line in text.splitlines():
        stripped = line.strip()
        if block is None:
            if not stripped or stripped.startswith("#"):
                continue
            if stripped != _BEGIN_CERTIFICATE:
                raise ConfigurationError("PEM bundle contains non-certificate text")
            block = [_BEGIN_CERTIFICATE]
            continue
        if stripped == _BEGIN_CERTIFICATE:
            raise ConfigurationError("PEM certificate blocks cannot be nested")
        block.append(stripped)
        if stripped == _END_CERTIFICATE:
            try:
                der = ssl.PEM_cert_to_DER_cert("\n".join(block) + "\n")
            except (ValueError, ssl.SSLError) as exc:
                raise ConfigurationError("PEM certificate is invalid") from exc
            if not der:
                raise ConfigurationError("PEM certificate is empty")
            anchors.append(der)
            block = None
    if block is not None:
        raise ConfigurationError("PEM certificate block is truncated")
    if not anchors:
        raise ConfigurationError("PEM bundle contains no certificates")
    return tuple(anchors)
