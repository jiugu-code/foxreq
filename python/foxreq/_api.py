"""Public synchronous foxreq request API."""

import warnings

from . import _foxreq
from ._exceptions import (
    ClosedSessionError,
    ConfigurationError,
    InsecureRequestWarning,
    translate_native_error,
)
from ._models import Response
from ._normalize import (
    normalize_profile,
    normalize_request,
    normalize_timeout,
    normalize_verify,
    resolve_runtime_dir,
)


def request(
    method,
    url,
    *,
    params=None,
    headers=None,
    data=None,
    json=None,
    timeout=30.0,
    verify=True,
    impersonate="firefox_152",
    runtime_dir=None,
):
    with Session(
        runtime_dir=runtime_dir,
        verify=verify,
        impersonate=impersonate,
        timeout=timeout,
    ) as session:
        return session.request(
            method,
            url,
            params=params,
            headers=headers,
            data=data,
            json=json,
        )


def get(url, **kwargs):
    return request("GET", url, **kwargs)


def post(url, **kwargs):
    return request("POST", url, **kwargs)


class Session:
    def __init__(
        self,
        *,
        runtime_dir=None,
        verify=True,
        impersonate="firefox_152",
        timeout=30.0,
    ):
        self._runtime_dir = resolve_runtime_dir(runtime_dir)
        self._verify = normalize_verify(verify)
        self._timeout = normalize_timeout(timeout)
        self._impersonate = normalize_profile(impersonate)
        self._closed = False
        try:
            self._native = _foxreq.NativeSession(
                str(self._runtime_dir),
                list(self._verify.anchors),
                self._impersonate,
            )
        except _foxreq.NativeError as error:
            raise translate_native_error(error) from error

    def request(
        self,
        method,
        url,
        *,
        params=None,
        headers=None,
        data=None,
        json=None,
        timeout=None,
        verify=None,
        impersonate=None,
    ):
        self._ensure_open()
        request_verify = self._resolve_request_verify(verify)
        request_profile = (
            self._impersonate
            if impersonate is None
            else normalize_profile(impersonate)
        )
        if request_profile != self._impersonate:
            raise ConfigurationError(
                "a Session cannot change its TLS profile after construction"
            )
        normalized = normalize_request(
            method,
            url,
            params,
            headers,
            data,
            json,
            self._timeout if timeout is None else timeout,
            request_profile,
        )
        if request_verify.insecure:
            warnings.warn(
                "TLS certificate verification is disabled",
                InsecureRequestWarning,
                stacklevel=2,
            )
        try:
            native = self._native.request(
                normalized.method,
                normalized.url,
                normalized.headers,
                normalized.body,
                normalized.timeout,
                request_verify.insecure,
            )
        except _foxreq.NativeError as error:
            raise translate_native_error(error) from error
        return Response.from_native(native)

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self._native.close()
        except _foxreq.NativeError as error:
            raise translate_native_error(error) from error

    def __enter__(self):
        self._ensure_open()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def _ensure_open(self):
        if self._closed:
            raise ClosedSessionError("Session is closed")

    def _resolve_request_verify(self, value):
        if value is None:
            return self._verify
        policy = normalize_verify(value)
        if policy.insecure:
            return policy
        if policy != self._verify:
            raise ConfigurationError(
                "a different CA bundle requires a separate Session"
            )
        return policy
