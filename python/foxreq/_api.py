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
from ._worker_session import ProfileWorkerSession


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
        self._runtime_dir_input = runtime_dir
        self._verify_input = verify
        self._timeout = normalize_timeout(timeout)
        self._impersonate = normalize_profile(impersonate)
        self._closed = False
        self._http = None
        self._https = None
        self._https_policy = None

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
        request_profile = (
            self._impersonate
            if impersonate is None
            else normalize_profile(impersonate)
        )
        if request_profile != self._impersonate:
            raise ConfigurationError(
                "a Session cannot change its Firefox profile after construction"
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
        if normalized.scheme == "http":
            native = self._http_session()
            insecure = False
        else:
            native, policy = self._https_session()
            request_verify = self._resolve_request_verify(verify, policy)
            insecure = request_verify.insecure
            if insecure:
                warnings.warn(
                    "TLS certificate verification is disabled",
                    InsecureRequestWarning,
                    stacklevel=2,
                )
        try:
            response = native.request(
                normalized.method,
                normalized.url,
                normalized.headers,
                normalized.body,
                normalized.timeout,
                insecure,
            )
        except _foxreq.NativeError as error:
            raise translate_native_error(error) from error
        return Response.from_native(response)

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def close(self):
        if self._closed:
            return
        self._closed = True
        failure = None
        for native in (self._http, self._https):
            if native is None:
                continue
            try:
                native.close()
            except _foxreq.NativeError as error:
                if failure is None:
                    failure = (translate_native_error(error), error)
        if failure is not None:
            translated, native_error = failure
            raise translated from native_error

    def __enter__(self):
        self._ensure_open()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False

    def _ensure_open(self):
        if self._closed:
            raise ClosedSessionError("Session is closed")

    def _http_session(self):
        if self._http is None:
            try:
                self._http = _foxreq.NativeHttpSession(self._impersonate)
            except _foxreq.NativeError as error:
                raise translate_native_error(error) from error
        return self._http

    def _https_session(self):
        if self._https is None:
            runtime_dir = resolve_runtime_dir(self._runtime_dir_input)
            policy = normalize_verify(self._verify_input)
            native = ProfileWorkerSession(
                str(runtime_dir),
                policy.anchors,
                self._impersonate,
            )
            self._https = native
            self._https_policy = policy
        return self._https, self._https_policy

    def _resolve_request_verify(self, value, session_policy):
        if value is None:
            return session_policy
        policy = normalize_verify(value)
        if policy.insecure:
            return policy
        if policy != session_policy:
            raise ConfigurationError(
                "a different CA bundle requires a separate Session"
            )
        return policy
