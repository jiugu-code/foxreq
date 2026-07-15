mod error;
mod ffi;

use std::{fmt, path::Path, ptr::NonNull, rc::Rc, time::Duration};

pub use error::{TlsError, TlsErrorKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestVerification {
    Default,
    InsecureTestOnly,
}

#[derive(Clone, Copy, Debug)]
pub struct ConnectConfig<'a> {
    pub host: &'a str,
    pub port: u16,
    pub timeout: Duration,
    pub profile_id: &'a str,
    pub alpn_wire: &'a [u8],
    pub verification: RequestVerification,
}

#[derive(Clone, Copy, Debug)]
pub struct RuntimeConfig<'a> {
    pub runtime_dir: &'a Path,
    pub trust_anchor_der: Option<&'a [u8]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeVersions {
    pub nss: String,
    pub nspr: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateResult {
    pub verification_performed: bool,
    pub verified: bool,
    pub error_kind: Option<TlsErrorKind>,
    pub nss_code: i32,
    pub nspr_code: i32,
}

struct RuntimeInner {
    raw: NonNull<ffi::RawRuntime>,
}

impl Drop for RuntimeInner {
    fn drop(&mut self) {
        ffi::runtime_free(self.raw);
    }
}

pub struct Runtime {
    inner: Rc<RuntimeInner>,
}

impl Runtime {
    pub fn new() -> Result<Self, TlsError> {
        let raw = ffi::runtime_create(&[], &[])
            .map_err(|code| error_from_code(code, "native runtime creation failed"))?;
        Ok(Self {
            inner: Rc::new(RuntimeInner { raw }),
        })
    }

    pub fn new_with_config(config: RuntimeConfig<'_>) -> Result<Self, TlsError> {
        let runtime_dir = config.runtime_dir.to_str().ok_or_else(|| {
            TlsError::local(
                TlsErrorKind::InvalidArgument,
                "runtime directory must be valid Unicode",
            )
        })?;
        if runtime_dir.is_empty() || runtime_dir.as_bytes().contains(&0) {
            return Err(TlsError::local(
                TlsErrorKind::InvalidArgument,
                "runtime directory must be non-empty and contain no NUL",
            ));
        }
        let trust_anchor_der = config.trust_anchor_der.unwrap_or_default();
        let raw = ffi::runtime_create(runtime_dir.as_bytes(), trust_anchor_der)
            .map_err(|code| error_from_code(code, "pinned native runtime creation failed"))?;
        Ok(Self {
            inner: Rc::new(RuntimeInner { raw }),
        })
    }

    pub fn versions(&self) -> Result<RuntimeVersions, TlsError> {
        let (nss, nspr) = ffi::runtime_versions(self.inner.raw)
            .map_err(|code| error_from_code(code, "native version query failed"))?;
        let nss = String::from_utf8(nss)
            .map_err(|_| TlsError::local(TlsErrorKind::State, "native NSS version is not UTF-8"))?;
        let nspr = String::from_utf8(nspr).map_err(|_| {
            TlsError::local(TlsErrorKind::State, "native NSPR version is not UTF-8")
        })?;
        Ok(RuntimeVersions { nss, nspr })
    }

    pub fn session_cache(&self, capacity: u32) -> Result<SessionCache, TlsError> {
        let raw = ffi::session_cache_create(self.inner.raw, capacity)
            .map_err(|code| error_from_code(code, "session cache creation failed"))?;
        Ok(SessionCache {
            inner: Rc::new(SessionCacheInner {
                raw,
                runtime: Rc::clone(&self.inner),
            }),
        })
    }

    pub fn connect(
        &self,
        config: &ConnectConfig<'_>,
        cache: Option<&SessionCache>,
    ) -> Result<Connection, TlsError> {
        validate_connect_config(config)?;
        if cache.is_some_and(|cache| !Rc::ptr_eq(&self.inner, &cache.inner.runtime)) {
            return Err(TlsError::local(
                TlsErrorKind::State,
                "session cache belongs to another runtime",
            ));
        }
        let timeout_millis = timeout_millis(config.timeout)?;
        let verification_mode = match config.verification {
            RequestVerification::Default => 0,
            RequestVerification::InsecureTestOnly => 1,
        };
        let arguments = ffi::ConnectArgs {
            host: config.host.as_bytes(),
            port: config.port,
            timeout_millis,
            profile_id: config.profile_id.as_bytes(),
            alpn_wire: config.alpn_wire,
            verification_mode,
            session_cache: cache.map(|cache| cache.inner.raw),
        };
        let raw = ffi::connect(self.inner.raw, &arguments).map_err(|failure| {
            if let Some(detail) = failure.detail {
                if detail.category == failure.code {
                    return TlsError::foreign(
                        TlsErrorKind::from_raw(failure.code),
                        detail.nss_code,
                        detail.nspr_code,
                        &detail.message,
                    );
                }
            }
            error_from_code(failure.code, "native connection failed")
        })?;
        Ok(Connection {
            raw,
            _runtime: Rc::clone(&self.inner),
            _cache: cache.map(|cache| Rc::clone(&cache.inner)),
            closed: false,
        })
    }
}

struct SessionCacheInner {
    raw: NonNull<ffi::RawSessionCache>,
    runtime: Rc<RuntimeInner>,
}

impl Drop for SessionCacheInner {
    fn drop(&mut self) {
        ffi::session_cache_free(self.raw);
    }
}

pub struct SessionCache {
    inner: Rc<SessionCacheInner>,
}

pub struct Connection {
    raw: NonNull<ffi::RawConnection>,
    _runtime: Rc<RuntimeInner>,
    _cache: Option<Rc<SessionCacheInner>>,
    closed: bool,
}

impl fmt::Debug for Connection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Connection")
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl Connection {
    pub fn negotiated_alpn(&self) -> Result<Vec<u8>, TlsError> {
        ffi::negotiated_alpn(self.raw).map_err(|code| self.operation_error(code))
    }

    pub fn certificate_result(&self) -> Result<CertificateResult, TlsError> {
        let result =
            ffi::certificate_result(self.raw).map_err(|code| self.operation_error(code))?;
        Ok(CertificateResult {
            verification_performed: result.verification_performed,
            verified: result.verified,
            error_kind: (result.category != ffi::RESULT_OK)
                .then(|| TlsErrorKind::from_raw(result.category)),
            nss_code: result.nss_code,
            nspr_code: result.nspr_code,
        })
    }

    pub fn read(&mut self, destination: &mut [u8], timeout: Duration) -> Result<usize, TlsError> {
        self.ensure_open()?;
        let timeout = timeout_millis(timeout)?;
        let result = ffi::read(self.raw, destination, timeout)
            .map_err(|code| error_from_code(code, "invalid native read result"))?;
        match result.code {
            ffi::RESULT_OK => Ok(result.transferred),
            ffi::RESULT_END_OF_STREAM => Ok(0),
            code => Err(self.operation_error(code)),
        }
    }

    pub fn write(&mut self, source: &[u8], timeout: Duration) -> Result<usize, TlsError> {
        self.ensure_open()?;
        let timeout = timeout_millis(timeout)?;
        let result = ffi::write(self.raw, source, timeout)
            .map_err(|code| error_from_code(code, "invalid native write result"))?;
        if result.code == ffi::RESULT_OK {
            Ok(result.transferred)
        } else {
            Err(self.operation_error(result.code))
        }
    }

    pub fn close(&mut self, timeout: Duration) -> Result<(), TlsError> {
        if self.closed {
            return Err(TlsError::local(
                TlsErrorKind::State,
                "connection already closed by Rust wrapper",
            ));
        }
        let code = ffi::close(self.raw, timeout_millis(timeout)?);
        if code != ffi::RESULT_OK {
            return Err(self.operation_error(code));
        }
        self.closed = true;
        Ok(())
    }

    pub fn last_error(&self) -> Result<TlsError, TlsError> {
        let error = ffi::last_error(self.raw)
            .map_err(|code| error_from_code(code, "last-error extraction failed"))?;
        Ok(TlsError::foreign(
            TlsErrorKind::from_raw(error.category),
            error.nss_code,
            error.nspr_code,
            &error.message,
        ))
    }

    fn ensure_open(&self) -> Result<(), TlsError> {
        if self.closed {
            Err(TlsError::local(TlsErrorKind::State, "connection is closed"))
        } else {
            Ok(())
        }
    }

    fn operation_error(&self, code: u32) -> TlsError {
        if let Ok(error) = ffi::last_error(self.raw) {
            if error.category == code {
                return TlsError::foreign(
                    TlsErrorKind::from_raw(code),
                    error.nss_code,
                    error.nspr_code,
                    &error.message,
                );
            }
        }
        error_from_code(code, "native TLS operation failed")
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if !self.closed {
            let _ = ffi::close(self.raw, 1);
        }
        ffi::connection_free(self.raw);
    }
}

fn validate_connect_config(config: &ConnectConfig<'_>) -> Result<(), TlsError> {
    if config.host.is_empty()
        || config.host.as_bytes().contains(&0)
        || config.port == 0
        || config.profile_id.is_empty()
        || config.profile_id.as_bytes().contains(&0)
        || config.alpn_wire.is_empty()
    {
        return Err(TlsError::local(
            TlsErrorKind::InvalidArgument,
            "invalid connection configuration",
        ));
    }
    Ok(())
}

fn timeout_millis(timeout: Duration) -> Result<u64, TlsError> {
    let millis = timeout.as_millis();
    let millis = if timeout.is_zero() { 0 } else { millis.max(1) };
    u64::try_from(millis).map_err(|_| {
        TlsError::local(
            TlsErrorKind::InvalidArgument,
            "timeout does not fit the native ABI",
        )
    })
}

fn error_from_code(code: u32, message: &'static str) -> TlsError {
    TlsError::local(TlsErrorKind::from_raw(code), message)
}

#[cfg(not(feature = "nss-real"))]
#[doc(hidden)]
pub mod testing {
    use std::sync::{Mutex, MutexGuard};

    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct LiveCounts {
        pub runtimes: u32,
        pub connections: u32,
        pub session_caches: u32,
        pub buffers: u32,
    }

    pub fn lock() -> MutexGuard<'static, ()> {
        TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn live_counts() -> Result<LiveCounts, TlsError> {
        let counts = ffi::stub_live_counts()
            .map_err(|code| error_from_code(code, "fake live-count query failed"))?;
        Ok(LiveCounts {
            runtimes: counts.runtimes,
            connections: counts.connections,
            session_caches: counts.session_caches,
            buffers: counts.buffers,
        })
    }

    pub fn set_read_data(connection: &mut Connection, data: &[u8]) -> Result<(), TlsError> {
        connection.ensure_open()?;
        result_for_connection(connection, ffi::stub_set_read_data(connection.raw, data))
    }

    pub fn set_io_limits(
        connection: &mut Connection,
        read_limit: u64,
        write_limit: u64,
    ) -> Result<(), TlsError> {
        connection.ensure_open()?;
        result_for_connection(
            connection,
            ffi::stub_set_io_limits(connection.raw, read_limit, write_limit),
        )
    }

    pub fn fail_next_read(
        connection: &mut Connection,
        kind: TlsErrorKind,
        nss_code: i32,
        nspr_code: i32,
        message: &str,
    ) -> Result<(), TlsError> {
        connection.ensure_open()?;
        result_for_connection(
            connection,
            ffi::stub_fail_next_read(
                connection.raw,
                kind.as_raw(),
                nss_code,
                nspr_code,
                message.as_bytes(),
            ),
        )
    }

    pub fn fail_next_write(
        connection: &mut Connection,
        kind: TlsErrorKind,
        nss_code: i32,
        nspr_code: i32,
        message: &str,
    ) -> Result<(), TlsError> {
        connection.ensure_open()?;
        result_for_connection(
            connection,
            ffi::stub_fail_next_write(
                connection.raw,
                kind.as_raw(),
                nss_code,
                nspr_code,
                message.as_bytes(),
            ),
        )
    }

    pub fn fail_next_close(
        connection: &mut Connection,
        kind: TlsErrorKind,
        nss_code: i32,
        nspr_code: i32,
        message: &str,
    ) -> Result<(), TlsError> {
        connection.ensure_open()?;
        result_for_connection(
            connection,
            ffi::stub_fail_next_close(
                connection.raw,
                kind.as_raw(),
                nss_code,
                nspr_code,
                message.as_bytes(),
            ),
        )
    }

    pub fn written_data(connection: &Connection) -> Result<Vec<u8>, TlsError> {
        ffi::stub_written_data(connection.raw).map_err(|code| connection.operation_error(code))
    }

    pub fn close_calls(connection: &Connection) -> Result<u32, TlsError> {
        ffi::stub_close_calls(connection.raw).map_err(|code| connection.operation_error(code))
    }

    fn result_for_connection(connection: &Connection, code: u32) -> Result<(), TlsError> {
        if code == ffi::RESULT_OK {
            Ok(())
        } else {
            Err(connection.operation_error(code))
        }
    }
}
