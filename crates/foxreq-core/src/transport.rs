use std::{error::Error, fmt, time::Duration};

#[cfg(feature = "nss")]
use crate::tls::{
    ConnectConfig, Connection, RequestVerification, Runtime, SessionCache, TlsError, TlsErrorKind,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VerificationMode {
    Default,
    InsecureTestOnly,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Scheme {
    Http,
    Https,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectTarget {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub profile_id: String,
    pub verification: VerificationMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportErrorKind {
    InvalidArgument,
    State,
    Io,
    Timeout,
    Tls,
    Certificate,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportError {
    kind: TransportErrorKind,
    message: String,
}

impl TransportError {
    pub fn new(kind: TransportErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> TransportErrorKind {
        self.kind
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for TransportError {}

pub trait TransportStream {
    fn read(&mut self, destination: &mut [u8], timeout: Duration) -> Result<usize, TransportError>;

    fn write(&mut self, source: &[u8], timeout: Duration) -> Result<usize, TransportError>;

    fn close(&mut self, timeout: Duration) -> Result<(), TransportError>;
}

pub trait Connector {
    type Stream: TransportStream;

    fn connect(
        &mut self,
        target: &ConnectTarget,
        timeout: Duration,
    ) -> Result<Self::Stream, TransportError>;
}

#[cfg(feature = "nss")]
pub struct NssConnector {
    runtime: Runtime,
    cache: SessionCache,
}

#[cfg(feature = "nss")]
impl NssConnector {
    pub fn new(runtime: Runtime, cache_capacity: u32) -> Result<Self, TransportError> {
        let cache = runtime
            .session_cache(cache_capacity)
            .map_err(map_tls_error)?;
        Ok(Self { runtime, cache })
    }
}

#[cfg(feature = "nss")]
impl Connector for NssConnector {
    type Stream = Connection;

    fn connect(
        &mut self,
        target: &ConnectTarget,
        timeout: Duration,
    ) -> Result<Self::Stream, TransportError> {
        let verification = match target.verification {
            VerificationMode::Default => RequestVerification::Default,
            VerificationMode::InsecureTestOnly => RequestVerification::InsecureTestOnly,
        };
        let mut connection = self
            .runtime
            .connect(
                &ConnectConfig {
                    host: &target.host,
                    port: target.port,
                    timeout,
                    profile_id: &target.profile_id,
                    alpn_wire: b"\x08http/1.1",
                    verification,
                },
                Some(&self.cache),
            )
            .map_err(map_tls_error)?;
        let protocol = connection.negotiated_alpn().map_err(map_tls_error)?;
        if protocol != b"http/1.1" {
            let _ = connection.close(Duration::from_millis(1));
            return Err(TransportError::new(
                TransportErrorKind::Unsupported,
                "NSS did not negotiate HTTP/1.1",
            ));
        }
        let certificate = connection.certificate_result().map_err(map_tls_error)?;
        if target.verification == VerificationMode::Default
            && (!certificate.verification_performed || !certificate.verified)
        {
            let _ = connection.close(Duration::from_millis(1));
            return Err(TransportError::new(
                TransportErrorKind::Certificate,
                "NSS certificate verification did not succeed",
            ));
        }
        Ok(connection)
    }
}

#[cfg(feature = "nss")]
impl TransportStream for Connection {
    fn read(&mut self, destination: &mut [u8], timeout: Duration) -> Result<usize, TransportError> {
        Connection::read(self, destination, timeout).map_err(map_tls_error)
    }

    fn write(&mut self, source: &[u8], timeout: Duration) -> Result<usize, TransportError> {
        Connection::write(self, source, timeout).map_err(map_tls_error)
    }

    fn close(&mut self, timeout: Duration) -> Result<(), TransportError> {
        Connection::close(self, timeout).map_err(map_tls_error)
    }
}

#[cfg(feature = "nss")]
fn map_tls_error(error: TlsError) -> TransportError {
    let kind = match error.kind() {
        TlsErrorKind::InvalidArgument => TransportErrorKind::InvalidArgument,
        TlsErrorKind::State => TransportErrorKind::State,
        TlsErrorKind::Io | TlsErrorKind::EndOfStream => TransportErrorKind::Io,
        TlsErrorKind::Timeout => TransportErrorKind::Timeout,
        TlsErrorKind::Certificate => TransportErrorKind::Certificate,
        TlsErrorKind::Unsupported => TransportErrorKind::Unsupported,
        TlsErrorKind::OutOfMemory
        | TlsErrorKind::Tls
        | TlsErrorKind::BufferTooSmall
        | TlsErrorKind::Unknown(_) => TransportErrorKind::Tls,
    };
    TransportError::new(kind, error.message())
}
