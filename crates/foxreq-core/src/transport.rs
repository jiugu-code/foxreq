use std::{error::Error, fmt, time::Duration};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VerificationMode {
    Default,
    InsecureTestOnly,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectTarget {
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
