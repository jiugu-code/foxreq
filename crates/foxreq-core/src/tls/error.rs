use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsErrorKind {
    InvalidArgument,
    OutOfMemory,
    State,
    Io,
    Timeout,
    Tls,
    Certificate,
    Unsupported,
    BufferTooSmall,
    EndOfStream,
    Unknown(u32),
}

impl TlsErrorKind {
    pub(crate) const fn from_raw(value: u32) -> Self {
        match value {
            1 => Self::InvalidArgument,
            2 => Self::OutOfMemory,
            3 => Self::State,
            4 => Self::Io,
            5 => Self::Timeout,
            6 => Self::Tls,
            7 => Self::Certificate,
            8 => Self::Unsupported,
            9 => Self::BufferTooSmall,
            10 => Self::EndOfStream,
            value => Self::Unknown(value),
        }
    }

    pub(crate) const fn as_raw(self) -> u32 {
        match self {
            Self::InvalidArgument => 1,
            Self::OutOfMemory => 2,
            Self::State => 3,
            Self::Io => 4,
            Self::Timeout => 5,
            Self::Tls => 6,
            Self::Certificate => 7,
            Self::Unsupported => 8,
            Self::BufferTooSmall => 9,
            Self::EndOfStream => 10,
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsError {
    kind: TlsErrorKind,
    nss_code: i32,
    nspr_code: i32,
    message: String,
}

impl TlsError {
    pub(crate) fn local(kind: TlsErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            nss_code: 0,
            nspr_code: 0,
            message: message.into(),
        }
    }

    pub(crate) fn foreign(
        kind: TlsErrorKind,
        nss_code: i32,
        nspr_code: i32,
        message: &[u8],
    ) -> Self {
        Self {
            kind,
            nss_code,
            nspr_code,
            message: String::from_utf8_lossy(message).into_owned(),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> TlsErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn nss_code(&self) -> i32 {
        self.nss_code
    }

    #[must_use]
    pub const fn nspr_code(&self) -> i32 {
        self.nspr_code
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for TlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.message.is_empty() {
            write!(formatter, "TLS transport error: {:?}", self.kind)
        } else {
            write!(
                formatter,
                "TLS transport error: {:?}: {}",
                self.kind, self.message
            )
        }
    }
}

impl std::error::Error for TlsError {}
