use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    InvalidMethod,
    UnsupportedMethod,
    InvalidTarget,
    InvalidAuthority,
    InvalidHeaderName,
    InvalidHeaderValue,
    DuplicateHost,
    DuplicateContentLength,
    DuplicateTransferEncoding,
    ConflictingFraming,
    InvalidContentLength,
    ContentLengthMismatch,
    UnsupportedTransferEncoding,
    InvalidChunk,
    HeaderLimitExceeded,
    BodyLimitExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    pub(crate) const fn new(kind: ErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            ErrorKind::InvalidMethod => "invalid HTTP method",
            ErrorKind::UnsupportedMethod => "unsupported HTTP method",
            ErrorKind::InvalidTarget => "invalid HTTP request target",
            ErrorKind::InvalidAuthority => "invalid HTTP authority",
            ErrorKind::InvalidHeaderName => "invalid HTTP header name",
            ErrorKind::InvalidHeaderValue => "invalid HTTP header value",
            ErrorKind::DuplicateHost => "duplicate Host header",
            ErrorKind::DuplicateContentLength => "duplicate Content-Length header",
            ErrorKind::DuplicateTransferEncoding => "duplicate Transfer-Encoding header",
            ErrorKind::ConflictingFraming => "conflicting HTTP message framing",
            ErrorKind::InvalidContentLength => "invalid Content-Length header",
            ErrorKind::ContentLengthMismatch => "Content-Length does not match the body",
            ErrorKind::UnsupportedTransferEncoding => "unsupported Transfer-Encoding header",
            ErrorKind::InvalidChunk => "invalid HTTP body chunk",
            ErrorKind::HeaderLimitExceeded => "HTTP header limit exceeded",
            ErrorKind::BodyLimitExceeded => "HTTP body limit exceeded",
        })
    }
}

impl std::error::Error for Error {}
