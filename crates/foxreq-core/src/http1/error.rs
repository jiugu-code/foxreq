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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseErrorKind {
    BareLineFeed,
    InvalidLineEnding,
    InvalidStatusLine,
    InvalidStatusCode,
    InvalidHeaderName,
    InvalidHeaderValue,
    ObsoleteLineFolding,
    HeaderLimitExceeded,
    TooManyHeaders,
    TooManyInformational,
    InvalidContentLength,
    ConflictingContentLength,
    UnsupportedTransferEncoding,
    ConflictingFraming,
    InvalidNoBodyFraming,
    UnsupportedUpgrade,
    InvalidChunkSize,
    InvalidChunkTerminator,
    ForbiddenTrailer,
    TooManyTrailers,
    TrailerLimitExceeded,
    BodyLimitExceeded,
    UnexpectedEof,
    AlreadyComplete,
    InputLimitExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseError {
    kind: ResponseErrorKind,
    offset: usize,
}

impl ResponseError {
    pub(crate) const fn new(kind: ResponseErrorKind, offset: usize) -> Self {
        Self { kind, offset }
    }

    #[must_use]
    pub const fn kind(&self) -> ResponseErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }
}

impl fmt::Display for ResponseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            ResponseErrorKind::BareLineFeed => "bare LF in HTTP response",
            ResponseErrorKind::InvalidLineEnding => "invalid HTTP response line ending",
            ResponseErrorKind::InvalidStatusLine => "invalid HTTP response status line",
            ResponseErrorKind::InvalidStatusCode => "invalid HTTP response status code",
            ResponseErrorKind::InvalidHeaderName => "invalid HTTP response header name",
            ResponseErrorKind::InvalidHeaderValue => "invalid HTTP response header value",
            ResponseErrorKind::ObsoleteLineFolding => "obsolete HTTP header line folding",
            ResponseErrorKind::HeaderLimitExceeded => "HTTP response header limit exceeded",
            ResponseErrorKind::TooManyHeaders => "too many HTTP response headers",
            ResponseErrorKind::TooManyInformational => "too many informational HTTP responses",
            ResponseErrorKind::InvalidContentLength => "invalid response Content-Length",
            ResponseErrorKind::ConflictingContentLength => {
                "conflicting response Content-Length values"
            }
            ResponseErrorKind::UnsupportedTransferEncoding => {
                "unsupported response Transfer-Encoding"
            }
            ResponseErrorKind::ConflictingFraming => "conflicting HTTP response framing",
            ResponseErrorKind::InvalidNoBodyFraming => {
                "framing is forbidden for this HTTP response"
            }
            ResponseErrorKind::UnsupportedUpgrade => "HTTP protocol upgrade is unsupported",
            ResponseErrorKind::InvalidChunkSize => "invalid HTTP response chunk size",
            ResponseErrorKind::InvalidChunkTerminator => "invalid HTTP response chunk terminator",
            ResponseErrorKind::ForbiddenTrailer => "forbidden HTTP response trailer",
            ResponseErrorKind::TooManyTrailers => "too many HTTP response trailers",
            ResponseErrorKind::TrailerLimitExceeded => "HTTP response trailer limit exceeded",
            ResponseErrorKind::BodyLimitExceeded => "HTTP response body limit exceeded",
            ResponseErrorKind::UnexpectedEof => "unexpected EOF in HTTP response",
            ResponseErrorKind::AlreadyComplete => "HTTP response parser is already complete",
            ResponseErrorKind::InputLimitExceeded => "HTTP response input offset overflow",
        };
        write!(formatter, "{message} at byte {}", self.offset)
    }
}

impl std::error::Error for ResponseError {}
