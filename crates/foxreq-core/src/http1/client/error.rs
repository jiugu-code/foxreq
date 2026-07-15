use std::{error::Error as StdError, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientErrorKind {
    InvalidUrl,
    InvalidProfile,
    InvalidTimeout,
    Closed,
    Timeout,
    Connection,
    Tls,
    Certificate,
    Transport,
    Request,
    Response,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientError {
    kind: ClientErrorKind,
    message: String,
}

impl ClientError {
    pub(super) fn new(kind: ClientErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> ClientErrorKind {
        self.kind
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl StdError for ClientError {}
