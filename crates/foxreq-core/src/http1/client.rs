mod error;
mod url;

use std::{collections::HashMap, time::Duration};

use crate::{
    deadline::{Deadline, DeadlineError},
    transport::{
        ConnectTarget, Connector, TransportError, TransportErrorKind, TransportStream,
        VerificationMode,
    },
};

use super::{
    serialize_request, FeedStatus, Header, Request, RequestBody, RequestLimits, RequestSemantics,
    ResponseLimits, ResponseParser, Version,
};

pub use error::{ClientError, ClientErrorKind};
use url::{parse_https_url, ParsedUrl};

const READ_BUFFER_BYTES: usize = 16 * 1024;
const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedHeader {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

impl OwnedHeader {
    #[must_use]
    pub fn new(name: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> Self {
        Self {
            name: name.as_ref().to_vec(),
            value: value.as_ref().to_vec(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientRequest {
    pub method: Vec<u8>,
    pub url: String,
    pub headers: Vec<OwnedHeader>,
    pub body: Vec<u8>,
    pub timeout: Duration,
    pub verification: VerificationMode,
    pub profile_id: String,
}

impl ClientRequest {
    #[must_use]
    pub fn get(url: impl Into<String>, timeout: Duration) -> Self {
        Self {
            method: b"GET".to_vec(),
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
            timeout,
            verification: VerificationMode::Default,
            profile_id: "firefox_152".to_owned(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientResponse {
    pub status: u16,
    pub reason: Vec<u8>,
    pub url: String,
    pub version: Version,
    pub headers: Vec<OwnedHeader>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Origin {
    host: String,
    port: u16,
    profile_id: String,
    verification: VerificationMode,
}

pub struct Http1Client<C: Connector> {
    connector: C,
    idle: HashMap<Origin, C::Stream>,
    closed: bool,
}

impl<C: Connector> Http1Client<C> {
    #[must_use]
    pub fn new(connector: C) -> Self {
        Self {
            connector,
            idle: HashMap::new(),
            closed: false,
        }
    }

    pub fn execute(&mut self, request: ClientRequest) -> Result<ClientResponse, ClientError> {
        if self.closed {
            return Err(ClientError::new(
                ClientErrorKind::Closed,
                "HTTP client is closed",
            ));
        }
        let deadline = Deadline::after(request.timeout).map_err(map_deadline)?;
        if request.profile_id != "firefox_152" {
            return Err(ClientError::new(
                ClientErrorKind::InvalidProfile,
                "invalid TLS profile",
            ));
        }
        let parsed = parse_https_url(&request.url)?;
        let origin = Origin {
            host: parsed.host.clone(),
            port: parsed.port,
            profile_id: request.profile_id.clone(),
            verification: request.verification,
        };
        let target = ConnectTarget {
            host: parsed.host.clone(),
            port: parsed.port,
            profile_id: request.profile_id.clone(),
            verification: request.verification,
        };
        let mut stream = match self.idle.remove(&origin) {
            Some(stream) => stream,
            None => self
                .connector
                .connect(&target, deadline.remaining().map_err(map_deadline)?)
                .map_err(map_transport)?,
        };
        let result = exchange(&mut stream, &request, &parsed, &deadline);
        match result {
            Ok((response, reusable)) => {
                if reusable {
                    if let Some(mut replaced) = self.idle.insert(origin, stream) {
                        let _ = replaced.close(CLOSE_TIMEOUT);
                    }
                } else {
                    let _ = stream.close(CLOSE_TIMEOUT);
                }
                Ok(response)
            }
            Err(error) => {
                let _ = stream.close(CLOSE_TIMEOUT);
                Err(error)
            }
        }
    }

    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        for (_, mut stream) in self.idle.drain() {
            let _ = stream.close(CLOSE_TIMEOUT);
        }
    }
}

impl<C: Connector> Drop for Http1Client<C> {
    fn drop(&mut self) {
        self.close();
    }
}

fn exchange<S: TransportStream>(
    stream: &mut S,
    request: &ClientRequest,
    parsed: &ParsedUrl,
    deadline: &Deadline,
) -> Result<(ClientResponse, bool), ClientError> {
    let headers: Vec<Header<'_>> = request
        .headers
        .iter()
        .map(|header| (header.name.as_slice(), header.value.as_slice()))
        .collect();
    let body = if request.body.is_empty() {
        RequestBody::None
    } else {
        RequestBody::Fixed(&request.body)
    };
    let serialized = serialize_request(
        &Request {
            method: &request.method,
            target: &parsed.target,
            authority: &parsed.authority,
            headers: &headers,
            body,
        },
        RequestLimits::default(),
    )
    .map_err(|error| ClientError::new(ClientErrorKind::Request, error.to_string()))?;

    let mut written = 0usize;
    while written < serialized.len() {
        let amount = stream
            .write(
                &serialized[written..],
                deadline.remaining().map_err(map_deadline)?,
            )
            .map_err(map_transport)?;
        if amount == 0 {
            return Err(ClientError::new(
                ClientErrorKind::Transport,
                "transport write made no progress",
            ));
        }
        if amount > serialized.len() - written {
            return Err(ClientError::new(
                ClientErrorKind::Transport,
                "transport write count exceeds the source buffer",
            ));
        }
        written = written.checked_add(amount).ok_or_else(|| {
            ClientError::new(
                ClientErrorKind::Transport,
                "transport write length overflow",
            )
        })?;
    }

    let semantics = if request.method.eq_ignore_ascii_case(b"HEAD") {
        RequestSemantics::Head
    } else {
        RequestSemantics::Normal
    };
    let mut parser = ResponseParser::new(semantics, ResponseLimits::default());
    let mut buffer = [0u8; READ_BUFFER_BYTES];
    loop {
        let amount = stream
            .read(&mut buffer, deadline.remaining().map_err(map_deadline)?)
            .map_err(map_transport)?;
        if amount > buffer.len() {
            return Err(ClientError::new(
                ClientErrorKind::Transport,
                "transport read count exceeds the destination buffer",
            ));
        }
        if amount == 0 {
            let response = parser
                .finish_eof()
                .map_err(|error| ClientError::new(ClientErrorKind::Response, error.to_string()))?;
            return Ok((owned_response(response, &request.url), false));
        }
        let fed = parser
            .feed(&buffer[..amount])
            .map_err(|error| ClientError::new(ClientErrorKind::Response, error.to_string()))?;
        if let FeedStatus::Complete(response) = fed.status {
            let reusable = fed.consumed == amount && !response.connection_close;
            return Ok((owned_response(response, &request.url), reusable));
        }
    }
}

fn owned_response(response: super::Response, url: &str) -> ClientResponse {
    ClientResponse {
        status: response.status,
        reason: response.reason,
        url: url.to_owned(),
        version: response.version,
        headers: response
            .headers
            .into_iter()
            .map(|header| OwnedHeader {
                name: header.name,
                value: header.value,
            })
            .collect(),
        body: response.body,
    }
}

fn map_deadline(error: DeadlineError) -> ClientError {
    match error {
        DeadlineError::InvalidTimeout => {
            ClientError::new(ClientErrorKind::InvalidTimeout, "invalid request timeout")
        }
        DeadlineError::Elapsed => {
            ClientError::new(ClientErrorKind::Timeout, "request deadline elapsed")
        }
    }
}

fn map_transport(error: TransportError) -> ClientError {
    let kind = if error.kind() == TransportErrorKind::Timeout {
        ClientErrorKind::Timeout
    } else {
        ClientErrorKind::Transport
    };
    ClientError::new(kind, error.message())
}
