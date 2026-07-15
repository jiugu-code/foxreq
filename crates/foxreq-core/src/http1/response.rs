use std::mem;

use super::chunked::parse_chunk_size;
use super::{ResponseError, ResponseErrorKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Version {
    Http10,
    Http11,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestSemantics {
    Normal,
    Head,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseHeader {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseHead {
    pub version: Version,
    pub status: u16,
    pub reason: Vec<u8>,
    pub headers: Vec<ResponseHeader>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Response {
    pub version: Version,
    pub status: u16,
    pub reason: Vec<u8>,
    pub headers: Vec<ResponseHeader>,
    pub body: Vec<u8>,
    pub trailers: Vec<ResponseHeader>,
    pub informational: Vec<ResponseHead>,
    pub connection_close: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseLimits {
    pub max_line_bytes: usize,
    pub max_head_bytes: usize,
    pub max_headers: usize,
    pub max_body_bytes: usize,
    pub max_trailer_bytes: usize,
    pub max_trailers: usize,
    pub max_informational: usize,
}

impl Default for ResponseLimits {
    fn default() -> Self {
        Self {
            max_line_bytes: 8 * 1024,
            max_head_bytes: 64 * 1024,
            max_headers: 128,
            max_body_bytes: 64 * 1024 * 1024,
            max_trailer_bytes: 16 * 1024,
            max_trailers: 32,
            max_informational: 16,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FeedStatus {
    NeedMore,
    Complete(Response),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeedResult {
    pub consumed: usize,
    pub status: FeedStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    StatusLine,
    Headers,
    FixedBody { remaining: usize },
    ChunkSize,
    ChunkData { remaining: usize },
    ChunkTerminator { consumed: u8 },
    Trailers,
    CloseBody,
    Done,
}

#[derive(Default)]
struct CurrentHead {
    version: Option<Version>,
    status: u16,
    reason: Vec<u8>,
    headers: Vec<ResponseHeader>,
    content_length: Option<usize>,
    transfer_chunked: bool,
    connection_close: bool,
    connection_keep_alive: bool,
}

#[derive(Clone, Copy)]
enum LineSection {
    Head,
    Chunk,
    Trailer,
}

pub struct ResponseParser {
    semantics: RequestSemantics,
    limits: ResponseLimits,
    state: State,
    offset: usize,
    line_start: usize,
    line: Vec<u8>,
    pending_cr: bool,
    head_bytes: usize,
    trailer_bytes: usize,
    current: CurrentHead,
    informational: Vec<ResponseHead>,
    body: Vec<u8>,
    trailers: Vec<ResponseHeader>,
    final_connection_close: bool,
}

impl ResponseParser {
    #[must_use]
    pub fn new(semantics: RequestSemantics, limits: ResponseLimits) -> Self {
        Self {
            semantics,
            limits,
            state: State::StatusLine,
            offset: 0,
            line_start: 0,
            line: Vec::new(),
            pending_cr: false,
            head_bytes: 0,
            trailer_bytes: 0,
            current: CurrentHead::default(),
            informational: Vec::new(),
            body: Vec::new(),
            trailers: Vec::new(),
            final_connection_close: false,
        }
    }

    pub fn feed(&mut self, input: &[u8]) -> Result<FeedResult, ResponseError> {
        if self.state == State::Done {
            return Err(self.error(ResponseErrorKind::AlreadyComplete));
        }

        let mut consumed = 0usize;
        loop {
            match self.state {
                State::StatusLine => {
                    let Some((line, start)) =
                        self.read_line(input, &mut consumed, LineSection::Head)?
                    else {
                        return Ok(need_more(consumed));
                    };
                    self.parse_status_line(&line, start)?;
                    self.state = State::Headers;
                }
                State::Headers => {
                    let Some((line, start)) =
                        self.read_line(input, &mut consumed, LineSection::Head)?
                    else {
                        return Ok(need_more(consumed));
                    };
                    if line.is_empty() {
                        if let Some(response) = self.finish_headers(start)? {
                            return Ok(FeedResult {
                                consumed,
                                status: FeedStatus::Complete(response),
                            });
                        }
                    } else {
                        self.parse_header_line(&line, start, false)?;
                    }
                }
                State::FixedBody { remaining } => {
                    if consumed == input.len() {
                        return Ok(need_more(consumed));
                    }
                    let amount = remaining.min(input.len() - consumed);
                    self.body
                        .extend_from_slice(&input[consumed..consumed + amount]);
                    self.advance(amount)?;
                    consumed += amount;
                    let remaining = remaining - amount;
                    if remaining == 0 {
                        let response = self.complete_response()?;
                        return Ok(FeedResult {
                            consumed,
                            status: FeedStatus::Complete(response),
                        });
                    }
                    self.state = State::FixedBody { remaining };
                }
                State::ChunkSize => {
                    let Some((line, start)) =
                        self.read_line(input, &mut consumed, LineSection::Chunk)?
                    else {
                        return Ok(need_more(consumed));
                    };
                    let size = parse_chunk_size(&line).map_err(|_| {
                        ResponseError::new(ResponseErrorKind::InvalidChunkSize, start)
                    })?;
                    let body_length = self.body.len().checked_add(size).ok_or_else(|| {
                        ResponseError::new(ResponseErrorKind::BodyLimitExceeded, start)
                    })?;
                    if body_length > self.limits.max_body_bytes {
                        return Err(ResponseError::new(
                            ResponseErrorKind::BodyLimitExceeded,
                            start,
                        ));
                    }
                    self.state = if size == 0 {
                        State::Trailers
                    } else {
                        State::ChunkData { remaining: size }
                    };
                }
                State::ChunkData { remaining } => {
                    if consumed == input.len() {
                        return Ok(need_more(consumed));
                    }
                    let amount = remaining.min(input.len() - consumed);
                    self.body
                        .extend_from_slice(&input[consumed..consumed + amount]);
                    self.advance(amount)?;
                    consumed += amount;
                    let remaining = remaining - amount;
                    self.state = if remaining == 0 {
                        State::ChunkTerminator { consumed: 0 }
                    } else {
                        State::ChunkData { remaining }
                    };
                }
                State::ChunkTerminator {
                    consumed: terminator_consumed,
                } => {
                    if consumed == input.len() {
                        return Ok(need_more(consumed));
                    }
                    let expected = if terminator_consumed == 0 {
                        b'\r'
                    } else {
                        b'\n'
                    };
                    if input[consumed] != expected {
                        return Err(self.error(ResponseErrorKind::InvalidChunkTerminator));
                    }
                    self.advance(1)?;
                    consumed += 1;
                    if terminator_consumed == 0 {
                        self.state = State::ChunkTerminator { consumed: 1 };
                    } else {
                        self.line_start = self.offset;
                        self.state = State::ChunkSize;
                    }
                }
                State::Trailers => {
                    let Some((line, start)) =
                        self.read_line(input, &mut consumed, LineSection::Trailer)?
                    else {
                        return Ok(need_more(consumed));
                    };
                    if line.is_empty() {
                        let response = self.complete_response()?;
                        return Ok(FeedResult {
                            consumed,
                            status: FeedStatus::Complete(response),
                        });
                    }
                    self.parse_header_line(&line, start, true)?;
                }
                State::CloseBody => {
                    let amount = input.len() - consumed;
                    let new_length = self
                        .body
                        .len()
                        .checked_add(amount)
                        .ok_or_else(|| self.error(ResponseErrorKind::BodyLimitExceeded))?;
                    if new_length > self.limits.max_body_bytes {
                        let offset = self
                            .offset
                            .checked_add(self.limits.max_body_bytes - self.body.len())
                            .unwrap_or(self.offset);
                        return Err(ResponseError::new(
                            ResponseErrorKind::BodyLimitExceeded,
                            offset,
                        ));
                    }
                    self.body.extend_from_slice(&input[consumed..]);
                    self.advance(amount)?;
                    consumed = input.len();
                    return Ok(need_more(consumed));
                }
                State::Done => return Err(self.error(ResponseErrorKind::AlreadyComplete)),
            }
        }
    }

    pub fn finish_eof(&mut self) -> Result<Response, ResponseError> {
        match self.state {
            State::CloseBody if !self.pending_cr => self.complete_response(),
            State::Done => Err(self.error(ResponseErrorKind::AlreadyComplete)),
            _ => Err(self.error(ResponseErrorKind::UnexpectedEof)),
        }
    }

    fn read_line(
        &mut self,
        input: &[u8],
        consumed: &mut usize,
        section: LineSection,
    ) -> Result<Option<(Vec<u8>, usize)>, ResponseError> {
        loop {
            if self.pending_cr {
                if *consumed == input.len() {
                    return Ok(None);
                }
                if input[*consumed] != b'\n' {
                    return Err(ResponseError::new(
                        ResponseErrorKind::InvalidLineEnding,
                        self.offset.saturating_sub(1),
                    ));
                }
                self.advance(1)?;
                *consumed += 1;
                self.pending_cr = false;
                let start = self.line_start;
                self.record_line(section, self.line.len(), start)?;
                let line = mem::take(&mut self.line);
                self.line_start = self.offset;
                return Ok(Some((line, start)));
            }

            if *consumed == input.len() {
                return Ok(None);
            }
            let byte = input[*consumed];
            match byte {
                b'\n' => {
                    return Err(ResponseError::new(
                        ResponseErrorKind::BareLineFeed,
                        self.offset,
                    ));
                }
                b'\r' => {
                    self.ensure_line_fits(section, self.line.len(), self.line_start)?;
                    self.pending_cr = true;
                    self.advance(1)?;
                    *consumed += 1;
                }
                _ => {
                    let new_length = self
                        .line
                        .len()
                        .checked_add(1)
                        .ok_or_else(|| self.line_limit_error(section, self.line_start))?;
                    self.ensure_line_fits(section, new_length, self.line_start)?;
                    self.line.push(byte);
                    self.advance(1)?;
                    *consumed += 1;
                }
            }
        }
    }

    fn ensure_line_fits(
        &self,
        section: LineSection,
        line_length: usize,
        start: usize,
    ) -> Result<(), ResponseError> {
        if line_length > self.limits.max_line_bytes {
            return Err(self.line_limit_error(section, start));
        }
        let aggregate = match section {
            LineSection::Head => Some((self.head_bytes, self.limits.max_head_bytes)),
            LineSection::Trailer => Some((self.trailer_bytes, self.limits.max_trailer_bytes)),
            LineSection::Chunk => None,
        };
        if let Some((used, limit)) = aggregate {
            let complete_length = used
                .checked_add(line_length)
                .and_then(|length| length.checked_add(2));
            if complete_length.is_none_or(|length| length > limit) {
                return Err(self.line_limit_error(section, start));
            }
        }
        Ok(())
    }

    fn record_line(
        &mut self,
        section: LineSection,
        line_length: usize,
        start: usize,
    ) -> Result<(), ResponseError> {
        let framed_length = line_length
            .checked_add(2)
            .ok_or_else(|| self.line_limit_error(section, start))?;
        match section {
            LineSection::Head => {
                self.head_bytes = self
                    .head_bytes
                    .checked_add(framed_length)
                    .ok_or_else(|| self.line_limit_error(section, start))?;
            }
            LineSection::Trailer => {
                self.trailer_bytes = self
                    .trailer_bytes
                    .checked_add(framed_length)
                    .ok_or_else(|| self.line_limit_error(section, start))?;
            }
            LineSection::Chunk => {}
        }
        Ok(())
    }

    fn line_limit_error(&self, section: LineSection, offset: usize) -> ResponseError {
        let kind = match section {
            LineSection::Head | LineSection::Chunk => ResponseErrorKind::HeaderLimitExceeded,
            LineSection::Trailer => ResponseErrorKind::TrailerLimitExceeded,
        };
        ResponseError::new(kind, offset)
    }

    fn parse_status_line(&mut self, line: &[u8], start: usize) -> Result<(), ResponseError> {
        if line.len() < 13 || line[8] != b' ' || line[12] != b' ' {
            return Err(ResponseError::new(
                ResponseErrorKind::InvalidStatusLine,
                start,
            ));
        }
        let version = match &line[..8] {
            b"HTTP/1.0" => Version::Http10,
            b"HTTP/1.1" => Version::Http11,
            _ => {
                return Err(ResponseError::new(
                    ResponseErrorKind::InvalidStatusLine,
                    start,
                ));
            }
        };
        let digits = &line[9..12];
        if !digits.iter().all(u8::is_ascii_digit) {
            return Err(ResponseError::new(
                ResponseErrorKind::InvalidStatusCode,
                start + 9,
            ));
        }
        let status = u16::from(digits[0] - b'0') * 100
            + u16::from(digits[1] - b'0') * 10
            + u16::from(digits[2] - b'0');
        if !(100..=599).contains(&status) {
            return Err(ResponseError::new(
                ResponseErrorKind::InvalidStatusCode,
                start + 9,
            ));
        }
        let reason = &line[13..];
        if !is_valid_field_bytes(reason) {
            return Err(ResponseError::new(
                ResponseErrorKind::InvalidStatusLine,
                start + 13,
            ));
        }

        self.current.version = Some(version);
        self.current.status = status;
        self.current.reason = reason.to_vec();
        Ok(())
    }

    fn parse_header_line(
        &mut self,
        line: &[u8],
        start: usize,
        trailer: bool,
    ) -> Result<(), ResponseError> {
        if line
            .first()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            return Err(ResponseError::new(
                ResponseErrorKind::ObsoleteLineFolding,
                start,
            ));
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| ResponseError::new(ResponseErrorKind::InvalidHeaderName, start))?;
        let name = &line[..colon];
        let raw_value = &line[colon + 1..];
        if name.is_empty() || !name.iter().copied().all(is_tchar) {
            return Err(ResponseError::new(
                ResponseErrorKind::InvalidHeaderName,
                start,
            ));
        }
        if !is_valid_field_bytes(raw_value) {
            return Err(ResponseError::new(
                ResponseErrorKind::InvalidHeaderValue,
                start + colon + 1,
            ));
        }
        let value = trim_ows(raw_value);

        if trailer {
            if is_forbidden_trailer(name) {
                return Err(ResponseError::new(
                    ResponseErrorKind::ForbiddenTrailer,
                    start,
                ));
            }
            if self.trailers.len() >= self.limits.max_trailers {
                return Err(ResponseError::new(
                    ResponseErrorKind::TooManyTrailers,
                    start,
                ));
            }
            self.trailers.push(ResponseHeader {
                name: name.to_vec(),
                value: value.to_vec(),
            });
            return Ok(());
        }

        if self.current.headers.len() >= self.limits.max_headers {
            return Err(ResponseError::new(ResponseErrorKind::TooManyHeaders, start));
        }
        self.apply_header_semantics(name, value, start)?;
        self.current.headers.push(ResponseHeader {
            name: name.to_vec(),
            value: value.to_vec(),
        });
        Ok(())
    }

    fn apply_header_semantics(
        &mut self,
        name: &[u8],
        value: &[u8],
        start: usize,
    ) -> Result<(), ResponseError> {
        if name.eq_ignore_ascii_case(b"content-length") {
            let parsed = parse_content_length(value).ok_or_else(|| {
                ResponseError::new(ResponseErrorKind::InvalidContentLength, start)
            })?;
            if self
                .current
                .content_length
                .is_some_and(|existing| existing != parsed)
            {
                return Err(ResponseError::new(
                    ResponseErrorKind::ConflictingContentLength,
                    start,
                ));
            }
            self.current.content_length = Some(parsed);
            if self.current.transfer_chunked {
                return Err(ResponseError::new(
                    ResponseErrorKind::ConflictingFraming,
                    start,
                ));
            }
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            if self.current.transfer_chunked || !value.eq_ignore_ascii_case(b"chunked") {
                return Err(ResponseError::new(
                    ResponseErrorKind::UnsupportedTransferEncoding,
                    start,
                ));
            }
            self.current.transfer_chunked = true;
            if self.current.content_length.is_some() {
                return Err(ResponseError::new(
                    ResponseErrorKind::ConflictingFraming,
                    start,
                ));
            }
        } else if name.eq_ignore_ascii_case(b"connection") {
            for token in value.split(|byte| *byte == b',').map(trim_ows) {
                if token.is_empty() || !token.iter().copied().all(is_tchar) {
                    return Err(ResponseError::new(
                        ResponseErrorKind::InvalidHeaderValue,
                        start,
                    ));
                }
                self.current.connection_close |= token.eq_ignore_ascii_case(b"close");
                self.current.connection_keep_alive |= token.eq_ignore_ascii_case(b"keep-alive");
            }
        }
        Ok(())
    }

    fn finish_headers(&mut self, offset: usize) -> Result<Option<Response>, ResponseError> {
        let version = self
            .current
            .version
            .ok_or_else(|| ResponseError::new(ResponseErrorKind::InvalidStatusLine, offset))?;
        let status = self.current.status;

        if version == Version::Http10 && self.current.transfer_chunked {
            return Err(ResponseError::new(
                ResponseErrorKind::UnsupportedTransferEncoding,
                offset,
            ));
        }
        if status == 101 {
            return Err(ResponseError::new(
                ResponseErrorKind::UnsupportedUpgrade,
                offset,
            ));
        }
        if (100..=199).contains(&status) {
            if self.current.content_length.is_some() || self.current.transfer_chunked {
                return Err(ResponseError::new(
                    ResponseErrorKind::InvalidNoBodyFraming,
                    offset,
                ));
            }
            if self.informational.len() >= self.limits.max_informational {
                return Err(ResponseError::new(
                    ResponseErrorKind::TooManyInformational,
                    offset,
                ));
            }
            let head = self.take_current_head()?;
            self.informational.push(head);
            self.head_bytes = 0;
            self.state = State::StatusLine;
            return Ok(None);
        }

        self.final_connection_close = self.current.connection_close
            || (version == Version::Http10 && !self.current.connection_keep_alive);

        if status == 204 {
            if self.current.content_length.is_some() || self.current.transfer_chunked {
                return Err(ResponseError::new(
                    ResponseErrorKind::InvalidNoBodyFraming,
                    offset,
                ));
            }
            return self.complete_response().map(Some);
        }
        if status == 205 {
            if self.current.transfer_chunked
                || self
                    .current
                    .content_length
                    .is_some_and(|length| length != 0)
            {
                return Err(ResponseError::new(
                    ResponseErrorKind::InvalidNoBodyFraming,
                    offset,
                ));
            }
            return self.complete_response().map(Some);
        }
        if self.semantics == RequestSemantics::Head || status == 304 {
            return self.complete_response().map(Some);
        }

        if self.current.transfer_chunked {
            self.state = State::ChunkSize;
        } else if let Some(length) = self.current.content_length {
            if length > self.limits.max_body_bytes {
                return Err(ResponseError::new(
                    ResponseErrorKind::BodyLimitExceeded,
                    offset,
                ));
            }
            if length == 0 {
                return self.complete_response().map(Some);
            }
            self.state = State::FixedBody { remaining: length };
        } else {
            self.final_connection_close = true;
            self.state = State::CloseBody;
        }
        Ok(None)
    }

    fn take_current_head(&mut self) -> Result<ResponseHead, ResponseError> {
        let version = self
            .current
            .version
            .take()
            .ok_or_else(|| self.error(ResponseErrorKind::InvalidStatusLine))?;
        let current = mem::take(&mut self.current);
        Ok(ResponseHead {
            version,
            status: current.status,
            reason: current.reason,
            headers: current.headers,
        })
    }

    fn complete_response(&mut self) -> Result<Response, ResponseError> {
        let head = self.take_current_head()?;
        self.state = State::Done;
        Ok(Response {
            version: head.version,
            status: head.status,
            reason: head.reason,
            headers: head.headers,
            body: mem::take(&mut self.body),
            trailers: mem::take(&mut self.trailers),
            informational: mem::take(&mut self.informational),
            connection_close: self.final_connection_close,
        })
    }

    fn advance(&mut self, amount: usize) -> Result<(), ResponseError> {
        self.offset = self
            .offset
            .checked_add(amount)
            .ok_or_else(|| self.error(ResponseErrorKind::InputLimitExceeded))?;
        Ok(())
    }

    fn error(&self, kind: ResponseErrorKind) -> ResponseError {
        ResponseError::new(kind, self.offset)
    }
}

fn need_more(consumed: usize) -> FeedResult {
    FeedResult {
        consumed,
        status: FeedStatus::NeedMore,
    }
}

fn parse_content_length(value: &[u8]) -> Option<usize> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    value.iter().try_fold(0usize, |length, digit| {
        length
            .checked_mul(10)
            .and_then(|length| length.checked_add(usize::from(digit - b'0')))
    })
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn is_valid_field_bytes(value: &[u8]) -> bool {
    !value
        .iter()
        .any(|byte| matches!(byte, 0x00..=0x08 | 0x0a..=0x1f | 0x7f))
}

const fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_forbidden_trailer(name: &[u8]) -> bool {
    [
        b"content-length".as_slice(),
        b"transfer-encoding",
        b"host",
        b"connection",
        b"trailer",
        b"upgrade",
        b"te",
        b"proxy-authenticate",
        b"proxy-authorization",
    ]
    .iter()
    .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
}
