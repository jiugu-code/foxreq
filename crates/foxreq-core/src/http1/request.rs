use super::{Error, ErrorKind};

pub type Header<'a> = (&'a [u8], &'a [u8]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestBody<'a> {
    None,
    Fixed(&'a [u8]),
    Chunked(&'a [&'a [u8]]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request<'a> {
    pub method: &'a [u8],
    pub target: &'a [u8],
    pub authority: &'a [u8],
    pub headers: &'a [Header<'a>],
    pub body: RequestBody<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestLimits {
    pub max_header_bytes: usize,
    pub max_body_bytes: usize,
    pub max_headers: usize,
}

impl Default for RequestLimits {
    fn default() -> Self {
        Self {
            max_header_bytes: 64 * 1024,
            max_body_bytes: 64 * 1024 * 1024,
            max_headers: 128,
        }
    }
}

#[derive(Clone, Copy)]
enum Framing {
    None,
    Fixed { length: usize, add_header: bool },
    Chunked { add_header: bool },
}

pub fn serialize_request(request: &Request<'_>, limits: RequestLimits) -> Result<Vec<u8>, Error> {
    validate_method(request.method)?;
    let target = validate_target(request.target)?;

    let mut host_count = 0usize;
    let mut content_length = None;
    let mut transfer_encoding = None;

    for &(name, value) in request.headers {
        validate_header_name(name)?;
        validate_header_value(value)?;

        if name.eq_ignore_ascii_case(b"host") {
            if !is_valid_authority(value) {
                return Err(Error::new(ErrorKind::InvalidAuthority));
            }
            host_count += 1;
            if host_count > 1 {
                return Err(Error::new(ErrorKind::DuplicateHost));
            }
        } else if name.eq_ignore_ascii_case(b"content-length") {
            if content_length.is_some() {
                return Err(Error::new(ErrorKind::DuplicateContentLength));
            }
            content_length = Some(parse_content_length(value)?);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            if transfer_encoding.is_some() {
                return Err(Error::new(ErrorKind::DuplicateTransferEncoding));
            }
            transfer_encoding = Some(value);
        }
    }

    if content_length.is_some() && transfer_encoding.is_some() {
        return Err(Error::new(ErrorKind::ConflictingFraming));
    }

    if host_count == 0 && !is_valid_authority(request.authority) {
        return Err(Error::new(ErrorKind::InvalidAuthority));
    }

    let framing = validate_framing(request.body, content_length, transfer_encoding, limits)?;
    let automatic_headers = usize::from(host_count == 0)
        + usize::from(matches!(
            framing,
            Framing::Fixed {
                add_header: true,
                ..
            } | Framing::Chunked { add_header: true }
        ));
    let header_count = request
        .headers
        .len()
        .checked_add(automatic_headers)
        .ok_or_else(|| Error::new(ErrorKind::HeaderLimitExceeded))?;
    if header_count > limits.max_headers {
        return Err(Error::new(ErrorKind::HeaderLimitExceeded));
    }

    let mut output = Vec::new();
    append_header_bytes(&mut output, request.method, limits.max_header_bytes)?;
    append_header_bytes(&mut output, b" ", limits.max_header_bytes)?;
    append_header_bytes(&mut output, target, limits.max_header_bytes)?;
    append_header_bytes(&mut output, b" HTTP/1.1\r\n", limits.max_header_bytes)?;

    if host_count == 0 {
        append_header(
            &mut output,
            b"Host",
            request.authority,
            limits.max_header_bytes,
        )?;
    }
    for &(name, value) in request.headers {
        append_header(&mut output, name, value, limits.max_header_bytes)?;
    }

    match framing {
        Framing::Fixed {
            length,
            add_header: true,
        } => append_usize_header(
            &mut output,
            b"Content-Length",
            length,
            limits.max_header_bytes,
        )?,
        Framing::Chunked { add_header: true } => append_header(
            &mut output,
            b"Transfer-Encoding",
            b"chunked",
            limits.max_header_bytes,
        )?,
        Framing::None
        | Framing::Fixed {
            add_header: false, ..
        }
        | Framing::Chunked { add_header: false } => {}
    }
    append_header_bytes(&mut output, b"\r\n", limits.max_header_bytes)?;

    match request.body {
        RequestBody::None => {}
        RequestBody::Fixed(body) => output.extend_from_slice(body),
        RequestBody::Chunked(chunks) => append_chunked_body(&mut output, chunks),
    }

    Ok(output)
}

fn validate_method(method: &[u8]) -> Result<(), Error> {
    if method.is_empty() || !method.iter().copied().all(is_tchar) {
        return Err(Error::new(ErrorKind::InvalidMethod));
    }
    if method.eq_ignore_ascii_case(b"connect") {
        return Err(Error::new(ErrorKind::UnsupportedMethod));
    }
    Ok(())
}

fn validate_target(target: &[u8]) -> Result<&[u8], Error> {
    if target.is_empty() {
        return Ok(b"/");
    }
    if target[0] != b'/'
        || target
            .iter()
            .any(|byte| !matches!(byte, 0x21..=0x7e) || *byte == b'#')
    {
        return Err(Error::new(ErrorKind::InvalidTarget));
    }
    Ok(target)
}

fn validate_header_name(name: &[u8]) -> Result<(), Error> {
    if name.is_empty() || !name.iter().copied().all(is_tchar) {
        return Err(Error::new(ErrorKind::InvalidHeaderName));
    }
    Ok(())
}

fn validate_header_value(value: &[u8]) -> Result<(), Error> {
    if value
        .iter()
        .any(|byte| matches!(byte, 0x00..=0x08 | 0x0a..=0x1f | 0x7f))
    {
        return Err(Error::new(ErrorKind::InvalidHeaderValue));
    }
    Ok(())
}

fn is_valid_authority(authority: &[u8]) -> bool {
    !authority.is_empty()
        && authority.iter().all(|byte| {
            matches!(byte, 0x21..=0x7e) && !matches!(byte, b'/' | b'?' | b'#' | b'@' | b'\\')
        })
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

fn parse_content_length(value: &[u8]) -> Result<usize, Error> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return Err(Error::new(ErrorKind::InvalidContentLength));
    }
    value.iter().try_fold(0usize, |length, digit| {
        length
            .checked_mul(10)
            .and_then(|length| length.checked_add(usize::from(digit - b'0')))
            .ok_or_else(|| Error::new(ErrorKind::InvalidContentLength))
    })
}

fn validate_framing(
    body: RequestBody<'_>,
    content_length: Option<usize>,
    transfer_encoding: Option<&[u8]>,
    limits: RequestLimits,
) -> Result<Framing, Error> {
    match body {
        RequestBody::None => {
            if transfer_encoding.is_some() {
                return Err(Error::new(ErrorKind::UnsupportedTransferEncoding));
            }
            if content_length.is_some_and(|length| length != 0) {
                return Err(Error::new(ErrorKind::ContentLengthMismatch));
            }
            Ok(Framing::None)
        }
        RequestBody::Fixed(body) => {
            if body.len() > limits.max_body_bytes {
                return Err(Error::new(ErrorKind::BodyLimitExceeded));
            }
            if transfer_encoding.is_some() {
                return Err(Error::new(ErrorKind::UnsupportedTransferEncoding));
            }
            if content_length.is_some_and(|length| length != body.len()) {
                return Err(Error::new(ErrorKind::ContentLengthMismatch));
            }
            Ok(Framing::Fixed {
                length: body.len(),
                add_header: content_length.is_none(),
            })
        }
        RequestBody::Chunked(chunks) => {
            if transfer_encoding
                .is_some_and(|value| !trim_ows(value).eq_ignore_ascii_case(b"chunked"))
            {
                return Err(Error::new(ErrorKind::UnsupportedTransferEncoding));
            }
            let mut length = 0usize;
            for chunk in chunks {
                if chunk.is_empty() {
                    return Err(Error::new(ErrorKind::InvalidChunk));
                }
                length = length
                    .checked_add(chunk.len())
                    .ok_or_else(|| Error::new(ErrorKind::BodyLimitExceeded))?;
                if length > limits.max_body_bytes {
                    return Err(Error::new(ErrorKind::BodyLimitExceeded));
                }
            }
            Ok(Framing::Chunked {
                add_header: transfer_encoding.is_none(),
            })
        }
    }
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

fn append_header(
    output: &mut Vec<u8>,
    name: &[u8],
    value: &[u8],
    limit: usize,
) -> Result<(), Error> {
    append_header_bytes(output, name, limit)?;
    append_header_bytes(output, b": ", limit)?;
    append_header_bytes(output, value, limit)?;
    append_header_bytes(output, b"\r\n", limit)
}

fn append_usize_header(
    output: &mut Vec<u8>,
    name: &[u8],
    value: usize,
    limit: usize,
) -> Result<(), Error> {
    let mut digits = [0u8; usize::BITS as usize / 3 + 1];
    let start = write_decimal(&mut digits, value);
    append_header(output, name, &digits[start..], limit)
}

fn append_header_bytes(output: &mut Vec<u8>, bytes: &[u8], limit: usize) -> Result<(), Error> {
    let new_length = output
        .len()
        .checked_add(bytes.len())
        .ok_or_else(|| Error::new(ErrorKind::HeaderLimitExceeded))?;
    if new_length > limit {
        return Err(Error::new(ErrorKind::HeaderLimitExceeded));
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn write_decimal(buffer: &mut [u8], mut value: usize) -> usize {
    let mut position = buffer.len();
    loop {
        position -= 1;
        buffer[position] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            return position;
        }
    }
}

fn append_chunked_body(output: &mut Vec<u8>, chunks: &[&[u8]]) {
    for chunk in chunks {
        append_hex(output, chunk.len());
        output.extend_from_slice(b"\r\n");
        output.extend_from_slice(chunk);
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"0\r\n\r\n");
}

fn append_hex(output: &mut Vec<u8>, mut value: usize) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut digits = [0u8; usize::BITS as usize / 4];
    let mut position = digits.len();
    loop {
        position -= 1;
        digits[position] = HEX[value & 0x0f];
        value >>= 4;
        if value == 0 {
            output.extend_from_slice(&digits[position..]);
            return;
        }
    }
}
