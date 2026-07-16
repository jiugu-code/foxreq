use std::net::Ipv6Addr;

use crate::transport::Scheme;

use super::{ClientError, ClientErrorKind};

pub(super) struct ParsedUrl {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub authority: Vec<u8>,
    pub target: Vec<u8>,
}

pub(super) fn parse_url(url: &str) -> Result<ParsedUrl, ClientError> {
    let (scheme, default_port, remainder) = if let Some(remainder) = url.strip_prefix("http://") {
        (Scheme::Http, 80, remainder)
    } else if let Some(remainder) = url.strip_prefix("https://") {
        (Scheme::Https, 443, remainder)
    } else {
        return Err(invalid_url());
    };
    if remainder.is_empty()
        || remainder.contains('#')
        || remainder
            .bytes()
            .any(|byte| !byte.is_ascii() || byte.is_ascii_control())
    {
        return Err(invalid_url());
    }
    let authority_end = remainder.find(['/', '?']).unwrap_or(remainder.len());
    let authority_text = &remainder[..authority_end];
    if authority_text.is_empty() || authority_text.contains('@') || authority_text.contains('\\') {
        return Err(invalid_url());
    }
    let suffix = &remainder[authority_end..];
    let target = if suffix.is_empty() {
        "/".to_owned()
    } else if suffix.starts_with('?') {
        format!("/{suffix}")
    } else {
        suffix.to_owned()
    };
    if target
        .bytes()
        .any(|byte| !matches!(byte, 0x21..=0x7e) || byte == b'\\')
        || !valid_percent_encoding(target.as_bytes())
    {
        return Err(invalid_url());
    }

    let (host, port) = parse_authority(authority_text, default_port)?;
    Ok(ParsedUrl {
        scheme,
        host,
        port,
        authority: authority_text.as_bytes().to_vec(),
        target: target.into_bytes(),
    })
}

fn valid_percent_encoding(value: &[u8]) -> bool {
    let mut index = 0usize;
    while index < value.len() {
        if value[index] == b'%' {
            if index + 2 >= value.len()
                || !value[index + 1].is_ascii_hexdigit()
                || !value[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

fn parse_authority(authority: &str, default_port: u16) -> Result<(String, u16), ClientError> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let end = bracketed.find(']').ok_or_else(invalid_url)?;
        let host = &bracketed[..end];
        host.parse::<Ipv6Addr>().map_err(|_| invalid_url())?;
        let tail = &bracketed[end + 1..];
        let port = if tail.is_empty() {
            default_port
        } else {
            parse_port(tail.strip_prefix(':').ok_or_else(invalid_url)?)?
        };
        return Ok((host.to_ascii_lowercase(), port));
    }
    if authority.contains('[') || authority.contains(']') {
        return Err(invalid_url());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, parse_port(port)?),
        Some(_) => return Err(invalid_url()),
        None => (authority, default_port),
    };
    if !valid_ascii_host(host) {
        return Err(invalid_url());
    }
    Ok((host.to_ascii_lowercase(), port))
}

fn parse_port(port: &str) -> Result<u16, ClientError> {
    let port = port.parse::<u16>().map_err(|_| invalid_url())?;
    if port == 0 {
        Err(invalid_url())
    } else {
        Ok(port)
    }
}

fn valid_ascii_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn invalid_url() -> ClientError {
    ClientError::new(ClientErrorKind::InvalidUrl, "invalid HTTP URL")
}
