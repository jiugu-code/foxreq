#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ChunkSizeError {
    Invalid,
    Overflow,
}

pub(super) fn parse_chunk_size(line: &[u8]) -> Result<usize, ChunkSizeError> {
    let semicolon = line.iter().position(|byte| *byte == b';');
    let (size, extension) = match semicolon {
        Some(position) => (&line[..position], Some(&line[position + 1..])),
        None => (line, None),
    };

    if size.is_empty() || !size.iter().all(u8::is_ascii_hexdigit) {
        return Err(ChunkSizeError::Invalid);
    }
    if extension.is_some_and(|value| !valid_extensions(value)) {
        return Err(ChunkSizeError::Invalid);
    }

    size.iter().try_fold(0usize, |parsed, digit| {
        parsed
            .checked_mul(16)
            .and_then(|parsed| parsed.checked_add(usize::from(hex_value(*digit))))
            .ok_or(ChunkSizeError::Overflow)
    })
}

fn valid_extensions(value: &[u8]) -> bool {
    if value.is_empty() {
        return false;
    }

    let mut position = 0usize;
    loop {
        skip_ows(value, &mut position);
        let name_start = position;
        while value.get(position).is_some_and(|byte| is_tchar(*byte)) {
            position += 1;
        }
        if position == name_start {
            return false;
        }
        skip_ows(value, &mut position);

        if value.get(position) == Some(&b'=') {
            position += 1;
            skip_ows(value, &mut position);
            if value.get(position) == Some(&b'"') {
                if !consume_quoted_string(value, &mut position) {
                    return false;
                }
            } else {
                let token_start = position;
                while value.get(position).is_some_and(|byte| is_tchar(*byte)) {
                    position += 1;
                }
                if position == token_start {
                    return false;
                }
            }
            skip_ows(value, &mut position);
        }

        if position == value.len() {
            return true;
        }
        if value[position] != b';' {
            return false;
        }
        position += 1;
        if position == value.len() {
            return false;
        }
    }
}

fn consume_quoted_string(value: &[u8], position: &mut usize) -> bool {
    *position += 1;
    while let Some(&byte) = value.get(*position) {
        match byte {
            b'"' => {
                *position += 1;
                return true;
            }
            b'\\' => {
                *position += 1;
                let Some(&escaped) = value.get(*position) else {
                    return false;
                };
                if !matches!(escaped, b'\t' | 0x20..=0x7e | 0x80..=0xff) {
                    return false;
                }
                *position += 1;
            }
            b'\t' | 0x20..=0x21 | 0x23..=0x5b | 0x5d..=0x7e | 0x80..=0xff => {
                *position += 1;
            }
            _ => return false,
        }
    }
    false
}

fn skip_ows(value: &[u8], position: &mut usize) {
    while value
        .get(*position)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        *position += 1;
    }
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

const fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}
