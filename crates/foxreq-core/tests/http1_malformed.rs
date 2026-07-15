use foxreq_core::http1::{
    FeedStatus, RequestSemantics, ResponseError, ResponseErrorKind, ResponseLimits, ResponseParser,
};

fn parse_error(wire: &[u8], limits: ResponseLimits) -> ResponseError {
    let mut parser = ResponseParser::new(RequestSemantics::Normal, limits);
    match parser.feed(wire) {
        Err(error) => error,
        Ok(result) => match result.status {
            FeedStatus::Complete(_) => panic!("malformed response was accepted"),
            FeedStatus::NeedMore => parser.finish_eof().unwrap_err(),
        },
    }
}

#[test]
fn rejects_bare_lf_invalid_line_endings_and_obsolete_folding() {
    let bare = parse_error(b"HTTP/1.1 200 OK\n", ResponseLimits::default());
    assert_eq!(bare.kind(), ResponseErrorKind::BareLineFeed);
    assert_eq!(bare.offset(), 15);

    let invalid = parse_error(b"HTTP/1.1 200 OK\rX", ResponseLimits::default());
    assert_eq!(invalid.kind(), ResponseErrorKind::InvalidLineEnding);

    let folded = parse_error(
        b"HTTP/1.1 200 OK\r\nX-Test: first\r\n second\r\n\r\n",
        ResponseLimits::default(),
    );
    assert_eq!(folded.kind(), ResponseErrorKind::ObsoleteLineFolding);
}

#[test]
fn rejects_invalid_status_lines_and_header_fields() {
    for wire in [
        b"HTTP/2.0 200 OK\r\n\r\n".as_slice(),
        b"HTTP/1.1 20A OK\r\n\r\n",
        b"HTTP/1.1 099 Bad\r\n\r\n",
        b"HTTP/1.1 600 Bad\r\n\r\n",
        b"HTTP/1.1 200\r\n\r\n",
    ] {
        let error = parse_error(wire, ResponseLimits::default());
        assert!(matches!(
            error.kind(),
            ResponseErrorKind::InvalidStatusLine | ResponseErrorKind::InvalidStatusCode
        ));
    }

    let invalid_name = parse_error(
        b"HTTP/1.1 200 OK\r\nBad Name: value\r\n\r\n",
        ResponseLimits::default(),
    );
    assert_eq!(invalid_name.kind(), ResponseErrorKind::InvalidHeaderName);

    let invalid_value = parse_error(
        b"HTTP/1.1 200 OK\r\nX-Test: one\0two\r\n\r\n",
        ResponseLimits::default(),
    );
    assert_eq!(invalid_value.kind(), ResponseErrorKind::InvalidHeaderValue);
}

#[test]
fn enforces_line_aggregate_header_and_count_limits() {
    let status_line = parse_error(
        b"HTTP/1.1 200 Reason-too-long\r\n\r\n",
        ResponseLimits {
            max_line_bytes: 15,
            ..ResponseLimits::default()
        },
    );
    assert_eq!(status_line.kind(), ResponseErrorKind::HeaderLimitExceeded);

    let aggregate = parse_error(
        b"HTTP/1.1 200 OK\r\nX-One: 1\r\nX-Two: 2\r\n\r\n",
        ResponseLimits {
            max_head_bytes: 35,
            ..ResponseLimits::default()
        },
    );
    assert_eq!(aggregate.kind(), ResponseErrorKind::HeaderLimitExceeded);

    let count = parse_error(
        b"HTTP/1.1 200 OK\r\nX-One: 1\r\nX-Two: 2\r\n\r\n",
        ResponseLimits {
            max_headers: 1,
            ..ResponseLimits::default()
        },
    );
    assert_eq!(count.kind(), ResponseErrorKind::TooManyHeaders);
}

#[test]
fn rejects_invalid_conflicting_or_ambiguous_framing() {
    for value in [b"".as_slice(), b"+3", b"3, 3", b"18446744073709551616"] {
        let mut wire = b"HTTP/1.1 200 OK\r\nContent-Length: ".to_vec();
        wire.extend_from_slice(value);
        wire.extend_from_slice(b"\r\n\r\n");
        let error = parse_error(&wire, ResponseLimits::default());
        assert_eq!(error.kind(), ResponseErrorKind::InvalidContentLength);
    }

    let conflict = parse_error(
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\ncontent-length: 4\r\n\r\n",
        ResponseLimits::default(),
    );
    assert_eq!(conflict.kind(), ResponseErrorKind::ConflictingContentLength);

    let both = parse_error(
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
        ResponseLimits::default(),
    );
    assert_eq!(both.kind(), ResponseErrorKind::ConflictingFraming);

    for value in [b"gzip".as_slice(), b"gzip, chunked", b"chunked, chunked"] {
        let mut wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: ".to_vec();
        wire.extend_from_slice(value);
        wire.extend_from_slice(b"\r\n\r\n");
        let error = parse_error(&wire, ResponseLimits::default());
        assert_eq!(error.kind(), ResponseErrorKind::UnsupportedTransferEncoding);
    }
}

#[test]
fn rejects_invalid_chunks_and_forbidden_trailers() {
    for chunked in [
        b"z\r\n".as_slice(),
        b"+1\r\na\r\n0\r\n\r\n",
        b"1;\r\na\r\n0\r\n\r\n",
        b"1;bad name=value\r\na\r\n0\r\n\r\n",
        b"10000000000000000\r\n",
        b"1\r\naX\n0\r\n\r\n",
    ] {
        let mut wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        wire.extend_from_slice(chunked);
        let error = parse_error(&wire, ResponseLimits::default());
        assert!(matches!(
            error.kind(),
            ResponseErrorKind::InvalidChunkSize
                | ResponseErrorKind::InvalidChunkTerminator
                | ResponseErrorKind::UnexpectedEof
        ));
    }

    let forbidden = parse_error(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
          0\r\nContent-Length: 3\r\n\r\n",
        ResponseLimits::default(),
    );
    assert_eq!(forbidden.kind(), ResponseErrorKind::ForbiddenTrailer);
}

#[test]
fn enforces_trailer_and_informational_limits() {
    let trailers = parse_error(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
          0\r\nX-One: 1\r\nX-Two: 2\r\n\r\n",
        ResponseLimits {
            max_trailers: 1,
            ..ResponseLimits::default()
        },
    );
    assert_eq!(trailers.kind(), ResponseErrorKind::TooManyTrailers);

    let trailer_bytes = parse_error(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
          0\r\nX-Test: value\r\n\r\n",
        ResponseLimits {
            max_trailer_bytes: b"X-Test: value\r\n\r\n".len() - 1,
            ..ResponseLimits::default()
        },
    );
    assert_eq!(
        trailer_bytes.kind(),
        ResponseErrorKind::TrailerLimitExceeded
    );

    let informational = parse_error(
        b"HTTP/1.1 100 Continue\r\n\r\n\
          HTTP/1.1 103 Early Hints\r\n\r\n\
          HTTP/1.1 204 No Content\r\n\r\n",
        ResponseLimits {
            max_informational: 1,
            ..ResponseLimits::default()
        },
    );
    assert_eq!(
        informational.kind(),
        ResponseErrorKind::TooManyInformational
    );
}

#[test]
fn rejects_chunked_transfer_encoding_on_http_10() {
    let error = parse_error(
        b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        ResponseLimits::default(),
    );
    assert_eq!(error.kind(), ResponseErrorKind::UnsupportedTransferEncoding);
}

#[test]
fn rejects_premature_eof_and_body_limit_overruns() {
    for wire in [
        b"HTTP/1.1 200".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nab",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab",
    ] {
        let error = parse_error(wire, ResponseLimits::default());
        assert_eq!(error.kind(), ResponseErrorKind::UnexpectedEof);
    }

    for wire in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n1234".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n1234\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n\r\n1234",
    ] {
        let error = parse_error(
            wire,
            ResponseLimits {
                max_body_bytes: 3,
                ..ResponseLimits::default()
            },
        );
        assert_eq!(error.kind(), ResponseErrorKind::BodyLimitExceeded);
    }
}

#[test]
fn rejects_forbidden_framing_on_informational_and_204_responses() {
    for wire in [
        b"HTTP/1.1 100 Continue\r\nContent-Length: 1\r\n\r\n".as_slice(),
        b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n",
    ] {
        let error = parse_error(wire, ResponseLimits::default());
        assert_eq!(error.kind(), ResponseErrorKind::InvalidNoBodyFraming);
    }

    let upgrade = parse_error(
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\n\r\n",
        ResponseLimits::default(),
    );
    assert_eq!(upgrade.kind(), ResponseErrorKind::UnsupportedUpgrade);
}
