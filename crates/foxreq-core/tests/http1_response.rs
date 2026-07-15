use foxreq_core::http1::{
    FeedStatus, RequestSemantics, Response, ResponseLimits, ResponseParser, Version,
};

fn parse_at_split(wire: &[u8], split: usize, semantics: RequestSemantics) -> Response {
    let mut parser = ResponseParser::new(semantics, ResponseLimits::default());
    let first = parser.feed(&wire[..split]).unwrap();
    assert_eq!(first.consumed, split);
    match first.status {
        FeedStatus::Complete(response) => {
            assert_eq!(split, wire.len());
            response
        }
        FeedStatus::NeedMore => {
            let second = parser.feed(&wire[split..]).unwrap();
            assert_eq!(second.consumed, wire.len() - split);
            match second.status {
                FeedStatus::Complete(response) => response,
                FeedStatus::NeedMore => panic!("framed response remained incomplete"),
            }
        }
    }
}

fn assert_header(header: &foxreq_core::http1::ResponseHeader, name: &[u8], value: &[u8]) {
    assert_eq!(header.name, name);
    assert_eq!(header.value, value);
}

#[test]
fn parses_fixed_response_at_every_byte_split() {
    let wire = b"HTTP/1.1 200 OK\r\n\
                 Content-Length: 5\r\n\
                 Set-Cookie: a=1\r\n\
                 Set-Cookie: b=2\r\n\r\nhello";

    for split in 0..=wire.len() {
        let response = parse_at_split(wire, split, RequestSemantics::Normal);
        assert_eq!(response.version, Version::Http11);
        assert_eq!(response.status, 200);
        assert_eq!(response.reason, b"OK");
        assert_eq!(response.headers.len(), 3);
        assert_header(&response.headers[0], b"Content-Length", b"5");
        assert_header(&response.headers[1], b"Set-Cookie", b"a=1");
        assert_header(&response.headers[2], b"Set-Cookie", b"b=2");
        assert_eq!(response.body, b"hello");
        assert!(response.trailers.is_empty());
        assert!(response.informational.is_empty());
        assert!(!response.connection_close);
    }
}

#[test]
fn parses_chunk_extensions_and_trailers_at_every_byte_split() {
    let wire = b"HTTP/1.1 200 OK\r\n\
                 Transfer-Encoding: chunked\r\n\
                 Trailer: X-Checksum\r\n\r\n\
                 4;source=test\r\nWiki\r\n\
                 5\r\npedia\r\n\
                 0\r\n\
                 X-Checksum: done\r\n\r\n";

    for split in 0..=wire.len() {
        let response = parse_at_split(wire, split, RequestSemantics::Normal);
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"Wikipedia");
        assert_eq!(response.trailers.len(), 1);
        assert_header(&response.trailers[0], b"X-Checksum", b"done");
        assert!(!response.connection_close);
    }
}

#[test]
fn retains_informational_responses_before_the_final_response() {
    let wire = b"HTTP/1.1 100 Continue\r\n\
                 X-Info: yes\r\n\r\n\
                 HTTP/1.1 103 Early Hints\r\n\
                 Link: </style.css>; rel=preload\r\n\r\n\
                 HTTP/1.1 200 OK\r\n\
                 Content-Length: 0\r\n\r\n";

    for split in 0..=wire.len() {
        let response = parse_at_split(wire, split, RequestSemantics::Normal);
        assert_eq!(response.status, 200);
        assert_eq!(response.informational.len(), 2);
        assert_eq!(response.informational[0].status, 100);
        assert_eq!(response.informational[0].reason, b"Continue");
        assert_header(&response.informational[0].headers[0], b"X-Info", b"yes");
        assert_eq!(response.informational[1].status, 103);
    }
}

#[test]
fn head_and_no_body_statuses_stop_at_the_header_boundary() {
    let cases = [
        (
            RequestSemantics::Head,
            b"HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\n".as_slice(),
        ),
        (
            RequestSemantics::Normal,
            b"HTTP/1.1 204 No Content\r\n\r\n".as_slice(),
        ),
        (
            RequestSemantics::Normal,
            b"HTTP/1.1 304 Not Modified\r\nContent-Length: 123\r\n\r\n".as_slice(),
        ),
    ];

    for (semantics, head) in cases {
        let mut wire = head.to_vec();
        wire.extend_from_slice(b"HTTP/1.1 200 NEXT");
        let mut parser = ResponseParser::new(semantics, ResponseLimits::default());
        let result = parser.feed(&wire).unwrap();
        assert_eq!(result.consumed, head.len());
        match result.status {
            FeedStatus::Complete(response) => assert!(response.body.is_empty()),
            FeedStatus::NeedMore => panic!("no-body response remained incomplete"),
        }
        assert_eq!(&wire[result.consumed..], b"HTTP/1.1 200 NEXT");
    }
}

#[test]
fn close_delimited_body_completes_only_at_eof() {
    let wire = b"HTTP/1.0 200 OK\r\nX-Test: value\r\n\r\nclose body";

    for split in 0..=wire.len() {
        let mut parser = ResponseParser::new(RequestSemantics::Normal, ResponseLimits::default());
        let first = parser.feed(&wire[..split]).unwrap();
        assert_eq!(first.consumed, split);
        assert!(matches!(first.status, FeedStatus::NeedMore));
        let second = parser.feed(&wire[split..]).unwrap();
        assert_eq!(second.consumed, wire.len() - split);
        assert!(matches!(second.status, FeedStatus::NeedMore));

        let response = parser.finish_eof().unwrap();
        assert_eq!(response.version, Version::Http10);
        assert_eq!(response.body, b"close body");
        assert!(response.connection_close);
    }
}

#[test]
fn fixed_framing_leaves_the_next_response_unconsumed() {
    let first = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none";
    let next = b"HTTP/1.1 204 No Content\r\n\r\n";
    let wire = [first.as_slice(), next.as_slice()].concat();
    let mut parser = ResponseParser::new(RequestSemantics::Normal, ResponseLimits::default());
    let result = parser.feed(&wire).unwrap();

    assert_eq!(result.consumed, first.len());
    match result.status {
        FeedStatus::Complete(response) => assert_eq!(response.body, b"one"),
        FeedStatus::NeedMore => panic!("fixed response remained incomplete"),
    }
    assert_eq!(&wire[result.consumed..], next);
}

#[test]
fn identical_content_lengths_are_accepted_and_order_is_preserved() {
    let wire = b"HTTP/1.1 200 OK\r\n\
                 Content-Length: 3\r\n\
                 X-Between: yes\r\n\
                 content-length: 3\r\n\r\none";
    let response = parse_at_split(wire, 17, RequestSemantics::Normal);

    assert_eq!(response.body, b"one");
    assert_eq!(response.headers.len(), 3);
    assert_header(&response.headers[0], b"Content-Length", b"3");
    assert_header(&response.headers[1], b"X-Between", b"yes");
    assert_header(&response.headers[2], b"content-length", b"3");
}

#[test]
fn accepts_exact_head_and_trailer_boundaries() {
    let fixed = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Empty:\r\n\r\n";
    let response = {
        let mut parser = ResponseParser::new(
            RequestSemantics::Normal,
            ResponseLimits {
                max_line_bytes: b"Content-Length: 0".len(),
                max_head_bytes: fixed.len(),
                max_headers: 2,
                ..ResponseLimits::default()
            },
        );
        let result = parser.feed(fixed).unwrap();
        match result.status {
            FeedStatus::Complete(response) => response,
            FeedStatus::NeedMore => panic!("exact-limit response remained incomplete"),
        }
    };
    assert_header(&response.headers[1], b"X-Empty", b"");

    let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    0\r\nX-T: v\r\n\r\n";
    let trailer_section = b"X-T: v\r\n\r\n";
    let mut parser = ResponseParser::new(
        RequestSemantics::Normal,
        ResponseLimits {
            max_trailer_bytes: trailer_section.len(),
            max_trailers: 1,
            ..ResponseLimits::default()
        },
    );
    let result = parser.feed(chunked).unwrap();
    match result.status {
        FeedStatus::Complete(response) => assert_header(&response.trailers[0], b"X-T", b"v"),
        FeedStatus::NeedMore => panic!("exact-limit trailer remained incomplete"),
    }
}
