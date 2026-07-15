use foxreq_core::http1::{serialize_request, ErrorKind, Request, RequestBody, RequestLimits};

fn serialize<'a>(
    method: &'a [u8],
    target: &'a [u8],
    authority: &'a [u8],
    headers: &'a [(&'a [u8], &'a [u8])],
    body: RequestBody<'a>,
) -> Result<Vec<u8>, foxreq_core::http1::Error> {
    serialize_request(
        &Request {
            method,
            target,
            authority,
            headers,
            body,
        },
        RequestLimits::default(),
    )
}

#[test]
fn serializes_origin_form_and_preserves_header_bytes() {
    let bytes = serialize(
        b"GET",
        b"/search?q=firefox",
        b"example.test",
        &[(b"Accept", b"*/*"), (b"X-Mixed-Case", b"Value")],
        RequestBody::None,
    )
    .unwrap();

    assert_eq!(
        bytes,
        b"GET /search?q=firefox HTTP/1.1\r\n\
          Host: example.test\r\n\
          Accept: */*\r\n\
          X-Mixed-Case: Value\r\n\r\n"
    );
}

#[test]
fn empty_target_becomes_slash() {
    let bytes = serialize(b"GET", b"", b"example.test", &[], RequestBody::None).unwrap();

    assert_eq!(bytes, b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n");
}

#[test]
fn user_host_is_preserved_in_place() {
    let bytes = serialize(
        b"GET",
        b"/",
        b"ignored.test",
        &[
            (b"Accept", b"text/plain"),
            (b"host", b"override.test:8443"),
            (b"X-After", b"yes"),
        ],
        RequestBody::None,
    )
    .unwrap();

    assert_eq!(
        bytes,
        b"GET / HTTP/1.1\r\n\
          Accept: text/plain\r\n\
          host: override.test:8443\r\n\
          X-After: yes\r\n\r\n"
    );
}

#[test]
fn fixed_body_adds_or_preserves_content_length() {
    let added = serialize(
        b"POST",
        b"/submit",
        b"example.test",
        &[(b"Content-Type", b"text/plain")],
        RequestBody::Fixed(b"hello"),
    )
    .unwrap();
    assert_eq!(
        added,
        b"POST /submit HTTP/1.1\r\n\
          Host: example.test\r\n\
          Content-Type: text/plain\r\n\
          Content-Length: 5\r\n\r\nhello"
    );

    let empty = serialize(
        b"POST",
        b"/empty",
        b"example.test",
        &[(b"content-length", b"0")],
        RequestBody::Fixed(b""),
    )
    .unwrap();
    assert_eq!(
        empty,
        b"POST /empty HTTP/1.1\r\n\
          Host: example.test\r\n\
          content-length: 0\r\n\r\n"
    );
}

#[test]
fn chunked_body_has_deterministic_framing() {
    let chunks: &[&[u8]] = &[b"Wiki", b"pedia"];
    let bytes = serialize(
        b"POST",
        b"/chunks",
        b"example.test",
        &[(b"Transfer-Encoding", b"chunked")],
        RequestBody::Chunked(chunks),
    )
    .unwrap();

    assert_eq!(
        bytes,
        b"POST /chunks HTTP/1.1\r\n\
          Host: example.test\r\n\
          Transfer-Encoding: chunked\r\n\r\n\
          4\r\nWiki\r\n\
          5\r\npedia\r\n\
          0\r\n\r\n"
    );

    let no_chunks: &[&[u8]] = &[];
    let empty = serialize(
        b"POST",
        b"/chunks",
        b"example.test",
        &[],
        RequestBody::Chunked(no_chunks),
    )
    .unwrap();
    assert_eq!(
        empty,
        b"POST /chunks HTTP/1.1\r\n\
          Host: example.test\r\n\
          Transfer-Encoding: chunked\r\n\r\n\
          0\r\n\r\n"
    );
}

#[test]
fn rejects_invalid_method_and_unsupported_connect() {
    for method in [b"".as_slice(), b"GE T", b"GET\r\nInjected:"] {
        let error = serialize(method, b"/", b"example.test", &[], RequestBody::None).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidMethod);
    }

    let error = serialize(
        b"CONNECT",
        b"example.test:443",
        b"example.test",
        &[],
        RequestBody::None,
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnsupportedMethod);
}

#[test]
fn rejects_absolute_fragmented_or_invalid_targets() {
    for target in [
        b"http://example.test/".as_slice(),
        b"https://example.test/",
        b"/path#fragment",
        b"/space here",
        b"relative",
        b"/line\r\nbreak",
    ] {
        let error = serialize(b"GET", target, b"example.test", &[], RequestBody::None).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidTarget);
    }
}

#[test]
fn rejects_invalid_header_names_values_and_duplicate_host() {
    let cases: &[(&[u8], &[u8], ErrorKind)] = &[
        (b"Bad Name", b"value", ErrorKind::InvalidHeaderName),
        (b":authority", b"value", ErrorKind::InvalidHeaderName),
        (
            b"X-Test",
            b"one\r\nInjected: yes",
            ErrorKind::InvalidHeaderValue,
        ),
        (b"X-Test", b"nul\0value", ErrorKind::InvalidHeaderValue),
    ];
    for (name, value, kind) in cases {
        let error = serialize(
            b"GET",
            b"/",
            b"example.test",
            &[(*name, *value)],
            RequestBody::None,
        )
        .unwrap_err();
        assert_eq!(error.kind(), *kind);
    }

    let error = serialize(
        b"GET",
        b"/",
        b"example.test",
        &[(b"Host", b"one.test"), (b"host", b"two.test")],
        RequestBody::None,
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::DuplicateHost);
}

#[test]
fn rejects_ambiguous_or_mismatched_framing() {
    let both = serialize(
        b"POST",
        b"/",
        b"example.test",
        &[
            (b"Content-Length", b"3"),
            (b"Transfer-Encoding", b"chunked"),
        ],
        RequestBody::Fixed(b"abc"),
    )
    .unwrap_err();
    assert_eq!(both.kind(), ErrorKind::ConflictingFraming);

    let duplicate = serialize(
        b"POST",
        b"/",
        b"example.test",
        &[(b"Content-Length", b"3"), (b"Content-Length", b"3")],
        RequestBody::Fixed(b"abc"),
    )
    .unwrap_err();
    assert_eq!(duplicate.kind(), ErrorKind::DuplicateContentLength);

    for value in [b"2".as_slice(), b"+3", b"3, 3", b"18446744073709551616"] {
        let error = serialize(
            b"POST",
            b"/",
            b"example.test",
            &[(b"Content-Length", value)],
            RequestBody::Fixed(b"abc"),
        )
        .unwrap_err();
        assert!(matches!(
            error.kind(),
            ErrorKind::InvalidContentLength | ErrorKind::ContentLengthMismatch
        ));
    }

    let unsupported = serialize(
        b"POST",
        b"/",
        b"example.test",
        &[(b"Transfer-Encoding", b"gzip")],
        RequestBody::Chunked(&[b"abc"]),
    )
    .unwrap_err();
    assert_eq!(unsupported.kind(), ErrorKind::UnsupportedTransferEncoding);
}

#[test]
fn rejects_empty_chunks_and_limit_overruns() {
    let chunks_with_empty: &[&[u8]] = &[b"abc", b""];
    let error = serialize(
        b"POST",
        b"/",
        b"example.test",
        &[],
        RequestBody::Chunked(chunks_with_empty),
    )
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidChunk);

    let request = Request {
        method: b"POST",
        target: b"/",
        authority: b"example.test",
        headers: &[(b"X-Large", b"value")],
        body: RequestBody::Fixed(b"1234"),
    };
    let header_error = serialize_request(
        &request,
        RequestLimits {
            max_header_bytes: 20,
            ..RequestLimits::default()
        },
    )
    .unwrap_err();
    assert_eq!(header_error.kind(), ErrorKind::HeaderLimitExceeded);

    let body_error = serialize_request(
        &request,
        RequestLimits {
            max_body_bytes: 3,
            ..RequestLimits::default()
        },
    )
    .unwrap_err();
    assert_eq!(body_error.kind(), ErrorKind::BodyLimitExceeded);
}

#[test]
fn enforces_token_and_empty_field_boundaries() {
    let empty_name = serialize(
        b"GET",
        b"/",
        b"example.test",
        &[(b"", b"value")],
        RequestBody::None,
    )
    .unwrap_err();
    assert_eq!(empty_name.kind(), ErrorKind::InvalidHeaderName);

    let empty_value = serialize(
        b"GET",
        b"/",
        b"example.test",
        &[(b"X-Empty", b"")],
        RequestBody::None,
    )
    .unwrap();
    assert_eq!(
        empty_value,
        b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Empty: \r\n\r\n"
    );

    let invalid_method =
        serialize(b"G\xc3\x89T", b"/", b"example.test", &[], RequestBody::None).unwrap_err();
    assert_eq!(invalid_method.kind(), ErrorKind::InvalidMethod);

    let invalid_name = serialize(
        b"GET",
        b"/",
        b"example.test",
        &[(b"X-\xff", b"value")],
        RequestBody::None,
    )
    .unwrap_err();
    assert_eq!(invalid_name.kind(), ErrorKind::InvalidHeaderName);

    let invalid_target =
        serialize(b"GET", b"/\xff", b"example.test", &[], RequestBody::None).unwrap_err();
    assert_eq!(invalid_target.kind(), ErrorKind::InvalidTarget);

    for host in [b"".as_slice(), b"bad host", b"user@example.test"] {
        let error = serialize(
            b"GET",
            b"/",
            b"ignored.test",
            &[(b"Host", host)],
            RequestBody::None,
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidAuthority);
    }
}

#[test]
fn accepts_exact_header_limits_and_rejects_one_byte_over() {
    let request = Request {
        method: b"GET",
        target: b"/",
        authority: b"example.test",
        headers: &[(b"X-Test", b"value")],
        body: RequestBody::None,
    };
    let expected = serialize_request(&request, RequestLimits::default()).unwrap();

    let exact = serialize_request(
        &request,
        RequestLimits {
            max_header_bytes: expected.len(),
            max_headers: 2,
            ..RequestLimits::default()
        },
    )
    .unwrap();
    assert_eq!(exact, expected);

    let bytes_over = serialize_request(
        &request,
        RequestLimits {
            max_header_bytes: expected.len() - 1,
            ..RequestLimits::default()
        },
    )
    .unwrap_err();
    assert_eq!(bytes_over.kind(), ErrorKind::HeaderLimitExceeded);

    let count_over = serialize_request(
        &request,
        RequestLimits {
            max_headers: 1,
            ..RequestLimits::default()
        },
    )
    .unwrap_err();
    assert_eq!(count_over.kind(), ErrorKind::HeaderLimitExceeded);
}

#[test]
fn chunk_lengths_cross_hex_digit_boundaries() {
    let fifteen = [b'a'; 15];
    let sixteen = [b'b'; 16];
    let chunks: &[&[u8]] = &[&fifteen, &sixteen];
    let bytes = serialize(
        b"POST",
        b"/chunks",
        b"example.test",
        &[],
        RequestBody::Chunked(chunks),
    )
    .unwrap();
    let expected = [
        b"POST /chunks HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n"
            .as_slice(),
        b"f\r\n",
        fifteen.as_slice(),
        b"\r\n10\r\n",
        sixteen.as_slice(),
        b"\r\n0\r\n\r\n",
    ]
    .concat();

    assert_eq!(bytes, expected);
}
