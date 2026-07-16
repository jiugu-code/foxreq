use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::{Duration, Instant},
};

use foxreq_core::{
    http1::{ClientRequest, Http1Client, OwnedHeader},
    tcp::TcpConnector,
    transport::{ConnectTarget, Connector, Scheme, TransportErrorKind, VerificationMode},
};

#[test]
fn rejects_https_before_dns_resolution() {
    let mut connector = TcpConnector::new();
    let error = connector
        .connect(
            &ConnectTarget {
                scheme: Scheme::Https,
                host: "must-not-resolve.invalid".to_owned(),
                port: 443,
                profile_id: "firefox_152".to_owned(),
                verification: VerificationMode::Default,
            },
            Duration::from_secs(1),
        )
        .expect_err("plain connector must reject HTTPS");

    assert_eq!(error.kind(), TransportErrorKind::Unsupported);
}

#[test]
fn sends_plain_http_and_preserves_ordered_duplicate_headers() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("configure nonblocking listener");
    let address = listener.local_addr().expect("listener address");
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "client did not connect");
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set server read timeout");
        let mut request = Vec::new();
        let mut buffer = [0u8; 1024];
        while !request.ends_with(b"\r\n\r\n") {
            let amount = stream.read(&mut buffer).expect("read HTTP request");
            assert_ne!(amount, 0, "request ended before headers completed");
            request.extend_from_slice(&buffer[..amount]);
            assert!(request.len() <= 16 * 1024, "request headers are too large");
        }
        let expected = format!(
            "GET /plain HTTP/1.1\r\nHost: {address}\r\nX-Order: first\r\nX-Order: second\r\n\r\n"
        );
        assert_eq!(request, expected.as_bytes());
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
            )
            .expect("write HTTP response");
    });

    let mut client = Http1Client::new(TcpConnector::new());
    let response = client
        .execute(ClientRequest {
            method: b"GET".to_vec(),
            url: format!("http://{address}/plain"),
            headers: vec![
                OwnedHeader::new(b"X-Order", b"first"),
                OwnedHeader::new(b"X-Order", b"second"),
            ],
            body: Vec::new(),
            timeout: Duration::from_secs(2),
            verification: VerificationMode::Default,
            profile_id: "firefox_152".to_owned(),
        })
        .expect("plain HTTP response");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"OK");
    assert_eq!(response.headers[0], OwnedHeader::new(b"Set-Cookie", b"a=1"));
    assert_eq!(response.headers[1], OwnedHeader::new(b"Set-Cookie", b"b=2"));
    server.join().expect("server thread");
}
