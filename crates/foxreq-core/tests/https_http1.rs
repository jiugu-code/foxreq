#![cfg(feature = "nss-real")]

use std::{env, fs, path::Path, time::Duration};

use foxreq_core::{
    http1::{ClientErrorKind, ClientRequest, Http1Client, OwnedHeader, Version},
    tls::{Runtime, RuntimeConfig},
    transport::{NssConnector, VerificationMode},
};

fn client() -> Http1Client<NssConnector> {
    let runtime_dir = env::var("FOXREQ_NSS_RUNTIME_DIR").expect("Firefox runtime path");
    let ca_path = env::var("FOXREQ_HTTP1_TEST_CA_DER").expect("fixture CA path");
    let ca_der = fs::read(ca_path).expect("fixture CA DER");
    let anchors = [ca_der.as_slice()];
    let runtime = Runtime::new_with_config(RuntimeConfig {
        runtime_dir: Path::new(&runtime_dir),
        trust_anchors_der: &anchors,
    })
    .expect("real NSS runtime");
    let connector = NssConnector::new(runtime, 16).expect("real NSS connector");
    Http1Client::new(connector)
}

fn url(path: &str) -> String {
    let port = env::var("FOXREQ_HTTP1_TEST_PORT").expect("fixture port");
    format!("https://127.0.0.1:{port}{path}")
}

fn request(method: &[u8], path: &str, body: &[u8]) -> ClientRequest {
    ClientRequest {
        method: method.to_vec(),
        url: url(path),
        headers: vec![
            OwnedHeader::new(b"X-Order", b"first"),
            OwnedHeader::new(b"X-Order", b"second"),
        ],
        body: body.to_vec(),
        timeout: Duration::from_secs(2),
        verification: VerificationMode::Default,
        profile_id: "firefox_152".to_owned(),
    }
}

#[test]
#[ignore = "requires the loopback HTTPS scenario fixture"]
fn gets_a_fixed_response_with_duplicate_headers() {
    let response = client()
        .execute(request(b"GET", "/fixed?x=1", b""))
        .expect("fixed response");

    assert_eq!(response.status, 200);
    assert_eq!(response.version, Version::Http11);
    assert_eq!(response.body, b"OK");
    assert_eq!(response.headers[0], OwnedHeader::new(b"Set-Cookie", b"a=1"));
    assert_eq!(response.headers[1], OwnedHeader::new(b"Set-Cookie", b"b=2"));
}

#[test]
#[ignore = "requires the loopback HTTPS scenario fixture"]
fn sends_a_head_request_without_accepting_response_body_bytes() {
    let response = client()
        .execute(request(b"HEAD", "/head", b""))
        .expect("HEAD response");

    assert_eq!(response.status, 200);
    assert!(response.body.is_empty());
}

#[test]
#[ignore = "requires the loopback HTTPS scenario fixture"]
fn sends_a_post_and_accepts_an_informational_response() {
    let response = client()
        .execute(request(b"POST", "/submit", b"payload"))
        .expect("POST response");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"OK");
}

#[test]
#[ignore = "requires the loopback HTTPS scenario fixture"]
fn decodes_a_chunked_response() {
    let response = client()
        .execute(request(b"GET", "/chunked", b""))
        .expect("chunked response");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"OK");
}

#[test]
#[ignore = "requires the loopback HTTPS scenario fixture"]
fn completes_a_close_delimited_response() {
    let response = client()
        .execute(request(b"GET", "/close", b""))
        .expect("close-delimited response");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"OK");
}

#[test]
#[ignore = "requires the loopback HTTPS scenario fixture"]
fn reuses_one_keepalive_connection() {
    let mut client = client();
    let first = client
        .execute(request(b"GET", "/one", b""))
        .expect("first keepalive response");
    let second = client
        .execute(request(b"GET", "/two", b""))
        .expect("second keepalive response");

    assert_eq!(first.body, b"one");
    assert_eq!(second.body, b"two");
}

#[test]
#[ignore = "requires the loopback HTTPS scenario fixture"]
fn reconnects_after_an_explicit_server_close() {
    let mut client = client();
    let first = client
        .execute(request(b"GET", "/one", b""))
        .expect("first closed response");
    let second = client
        .execute(request(b"GET", "/two", b""))
        .expect("second closed response");

    assert_eq!(first.body, b"OK");
    assert_eq!(second.body, b"OK");
}

#[test]
#[ignore = "requires the loopback HTTPS scenario fixture"]
fn rejects_an_early_response_eof() {
    let error = client()
        .execute(request(b"GET", "/early", b""))
        .expect_err("early EOF must fail");

    assert_eq!(error.kind(), ClientErrorKind::Response);
}

#[test]
#[ignore = "requires the loopback HTTPS scenario fixture"]
fn rejects_ambiguous_response_framing() {
    let error = client()
        .execute(request(b"GET", "/malformed", b""))
        .expect_err("ambiguous response framing must fail");

    assert_eq!(error.kind(), ClientErrorKind::Response);
}

#[test]
#[ignore = "requires the loopback HTTPS scenario fixture"]
fn times_out_a_stalled_response_read() {
    let mut request = request(b"GET", "/stall", b"");
    request.timeout = Duration::from_millis(150);
    let error = client()
        .execute(request)
        .expect_err("stalled response must time out");

    assert_eq!(error.kind(), ClientErrorKind::Timeout);
}
