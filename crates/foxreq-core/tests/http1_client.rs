use std::{cell::RefCell, collections::VecDeque, rc::Rc, time::Duration};

use foxreq_core::{
    http1::{ClientErrorKind, ClientRequest, Http1Client, OwnedHeader},
    transport::{ConnectTarget, Connector, TransportError, TransportErrorKind, TransportStream},
};

#[derive(Default)]
struct ScriptState {
    connect_count: usize,
    close_count: usize,
    responses: VecDeque<Vec<u8>>,
    read_extra: usize,
    writes: Vec<Vec<u8>>,
    write_extra: usize,
}

struct ScriptedConnector {
    state: Rc<RefCell<ScriptState>>,
}

impl ScriptedConnector {
    fn new(responses: impl IntoIterator<Item = Vec<u8>>) -> (Self, Rc<RefCell<ScriptState>>) {
        let state = Rc::new(RefCell::new(ScriptState {
            responses: responses.into_iter().collect(),
            ..ScriptState::default()
        }));
        (
            Self {
                state: Rc::clone(&state),
            },
            state,
        )
    }
}

struct ScriptedStream {
    state: Rc<RefCell<ScriptState>>,
}

impl Connector for ScriptedConnector {
    type Stream = ScriptedStream;

    fn connect(
        &mut self,
        _target: &ConnectTarget,
        _timeout: Duration,
    ) -> Result<Self::Stream, TransportError> {
        self.state.borrow_mut().connect_count += 1;
        Ok(ScriptedStream {
            state: Rc::clone(&self.state),
        })
    }
}

impl TransportStream for ScriptedStream {
    fn read(
        &mut self,
        destination: &mut [u8],
        _timeout: Duration,
    ) -> Result<usize, TransportError> {
        let mut state = self.state.borrow_mut();
        let response = state.responses.pop_front().expect("scripted response");
        assert!(response.len() <= destination.len());
        destination[..response.len()].copy_from_slice(&response);
        Ok(response.len() + state.read_extra)
    }

    fn write(&mut self, source: &[u8], _timeout: Duration) -> Result<usize, TransportError> {
        let mut state = self.state.borrow_mut();
        state.writes.push(source.to_vec());
        Ok(source.len() + state.write_extra)
    }

    fn close(&mut self, _timeout: Duration) -> Result<(), TransportError> {
        self.state.borrow_mut().close_count += 1;
        Ok(())
    }
}

struct FailingConnector(TransportErrorKind);

impl Connector for FailingConnector {
    type Stream = ScriptedStream;

    fn connect(
        &mut self,
        _target: &ConnectTarget,
        _timeout: Duration,
    ) -> Result<Self::Stream, TransportError> {
        Err(TransportError::new(self.0, "safe transport failure"))
    }
}

#[test]
fn preserves_transport_error_categories() {
    let cases = [
        (TransportErrorKind::Io, ClientErrorKind::Connection),
        (TransportErrorKind::Timeout, ClientErrorKind::Timeout),
        (TransportErrorKind::Tls, ClientErrorKind::Tls),
        (TransportErrorKind::Unsupported, ClientErrorKind::Tls),
        (
            TransportErrorKind::Certificate,
            ClientErrorKind::Certificate,
        ),
        (
            TransportErrorKind::InvalidArgument,
            ClientErrorKind::Transport,
        ),
        (TransportErrorKind::State, ClientErrorKind::Transport),
    ];

    for (transport_kind, client_kind) in cases {
        let mut client = Http1Client::new(FailingConnector(transport_kind));
        let error = client
            .execute(ClientRequest::get(
                "https://example.test/error",
                Duration::from_secs(1),
            ))
            .expect_err("connector must fail");
        assert_eq!(error.kind(), client_kind);
    }
}

#[test]
fn preserves_duplicate_headers_and_reuses_a_clean_connection() {
    let (connector, state) = ScriptedConnector::new([
        b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: 2\r\n\r\nOK"
            .to_vec(),
        b"HTTP/1.1 204 No Content\r\n\r\n".to_vec(),
    ]);
    let mut client = Http1Client::new(connector);

    let first = client
        .execute(ClientRequest::get(
            "https://example.test/one",
            Duration::from_secs(1),
        ))
        .expect("first response");
    let second = client
        .execute(ClientRequest::get(
            "https://example.test/two",
            Duration::from_secs(1),
        ))
        .expect("second response");

    assert_eq!(first.status, 200);
    assert_eq!(first.body, b"OK");
    assert_eq!(first.headers[0], OwnedHeader::new(b"Set-Cookie", b"a=1"));
    assert_eq!(first.headers[1], OwnedHeader::new(b"Set-Cookie", b"b=2"));
    assert_eq!(second.status, 204);
    assert_eq!(state.borrow().connect_count, 1);
    assert_eq!(state.borrow().writes.len(), 2);
}

#[test]
fn rejects_an_empty_profile_before_connecting() {
    let (connector, state) = ScriptedConnector::new([]);
    let mut client = Http1Client::new(connector);
    let mut request = ClientRequest::get("https://example.test/profile", Duration::from_secs(1));
    request.profile_id.clear();

    let error = client
        .execute(request)
        .expect_err("empty profile must fail");

    assert_eq!(error.kind(), ClientErrorKind::InvalidProfile);
    assert_eq!(state.borrow().connect_count, 0);
}

#[test]
fn rejects_an_unsupported_profile_before_connecting() {
    let (connector, state) = ScriptedConnector::new([b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()]);
    let mut client = Http1Client::new(connector);
    let mut request = ClientRequest::get("https://example.test/profile", Duration::from_secs(1));
    request.profile_id = "firefox_latest".to_owned();

    let error = client
        .execute(request)
        .expect_err("unsupported profile must fail");

    assert_eq!(error.kind(), ClientErrorKind::InvalidProfile);
    assert_eq!(state.borrow().connect_count, 0);
}

#[test]
fn rejects_malformed_percent_encoding_before_connecting() {
    let (connector, state) = ScriptedConnector::new([b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()]);
    let mut client = Http1Client::new(connector);

    let error = client
        .execute(ClientRequest::get(
            "https://example.test/bad%2",
            Duration::from_secs(1),
        ))
        .expect_err("malformed percent escape must fail");

    assert_eq!(error.kind(), ClientErrorKind::InvalidUrl);
    assert_eq!(state.borrow().connect_count, 0);
}

#[test]
fn rejects_an_oversized_dns_label_before_connecting() {
    let (connector, state) = ScriptedConnector::new([b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()]);
    let mut client = Http1Client::new(connector);
    let host = "a".repeat(64);
    let url = format!("https://{host}.test/");

    let error = client
        .execute(ClientRequest::get(url, Duration::from_secs(1)))
        .expect_err("oversized DNS label must fail");

    assert_eq!(error.kind(), ClientErrorKind::InvalidUrl);
    assert_eq!(state.borrow().connect_count, 0);
}

#[test]
fn rejects_a_transport_write_count_larger_than_the_buffer() {
    let (connector, state) = ScriptedConnector::new([b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()]);
    state.borrow_mut().write_extra = 1;
    let mut client = Http1Client::new(connector);

    let error = client
        .execute(ClientRequest::get(
            "https://example.test/write",
            Duration::from_secs(1),
        ))
        .expect_err("oversized transport count must fail");

    assert_eq!(error.kind(), ClientErrorKind::Transport);
    assert_eq!(state.borrow().close_count, 1);
}

#[test]
fn rejects_a_transport_read_count_larger_than_the_buffer() {
    let (connector, state) = ScriptedConnector::new([b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()]);
    state.borrow_mut().read_extra = 16 * 1024;
    let mut client = Http1Client::new(connector);

    let error = client
        .execute(ClientRequest::get(
            "https://example.test/read",
            Duration::from_secs(1),
        ))
        .expect_err("oversized transport count must fail");

    assert_eq!(error.kind(), ClientErrorKind::Transport);
    assert_eq!(state.borrow().close_count, 1);
}
