use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    path::PathBuf,
    sync::{mpsc, Mutex},
    thread::{self, JoinHandle},
    time::Duration,
};

use foxreq_core::{
    http1::{ClientError, ClientErrorKind, ClientRequest, Http1Client, OwnedHeader, Version},
    tls::{Runtime, RuntimeConfig, TlsError, TlsErrorKind},
    transport::{NssConnector, TransportError, TransportErrorKind, VerificationMode},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeFailureKind {
    InvalidArgument,
    Closed,
    Timeout,
    Connection,
    Tls,
    Certificate,
    Protocol,
    WorkerPanic,
    Internal,
}

impl NativeFailureKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid_argument",
            Self::Closed => "closed",
            Self::Timeout => "timeout",
            Self::Connection => "connection",
            Self::Tls => "tls",
            Self::Certificate => "certificate",
            Self::Protocol => "protocol",
            Self::WorkerPanic => "worker_panic",
            Self::Internal => "internal",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeFailure {
    kind: NativeFailureKind,
    message: String,
}

impl NativeFailure {
    fn new(kind: NativeFailureKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub(crate) const fn kind(&self) -> NativeFailureKind {
        self.kind
    }

    pub(crate) fn message(&self) -> &str {
        &self.message
    }

    fn closed() -> Self {
        Self::new(NativeFailureKind::Closed, "native session is closed")
    }

    fn worker_panic() -> Self {
        Self::new(
            NativeFailureKind::WorkerPanic,
            "native session worker stopped unexpectedly",
        )
    }

    fn internal(message: &'static str) -> Self {
        Self::new(NativeFailureKind::Internal, message)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct NativeRequest {
    pub(crate) method: Vec<u8>,
    pub(crate) url: String,
    pub(crate) headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub(crate) body: Vec<u8>,
    pub(crate) timeout_seconds: f64,
    pub(crate) insecure: bool,
    pub(crate) profile_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeResponseData {
    pub(crate) status: u16,
    pub(crate) reason: Vec<u8>,
    pub(crate) url: String,
    pub(crate) version: String,
    pub(crate) headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub(crate) body: Vec<u8>,
}

pub(crate) trait ClientBackend: 'static {
    fn execute(&mut self, request: NativeRequest) -> Result<NativeResponseData, NativeFailure>;
    fn close(&mut self) -> Result<(), NativeFailure>;
}

enum Command {
    Request(
        NativeRequest,
        mpsc::Sender<Result<NativeResponseData, NativeFailure>>,
    ),
    Close(mpsc::Sender<Result<(), NativeFailure>>),
}

pub(crate) struct WorkerHandle {
    sender: Mutex<Option<mpsc::Sender<Command>>>,
    join: Mutex<Option<JoinHandle<()>>>,
}

impl WorkerHandle {
    pub(crate) fn spawn(
        runtime_dir: PathBuf,
        trust_anchors_der: Vec<Vec<u8>>,
        cache_capacity: u32,
    ) -> Result<Self, NativeFailure> {
        Self::spawn_with(move || NssBackend::new(runtime_dir, trust_anchors_der, cache_capacity))
    }

    fn spawn_with<F, B>(factory: F) -> Result<Self, NativeFailure>
    where
        F: FnOnce() -> Result<B, NativeFailure> + Send + 'static,
        B: ClientBackend,
    {
        let (sender, receiver) = mpsc::channel();
        let (init_sender, init_receiver) = mpsc::sync_channel(1);
        let join = thread::Builder::new()
            .name("foxreq-native-session".to_owned())
            .spawn(move || {
                let mut backend = match catch_unwind(AssertUnwindSafe(factory)) {
                    Ok(Ok(backend)) => backend,
                    Ok(Err(error)) => {
                        let _ = init_sender.send(Err(error));
                        return;
                    }
                    Err(_) => {
                        let _ = init_sender.send(Err(NativeFailure::worker_panic()));
                        return;
                    }
                };
                if init_sender.send(Ok(())).is_err() {
                    return;
                }
                run_worker(&receiver, &mut backend);
            })
            .map_err(|_| NativeFailure::internal("failed to create native session worker"))?;

        match init_receiver.recv() {
            Ok(Ok(())) => Ok(Self {
                sender: Mutex::new(Some(sender)),
                join: Mutex::new(Some(join)),
            }),
            Ok(Err(error)) => {
                let _ = join.join();
                Err(error)
            }
            Err(_) => {
                let _ = join.join();
                Err(NativeFailure::worker_panic())
            }
        }
    }

    pub(crate) fn request(
        &self,
        request: NativeRequest,
    ) -> Result<NativeResponseData, NativeFailure> {
        let mut sender = self
            .sender
            .lock()
            .map_err(|_| NativeFailure::internal("native session lock is poisoned"))?;
        let active = sender.as_ref().ok_or_else(NativeFailure::closed)?;
        let (reply_sender, reply_receiver) = mpsc::channel();
        if active
            .send(Command::Request(request, reply_sender))
            .is_err()
        {
            *sender = None;
            return Err(NativeFailure::worker_panic());
        }
        match reply_receiver.recv() {
            Ok(result) => result,
            Err(_) => {
                *sender = None;
                Err(NativeFailure::worker_panic())
            }
        }
    }

    pub(crate) fn close(&self) -> Result<(), NativeFailure> {
        let close_result = {
            let mut sender = self
                .sender
                .lock()
                .map_err(|_| NativeFailure::internal("native session lock is poisoned"))?;
            match sender.take() {
                Some(active) => {
                    let (reply_sender, reply_receiver) = mpsc::channel();
                    if active.send(Command::Close(reply_sender)).is_ok() {
                        reply_receiver.recv().unwrap_or(Ok(()))
                    } else {
                        Ok(())
                    }
                }
                None => Ok(()),
            }
        };
        let join_result = {
            let mut join = self
                .join
                .lock()
                .map_err(|_| NativeFailure::internal("native worker join lock is poisoned"))?;
            match join.take() {
                Some(handle) => handle.join().map_err(|_| NativeFailure::worker_panic()),
                None => Ok(()),
            }
        };
        close_result.and(join_result)
    }
}

impl Drop for WorkerHandle {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn run_worker<B: ClientBackend>(receiver: &mpsc::Receiver<Command>, backend: &mut B) {
    while let Ok(command) = receiver.recv() {
        match command {
            Command::Request(request, reply) => {
                match catch_unwind(AssertUnwindSafe(|| backend.execute(request))) {
                    Ok(result) => {
                        let _ = reply.send(result);
                    }
                    Err(_) => {
                        let _ = reply.send(Err(NativeFailure::worker_panic()));
                        break;
                    }
                }
            }
            Command::Close(reply) => {
                let result = catch_unwind(AssertUnwindSafe(|| backend.close()))
                    .unwrap_or_else(|_| Err(NativeFailure::worker_panic()));
                let _ = reply.send(result);
                break;
            }
        }
    }
}

struct NssBackend {
    client: Http1Client<NssConnector>,
}

impl NssBackend {
    fn new(
        runtime_dir: PathBuf,
        trust_anchors_der: Vec<Vec<u8>>,
        cache_capacity: u32,
    ) -> Result<Self, NativeFailure> {
        let anchors: Vec<&[u8]> = trust_anchors_der.iter().map(Vec::as_slice).collect();
        let runtime = Runtime::new_with_config(RuntimeConfig {
            runtime_dir: &runtime_dir,
            trust_anchors_der: &anchors,
        })
        .map_err(map_tls_error)?;
        let connector = NssConnector::new(runtime, cache_capacity).map_err(map_transport_error)?;
        Ok(Self {
            client: Http1Client::new(connector),
        })
    }
}

impl ClientBackend for NssBackend {
    fn execute(&mut self, request: NativeRequest) -> Result<NativeResponseData, NativeFailure> {
        if !request.timeout_seconds.is_finite() || request.timeout_seconds <= 0.0 {
            return Err(NativeFailure::new(
                NativeFailureKind::InvalidArgument,
                "request timeout must be finite and positive",
            ));
        }
        let timeout = Duration::try_from_secs_f64(request.timeout_seconds).map_err(|_| {
            NativeFailure::new(
                NativeFailureKind::InvalidArgument,
                "request timeout is outside the supported range",
            )
        })?;
        let response = self
            .client
            .execute(ClientRequest {
                method: request.method,
                url: request.url,
                headers: request
                    .headers
                    .into_iter()
                    .map(|(name, value)| OwnedHeader { name, value })
                    .collect(),
                body: request.body,
                timeout,
                verification: if request.insecure {
                    VerificationMode::InsecureTestOnly
                } else {
                    VerificationMode::Default
                },
                profile_id: request.profile_id,
            })
            .map_err(map_client_error)?;
        Ok(NativeResponseData {
            status: response.status,
            reason: response.reason,
            url: response.url,
            version: match response.version {
                Version::Http10 => "HTTP/1.0",
                Version::Http11 => "HTTP/1.1",
            }
            .to_owned(),
            headers: response
                .headers
                .into_iter()
                .map(|header| (header.name, header.value))
                .collect(),
            body: response.body,
        })
    }

    fn close(&mut self) -> Result<(), NativeFailure> {
        self.client.close();
        Ok(())
    }
}

fn map_client_error(error: ClientError) -> NativeFailure {
    let kind = match error.kind() {
        ClientErrorKind::InvalidUrl
        | ClientErrorKind::InvalidProfile
        | ClientErrorKind::InvalidTimeout
        | ClientErrorKind::Request => NativeFailureKind::InvalidArgument,
        ClientErrorKind::Closed => NativeFailureKind::Closed,
        ClientErrorKind::Timeout => NativeFailureKind::Timeout,
        ClientErrorKind::Transport => NativeFailureKind::Connection,
        ClientErrorKind::Response => NativeFailureKind::Protocol,
    };
    NativeFailure::new(kind, error.message())
}

fn map_tls_error(error: TlsError) -> NativeFailure {
    let kind = match error.kind() {
        TlsErrorKind::InvalidArgument => NativeFailureKind::InvalidArgument,
        TlsErrorKind::State => NativeFailureKind::Internal,
        TlsErrorKind::Io | TlsErrorKind::EndOfStream => NativeFailureKind::Connection,
        TlsErrorKind::Timeout => NativeFailureKind::Timeout,
        TlsErrorKind::Certificate => NativeFailureKind::Certificate,
        TlsErrorKind::Unsupported | TlsErrorKind::Tls => NativeFailureKind::Tls,
        TlsErrorKind::OutOfMemory | TlsErrorKind::BufferTooSmall | TlsErrorKind::Unknown(_) => {
            NativeFailureKind::Internal
        }
    };
    NativeFailure::new(kind, error.message())
}

fn map_transport_error(error: TransportError) -> NativeFailure {
    let kind = match error.kind() {
        TransportErrorKind::InvalidArgument => NativeFailureKind::InvalidArgument,
        TransportErrorKind::State => NativeFailureKind::Internal,
        TransportErrorKind::Io => NativeFailureKind::Connection,
        TransportErrorKind::Timeout => NativeFailureKind::Timeout,
        TransportErrorKind::Certificate => NativeFailureKind::Certificate,
        TransportErrorKind::Tls | TransportErrorKind::Unsupported => NativeFailureKind::Tls,
    };
    NativeFailure::new(kind, error.message())
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    use super::{
        ClientBackend, NativeFailure, NativeFailureKind, NativeRequest, NativeResponseData,
        WorkerHandle,
    };

    struct FakeBackend {
        dropped: Arc<AtomicBool>,
        panic_on_request: bool,
    }

    impl Drop for FakeBackend {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl ClientBackend for FakeBackend {
        fn execute(&mut self, request: NativeRequest) -> Result<NativeResponseData, NativeFailure> {
            if self.panic_on_request {
                panic!("scripted worker panic");
            }
            Ok(NativeResponseData {
                status: 200,
                reason: b"OK".to_vec(),
                url: request.url,
                version: "HTTP/1.1".to_owned(),
                headers: request.headers,
                body: request.body,
            })
        }

        fn close(&mut self) -> Result<(), NativeFailure> {
            Ok(())
        }
    }

    fn request(path: &str) -> NativeRequest {
        NativeRequest {
            method: b"POST".to_vec(),
            url: format!("https://example.test{path}"),
            headers: vec![(b"X-Order".to_vec(), path.as_bytes().to_vec())],
            body: path.as_bytes().to_vec(),
            timeout_seconds: 1.0,
            insecure: false,
            profile_id: "firefox_152".to_owned(),
        }
    }

    fn worker(dropped: Arc<AtomicBool>, panic_on_request: bool) -> WorkerHandle {
        WorkerHandle::spawn_with(move || {
            Ok(FakeBackend {
                dropped,
                panic_on_request,
            })
        })
        .unwrap()
    }

    #[test]
    fn executes_requests_in_order_on_one_worker() {
        let dropped = Arc::new(AtomicBool::new(false));
        let worker = worker(Arc::clone(&dropped), false);

        let first = worker.request(request("/one")).unwrap();
        let second = worker.request(request("/two")).unwrap();

        assert_eq!(first.body, b"/one");
        assert_eq!(second.body, b"/two");
        worker.close().unwrap();
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn close_is_idempotent_and_rejects_later_requests() {
        let worker = worker(Arc::new(AtomicBool::new(false)), false);
        worker.close().unwrap();
        worker.close().unwrap();

        let error = worker.request(request("/closed")).unwrap_err();
        assert_eq!(error.kind(), NativeFailureKind::Closed);
    }

    #[test]
    fn converts_a_backend_panic_and_joins_on_drop() {
        let dropped = Arc::new(AtomicBool::new(false));
        let worker = worker(Arc::clone(&dropped), true);

        let error = worker.request(request("/panic")).unwrap_err();
        assert_eq!(error.kind(), NativeFailureKind::WorkerPanic);
        drop(worker);
        assert!(dropped.load(Ordering::SeqCst));
    }
}
