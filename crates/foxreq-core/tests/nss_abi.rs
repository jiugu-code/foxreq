#![cfg(all(feature = "nss", not(feature = "nss-real")))]

use std::time::Duration;

use foxreq_core::tls::{testing, ConnectConfig, RequestVerification, Runtime, TlsErrorKind};

fn config<'a>() -> ConnectConfig<'a> {
    ConnectConfig {
        host: "example.test",
        port: 443,
        timeout: Duration::from_secs(1),
        profile_id: "firefox_152",
        alpn_wire: b"\x08http/1.1",
        verification: RequestVerification::Default,
    }
}

#[test]
fn owns_runtime_cache_connection_and_foreign_buffers() {
    let _guard = testing::lock();
    let baseline = testing::live_counts().unwrap();
    let runtime = Runtime::new().unwrap();
    let cache = runtime.session_cache(32).unwrap();
    let mut connection = runtime.connect(&config(), Some(&cache)).unwrap();

    assert_eq!(connection.negotiated_alpn().unwrap(), b"http/1.1");
    let certificate = connection.certificate_result().unwrap();
    assert!(certificate.verification_performed);
    assert!(certificate.verified);
    assert_eq!(certificate.error_kind, None);
    assert_eq!(testing::live_counts().unwrap().buffers, baseline.buffers);

    let live = testing::live_counts().unwrap();
    assert_eq!(live.runtimes, baseline.runtimes + 1);
    assert_eq!(live.session_caches, baseline.session_caches + 1);
    assert_eq!(live.connections, baseline.connections + 1);

    drop(runtime);
    assert_eq!(
        testing::live_counts().unwrap().runtimes,
        baseline.runtimes + 1
    );
    connection.close(Duration::from_secs(1)).unwrap();
    drop(connection);
    drop(cache);
    assert_eq!(testing::live_counts().unwrap(), baseline);
}

#[test]
fn supports_zero_length_and_scripted_partial_io() {
    let _guard = testing::lock();
    let runtime = Runtime::new().unwrap();
    let mut connection = runtime.connect(&config(), None).unwrap();
    testing::set_read_data(&mut connection, b"abcdef").unwrap();
    testing::set_io_limits(&mut connection, 2, 3).unwrap();

    assert_eq!(connection.read(&mut [], Duration::from_secs(1)).unwrap(), 0);
    assert_eq!(connection.write(&[], Duration::from_secs(1)).unwrap(), 0);

    let mut buffer = [0u8; 16];
    assert_eq!(
        connection
            .read(&mut buffer, Duration::from_secs(1))
            .unwrap(),
        2
    );
    assert_eq!(&buffer[..2], b"ab");
    assert_eq!(
        connection
            .read(&mut buffer, Duration::from_secs(1))
            .unwrap(),
        2
    );
    assert_eq!(&buffer[..2], b"cd");
    assert_eq!(
        connection
            .read(&mut buffer, Duration::from_secs(1))
            .unwrap(),
        2
    );
    assert_eq!(&buffer[..2], b"ef");
    assert_eq!(
        connection
            .read(&mut buffer, Duration::from_secs(1))
            .unwrap(),
        0
    );
    assert_eq!(
        connection.write(b"abcde", Duration::from_secs(1)).unwrap(),
        3
    );
    assert_eq!(connection.write(b"de", Duration::from_secs(1)).unwrap(), 2);
    assert_eq!(testing::written_data(&connection).unwrap(), b"abcde");
}

#[test]
fn maps_injected_errors_and_copies_messages_into_rust_memory() {
    let _guard = testing::lock();
    let runtime = Runtime::new().unwrap();
    let mut connection = runtime.connect(&config(), None).unwrap();
    testing::fail_next_read(
        &mut connection,
        TlsErrorKind::Io,
        -12276,
        -5990,
        "scripted read failure",
    )
    .unwrap();

    let mut buffer = [0u8; 8];
    let error = connection
        .read(&mut buffer, Duration::from_secs(1))
        .unwrap_err();
    assert_eq!(error.kind(), TlsErrorKind::Io);
    assert_eq!(error.nss_code(), -12276);
    assert_eq!(error.nspr_code(), -5990);
    assert_eq!(error.message(), "scripted read failure");

    let copied = error.message().to_owned();
    let last = connection.last_error().unwrap();
    assert_eq!(last.message(), copied);
}

#[test]
fn rust_wrapper_prevents_a_second_native_close() {
    let _guard = testing::lock();
    let runtime = Runtime::new().unwrap();
    let mut connection = runtime.connect(&config(), None).unwrap();

    connection.close(Duration::from_secs(1)).unwrap();
    assert_eq!(testing::close_calls(&connection).unwrap(), 1);
    let error = connection.close(Duration::from_secs(1)).unwrap_err();
    assert_eq!(error.kind(), TlsErrorKind::State);
    assert_eq!(testing::close_calls(&connection).unwrap(), 1);
}

#[test]
fn validates_cache_affinity_timeouts_and_alpn_wire_format() {
    let _guard = testing::lock();
    let first = Runtime::new().unwrap();
    let second = Runtime::new().unwrap();
    let cache = first.session_cache(8).unwrap();

    let mismatch = second.connect(&config(), Some(&cache)).unwrap_err();
    assert_eq!(mismatch.kind(), TlsErrorKind::State);

    let mut zero_timeout = config();
    zero_timeout.timeout = Duration::ZERO;
    let timeout = first.connect(&zero_timeout, None).unwrap_err();
    assert_eq!(timeout.kind(), TlsErrorKind::Timeout);

    let mut malformed_alpn = config();
    malformed_alpn.alpn_wire = b"\x08h2";
    let invalid = first.connect(&malformed_alpn, None).unwrap_err();
    assert_eq!(invalid.kind(), TlsErrorKind::InvalidArgument);

    let mut insecure = config();
    insecure.verification = RequestVerification::InsecureTestOnly;
    let connection = first.connect(&insecure, None).unwrap();
    let certificate = connection.certificate_result().unwrap();
    assert!(!certificate.verification_performed);
    assert!(!certificate.verified);
    assert_eq!(certificate.error_kind, None);
}

#[test]
fn injected_write_and_close_failures_are_one_shot() {
    let _guard = testing::lock();
    let runtime = Runtime::new().unwrap();
    let mut connection = runtime.connect(&config(), None).unwrap();

    testing::fail_next_write(
        &mut connection,
        TlsErrorKind::Io,
        -1,
        -2,
        "scripted write failure",
    )
    .unwrap();
    let write = connection
        .write(b"data", Duration::from_secs(1))
        .unwrap_err();
    assert_eq!(write.kind(), TlsErrorKind::Io);
    assert_eq!(write.message(), "scripted write failure");
    assert_eq!(
        connection.write(b"data", Duration::from_secs(1)).unwrap(),
        4
    );

    testing::fail_next_close(
        &mut connection,
        TlsErrorKind::Timeout,
        0,
        -3,
        "scripted close timeout",
    )
    .unwrap();
    let close = connection.close(Duration::from_secs(1)).unwrap_err();
    assert_eq!(close.kind(), TlsErrorKind::Timeout);
    assert_eq!(testing::close_calls(&connection).unwrap(), 1);
    connection.close(Duration::from_secs(1)).unwrap();
    assert_eq!(testing::close_calls(&connection).unwrap(), 2);
}
