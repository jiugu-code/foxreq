#![cfg(all(feature = "nss", not(feature = "nss-real")))]

use std::time::Duration;

use foxreq_core::{
    tls::{testing, Runtime},
    transport::{
        ConnectTarget, Connector, NssConnector, Scheme, TransportStream, VerificationMode,
    },
};

#[test]
fn adapts_nss_connections_to_deadline_aware_transport() {
    let _guard = testing::lock();
    let runtime = Runtime::new().unwrap();
    let mut connector = NssConnector::new(runtime, 8).expect("NSS connector");
    let mut stream = connector
        .connect(
            &ConnectTarget {
                scheme: Scheme::Https,
                host: "example.test".to_owned(),
                port: 443,
                profile_id: "firefox_152".to_owned(),
                verification: VerificationMode::Default,
            },
            Duration::from_secs(1),
        )
        .expect("NSS stream");
    testing::set_read_data(&mut stream, b"response").unwrap();
    testing::set_io_limits(&mut stream, 3, 2).unwrap();

    let mut buffer = [0u8; 8];
    assert_eq!(
        TransportStream::read(&mut stream, &mut buffer, Duration::from_secs(1)).unwrap(),
        3
    );
    assert_eq!(&buffer[..3], b"res");
    assert_eq!(
        TransportStream::write(&mut stream, b"body", Duration::from_secs(1)).unwrap(),
        2
    );
    assert_eq!(testing::written_data(&stream).unwrap(), b"bo");
}

#[test]
fn rejects_plain_http_before_opening_an_nss_connection() {
    let _guard = testing::lock();
    let runtime = Runtime::new().unwrap();
    let mut connector = NssConnector::new(runtime, 8).expect("NSS connector");

    let error = connector
        .connect(
            &ConnectTarget {
                scheme: Scheme::Http,
                host: "example.test".to_owned(),
                port: 80,
                profile_id: "firefox_152".to_owned(),
                verification: VerificationMode::Default,
            },
            Duration::from_secs(1),
        )
        .expect_err("NSS connector must reject plain HTTP");

    assert_eq!(
        error.kind(),
        foxreq_core::transport::TransportErrorKind::Unsupported
    );
}
