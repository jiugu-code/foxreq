#![cfg(all(feature = "nss-real", target_os = "windows"))]

use std::{path::Path, time::Duration};

use foxreq_core::tls::{ConnectConfig, RequestVerification, Runtime, RuntimeConfig, TlsErrorKind};

fn runtime_dir() -> &'static Path {
    static RUNTIME_DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    RUNTIME_DIR
        .get_or_init(|| {
            std::env::var_os("FOXREQ_NSS_RUNTIME_DIR")
                .expect("FOXREQ_NSS_RUNTIME_DIR must identify the test runtime")
                .into()
        })
        .as_path()
}

#[test]
#[ignore = "requires the serial loopback TLS fixture orchestrator"]
fn exchanges_http_11_over_the_local_tls_fixture() {
    let port = std::env::var("FOXREQ_NSS_TEST_PORT")
        .expect("FOXREQ_NSS_TEST_PORT must identify the loopback fixture")
        .parse::<u16>()
        .unwrap();
    let runtime = Runtime::new_with_config(RuntimeConfig {
        runtime_dir: runtime_dir(),
        trust_anchors_der: &[],
        profile_id: "firefox_152",
    })
    .unwrap();
    let mut connection = runtime
        .connect(
            &ConnectConfig {
                host: "127.0.0.1",
                port,
                timeout: Duration::from_secs(3),
                profile_id: "firefox_152",
                alpn_wire: b"\x08http/1.1",
                verification: RequestVerification::InsecureTestOnly,
            },
            None,
        )
        .unwrap();

    assert_eq!(connection.negotiated_alpn().unwrap(), b"http/1.1");
    let certificate = connection.certificate_result().unwrap();
    assert!(!certificate.verification_performed);
    assert!(!certificate.verified);

    let request = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let mut sent = 0;
    while sent < request.len() {
        sent += connection
            .write(&request[sent..], Duration::from_secs(3))
            .unwrap();
    }
    let mut response = Vec::new();
    let mut buffer = [0u8; 512];
    loop {
        let read = connection
            .read(&mut buffer, Duration::from_secs(3))
            .unwrap();
        if read == 0 {
            break;
        }
        response.extend_from_slice(&buffer[..read]);
    }
    assert_eq!(
        response,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
    );
    connection.close(Duration::from_secs(1)).unwrap();
}

#[test]
#[ignore = "requires the serial loopback TLS fixture orchestrator"]
fn verifies_an_explicit_ephemeral_local_ca() {
    let port = std::env::var("FOXREQ_NSS_TEST_PORT")
        .expect("FOXREQ_NSS_TEST_PORT must identify the loopback fixture")
        .parse::<u16>()
        .unwrap();
    let ca_der = std::fs::read(
        std::env::var_os("FOXREQ_NSS_TEST_CA_DER")
            .expect("FOXREQ_NSS_TEST_CA_DER must identify the ephemeral CA"),
    )
    .unwrap();
    let runtime = Runtime::new_with_config(RuntimeConfig {
        runtime_dir: runtime_dir(),
        trust_anchors_der: &[&ca_der],
        profile_id: "firefox_152",
    })
    .unwrap();
    let mut connection = runtime
        .connect(
            &ConnectConfig {
                host: "127.0.0.1",
                port,
                timeout: Duration::from_secs(3),
                profile_id: "firefox_152",
                alpn_wire: b"\x08http/1.1",
                verification: RequestVerification::Default,
            },
            None,
        )
        .unwrap();

    let certificate = connection.certificate_result().unwrap();
    assert!(certificate.verification_performed);
    assert!(certificate.verified);
    assert_eq!(certificate.error_kind, None);
    connection.close(Duration::from_secs(1)).unwrap();
}

#[test]
#[ignore = "requires the serial loopback TLS fixture orchestrator"]
fn rejects_an_untrusted_local_ca() {
    let port = std::env::var("FOXREQ_NSS_TEST_PORT")
        .expect("FOXREQ_NSS_TEST_PORT must identify the loopback fixture")
        .parse::<u16>()
        .unwrap();
    let runtime = Runtime::new_with_config(RuntimeConfig {
        runtime_dir: runtime_dir(),
        trust_anchors_der: &[],
        profile_id: "firefox_152",
    })
    .unwrap();
    let error = runtime
        .connect(
            &ConnectConfig {
                host: "127.0.0.1",
                port,
                timeout: Duration::from_secs(3),
                profile_id: "firefox_152",
                alpn_wire: b"\x08http/1.1",
                verification: RequestVerification::Default,
            },
            None,
        )
        .unwrap_err();

    assert_eq!(error.kind(), TlsErrorKind::Certificate);
    assert!(error.nss_code() != 0 || error.nspr_code() != 0);
    assert_eq!(error.message(), "TLS handshake failed");
}

#[test]
#[ignore = "requires the serial loopback TLS fixture orchestrator"]
fn rejects_an_expired_certificate_from_a_trusted_ca() {
    assert_trusted_fixture_is_rejected("127.0.0.1");
}

#[test]
#[ignore = "requires the serial loopback TLS fixture orchestrator"]
fn rejects_a_hostname_mismatch_from_a_trusted_ca() {
    assert_trusted_fixture_is_rejected("localhost");
}

fn assert_trusted_fixture_is_rejected(host: &str) {
    let port = std::env::var("FOXREQ_NSS_TEST_PORT")
        .expect("FOXREQ_NSS_TEST_PORT must identify the loopback fixture")
        .parse::<u16>()
        .unwrap();
    let ca_der = std::fs::read(
        std::env::var_os("FOXREQ_NSS_TEST_CA_DER")
            .expect("FOXREQ_NSS_TEST_CA_DER must identify the ephemeral CA"),
    )
    .unwrap();
    let runtime = Runtime::new_with_config(RuntimeConfig {
        runtime_dir: runtime_dir(),
        trust_anchors_der: &[&ca_der],
        profile_id: "firefox_152",
    })
    .unwrap();
    let error = runtime
        .connect(
            &ConnectConfig {
                host,
                port,
                timeout: Duration::from_secs(3),
                profile_id: "firefox_152",
                alpn_wire: b"\x08http/1.1",
                verification: RequestVerification::Default,
            },
            None,
        )
        .unwrap_err();

    assert_eq!(error.kind(), TlsErrorKind::Certificate);
    assert!(error.nss_code() != 0 || error.nspr_code() != 0);
    assert_eq!(error.message(), "TLS handshake failed");
}

#[test]
#[ignore = "requires the serial loopback TLS fixture orchestrator"]
fn isolates_active_runtime_trust_anchors() {
    let first = std::fs::read(
        std::env::var_os("FOXREQ_NSS_TEST_CA_DER")
            .expect("FOXREQ_NSS_TEST_CA_DER must identify the first CA"),
    )
    .unwrap();
    let second = std::fs::read(
        std::env::var_os("FOXREQ_NSS_TEST_OTHER_CA_DER")
            .expect("FOXREQ_NSS_TEST_OTHER_CA_DER must identify the second CA"),
    )
    .unwrap();
    assert_ne!(first, second);

    let first_runtime = Runtime::new_with_config(RuntimeConfig {
        runtime_dir: runtime_dir(),
        trust_anchors_der: &[&first],
        profile_id: "firefox_152",
    })
    .unwrap();
    let same_runtime = Runtime::new_with_config(RuntimeConfig {
        runtime_dir: runtime_dir(),
        trust_anchors_der: &[&first],
        profile_id: "firefox_152",
    })
    .unwrap();
    let mixed_error = Runtime::new_with_config(RuntimeConfig {
        runtime_dir: runtime_dir(),
        trust_anchors_der: &[&second],
        profile_id: "firefox_152",
    })
    .err()
    .expect("an active NSS lifecycle must not mix trust anchors");
    assert_eq!(mixed_error.kind(), TlsErrorKind::State);

    drop(same_runtime);
    drop(first_runtime);
    let replacement = Runtime::new_with_config(RuntimeConfig {
        runtime_dir: runtime_dir(),
        trust_anchors_der: &[&second],
        profile_id: "firefox_152",
    })
    .unwrap();
    assert_eq!(replacement.versions().unwrap().nss, "3.124");
    drop(replacement);

    let combined = Runtime::new_with_config(RuntimeConfig {
        runtime_dir: runtime_dir(),
        trust_anchors_der: &[&first, &second],
        profile_id: "firefox_152",
    })
    .unwrap();
    assert_eq!(combined.versions().unwrap().nss, "3.124");
}

#[test]
#[ignore = "requires the serial loopback TLS fixture orchestrator"]
fn rejects_an_invalid_der_trust_anchor() {
    let error = Runtime::new_with_config(RuntimeConfig {
        runtime_dir: runtime_dir(),
        trust_anchors_der: &[b"not a DER certificate"],
        profile_id: "firefox_152",
    })
    .err()
    .expect("invalid DER must not initialize a trusted runtime");
    assert_eq!(error.kind(), TlsErrorKind::Certificate);

    let valid = std::fs::read(
        std::env::var("FOXREQ_NSS_TEST_CA_DER")
            .expect("FOXREQ_NSS_TEST_CA_DER must identify a valid local CA"),
    )
    .unwrap();
    let recovered = Runtime::new_with_config(RuntimeConfig {
        runtime_dir: runtime_dir(),
        trust_anchors_der: &[&valid],
        profile_id: "firefox_152",
    })
    .expect("a failed trust install must not poison later runtimes");
    assert_eq!(recovered.versions().unwrap().nss, "3.124");
}

#[test]
#[ignore = "requires the serial loopback TLS fixture orchestrator"]
fn times_out_a_stalled_tls_handshake() {
    let port = std::env::var("FOXREQ_NSS_TEST_PORT")
        .expect("FOXREQ_NSS_TEST_PORT must identify the loopback fixture")
        .parse::<u16>()
        .unwrap();
    let runtime = Runtime::new_with_config(RuntimeConfig {
        runtime_dir: runtime_dir(),
        trust_anchors_der: &[],
        profile_id: "firefox_152",
    })
    .unwrap();
    let error = runtime
        .connect(
            &ConnectConfig {
                host: "127.0.0.1",
                port,
                timeout: Duration::from_millis(100),
                profile_id: "firefox_152",
                alpn_wire: b"\x08http/1.1",
                verification: RequestVerification::InsecureTestOnly,
            },
            None,
        )
        .unwrap_err();

    assert_eq!(error.kind(), TlsErrorKind::Timeout, "{error:?}");
    assert!(error.nss_code() != 0 || error.nspr_code() != 0);
}

#[test]
#[ignore = "requires the serial loopback TLS fixture orchestrator"]
fn times_out_a_stalled_tls_read() {
    let port = std::env::var("FOXREQ_NSS_TEST_PORT")
        .expect("FOXREQ_NSS_TEST_PORT must identify the loopback fixture")
        .parse::<u16>()
        .unwrap();
    let runtime = Runtime::new_with_config(RuntimeConfig {
        runtime_dir: runtime_dir(),
        trust_anchors_der: &[],
        profile_id: "firefox_152",
    })
    .unwrap();
    let mut connection = runtime
        .connect(
            &ConnectConfig {
                host: "127.0.0.1",
                port,
                timeout: Duration::from_secs(3),
                profile_id: "firefox_152",
                alpn_wire: b"\x08http/1.1",
                verification: RequestVerification::InsecureTestOnly,
            },
            None,
        )
        .unwrap();
    let error = connection
        .read(&mut [0u8; 1], Duration::from_millis(100))
        .unwrap_err();

    assert_eq!(error.kind(), TlsErrorKind::Timeout, "{error:?}");
    assert!(error.nss_code() != 0 || error.nspr_code() != 0);
}
