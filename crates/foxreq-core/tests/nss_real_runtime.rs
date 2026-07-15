#![cfg(all(feature = "nss-real", target_os = "windows"))]

use std::{path::Path, thread};

use foxreq_core::tls::{Runtime, RuntimeConfig};

fn runtime() -> Runtime {
    Runtime::new_with_config(RuntimeConfig {
        runtime_dir: Path::new(env!("FOXREQ_NSS_RUNTIME_DIR")),
        trust_anchors_der: &[],
    })
    .expect("the hash-verified Firefox runtime must initialize")
}

#[test]
fn reports_the_exact_pinned_firefox_component_versions() {
    let runtime = runtime();
    let versions = runtime.versions().unwrap();

    assert_eq!(versions.nss, "3.124");
    assert_eq!(versions.nspr, "4.39");
}

#[test]
fn supports_concurrent_runtime_acquisition_and_release() {
    let workers: Vec<_> = (0..8)
        .map(|_| {
            thread::spawn(|| {
                for _ in 0..25 {
                    let runtime = runtime();
                    assert_eq!(runtime.versions().unwrap().nss, "3.124");
                }
            })
        })
        .collect();

    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn survives_one_thousand_runtime_teardowns() {
    for _ in 0..1_000 {
        let runtime = runtime();
        let versions = runtime.versions().unwrap();
        assert_eq!(
            (versions.nss.as_str(), versions.nspr.as_str()),
            ("3.124", "4.39")
        );
    }
}
