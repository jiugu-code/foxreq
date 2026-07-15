#![forbid(unsafe_code)]

pub mod http1;

const PROFILE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildContract {
    pub package_version: &'static str,
    pub target: &'static str,
    pub native_backend: &'static str,
    pub profile_schema_version: u32,
}

#[must_use]
pub const fn build_contract() -> BuildContract {
    BuildContract {
        package_version: env!("CARGO_PKG_VERSION"),
        target: env!("FOXREQ_TARGET"),
        native_backend: native_backend(),
        profile_schema_version: PROFILE_SCHEMA_VERSION,
    }
}

const fn native_backend() -> &'static str {
    if cfg!(feature = "nss") {
        "nss"
    } else {
        "stub"
    }
}
