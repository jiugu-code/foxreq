use foxreq_core::build_contract;

#[test]
fn build_contract_is_deterministic_and_complete() {
    let contract = build_contract();

    assert_eq!(contract.package_version, "0.1.0");
    assert_eq!(contract.target, "x86_64-pc-windows-msvc");
    let expected_backend = if cfg!(feature = "nss") { "nss" } else { "stub" };
    assert_eq!(contract.native_backend, expected_backend);
    assert_eq!(contract.profile_schema_version, 1);
}
