use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    let target = env::var("TARGET").expect("Cargo always sets TARGET for build scripts");
    println!("cargo:rustc-env=FOXREQ_TARGET={target}");

    if env::var_os("CARGO_FEATURE_NSS").is_some() {
        build_native_stub(&target);
    }
}

fn build_native_stub(target: &str) {
    let manifest = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo always sets CARGO_MANIFEST_DIR"),
    );
    let repository = manifest
        .parent()
        .and_then(Path::parent)
        .expect("foxreq-core remains inside crates/");
    let source = repository.join("native/nss-shim");
    let build =
        PathBuf::from(env::var_os("OUT_DIR").expect("Cargo always sets OUT_DIR")).join("nss-shim");
    let cmake = resolve_cmake();

    println!("cargo:rerun-if-changed={}", source.display());
    println!(
        "cargo:rerun-if-changed={}",
        repository.join("cmake").display()
    );

    let mut configure = Command::new(&cmake);
    configure
        .arg("-S")
        .arg(&source)
        .arg("-B")
        .arg(&build)
        .arg("-DFOXREQ_NSS_STUB=ON")
        .arg("-DBUILD_TESTING=OFF");

    let link_directory = if target.contains("windows-msvc") {
        let architecture = if target.starts_with("x86_64") {
            "x64"
        } else if target.starts_with("aarch64") {
            "ARM64"
        } else {
            panic!("unsupported Windows NSS target: {target}");
        };
        configure
            .arg("-G")
            .arg("Visual Studio 17 2022")
            .arg("-A")
            .arg(architecture);
        build.join("Release")
    } else {
        configure.arg("-G").arg("Ninja");
        build.clone()
    };
    run(&mut configure, "configure the NSS shim");

    let mut compile = Command::new(&cmake);
    compile
        .arg("--build")
        .arg(&build)
        .arg("--target")
        .arg("foxreq_nss");
    if target.contains("windows-msvc") {
        compile.arg("--config").arg("Release");
    }
    run(&mut compile, "build the NSS shim");

    println!(
        "cargo:rustc-link-search=native={}",
        link_directory.display()
    );
    println!("cargo:rustc-link-lib=static=foxreq_nss");
}

fn resolve_cmake() -> PathBuf {
    if let Some(value) = env::var_os("CMAKE") {
        return PathBuf::from(value);
    }
    let windows_default = PathBuf::from(r"C:\Program Files\CMake\bin\cmake.exe");
    if windows_default.is_file() {
        windows_default
    } else {
        PathBuf::from("cmake")
    }
}

fn run(command: &mut Command, description: &str) {
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("failed to {description}: {error}"));
    assert!(status.success(), "failed to {description}: {status}");
}
