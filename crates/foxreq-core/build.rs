use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    let target = env::var("TARGET").expect("Cargo always sets TARGET for build scripts");
    println!("cargo:rustc-env=FOXREQ_TARGET={target}");

    if env::var_os("CARGO_FEATURE_NSS").is_some() {
        build_native(&target);
    }
}

fn build_native(target: &str) {
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
    let real = env::var_os("CARGO_FEATURE_NSS_REAL").is_some();

    if real {
        assert!(
            target == "x86_64-pc-windows-msvc",
            "the pinned real NSS backend currently supports x86_64-pc-windows-msvc only"
        );
        let runtime_dir = env::var_os("FOXREQ_NSS_RUNTIME_DIR")
            .expect("FOXREQ_NSS_RUNTIME_DIR is required for nss-real tests");
        let runtime_dir = runtime_dir
            .into_string()
            .expect("FOXREQ_NSS_RUNTIME_DIR must be valid Unicode");
        println!("cargo:rerun-if-env-changed=FOXREQ_NSS_RUNTIME_DIR");
        println!("cargo:rustc-env=FOXREQ_NSS_RUNTIME_DIR={runtime_dir}");
    }

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
        .arg("-DBUILD_TESTING=OFF");
    if real {
        configure
            .arg("-DFOXREQ_NSS_REAL=ON")
            .arg("-DFOXREQ_NSS_STUB=OFF");
    } else {
        configure
            .arg("-DFOXREQ_NSS_STUB=ON")
            .arg("-DFOXREQ_NSS_REAL=OFF");
    }

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
    sanitize_windows_environment(&mut configure);
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
    sanitize_windows_environment(&mut compile);
    run(&mut compile, "build the NSS shim");

    println!(
        "cargo:rustc-link-search=native={}",
        link_directory.display()
    );
    println!("cargo:rustc-link-lib=static=foxreq_nss");
    if real && target.contains("windows-msvc") {
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=ws2_32");
    }
}

fn sanitize_windows_environment(command: &mut Command) {
    if !cfg!(windows) {
        return;
    }
    let mut values: BTreeMap<String, (bool, OsString, OsString)> = BTreeMap::new();
    for (key, value) in env::vars_os() {
        let text = key.to_string_lossy();
        let normalized = text.to_ascii_uppercase();
        let exact_uppercase = text == normalized;
        let canonical = if normalized == "PATH" {
            OsString::from("PATH")
        } else {
            key
        };
        match values.get(&normalized) {
            Some((existing_uppercase, _, _)) if *existing_uppercase && !exact_uppercase => {}
            _ => {
                values.insert(normalized, (exact_uppercase, canonical, value));
            }
        }
    }
    command.env_clear();
    command.envs(values.into_values().map(|(_, key, value)| (key, value)));
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
