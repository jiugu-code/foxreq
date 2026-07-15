use std::env;

fn main() {
    let target = env::var("TARGET").expect("Cargo always sets TARGET for build scripts");
    println!("cargo:rustc-env=FOXREQ_TARGET={target}");
}
