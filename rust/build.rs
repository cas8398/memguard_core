// build.rs
use std::env;

fn main() {
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    
    let target = env::var("TARGET").unwrap();
    
    // iOS specific flags
    if target.contains("apple-ios") {
        println!("cargo:rustc-link-arg=-Wl,-dead_strip");
        println!("cargo:rustc-link-arg=-fembed-bitcode");
    }
    
    // Android specific flags
    if target.contains("android") {
        println!("cargo:rustc-link-lib=dylib=log");
        println!("cargo:rustc-link-lib=dylib=c++_shared");
    }
}