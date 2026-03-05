/// Based on architecture & feature configurations, choose between
/// native executor and portable executor.
#[allow(clippy::print_stdout)]
pub fn detect_executor() {
    assert!(std::env::var("OUT_DIR").is_ok(), "detect_executor is not run inside build script!");

    #[cfg(all(target_arch = "x86_64", target_endian = "little", target_os = "linux",))]
    println!("cargo:rustc-cfg=sp1_native_executor_available");

    #[cfg(all(
        target_arch = "x86_64",
        target_endian = "little",
        target_os = "linux",
        not(feature = "profiling")
    ))]
    println!("cargo:rustc-cfg=sp1_use_native_executor");

    #[cfg(not(all(
        target_arch = "x86_64",
        target_endian = "little",
        target_os = "linux",
        not(feature = "profiling")
    )))]
    println!("cargo:rustc-cfg=sp1_use_portable_executor");
}
