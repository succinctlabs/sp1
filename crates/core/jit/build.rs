fn main() {
    #[cfg(all(target_arch = "x86_64", target_endian = "little", target_os = "linux",))]
    println!("cargo:rustc-cfg=sp1_native_executor_available");
}
