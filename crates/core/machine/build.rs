fn main() {
    // Tell Cargo that if the given file changes, to rerun this build script.
    //println!("cargo:rerun-if-changed=ffi/mod.cpp");
    // Use the `cc` crate to build a C++ file and statically link it.
    cc::Build::new().cpp(true).file("ffi/mod.cpp").compile("mod");
}
