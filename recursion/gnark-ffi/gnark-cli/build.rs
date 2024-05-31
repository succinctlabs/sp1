use std::env;
use std::path::PathBuf;

#[allow(deprecated)]
use bindgen::CargoCallbacks;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = PathBuf::from(&out_dir);
    let lib_name = "sp1gnark";

    // Generate bindings using bindgen
    let header_path = format!("/usr/include/lib{}.h", lib_name);
    let bindings = bindgen::Builder::default()
        .header(header_path)
        .parse_callbacks(Box::new(CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(dest_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    println!("cargo:rustc-link-lib=static={}", lib_name);
}
