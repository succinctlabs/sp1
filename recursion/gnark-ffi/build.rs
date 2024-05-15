use std::env;
use std::path::PathBuf;
use std::process::Command;

#[allow(deprecated)]
use bindgen::CargoCallbacks;

fn main() {
    println!("cargo:rerun-if-changed=go");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:warning=Building Go library");
    // Define the output directory
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = PathBuf::from(&out_dir);
    let lib_name = "sp1gnark";
    let dest = dest_path.join(format!("lib{}.a", lib_name));

    println!("cargo:warning=Building Go library at {}", dest.display());

    // Run the go build command
    let status = Command::new("go")
        .current_dir("go")
        .env("CGO_ENABLED", "1")
        .args([
            "build",
            "-o",
            dest.to_str().unwrap(),
            "-buildmode=c-archive",
            "main.go",
        ])
        .status()
        .expect("Failed to build Go library");
    if !status.success() {
        panic!("Go build failed");
    }

    // Copy go/lib/babybear.h to OUT_DIR/lib/babybear.h
    let header_src = PathBuf::from("go/lib/babybear.h");
    let header_dest_dir = dest_path.join("lib/");
    let header_dest = header_dest_dir.join("babybear.h");
    // mkdirs
    std::fs::create_dir_all(&header_dest_dir).unwrap();
    std::fs::copy(header_src, header_dest).unwrap();

    // Generate bindings using bindgen
    let header_path = dest_path.join(format!("lib{}.h", lib_name));
    let bindings = bindgen::Builder::default()
        .header(header_path.to_str().unwrap())
        .parse_callbacks(Box::new(CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(dest_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    println!("cargo:warning=Go library built");

    // Link the Go library
    println!("cargo:rustc-link-search=native={}", dest_path.display());
    println!("cargo:rustc-link-lib=static={}", lib_name);
}
