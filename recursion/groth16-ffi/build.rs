use std::env;
use std::process::Command;

fn main() {
    // Rebuild if the groth16 program or lib changes.
    println!("cargo:rerun-if-changed=../groth16/babybear");
    println!("cargo:rerun-if-changed=../groth16/lib/babybear/src");
    println!("cargo:rerun-if-changed=../groth16/poseidon2");
    println!("cargo:rerun-if-changed=../groth16/go.mod");
    println!("cargo:rerun-if-changed=../groth16/go.sum");
    println!("cargo:rerun-if-changed=../groth16/main.go");

    // Get the current directory of the build script.
    let current_dir = env::current_dir().expect("failed to get current directory");

    // Navigate to the parent directory.
    let parent_dir = current_dir
        .parent()
        .expect("failed to find parent directory")
        .join("groth16");

    // Run `make` in the parent directory.
    let status = Command::new("make")
        .current_dir(parent_dir.clone())
        .status()
        .expect("failed to build groth16");
    if !status.success() {
        panic!("failed to execute make with status: {}", status);
    }

    // Create the "build" directory.
    let status = Command::new("mkdir")
        .args(["-p", "../groth16-ffi/build"])
        .current_dir(parent_dir.clone())
        .status()
        .expect("failed to create build directory");
    if !status.success() {
        panic!("failed to create build directory");
    }

    // Move `main` binary to groth16-ffi.
    let status = Command::new("mv")
        .args(["main", "../groth16-ffi/build/bin"])
        .current_dir(parent_dir)
        .status()
        .expect("failed to copy groth16 binary");
    if !status.success() {
        panic!("failed to move binary with status: {}", status);
    }

    println!("successfully ran make in the parent directory");
}
