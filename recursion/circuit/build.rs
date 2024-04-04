use std::env;
use std::process::Command;

fn main() {
    // Get the current directory of the build script
    let current_dir = env::current_dir().expect("failed to get current directory");

    // Navigate to the parent directory
    let parent_dir = current_dir
        .parent()
        .expect("failed to find parent directory")
        .join("groth16");

    // Run `make` in the parent directory
    let status = Command::new("make")
        .current_dir(parent_dir) // This sets the working directory for the command
        .status()
        .expect("failed to build groth16");

    if !status.success() {
        panic!("failed to execute make with status: {}", status);
    }

    println!("successfully ran make in the parent directory");
}
