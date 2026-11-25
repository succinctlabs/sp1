#[path = "native/build.rs"]
mod native;

fn main() {
    sp1_build::build_program("./program-v0.29.1");
    sp1_build::build_program("./program-v0.30.0");
    native::build();
}
