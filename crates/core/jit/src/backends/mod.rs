pub mod debug;
pub use debug::DebugBackend;

#[cfg(all(target_arch = "x86_64", target_endian = "little", target_os = "linux"))]
pub mod x86;
#[cfg(all(target_arch = "x86_64", target_endian = "little", target_os = "linux"))]
pub use x86::TranspilerBackend;
