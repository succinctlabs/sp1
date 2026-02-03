cfg_if::cfg_if! {
    // On x86_64 Linux without profiling: use native backend only
    if #[cfg(all(target_arch = "x86_64", target_endian = "little", target_os = "linux", not(feature = "profiling")))] {
        mod x86_64;
        pub use x86_64::*;
    }
    // On x86_64 Linux with profiling: use portable backend, build native only for tests
    else if #[cfg(all(target_arch = "x86_64", target_endian = "little", target_os = "linux", feature = "profiling"))] {
        mod portable;
        pub use portable::*;

        // Build native backend only for differential testing
        #[cfg(test)]
        #[allow(dead_code)]
        pub mod x86_64;
    }
    // On other architectures/platforms: use portable backend only
    else {
        mod portable;
        pub use portable::*;
    }
}
