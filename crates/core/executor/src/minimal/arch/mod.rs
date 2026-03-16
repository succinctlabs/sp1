cfg_if::cfg_if! {
    // On x86_64 Linux without profiling: use native backend only
    if #[cfg(sp1_use_native_executor)] {
        mod x86_64;
        pub use x86_64::*;
    }
    // On x86_64 Linux with profiling: use portable backend, build native only for tests
    else if #[cfg(all(sp1_native_executor_available, feature = "profiling"))] {
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
