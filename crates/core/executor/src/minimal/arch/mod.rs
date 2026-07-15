cfg_if::cfg_if! {
    // On x86_64 Linux without profiling: use native backend only
    if #[cfg(sp1_use_native_executor)] {
        pub mod x86_64;
        pub use x86_64::*;
        // Also expose `portable` for the `sp1-perf` bench harness.
        /// The portable executor.
        pub mod portable;
    }
    // On x86_64 Linux with profiling: use portable backend, build native only for tests
    else if #[cfg(all(sp1_native_executor_available, feature = "profiling"))] {
        /// The portable executor. `pub` so the `arch::portable` path resolves on every target.
        pub mod portable;
        pub use portable::*;

        // Build native backend for differential testing and for the bench harness.
        #[allow(dead_code)]
        pub mod x86_64;
    }
    // On other architectures/platforms: use portable backend only
    else {
        /// The portable executor. `pub` so the `arch::portable` path resolves on every target.
        pub mod portable;
        pub use portable::*;
    }
}
