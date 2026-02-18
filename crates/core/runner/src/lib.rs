//! This crate provides a safe MinimalExecutor runner for arbitrary,
//! unknown SP1 programs. It runs MinimalExecutor with additional protections:
//!
//! * For native executor, it runs SP1 programs in a dedicated, separated child
//!   process, the SP1 program is then guarded against out-of-bound accesses.
//!   The total memory used by the child process(resident set size, or RSS) is
//!   also limited, so an SP1 program won't use too much memory of host machine.
//! * For portable executor, it just limits the number of entries in `PagedMemory`.
//!   In a way, this also limits the maximum memory used by a SP1 program.
//!
//! Due to the different in implementations, portable executor is likely to consume
//! more memory, when using the same memory limit. Since portable executor only
//! caps actually used memory.

/// Default memory limit to use, note this value has different semantics on
/// different implementation. For native executor, it is the limit on total
/// process memory(resident set size, or RSS) of thie entire child process. For
/// portable executor, it is merely the limit on created memory entries. This
/// means the actual memory usage for portable executor will exceed this limit.
pub const DEFAULT_MEMORY_LIMIT: u64 = 24 * 1024 * 1024 * 1024; // 24 GB

#[cfg(test)]
pub mod tests;

#[cfg(sp1_use_native_executor)]
mod native;

#[cfg(sp1_use_native_executor)]
pub use crate::native::MinimalExecutorRunner;

#[cfg(not(sp1_use_native_executor))]
mod portable;

#[cfg(not(sp1_use_native_executor))]
pub use crate::portable::MinimalExecutorRunner;

#[cfg(sp1_use_native_executor)]
mod binary {
    use std::path::Path;

    // =================================================================
    // CASE 1: OVERRIDE MODE
    // =================================================================
    // If the override env var was detected by build.rs, we compile this simple function.
    // It just points to the external binary path provided at build time.
    #[cfg(sp1_core_runner_override)]
    pub fn get_binary_path() -> &'static Path {
        Path::new(env!("SP1_CORE_RUNNER_OVERRIDE_BINARY"))
    }

    // =================================================================
    // CASE 2: DEFAULT MODE (Embed + TempFile)
    // =================================================================
    // If no override, we compile this inline module to handle extraction.
    #[cfg(not(sp1_core_runner_override))]
    mod embedded {
        use std::fs;
        use std::path::PathBuf;
        use std::sync::OnceLock;

        // This static variable holds the "Guard" for the temporary file.
        // As long as this variable exists (which is the lifetime of the process),
        // the file exists on disk. When the process dies, this is dropped, and the file is deleted.
        static BINARY_GUARD: OnceLock<PathBuf> = OnceLock::new();

        pub fn get_path() -> &'static std::path::Path {
            BINARY_GUARD.get_or_init(extract_binary)
        }

        fn extract_binary() -> PathBuf {
            // 1. Configure the temp file
            let filename = format!("sp1-native-runner-bin-{}", env!("SP1_CORE_RUNNER_BINARY_HASH"));
            let mut target_path = std::env::temp_dir();
            target_path.push(&filename);

            // 2. Fast Path: if it exists, we just trust and use it;
            if target_path.exists() {
                return target_path;
            }

            // 3. Get the embedded bytes
            const BYTES: &[u8] = include_bytes!(env!("SP1_CORE_RUNNER_BINARY"));

            // 4. Create a generic temp file first to ensure atomicity
            let temp_path = {
                let random_suffix = format!(".tmp.{}", std::process::id());
                let temp_filename = format!("{}{}", filename, random_suffix);
                let mut temp_path = std::env::temp_dir();
                temp_path.push(temp_filename);
                temp_path
            };

            // 5. Write the binary data
            fs::write(&temp_path, BYTES).expect("Failed to write internal binary to disk");

            // 6 Set executable permissions (Unix/Linux/Mac only)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&temp_path).unwrap().permissions();
                perms.set_mode(0o755); // rwxr-xr-x
                fs::set_permissions(&temp_path, perms).expect("Failed to make binary executable");
            }

            // 7. Atomic rename
            match fs::rename(&temp_path, &target_path) {
                Ok(_) => (),
                Err(_) => {
                    // Another process must be doing the same steps, we should be fine here.
                    assert!(target_path.exists());
                    let _ = fs::remove_file(&temp_path);
                }
            }

            target_path
        }
    }

    // The public function simply delegates to the inline module
    #[cfg(not(sp1_core_runner_override))]
    pub fn get_binary_path() -> &'static Path {
        embedded::get_path()
    }
}
