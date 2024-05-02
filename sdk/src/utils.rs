pub use sp1_core::utils::{setup_logger, setup_tracer};

use std::env;

/// A guard that sets an environment variable to a new value and restores the original value when
/// dropped.
pub(crate) struct EnvVarGuard {
    name: String,
    original_value: Option<String>,
}

impl EnvVarGuard {
    pub(crate) fn new(name: &str, value: &str) -> Self {
        let original_value = env::var(name).ok();
        env::set_var(name, value);
        EnvVarGuard {
            name: name.to_string(),
            original_value,
        }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match &self.original_value {
            Some(value) => env::set_var(&self.name, value),
            None => env::remove_var(&self.name),
        }
    }
}
