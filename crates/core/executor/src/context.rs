use crate::hook::{hookify, BoxedHook, HookEnv, HookRegistry};
use core::mem::take;
use hashbrown::HashMap;
use sp1_hypercube::air::PROOF_NONCE_NUM_WORDS;
use std::io::Write;

use sp1_primitives::consts::fd::LOWEST_ALLOWED_FD;

/// The status code of the execution.
///
/// Currently the only supported status codes are `0` for success and `1` for failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusCode(u32);

impl StatusCode {
    /// The success status code.
    pub const SUCCESS: Self = Self(0);
    /// The panic status code.
    pub const PANIC: Self = Self(1);
    /// Accept either success or panic.
    pub const ANY: Self = Self(u32::MAX);

    /// Create a new status code from a u32.
    ///
    /// # Arguments
    /// * `code` - The status code to create.
    ///
    /// # Returns
    /// * `Some(StatusCode)` - The status code if it is valid: {0, 1}.
    /// * `None` - The status code is not valid.
    #[must_use]
    pub const fn new(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::SUCCESS),
            1 => Some(Self::PANIC),
            _ => None,
        }
    }

    /// Get the u32 value of the status code.
    #[must_use]
    pub const fn as_u32(&self) -> u32 {
        self.0
    }

    /// Check if the status code is equal to the given value.
    #[must_use]
    pub const fn is_accepted_code(&self, code: u32) -> bool {
        (code == 0 || code == 1) && (self.0 == Self::ANY.0 || self.0 == code)
    }
}

/// Context to run a program inside SP1.
#[derive(Clone)]
pub struct SP1Context<'a> {
    /// The registry of hooks invocable from inside SP1.
    ///
    /// Note: `None` denotes the default list of hooks.
    pub hook_registry: Option<HookRegistry<'a>>,

    /// The maximum number of cpu cycles to use for execution.
    pub max_cycles: Option<u64>,

    /// Deferred proof verification.
    pub deferred_proof_verification: bool,

    /// The expected exit code of the program.
    pub expected_exit_code: StatusCode,

    /// Whether gas (available in the `ExecutionReport`) should be calculated during execution.
    /// Does nothing while proving.
    ///
    /// This option will noticeably slow down execution, so it should be disabled in most cases.
    pub calculate_gas: bool,

    /// The nonce used for this specific proof execution (4 x u32 = 128 bits of entropy).
    /// This nonce ensures each proof is unique even for identical programs and inputs.
    pub proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],

    /// The IO options for the [`SP1Executor`].
    pub io_options: IoOptions<'a>,
}

impl Default for SP1Context<'_> {
    fn default() -> Self {
        Self::builder().build()
    }
}

/// A builder for [`SP1Context`].
pub struct SP1ContextBuilder<'a> {
    no_default_hooks: bool,
    hook_registry_entries: Vec<(u32, BoxedHook<'a>)>,
    max_cycles: Option<u64>,
    deferred_proof_verification: bool,
    calculate_gas: bool,
    expected_exit_code: Option<StatusCode>,
    proof_nonce: [u32; 4],
    // TODO remove the lifetime here, change stdout and stderr options to accept channels.
    io_options: IoOptions<'a>,
}

impl Default for SP1ContextBuilder<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> SP1Context<'a> {
    /// Create a new context builder. See [`SP1ContextBuilder`] for more details.
    #[must_use]
    pub fn builder() -> SP1ContextBuilder<'a> {
        SP1ContextBuilder::new()
    }
}

impl<'a> SP1ContextBuilder<'a> {
    /// Create a new [`SP1ContextBuilder`].
    ///
    /// Prefer using [`SP1Context::builder`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            no_default_hooks: false,
            hook_registry_entries: Vec::new(),
            max_cycles: None,
            // Always verify deferred proofs by default.
            deferred_proof_verification: true,
            calculate_gas: true,
            expected_exit_code: None,
            proof_nonce: [0, 0, 0, 0], // Default to zeros, will be set by SDK
            io_options: IoOptions::new(),
        }
    }

    /// Build and return the [`SP1Context`].
    ///
    /// Clears and resets the builder, allowing it to be reused.
    pub fn build(&mut self) -> SP1Context<'a> {
        // If hook_registry_entries is nonempty or no_default_hooks true,
        // indicating a non-default value of hook_registry.
        //
        // Panics:
        // - If any hook file descriptor is less than [`LOWEST_ALLOWED_FD`].
        let hook_registry =
            (!self.hook_registry_entries.is_empty() || self.no_default_hooks).then(|| {
                let mut table = if take(&mut self.no_default_hooks) {
                    HashMap::default()
                } else {
                    HookRegistry::default().table
                };

                self.hook_registry_entries
                    .iter()
                    .map(|(fd, _)| fd)
                    .filter(|fd| table.contains_key(*fd))
                    .for_each(|fd| {
                        tracing::warn!("Overriding default hook with file descriptor {}", fd);
                    });

                // Allows overwriting default hooks.
                table.extend(take(&mut self.hook_registry_entries));
                HookRegistry { table }
            });

        let cycle_limit = take(&mut self.max_cycles);
        let deferred_proof_verification = take(&mut self.deferred_proof_verification);
        let calculate_gas = take(&mut self.calculate_gas);
        let proof_nonce = take(&mut self.proof_nonce);
        SP1Context {
            hook_registry,
            max_cycles: cycle_limit,
            deferred_proof_verification,
            calculate_gas,
            proof_nonce,
            io_options: take(&mut self.io_options),
            expected_exit_code: self.expected_exit_code.unwrap_or(StatusCode::SUCCESS),
        }
    }

    /// Add a runtime [Hook](super::Hook) into the context.
    ///
    /// Hooks may be invoked from within SP1 by writing to the specified file descriptor `fd`
    /// with [`sp1_zkvm::io::write`], returning a list of arbitrary data that may be read
    /// with successive calls to [`sp1_zkvm::io::read`].
    ///
    /// # Panics
    /// Panics if `fd` <= [`LOWEST_ALLOWED_FD`].
    pub fn hook(
        &mut self,
        fd: u32,
        f: impl FnMut(HookEnv, &[u8]) -> Vec<Vec<u8>> + Send + Sync + 'a,
    ) -> &mut Self {
        assert!(fd > LOWEST_ALLOWED_FD, "Hook file descriptors must be greater than 10.");

        self.hook_registry_entries.push((fd, hookify(f)));
        self
    }

    /// Avoid registering the default hooks in the runtime.
    ///
    /// It is not necessary to call this to override hooks --- instead, simply
    /// register a hook with the same value of `fd` by calling [`Self::hook`].
    pub fn without_default_hooks(&mut self) -> &mut Self {
        self.no_default_hooks = true;
        self
    }

    /// Whether gas should be calculated while executing. Defaults to `true`.
    /// Determines whether the gas field in the `ExecutionReport` is `None` or `Some`.
    ///
    /// During proving, gas is not calculated, so this option has no effect.
    ///
    /// Disabling gas calculation will likely speed up execution.
    pub fn calculate_gas(&mut self, value: bool) -> &mut Self {
        self.calculate_gas = value;
        self
    }

    /// Set the maximum number of cpu cycles to use for execution.
    /// `report.total_instruction_count()` will be less than or equal to `max_cycles`.
    pub fn max_cycles(&mut self, max_cycles: u64) -> &mut Self {
        self.max_cycles = Some(max_cycles);
        self
    }

    /// Set the deferred proof verification flag.
    pub fn set_deferred_proof_verification(&mut self, value: bool) -> &mut Self {
        self.deferred_proof_verification = value;
        self
    }

    /// Set the `stdout` writer.
    pub fn stdout<W: IoWriter>(&mut self, writer: &'a mut W) -> &mut Self {
        self.io_options.stdout = Some(writer);
        self
    }

    /// Set the `stderr` writer.
    pub fn stderr<W: IoWriter>(&mut self, writer: &'a mut W) -> &mut Self {
        self.io_options.stderr = Some(writer);
        self
    }

    /// Set the expected exit code of the program.
    pub fn expected_exit_code(&mut self, code: StatusCode) -> &mut Self {
        self.expected_exit_code = Some(code);
        self
    }

    /// Set the proof nonce for this execution.
    /// This nonce ensures each proof is unique even for identical programs and inputs.
    pub fn proof_nonce(&mut self, nonce: [u32; 4]) -> &mut Self {
        self.proof_nonce = nonce;
        self
    }
}

/// The IO options for the [`SP1Executor`].
///
/// This struct is used to redirect the `stdout` and `stderr` of the [`SP1Executor`].
///
/// Note: Cloning this type will not clone the writers.
#[derive(Default)]
pub struct IoOptions<'a> {
    /// A writer to redirect `stdout` to.
    pub stdout: Option<&'a mut dyn IoWriter>,
    /// A writer to redirect `stderr` to.
    pub stderr: Option<&'a mut dyn IoWriter>,
}

impl IoOptions<'_> {
    /// Create a new [`IoOptions`] with no writers.
    #[must_use]
    pub const fn new() -> Self {
        Self { stdout: None, stderr: None }
    }
}
impl Clone for IoOptions<'_> {
    fn clone(&self) -> Self {
        IoOptions { stdout: None, stderr: None }
    }
}

/// A trait for [`Write`] types to be used in the executor.
///
/// This trait is generically implemented for any [`Write`] + [`Send`] type.
pub trait IoWriter: Write + Send + Sync {}

impl<W: Write + Send + Sync> IoWriter for W {}

#[cfg(test)]
mod tests {
    use crate::SP1Context;

    #[test]
    fn defaults() {
        let SP1Context { hook_registry, max_cycles: cycle_limit, .. } =
            SP1Context::builder().build();
        assert!(hook_registry.is_none());
        assert!(cycle_limit.is_none());
    }

    #[test]
    fn without_default_hooks() {
        let SP1Context { hook_registry, .. } =
            SP1Context::builder().without_default_hooks().build();
        assert!(hook_registry.unwrap().table.is_empty());
    }

    #[test]
    fn with_custom_hook() {
        let SP1Context { hook_registry, .. } =
            SP1Context::builder().hook(30, |_, _| vec![]).build();
        assert!(hook_registry.unwrap().table.contains_key(&30));
    }

    #[test]
    fn without_default_hooks_with_custom_hook() {
        let SP1Context { hook_registry, .. } =
            SP1Context::builder().without_default_hooks().hook(30, |_, _| vec![]).build();
        assert_eq!(&hook_registry.unwrap().table.into_keys().collect::<Vec<_>>(), &[30]);
    }
}
