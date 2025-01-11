use core::mem::take;

use hashbrown::HashMap;

use crate::{
    hook::{hookify, BoxedHook, HookEnv, HookRegistry},
    subproof::SubproofVerifier,
};

use sp1_primitives::consts::fd::LOWEST_ALLOWED_FD;

/// Context to run a program inside SP1.
#[derive(Clone, Default)]
pub struct SP1Context<'a> {
    /// The registry of hooks invocable from inside SP1.
    ///
    /// Note: `None` denotes the default list of hooks.
    pub hook_registry: Option<HookRegistry<'a>>,

    /// The verifier for verifying subproofs.
    pub subproof_verifier: Option<&'a dyn SubproofVerifier>,

    /// The maximum number of cpu cycles to use for execution.
    pub max_cycles: Option<u64>,

    /// Deferred proof verification.
    pub deferred_proof_verification: bool,
}

/// A builder for [`SP1Context`].
#[derive(Clone)]
pub struct SP1ContextBuilder<'a> {
    no_default_hooks: bool,
    hook_registry_entries: Vec<(u32, BoxedHook<'a>)>,
    subproof_verifier: Option<&'a dyn SubproofVerifier>,
    max_cycles: Option<u64>,
    deferred_proof_verification: bool,
}

impl Default for SP1ContextBuilder<'_> {
    fn default() -> Self {
        Self {
            no_default_hooks: false,
            hook_registry_entries: Vec::new(),
            subproof_verifier: None,
            max_cycles: None,
            // Always verify deferred proofs by default.
            deferred_proof_verification: true,
        }
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
    pub fn new() -> Self {
        SP1ContextBuilder::default()
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

        let subproof_verifier = take(&mut self.subproof_verifier);
        let cycle_limit = take(&mut self.max_cycles);
        let deferred_proof_verification = take(&mut self.deferred_proof_verification);
        SP1Context {
            hook_registry,
            subproof_verifier,
            max_cycles: cycle_limit,
            deferred_proof_verification,
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

    /// Add a subproof verifier.
    ///
    /// The verifier is used to sanity check `verify_sp1_proof` during runtime.
    pub fn subproof_verifier(&mut self, subproof_verifier: &'a dyn SubproofVerifier) -> &mut Self {
        self.subproof_verifier = Some(subproof_verifier);
        self
    }

    /// Set the maximum number of cpu cycles to use for execution.
    pub fn max_cycles(&mut self, max_cycles: u64) -> &mut Self {
        self.max_cycles = Some(max_cycles);
        self
    }

    /// Set the deferred proof verification flag.
    pub fn set_deferred_proof_verification(&mut self, value: bool) -> &mut Self {
        self.deferred_proof_verification = value;
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::{subproof::NoOpSubproofVerifier, SP1Context};

    #[test]
    fn defaults() {
        let SP1Context { hook_registry, subproof_verifier, max_cycles: cycle_limit, .. } =
            SP1Context::builder().build();
        assert!(hook_registry.is_none());
        assert!(subproof_verifier.is_none());
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

    #[test]
    fn subproof_verifier() {
        let verifier = NoOpSubproofVerifier;

        let SP1Context { subproof_verifier, .. } =
            SP1Context::builder().subproof_verifier(&verifier).build();
        assert!(subproof_verifier.is_some());
    }
}
