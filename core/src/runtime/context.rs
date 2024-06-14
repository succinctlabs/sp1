use core::mem::take;

use super::{hookify, BoxedHook, HookEnv, HookRegistry};

/// Context to run a program inside SP1.
#[derive(Debug, Clone, Default)]
pub struct SP1Context<'a> {
    /// The registry of hooks invokable from inside SP1.
    /// `None` denotes the default list of hooks.
    pub(crate) hook_registry: Option<HookRegistry<'a>>,
}

#[derive(Clone, Default)]
pub struct SP1ContextBuilder<'a> {
    no_default_hooks: bool,
    hook_registry_entries: Vec<(u32, BoxedHook<'a>)>,
}

impl<'a> SP1Context<'a> {
    /// Create a new context builder. See [SP1ContextBuilder] for more details.
    pub fn builder() -> SP1ContextBuilder<'a> {
        SP1ContextBuilder::new()
    }
}

impl<'a> SP1ContextBuilder<'a> {
    /// Create a new [`SP1ContextBuilder`].
    ///
    /// Prefer using [`SP1Context::builder`].
    pub fn new() -> Self {
        Default::default()
    }

    /// Build and return the [SP1Context].
    ///
    /// Clears and resets the builder, allowing it to be reused.
    pub fn build(&mut self) -> SP1Context<'a> {
        let mut table = if take(&mut self.no_default_hooks) {
            Default::default()
        } else {
            HookRegistry::default().table
        };
        // Allows overwriting default hooks.
        table.extend(take(&mut self.hook_registry_entries));
        SP1Context {
            hook_registry: Some(HookRegistry { table }),
        }
    }

    /// Add a runtime [Hook](super::Hook) into the context.
    ///
    /// Hooks may be invoked from within SP1 by writing to the specified file descriptor `fd`
    /// with [`sp1_zkvm::io::write`], returning a list of arbitrary data that may be read
    /// with successive calls to [`sp1_zkvm::io::read`].
    pub fn hook(
        &mut self,
        fd: u32,
        f: impl FnMut(HookEnv, &[u8]) -> Vec<Vec<u8>> + Send + Sync + 'a,
    ) -> &mut Self {
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
}

// TODO tests?
