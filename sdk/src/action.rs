use sp1_core::runtime::{ExecutionReport, HookEnv, SP1ContextBuilder};
use sp1_prover::{SP1Prover, SP1ProvingKey, SP1PublicValues, SP1Stdin};

use anyhow::{Ok, Result};

use crate::{Prover, SP1Proof};

#[derive(Default)]
pub struct Execute<'a> {
    context_builder: SP1ContextBuilder<'a>,
    elf: &'a [u8],
    stdin: SP1Stdin,
}

impl<'a> Execute<'a> {
    pub fn new(elf: &'a [u8], stdin: SP1Stdin) -> Self {
        Self {
            elf,
            stdin,
            context_builder: Default::default(),
        }
    }

    pub fn run(self) -> Result<(SP1PublicValues, ExecutionReport)> {
        let Self {
            elf,
            stdin,
            mut context_builder,
        } = self;
        let context = context_builder.build();
        Ok(SP1Prover::execute_with_context(elf, &stdin, context)?)
    }

    /// Add a runtime [Hook](super::Hook) into the context.
    ///
    /// Hooks may be invoked from within SP1 by writing to the specified file descriptor `fd`
    /// with [`sp1_zkvm::io::write`], returning a list of arbitrary data that may be read
    /// with successive calls to [`sp1_zkvm::io::read`].
    pub fn with_hook(
        mut self,
        fd: u32,
        f: impl FnMut(HookEnv, &[u8]) -> Vec<Vec<u8>> + Send + Sync + 'a,
    ) -> Self {
        self.context_builder.hook(fd, f);
        self
    }

    /// Avoid registering the default hooks in the runtime.
    ///
    /// It is not necessary to call this to override hooks --- instead, simply
    /// register a hook with the same value of `fd` by calling [`Self::hook`].
    pub fn without_default_hooks(mut self) -> Self {
        self.context_builder.without_default_hooks();
        self
    }
}

pub struct Prove<'a> {
    prover: &'a dyn Prover,
    context_builder: SP1ContextBuilder<'a>,
    pk: &'a SP1ProvingKey,
    stdin: SP1Stdin,
}

impl<'a> Prove<'a> {
    pub fn new(prover: &'a dyn Prover, pk: &'a SP1ProvingKey, stdin: SP1Stdin) -> Self {
        Self {
            prover,
            pk,
            stdin,
            context_builder: Default::default(),
        }
    }

    pub fn run(self) -> Result<SP1Proof> {
        let Self {
            prover,
            pk,
            stdin,
            mut context_builder,
        } = self;
        let context = context_builder.build();
        // TODO remove all the extra with_context

        prover.prove_with_context(pk, stdin, context)
    }

    /// Add a runtime [Hook](super::Hook) into the context.
    ///
    /// Hooks may be invoked from within SP1 by writing to the specified file descriptor `fd`
    /// with [`sp1_zkvm::io::write`], returning a list of arbitrary data that may be read
    /// with successive calls to [`sp1_zkvm::io::read`].
    pub fn with_hook(
        mut self,
        fd: u32,
        f: impl FnMut(HookEnv, &[u8]) -> Vec<Vec<u8>> + Send + Sync + 'a,
    ) -> Self {
        self.context_builder.hook(fd, f);
        self
    }

    /// Avoid registering the default hooks in the runtime.
    ///
    /// It is not necessary to call this to override hooks --- instead, simply
    /// register a hook with the same value of `fd` by calling [`Self::hook`].
    pub fn without_default_hooks(mut self) -> Self {
        self.context_builder.without_default_hooks();
        self
    }
}
