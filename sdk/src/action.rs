use sp1_core::{
    runtime::{ExecutionReport, HookEnv, SP1ContextBuilder},
    utils::{SP1CoreOpts, SP1ProverOpts},
};
use sp1_prover::{
    components::DefaultProverComponents, SP1Prover, SP1ProvingKey, SP1PublicValues, SP1Stdin,
};

use anyhow::{Ok, Result};

use crate::{Prover, SP1ProofKind, SP1ProofWithPublicValues};

/// Builder to prepare and configure execution of a program on an input.
/// May be run with [Self::run].
#[derive(Default)]
pub struct Execute<'a> {
    context_builder: SP1ContextBuilder<'a>,
    elf: &'a [u8],
    stdin: SP1Stdin,
}

impl<'a> Execute<'a> {
    /// Prepare to execute the given program on the given input (without generating a proof).
    ///
    /// Prefer using [ProverClient::execute](super::ProverClient::execute).
    /// See there for more documentation.
    pub fn new(elf: &'a [u8], stdin: SP1Stdin) -> Self {
        Self {
            elf,
            stdin,
            context_builder: Default::default(),
        }
    }

    /// Execute the program on the input, consuming the built action `self`.
    pub fn run(self) -> Result<(SP1PublicValues, ExecutionReport)> {
        let Self {
            elf,
            stdin,
            mut context_builder,
        } = self;
        let context = context_builder.build();
        Ok(SP1Prover::<DefaultProverComponents>::execute(
            elf, &stdin, context,
        )?)
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

    /// Set the maximum number of cpu cycles to use for execution.
    ///
    /// If the cycle limit is exceeded, execution will return [sp1_core::runtime::ExecutionError::ExceededCycleLimit].
    pub fn max_cycles(mut self, max_cycles: u64) -> Self {
        self.context_builder.max_cycles(max_cycles);
        self
    }
}

/// Builder to prepare and configure proving execution of a program on an input.
/// May be run with [Self::run].
pub struct Prove<'a> {
    prover: &'a dyn Prover<DefaultProverComponents>,
    kind: SP1ProofKind,
    context_builder: SP1ContextBuilder<'a>,
    pk: &'a SP1ProvingKey,
    stdin: SP1Stdin,
    core_opts: SP1CoreOpts,
    recursion_opts: SP1CoreOpts,
}

impl<'a> Prove<'a> {
    /// Prepare to prove the execution of the given program with the given input.
    ///
    /// Prefer using [ProverClient::prove](super::ProverClient::prove).
    /// See there for more documentation.
    pub fn new(
        prover: &'a dyn Prover<DefaultProverComponents>,
        pk: &'a SP1ProvingKey,
        stdin: SP1Stdin,
    ) -> Self {
        Self {
            prover,
            kind: Default::default(),
            pk,
            stdin,
            context_builder: Default::default(),
            core_opts: SP1CoreOpts::default(),
            recursion_opts: SP1CoreOpts::recursion(),
        }
    }

    /// Prove the execution of the program on the input, consuming the built action `self`.
    pub fn run(self) -> Result<SP1ProofWithPublicValues> {
        let Self {
            prover,
            kind,
            pk,
            stdin,
            mut context_builder,
            core_opts,
            recursion_opts,
        } = self;
        let opts = SP1ProverOpts {
            core_opts,
            recursion_opts,
        };
        let context = context_builder.build();

        prover.prove(pk, stdin, opts, context, kind)
    }

    /// Set the proof kind to the core mode. This is the default.
    pub fn core(mut self) -> Self {
        self.kind = SP1ProofKind::Core;
        self
    }

    /// Set the proof kind to the compressed mode.
    pub fn compressed(mut self) -> Self {
        self.kind = SP1ProofKind::Compressed;
        self
    }

    /// Set the proof mode to the plonk bn254 mode.
    pub fn plonk(mut self) -> Self {
        self.kind = SP1ProofKind::Plonk;
        self
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

    /// Set the shard size for proving.
    pub fn shard_size(mut self, value: usize) -> Self {
        self.core_opts.shard_size = value;
        self
    }

    /// Set the shard batch size for proving.
    pub fn shard_batch_size(mut self, value: usize) -> Self {
        self.core_opts.shard_batch_size = value;
        self
    }

    /// Set whether we should reconstruct commitments while proving.
    pub fn reconstruct_commitments(mut self, value: bool) -> Self {
        self.core_opts.reconstruct_commitments = value;
        self
    }

    /// Set the maximum number of cpu cycles to use for execution.
    ///
    /// If the cycle limit is exceeded, execution will return [sp1_core::runtime::ExecutionError::ExceededCycleLimit].
    pub fn cycle_limit(mut self, cycle_limit: u64) -> Self {
        self.context_builder.max_cycles(cycle_limit);
        self
    }
}
