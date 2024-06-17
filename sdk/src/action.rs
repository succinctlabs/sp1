use sp1_core::{
    runtime::{ExecutionReport, HookEnv, SP1ContextBuilder},
    utils::{SP1CoreOpts, SP1ProverOpts},
};
use sp1_prover::{SP1Prover, SP1ProvingKey, SP1PublicValues, SP1Stdin};

use anyhow::{Ok, Result};

use crate::{Prover, SP1Proof, SP1ProofKind};

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
        Ok(SP1Prover::execute(elf, &stdin, context)?)
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
    kind: SP1ProofKind,
    context_builder: SP1ContextBuilder<'a>,
    pk: &'a SP1ProvingKey,
    stdin: SP1Stdin,
    opts: SP1CoreOpts,
}

impl<'a> Prove<'a> {
    pub fn new(prover: &'a dyn Prover, pk: &'a SP1ProvingKey, stdin: SP1Stdin) -> Self {
        Self {
            prover,
            kind: Default::default(),
            pk,
            stdin,
            context_builder: Default::default(),
            opts: Default::default(),
        }
    }

    /// Set the proof kind to the core mode. This is the default.
    pub fn core(mut self) -> Self {
        self.kind = SP1ProofKind::Core;
        self
    }

    /// Set the proof kind to the compressed mode.
    pub fn compress(mut self) -> Self {
        self.kind = SP1ProofKind::Compress;
        self
    }

    /// Set the proof mode to the plonk bn254 mode.
    pub fn plonk(mut self) -> Self {
        self.kind = SP1ProofKind::PlonkBn254;
        self
    }

    pub fn run(self) -> Result<SP1Proof> {
        let Self {
            prover,
            kind,
            pk,
            stdin,
            mut context_builder,
            opts,
        } = self;
        let opts = SP1ProverOpts {
            core_opts: opts,
            recursion_opts: opts,
        };
        let context = context_builder.build();

        Ok(match kind {
            SP1ProofKind::Core => SP1Proof::Core(prover.prove(pk, stdin, opts, context)?),
            SP1ProofKind::Compress => {
                SP1Proof::Compress(prover.prove_compressed(pk, stdin, opts, context)?)
            }
            SP1ProofKind::PlonkBn254 => {
                SP1Proof::PlonkBn254(prover.prove_plonk(pk, stdin, opts, context)?)
            }
        })
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
        self.opts.shard_size = value;
        self
    }

    /// Set the shard batch size for proving.
    pub fn shard_batch_size(mut self, value: usize) -> Self {
        self.opts.shard_batch_size = value;
        self
    }

    /// Set the chunking multiplier for proving.
    pub fn shard_chunking_multiplier(mut self, value: usize) -> Self {
        self.opts.shard_chunking_multiplier = value;
        self
    }

    /// Set whether we should reconstruct commitments while proving.
    pub fn reconstruct_commitments(mut self, value: bool) -> Self {
        self.opts.reconstruct_commitments = value;
        self
    }
}
