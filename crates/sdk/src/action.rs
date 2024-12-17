use sp1_core_executor::{ExecutionReport, HookEnv, SP1Context, SP1ContextBuilder};
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::io::SP1PublicValues;
use sp1_prover::{components::DefaultProverComponents, SP1ProvingKey};

use anyhow::{Ok, Result};
use sp1_stark::{SP1CoreOpts, SP1ProverOpts};
use std::time::Duration;

use crate::{provers::ProveOpts, Prover, SP1ProofKind, SP1ProofWithPublicValues};

/// Builder to prepare and configure execution of a program on an input.
/// May be run with [Self::run].
pub struct Execute<'a> {
    prover: &'a dyn Prover<DefaultProverComponents>,
    context_builder: SP1ContextBuilder<'a>,
    elf: &'a [u8],
    stdin: SP1Stdin,
}

impl<'a> Execute<'a> {
    /// Prepare to execute the given program on the given input (without generating a proof).
    ///
    /// Prefer using [ProverClient::execute](super::ProverClient::execute).
    /// See there for more documentation.
    pub fn new(
        prover: &'a dyn Prover<DefaultProverComponents>,
        elf: &'a [u8],
        stdin: SP1Stdin,
    ) -> Self {
        Self { prover, elf, stdin, context_builder: Default::default() }
    }

    /// Execute the program on the input, consuming the built action `self`.
    pub fn run(self) -> Result<(SP1PublicValues, ExecutionReport)> {
        let Self { prover, elf, stdin, mut context_builder } = self;
        let context = context_builder.build();
        Ok(prover.sp1_prover().execute(elf, &stdin, context)?)
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
    /// register a hook with the same value of `fd` by calling [`Self::with_hook`].
    pub fn without_default_hooks(mut self) -> Self {
        self.context_builder.without_default_hooks();
        self
    }

    /// Set the maximum number of cpu cycles to use for execution.
    ///
    /// If the cycle limit is exceeded, execution will return
    /// [`sp1_core_executor::ExecutionError::ExceededCycleLimit`].
    pub fn max_cycles(mut self, max_cycles: u64) -> Self {
        self.context_builder.max_cycles(max_cycles);
        self
    }

    /// Skip deferred proof verification.
    pub fn set_skip_deferred_proof_verification(mut self, value: bool) -> Self {
        self.context_builder.set_skip_deferred_proof_verification(value);
        self
    }
}

#[derive(Default, Clone)]
pub struct LocalProveOpts<'a> {
    pub(crate) prover_opts: SP1ProverOpts,
    pub(crate) context: SP1Context<'a>,
}

impl<'a> LocalProveOpts<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn prover_opts(mut self, prover_opts: SP1ProverOpts) -> Self {
        self.prover_opts = prover_opts;
        self
    }

    pub fn context(mut self, context: SP1Context<'a>) -> Self {
        self.context = context;
        self
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub struct NetworkProveOpts {
    pub(crate) timeout: Option<Duration>,
}

impl NetworkProveOpts {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn timeout(&mut self, timeout: Duration) -> &mut Self {
        self.timeout = Some(timeout);
        self
    }
}

/// Builder to prepare and configure proving execution of a program on an input.
/// May be run with [Self::run].
pub struct Prove<'a> {
    prover: &'a dyn Prover<DefaultProverComponents>,
    kind: SP1ProofKind,
    pk: &'a SP1ProvingKey,
    stdin: SP1Stdin,
    local_opts: Option<LocalProveOpts<'a>>,
    network_opts: Option<NetworkProveOpts>,
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
        Self { prover, kind: Default::default(), pk, stdin, local_opts: None, network_opts: None }
    }

    /// Prove the execution of the program on the input, consuming the built action `self`.
    pub fn run(self) -> Result<SP1ProofWithPublicValues> {
        let Self { prover, kind, pk, stdin, local_opts, network_opts } = self;
        let opts = ProveOpts {
            local_opts: local_opts.unwrap_or_default(),
            network_opts: network_opts.unwrap_or_default(),
        };

        // Dump the program and stdin to files for debugging if `SP1_DUMP` is set.
        if std::env::var("SP1_DUMP")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false)
        {
            let program = pk.elf.clone();
            std::fs::write("program.bin", program).unwrap();
            let stdin = bincode::serialize(&stdin).unwrap();
            std::fs::write("stdin.bin", stdin.clone()).unwrap();
        }

        prover.prove(pk, stdin, opts, kind)
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

    /// Set the proof mode to the groth16 bn254 mode.
    pub fn groth16(mut self) -> Self {
        self.kind = SP1ProofKind::Groth16;
        self
    }

    pub fn local_opts(mut self, local_opts: LocalProveOpts<'a>) -> Self {
        self.local_opts = Some(local_opts);
        self
    }

    pub fn network_opts(mut self, network_opts: NetworkProveOpts) -> Self {
        self.network_opts = Some(network_opts);
        self
    }
}
