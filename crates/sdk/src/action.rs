use crate::{provers::ProveOpts, Prover, SP1ProofKind, SP1ProofWithPublicValues};
use anyhow::{Ok, Result};
use sp1_core_executor::{ExecutionReport, SP1Context};
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::io::SP1PublicValues;
use sp1_prover::{components::DefaultProverComponents, SP1ProvingKey};
use sp1_stark::SP1ProverOpts;
use std::time::Duration;

/// Builder to prepare and configure execution of a program on an input.
/// May be run with [Self::run].
pub struct Execute<'a> {
    prover: &'a dyn Prover<DefaultProverComponents>,
    elf: &'a [u8],
    stdin: SP1Stdin,
    local_opts: LocalProveOpts<'a>,
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
        Self { prover, elf, stdin, local_opts: Default::default() }
    }

    /// Execute the program on the input, consuming the built action `self`.
    pub fn run(self) -> Result<(SP1PublicValues, ExecutionReport)> {
        let Self { prover, elf, stdin, local_opts } = self;
        Ok(prover.sp1_prover().execute(elf, &stdin, local_opts.context)?)
    }

    /// Set the [LocalProveOpts] for this execution.
    pub fn with_local_opts(mut self, local_opts: LocalProveOpts<'a>) -> Self {
        self.local_opts = local_opts;
        self
    }
}

/// Options to configure execution and proving for the CPU and mock provers.
#[derive(Default, Clone)]
pub struct LocalProveOpts<'a> {
    pub(crate) prover_opts: SP1ProverOpts,
    pub(crate) context: SP1Context<'a>,
}

impl<'a> LocalProveOpts<'a> {
    /// Create a new `LocalProveOpts` with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the SP1ProverOpts.
    pub fn prover_opts(mut self, prover_opts: SP1ProverOpts) -> Self {
        self.prover_opts = prover_opts;
        self
    }

    /// Set the SP1Context.
    pub fn context(mut self, context: SP1Context<'a>) -> Self {
        self.context = context;
        self
    }

    /// Warns if `opts` or `context` are not default values, since they are currently unsupported by
    /// certain provers.
    pub(crate) fn warn_if_not_default(&self, prover_type: &str) {
        if self.prover_opts != SP1ProverOpts::default() {
            tracing::warn!("non-default opts will be ignored: {:?}", self.prover_opts);
            tracing::warn!(
                "custom SP1ProverOpts are currently unsupported by the {} prover",
                prover_type
            );
        }
        // Exhaustive match is done to ensure we update the warnings if the types change.
        let SP1Context { hook_registry, subproof_verifier, .. } = &self.context;
        if hook_registry.is_some() {
            tracing::warn!(
                "non-default context.hook_registry will be ignored: {:?}",
                hook_registry
            );
            tracing::warn!(
                "custom runtime hooks are currently unsupported by the {} prover",
                prover_type
            );
            tracing::warn!("proving may fail due to missing hooks");
        }
        if subproof_verifier.is_some() {
            tracing::warn!("non-default context.subproof_verifier will be ignored");
            tracing::warn!(
                "custom subproof verifiers are currently unsupported by the {} prover",
                prover_type
            );
        }
    }
}

/// Options to configure the network prover.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub struct NetworkProveOpts {
    pub(crate) timeout: Option<Duration>,
}

impl NetworkProveOpts {
    /// Create a new `NetworkProveOpts` with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the timeout.
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

    /// Set the local prover options, which are only used by the local and mock provers.
    pub fn local_opts(mut self, local_opts: LocalProveOpts<'a>) -> Self {
        self.local_opts = Some(local_opts);
        self
    }

    /// Set the network prover options, which are only used by the network prover.
    pub fn network_opts(mut self, network_opts: NetworkProveOpts) -> Self {
        self.network_opts = Some(network_opts);
        self
    }
}
