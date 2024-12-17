use anyhow::Result;
use sp1_core_executor::ExecutionReport;
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::io::SP1PublicValues;
use sp1_prover::{components::DefaultProverComponents, SP1Prover, SP1ProvingKey, SP1VerifyingKey};

use crate::{SP1ProofKind, SP1ProofWithPublicValues};

use super::{Prover, ProverType, SP1VerificationError};

/// A simple prover that allows executing programs and generating proofs. The actual implementation
pub struct SimpleProver {
    /// The underlying prover implementation.
    pub prover: Box<dyn Prover<DefaultProverComponents>>,
}

impl SimpleProver {
    /// Execute the given program on the given input (without generating a proof). Returns the
    /// public values and execution report of the program after it has been executed.
    ///
    /// ### Examples
    /// ```no_run
    /// use sp1_sdk::{ProverClient, SP1Context, SP1Stdin};
    ///
    /// // Load the program.
    /// let elf = test_artifacts::FIBONACCI_ELF;
    ///
    /// // Initialize the prover client.
    /// let client = ProverClient::new();
    ///
    /// // Setup the inputs.
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    ///
    /// // Execute the program on the inputs.
    /// let (public_values, report) = client.execute(elf, stdin).unwrap();
    /// ```
    pub fn execute<'a>(
        &'a self,
        elf: &'a [u8],
        stdin: SP1Stdin,
    ) -> Result<(SP1PublicValues, ExecutionReport)> {
        Ok(self.prover.sp1_prover().execute(elf, &stdin, Default::default())?)
    }

    /// Prepare to prove the execution of the given program with the given input in the default
    /// mode. The returned [action::Prove] may be configured via its methods before running.
    /// For example, calling [action::Prove::compressed] sets the mode to compressed mode.
    ///
    /// To prove, call [action::Prove::run], which returns a proof of the program's execution.
    /// By default the proof generated will not be compressed to constant size.
    /// To create a more succinct proof, use the [action::Prove::compressed],
    /// [action::Prove::plonk], or [action::Prove::groth16] methods.
    ///
    /// ### Examples
    /// ```no_run
    /// use sp1_sdk::{ProverClient, SP1Context, SP1Stdin};
    ///
    /// // Load the program.
    /// let elf = test_artifacts::FIBONACCI_ELF;
    ///
    /// // Initialize the prover client.
    /// let client = ProverClient::new();
    ///
    /// // Setup the program.
    /// let (pk, vk) = client.setup(elf);
    ///
    /// // Setup the inputs.
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    ///
    /// // Generate the proof.
    /// let proof = client.prove(&pk, stdin).run().unwrap();
    /// ```
    pub fn prove<'a>(&'a self, pk: &'a SP1ProvingKey, stdin: SP1Stdin) -> SimpleProve<'a> {
        SimpleProve::new(self.prover.as_ref(), pk, stdin)
    }

    /// Verifies that the given proof is valid and matches the given verification key produced by
    /// [Self::setup].
    ///
    /// ### Examples
    /// ```no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin};
    ///
    /// let elf = test_artifacts::FIBONACCI_ELF;
    /// let client = ProverClient::new();
    /// let (pk, vk) = client.setup(elf);
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    /// let proof = client.prove(&pk, stdin).run().unwrap();
    /// client.verify(&proof, &vk).unwrap();
    /// ```
    pub fn verify(
        &self,
        proof: &SP1ProofWithPublicValues,
        vk: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        self.prover.verify(proof, vk)
    }

    /// Setup a program to be proven and verified by the SP1 RISC-V zkVM by computing the proving
    /// and verifying keys.
    ///
    /// The proving key and verifying key essentially embed the program, as well as other auxiliary
    /// data (such as lookup tables) that are used to prove the program's correctness.
    ///
    /// ### Examples
    /// ```no_run
    /// use sp1_sdk::{ProverClient, SP1Stdin};
    ///
    /// let elf = test_artifacts::FIBONACCI_ELF;
    /// let client = ProverClient::new();
    /// let mut stdin = SP1Stdin::new();
    /// stdin.write(&10usize);
    /// let (pk, vk) = client.setup(elf);
    /// ```
    pub fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }
}

impl Prover<DefaultProverComponents> for SimpleProver {
    fn id(&self) -> ProverType {
        self.prover.id()
    }

    fn sp1_prover(&self) -> &SP1Prover<DefaultProverComponents> {
        self.prover.sp1_prover()
    }

    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        self.prover.setup(elf)
    }

    fn prove<'a>(
        &'a self,
        pk: &SP1ProvingKey,
        stdin: SP1Stdin,
        kind: SP1ProofKind,
    ) -> Result<SP1ProofWithPublicValues> {
        self.prover.prove(pk, stdin, kind)
    }
}

/// Builder to prepare and configure proving execution of a program on an input.
/// May be run with [Self::run].
pub struct SimpleProve<'a> {
    prover: &'a dyn Prover<DefaultProverComponents>,
    kind: SP1ProofKind,
    pk: &'a SP1ProvingKey,
    stdin: SP1Stdin,
}

impl<'a> SimpleProve<'a> {
    fn new(
        prover: &'a dyn Prover<DefaultProverComponents>,
        pk: &'a SP1ProvingKey,
        stdin: SP1Stdin,
    ) -> Self {
        Self { prover, kind: Default::default(), pk, stdin }
    }

    /// Prove the execution of the program on the input, consuming the built action `self`.
    pub fn run(self) -> Result<SP1ProofWithPublicValues> {
        let Self { prover, kind, pk, stdin } = self;

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

        prover.prove(pk, stdin, kind)
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

    /// Set the proof mode to the given mode.
    pub fn mode(mut self, mode: SP1ProofKind) -> Self {
        self.kind = mode;
        self
    }
}
