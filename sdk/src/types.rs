pub struct ProofStatistics {
    pub cycle_count: u64,
    pub cost: u64,
    pub total_time: u64,
    pub latency: u64,
}

/// A proof of a RISCV ELF execution with given inputs and outputs.
#[derive(Serialize, Deserialize)]
pub struct SP1ProofWithMetadata<P> {
    #[serde(with = "proof_serde")]
    pub proof: P,
    pub stdin: SP1Stdin,
    pub public_values: SP1PublicValues,
    pub statistics: ProofStatistics,
}

type SP1DefaultProof = Proof<BabyBearPoseidon2>;
type SP1CompressedProof = ReduceProofType::Recursive;
type SP1Groth16Proof = ReduceProofType::Groth16;

pub enum SP1Proof {
    Mock(SP1ProofWithMetadata<PhantomData>),
    Default(SP1ProofWithMetadata<SP1DefaultProof>),
    Compressed(SP1ProofWithMetadata<SP1CompressedProof>),
    Groth16(SP1ProofWithMetadata<SP1Groth16Proof>),
}

impl SP1Proof {
    pub fn read() -> Self;
    pub fn save(&self) -> Result<()>;

    // Return none if the proof is not of the correct type.
    pub fn as_groth16() -> Option<&SP1Groth16Proof>;
    pub fn as_default() -> Option<&SP1DefaultProof>;
    pub fn as_compressed() -> Option<&SP1CompressedProof>;
    pub fn as_mock() -> Option<&PhantomData>;

    pub fn statistics() -> ProofStatistics;
    pub fn stdin() -> SP1Stdin;
    pub fn public_values() -> SP1PublicValues;
}

// Now we have an enum to deal with provers.

pub enum ProverMode {
    Default,
    Compressed,
    Groth16,
}

pub trait Prover {
    fn new() -> Self;
    fn with_mode(mode: ProverMode) -> Self;
    fn prove() -> Result<SP1Proof>;
}

pub struct NetworkProver {
    pub mode: ProverMode,
}

impl Prover for NetworkProver {
    fn new() -> Self {
        Self {
            mode: ProverMode::Default,
        }
    }

    fn with_mode(mut self, mode: ProverMode) -> Self {
        self.mode = mode;
        self
    }

    // Depending on the mode, will send a request to the network
    // And will return the correct variant of the SP1Proof
    fn prove() -> Result<SP1Proof> {
        unimplemented!()
    }
}

pub struct LocalProver {
    pub mode: ProverMode,
}

impl Prover for LocalProver {
    fn new() -> Self {
        // TODO: make sure mode "groth16" not supported locally
        Self {
            mode: ProverMode::Default,
        }
    }

    fn with_mode(mut self, mode: ProverMode) -> Self {
        self.mode = mode;
        self
    }

    // Depending on the mode, will run the prover locally
    // And will return the correct variant of the SP1Proof
    fn prove() -> Result<SP1Proof> {
        unimplemented!()
    }
}

pub struct MockProver {}

impl Prover for MockProver {
    fn new() -> Self {
        Self {}
    }

    // Will run the prover locally
    // And will return the correct variant of the SP1Proof
    fn prove() -> Result<SP1Proof> {
        unimplemented!()
    }
}

pub struct Prover {
    pub prover: dyn Prover,
}

impl ProverClient {
    pub fn new() -> Self {
        // Based on env variables, initialize relevant prover
        Self {
            prover: MockProver::new(),
        }
    }

    /// Given an ELF and a SP1Stdin, will execute the program and return the public values.
    pub fn execute(elf: ELF, stdin: SP1Stdin) -> Result<SP1PublicValues>;

    /// Given an ELF and a SP1Stdin, it will generate a proof using the stored prover.
    pub fn prove(&self, elf: ELF, stdin: SP1Stdin) -> Result<SP1Proof> {
        prover.prove()
    }

    pub fn prove_from_id(&self, id: bytes32) -> Result<SP1Proof> {}

    pub fn verify(elf: ELF, proof: SP1Proof) -> Result {}

    pub fn relay() -> Result<()> {
        unimplemented!()
    }

    pub fn get_program_hash(elf: ELF) -> bytes32 {}

    pub fn get_vkey(elf: ELF) -> Vkey {}
}
