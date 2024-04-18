use std::fs::File;
use std::io::{Seek, Write};
use web_time::Instant;

pub use baby_bear_blake3::BabyBearBlake3;
use p3_challenger::CanObserve;
use p3_field::PrimeField32;
use serde::de::DeserializeOwned;
use serde::Serialize;
use size::Size;

use crate::runtime::{ExecutionRecord, ShardingConfig};
use crate::stark::MachineRecord;
use crate::stark::{Com, PcsProverData, RiscvAir, ShardProof, UniConfig};
use crate::utils::env::shard_batch_size;
use crate::{
    runtime::{Program, Runtime},
    stark::StarkGenericConfig,
    stark::{LocalProver, OpeningProof, ShardMainData},
};

use crate::{SP1ProofWithIO, SP1PublicValues, SP1Stdin};

const LOG_DEGREE_BOUND: usize = 31;

pub fn get_cycles(program: Program) -> u64 {
    let mut runtime = Runtime::new(program);
    runtime.run();
    runtime.state.global_clk as u64
}

pub fn run_test_io(
    program: Program,
    inputs: SP1Stdin,
) -> Result<SP1ProofWithIO<BabyBearBlake3>, crate::stark::ProgramVerificationError> {
    let runtime = tracing::info_span!("runtime.run(...)").in_scope(|| {
        let mut runtime = Runtime::new(program);
        runtime.write_vecs(&inputs.buffer);
        runtime.run();
        runtime
    });
    let public_values = SP1PublicValues::from(&runtime.state.public_values_stream);
    let proof = run_test_core(runtime)?;
    Ok(SP1ProofWithIO {
        proof,
        stdin: inputs,
        public_values,
    })
}

pub fn run_test(
    program: Program,
) -> Result<crate::stark::Proof<BabyBearBlake3>, crate::stark::ProgramVerificationError> {
    let runtime = tracing::info_span!("runtime.run(...)").in_scope(|| {
        let mut runtime = Runtime::new(program);
        runtime.run();
        runtime
    });
    run_test_core(runtime)
}

#[allow(unused_variables)]
pub fn run_test_core(
    runtime: Runtime,
) -> Result<crate::stark::Proof<BabyBearBlake3>, crate::stark::ProgramVerificationError> {
    let config = BabyBearBlake3::new();
    let machine = RiscvAir::machine(config);
    let (pk, vk) = machine.setup(runtime.program.as_ref());
    let mut challenger = machine.config().challenger();

    #[cfg(feature = "debug")]
    {
        let mut challenger_clone = machine.config().challenger();
        let record_clone = runtime.record.clone();
        machine.debug_constraints(&pk, record_clone, &mut challenger_clone);
        log::debug!("debug_constraints done");
    }
    let start = Instant::now();
    let proof = tracing::info_span!("prove")
        .in_scope(|| machine.prove::<LocalProver<_, _>>(&pk, runtime.record, &mut challenger));

    let cycles = runtime.state.global_clk;
    let time = start.elapsed().as_millis();
    let nb_bytes = bincode::serialize(&proof).unwrap().len();

    let mut challenger = machine.config().challenger();
    machine.verify(&vk, &proof, &mut challenger)?;

    tracing::info!(
        "summary: cycles={}, e2e={}, khz={:.2}, proofSize={}",
        cycles,
        time,
        (cycles as f64 / time as f64),
        Size::from_bytes(nb_bytes),
    );

    Ok(proof)
}

fn trace_checkpoint(program: Program, file: &File) -> ExecutionRecord {
    let mut reader = std::io::BufReader::new(file);
    let state = bincode::deserialize_from(&mut reader).expect("failed to deserialize state");
    let mut runtime = Runtime::recover(program.clone(), state);
    let (events, _) = tracing::debug_span!("runtime.trace").in_scope(|| runtime.execute_record());
    events
}

fn reset_seek(file: &mut File) {
    file.seek(std::io::SeekFrom::Start(0))
        .expect("failed to seek to start of tempfile");
}

pub fn run_and_prove<SC: StarkGenericConfig + Send + Sync>(
    program: Program,
    stdin: &[Vec<u8>],
    config: SC,
) -> (crate::stark::Proof<SC>, Vec<u8>)
where
    SC::Challenger: Clone,
    OpeningProof<SC>: Send + Sync,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    ShardMainData<SC>: Serialize + DeserializeOwned,
    <SC as StarkGenericConfig>::Val: PrimeField32,
{
    let mut challenger = config.challenger();

    let machine = RiscvAir::machine(config);
    let mut runtime = Runtime::new(program.clone());
    runtime.write_vecs(stdin);
    let (pk, _) = machine.setup(runtime.program.as_ref());
    let should_batch = shard_batch_size() > 0;

    // If we don't need to batch, we can just run the program normally and prove it.
    if !should_batch {
        runtime.run();
        #[cfg(feature = "debug")]
        {
            let record_clone = runtime.record.clone();
            machine.debug_constraints(&pk, record_clone, &mut challenger);
        }
        let public_values = std::mem::take(&mut runtime.state.public_values_stream);
        let proof = prove_core(machine.config().clone(), runtime);
        return (proof, public_values);
    }

    // Execute the program, saving checkpoints at the start of every `shard_batch_size` cycle range.
    let mut cycles = 0;
    let mut prove_time = 0;
    let mut checkpoints = Vec::new();
    let mut public_values: Vec<SC::Val> = Vec::new();
    let public_values_stream = tracing::info_span!("runtime.state").in_scope(|| loop {
        // Get checkpoint + move to next checkpoint, then save checkpoint to temp file
        let (state, done) = runtime.execute_state();
        let mut tempfile = tempfile::tempfile().expect("failed to create tempfile");
        let mut writer = std::io::BufWriter::new(&mut tempfile);
        bincode::serialize_into(&mut writer, &state).expect("failed to serialize state");
        writer.flush().expect("failed to flush writer");
        drop(writer);
        tempfile
            .seek(std::io::SeekFrom::Start(0))
            .expect("failed to seek to start of tempfile");
        checkpoints.push(tempfile);
        if done {
            public_values = runtime.record.public_values();
            return std::mem::take(&mut runtime.state.public_values_stream);
        }
    });

    // For each checkpoint, generate events, shard them, commit shards, and observe in challenger.
    let sharding_config = ShardingConfig::default();
    let mut shard_main_datas = Vec::new();

    // If there's only one batch, it already must fit in memory so reuse it later in open multi
    // rather than running the runtime again.
    let reuse_shards = checkpoints.len() == 1;
    let mut all_shards = None;

    for file in checkpoints.iter_mut() {
        let events = trace_checkpoint(program.clone(), file);
        reset_seek(&mut *file);
        cycles += events.cpu_events.len();
        let shards =
            tracing::debug_span!("shard").in_scope(|| machine.shard(events, &sharding_config));
        let (commitments, commit_data) = tracing::info_span!("commit")
            .in_scope(|| LocalProver::commit_shards(&machine, &shards));

        shard_main_datas.push(commit_data);

        if reuse_shards {
            all_shards = Some(shards.clone());
        }

        for (commitment, shard) in commitments.into_iter().zip(shards.iter()) {
            challenger.observe(commitment);
            challenger.observe_slice(&shard.public_values::<SC::Val>()[0..machine.num_pv_elts()]);
        }
    }

    // For each checkpoint, generate events and shard again, then prove the shards.
    let mut shard_proofs = Vec::<ShardProof<SC>>::new();
    for mut file in checkpoints.into_iter() {
        let shards = if reuse_shards {
            Option::take(&mut all_shards).unwrap()
        } else {
            let events = trace_checkpoint(program.clone(), &file);
            reset_seek(&mut file);
            tracing::debug_span!("shard").in_scope(|| machine.shard(events, &sharding_config))
        };
        let start = Instant::now();
        let mut new_proofs = shards
            .into_iter()
            .map(|shard| {
                let chips = machine.shard_chips(&shard).collect::<Vec<_>>();
                let config = machine.config();
                let shard_data =
                    LocalProver::commit_main(config, &machine, &shard, shard.index() as usize);
                LocalProver::prove_shard(config, &pk, &chips, shard_data, &mut challenger.clone())
            })
            .collect::<Vec<_>>();
        prove_time += start.elapsed().as_millis();
        shard_proofs.append(&mut new_proofs);
    }

    let proof = crate::stark::Proof::<SC> { shard_proofs };

    // Prove the program.
    let nb_bytes = bincode::serialize(&proof).unwrap().len();

    tracing::info!(
        "summary: cycles={}, e2e={}, khz={:.2}, proofSize={}",
        cycles,
        prove_time,
        (cycles as f64 / prove_time as f64),
        Size::from_bytes(nb_bytes),
    );

    (proof, public_values_stream)
}

pub fn prove_core<SC: StarkGenericConfig>(config: SC, runtime: Runtime) -> crate::stark::Proof<SC>
where
    SC::Challenger: Clone,
    OpeningProof<SC>: Send + Sync,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    ShardMainData<SC>: Serialize + DeserializeOwned,
    <SC as StarkGenericConfig>::Val: PrimeField32,
{
    let mut challenger = config.challenger();

    let start = Instant::now();

    let machine = RiscvAir::machine(config);
    let (pk, _) = machine.setup(runtime.program.as_ref());

    // Prove the program.
    let cycles = runtime.state.global_clk;
    let proof = tracing::info_span!("prove")
        .in_scope(|| machine.prove::<LocalProver<_, _>>(&pk, runtime.record, &mut challenger));
    let time = start.elapsed().as_millis();
    let nb_bytes = bincode::serialize(&proof).unwrap().len();

    tracing::info!(
        "summary: cycles={}, e2e={}, khz={:.2}, proofSize={}",
        cycles,
        time,
        (cycles as f64 / time as f64),
        Size::from_bytes(nb_bytes),
    );

    proof
}

#[cfg(debug_assertions)]
pub fn uni_stark_prove<SC, A>(
    config: &SC,
    air: &A,
    challenger: &mut SC::Challenger,
    trace: RowMajorMatrix<SC::Val>,
) -> Proof<UniConfig<SC>>
where
    SC: StarkGenericConfig,
    A: Air<p3_uni_stark::SymbolicAirBuilder<SC::Val>>
        + for<'a> Air<p3_uni_stark::ProverConstraintFolder<'a, UniConfig<SC>>>
        + for<'a> Air<p3_uni_stark::DebugConstraintBuilder<'a, SC::Val>>,
{
    p3_uni_stark::prove(&UniConfig(config.clone()), air, challenger, trace, &vec![])
}

#[cfg(not(debug_assertions))]
pub fn uni_stark_prove<SC, A>(
    config: &SC,
    air: &A,
    challenger: &mut SC::Challenger,
    trace: RowMajorMatrix<SC::Val>,
) -> Proof<UniConfig<SC>>
where
    SC: StarkGenericConfig,
    A: Air<p3_uni_stark::SymbolicAirBuilder<SC::Val>>
        + for<'a> Air<p3_uni_stark::ProverConstraintFolder<'a, UniConfig<SC>>>,
{
    p3_uni_stark::prove(&UniConfig(config.clone()), air, challenger, trace, &vec![])
}

#[cfg(debug_assertions)]
pub fn uni_stark_verify<SC, A>(
    config: &SC,
    air: &A,
    challenger: &mut SC::Challenger,
    proof: &Proof<UniConfig<SC>>,
) -> Result<(), p3_uni_stark::VerificationError>
where
    SC: StarkGenericConfig,
    A: Air<p3_uni_stark::SymbolicAirBuilder<SC::Val>>
        + for<'a> Air<p3_uni_stark::VerifierConstraintFolder<'a, UniConfig<SC>>>
        + for<'a> Air<p3_uni_stark::DebugConstraintBuilder<'a, SC::Val>>,
{
    p3_uni_stark::verify(&UniConfig(config.clone()), air, challenger, proof, &vec![])
}

#[cfg(not(debug_assertions))]
pub fn uni_stark_verify<SC, A>(
    config: &SC,
    air: &A,
    challenger: &mut SC::Challenger,
    proof: &Proof<UniConfig<SC>>,
) -> Result<(), p3_uni_stark::VerificationError>
where
    SC: StarkGenericConfig,
    A: Air<p3_uni_stark::SymbolicAirBuilder<SC::Val>>
        + for<'a> Air<p3_uni_stark::VerifierConstraintFolder<'a, UniConfig<SC>>>,
{
    p3_uni_stark::verify(&UniConfig(config.clone()), air, challenger, proof, &vec![])
}

pub use baby_bear_keccak::BabyBearKeccak;
pub use baby_bear_poseidon2::BabyBearPoseidon2;
use p3_air::Air;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::Proof;

pub mod baby_bear_poseidon2 {

    use p3_baby_bear::{BabyBear, DiffusionMatrixBabybear};
    use p3_challenger::DuplexChallenger;
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::{extension::BinomialExtensionField, Field};
    use p3_fri::{FriConfig, TwoAdicFriPcs};
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_poseidon2::Poseidon2;
    use p3_poseidon2::Poseidon2ExternalMatrixGeneral;
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use serde::{Deserialize, Serialize};
    use sp1_primitives::RC_16_30;

    use crate::stark::StarkGenericConfig;

    pub type Val = BabyBear;

    pub type Challenge = BinomialExtensionField<Val, 4>;

    pub type Perm = Poseidon2<Val, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabybear, 16, 7>;
    pub type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;

    pub type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;

    pub type ValMmcs = FieldMerkleTreeMmcs<
        <Val as Field>::Packing,
        <Val as Field>::Packing,
        MyHash,
        MyCompress,
        8,
    >;
    pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

    pub type Dft = Radix2DitParallel;

    pub type Challenger = DuplexChallenger<Val, Perm, 16>;

    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

    #[derive(Deserialize)]
    #[serde(from = "std::marker::PhantomData<BabyBearPoseidon2>")]
    pub struct BabyBearPoseidon2 {
        pub perm: Perm,
        pcs: Pcs,
    }

    /// Implement serialization manually instead of using serde to avoid cloing the config.
    impl Serialize for BabyBearPoseidon2 {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            std::marker::PhantomData::<BabyBearPoseidon2>.serialize(serializer)
        }
    }

    impl From<std::marker::PhantomData<BabyBearPoseidon2>> for BabyBearPoseidon2 {
        fn from(_: std::marker::PhantomData<BabyBearPoseidon2>) -> Self {
            Self::new()
        }
    }

    impl Clone for BabyBearPoseidon2 {
        fn clone(&self) -> Self {
            Self::new()
        }
    }

    impl BabyBearPoseidon2 {
        pub fn new() -> Self {
            const ROUNDS_F: usize = 8;
            const ROUNDS_P: usize = 22;
            let mut round_constants = RC_16_30.to_vec();
            let internal_start = ROUNDS_F / 2;
            let internal_end = (ROUNDS_F / 2) + ROUNDS_P;
            let internal_round_constants = round_constants
                .drain(internal_start..internal_end)
                .map(|vec| vec[0])
                .collect::<Vec<_>>();
            let external_round_constants = round_constants;
            let perm = Perm::new(
                ROUNDS_F,
                external_round_constants,
                Poseidon2ExternalMatrixGeneral,
                ROUNDS_P,
                internal_round_constants,
                DiffusionMatrixBabybear,
            );

            let hash = MyHash::new(perm.clone());

            let compress = MyCompress::new(perm.clone());

            let val_mmcs = ValMmcs::new(hash, compress);

            let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

            let dft = Dft {};

            let num_queries = match std::env::var("FRI_QUERIES") {
                Ok(value) => value.parse().unwrap(),
                Err(_) => 100,
            };
            let fri_config = FriConfig {
                log_blowup: 1,
                num_queries,
                proof_of_work_bits: 16,
                mmcs: challenge_mmcs,
            };
            let pcs = Pcs::new(27, dft, val_mmcs, fri_config);

            Self { pcs, perm }
        }
    }

    impl Default for BabyBearPoseidon2 {
        fn default() -> Self {
            Self::new()
        }
    }

    impl StarkGenericConfig for BabyBearPoseidon2 {
        type Val = BabyBear;
        type Domain = <Pcs as p3_commit::Pcs<Challenge, Challenger>>::Domain;
        type Pcs = Pcs;
        type Challenge = Challenge;
        type Challenger = Challenger;

        fn pcs(&self) -> &Self::Pcs {
            &self.pcs
        }

        fn challenger(&self) -> Self::Challenger {
            Challenger::new(self.perm.clone())
        }
    }
}

pub(super) mod baby_bear_keccak {

    use p3_baby_bear::BabyBear;
    use p3_challenger::{HashChallenger, SerializingChallenger32};
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{FriConfig, TwoAdicFriPcs};
    use p3_keccak::Keccak256Hash;
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
    use serde::{Deserialize, Serialize};

    use crate::stark::StarkGenericConfig;

    use super::LOG_DEGREE_BOUND;

    pub type Val = BabyBear;

    pub type Challenge = BinomialExtensionField<Val, 4>;

    type ByteHash = Keccak256Hash;
    type FieldHash = SerializingHasher32<ByteHash>;

    type MyCompress = CompressionFunctionFromHasher<u8, ByteHash, 2, 32>;

    pub type ValMmcs = FieldMerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
    pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

    pub type Dft = Radix2DitParallel;

    type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;

    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

    #[derive(Deserialize)]
    #[serde(from = "std::marker::PhantomData<BabyBearKeccak>")]
    pub struct BabyBearKeccak {
        pcs: Pcs,
    }
    // Implement serialization manually instead of using serde(into) to avoid cloing the config
    impl Serialize for BabyBearKeccak {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            std::marker::PhantomData::<BabyBearKeccak>.serialize(serializer)
        }
    }

    impl From<std::marker::PhantomData<BabyBearKeccak>> for BabyBearKeccak {
        fn from(_: std::marker::PhantomData<BabyBearKeccak>) -> Self {
            Self::new()
        }
    }

    impl BabyBearKeccak {
        #[allow(dead_code)]
        pub fn new() -> Self {
            let byte_hash = ByteHash {};
            let field_hash = FieldHash::new(byte_hash);

            let compress = MyCompress::new(byte_hash);

            let val_mmcs = ValMmcs::new(field_hash, compress);

            let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

            let dft = Dft {};

            let fri_config = FriConfig {
                log_blowup: 1,
                num_queries: 100,
                proof_of_work_bits: 16,
                mmcs: challenge_mmcs,
            };
            let pcs = Pcs::new(LOG_DEGREE_BOUND, dft, val_mmcs, fri_config);

            Self { pcs }
        }
    }

    impl Default for BabyBearKeccak {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Clone for BabyBearKeccak {
        fn clone(&self) -> Self {
            Self::new()
        }
    }

    impl StarkGenericConfig for BabyBearKeccak {
        type Val = Val;
        type Challenge = Challenge;

        type Domain = <Pcs as p3_commit::Pcs<Challenge, Challenger>>::Domain;

        type Pcs = Pcs;
        type Challenger = Challenger;

        fn pcs(&self) -> &Self::Pcs {
            &self.pcs
        }

        fn challenger(&self) -> Self::Challenger {
            let byte_hash = ByteHash {};
            Challenger::from_hasher(vec![], byte_hash)
        }
    }
}

pub(super) mod baby_bear_blake3 {

    use p3_baby_bear::BabyBear;
    use p3_blake3::Blake3;
    use p3_challenger::{HashChallenger, SerializingChallenger32};
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{FriConfig, TwoAdicFriPcs};
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
    use serde::{Deserialize, Serialize};

    use crate::stark::StarkGenericConfig;

    use super::LOG_DEGREE_BOUND;

    pub type Val = BabyBear;

    pub type Challenge = BinomialExtensionField<Val, 4>;

    type ByteHash = Blake3;
    type FieldHash = SerializingHasher32<ByteHash>;

    type MyCompress = CompressionFunctionFromHasher<u8, ByteHash, 2, 32>;

    pub type ValMmcs = FieldMerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
    pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

    pub type Dft = Radix2DitParallel;

    type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;

    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

    #[derive(Deserialize)]
    #[serde(from = "std::marker::PhantomData<BabyBearBlake3>")]
    pub struct BabyBearBlake3 {
        pcs: Pcs,
    }

    // Implement serialization manually instead of using serde(into) to avoid cloing the config
    impl Serialize for BabyBearBlake3 {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            std::marker::PhantomData::<Self>.serialize(serializer)
        }
    }

    impl From<std::marker::PhantomData<BabyBearBlake3>> for BabyBearBlake3 {
        fn from(_: std::marker::PhantomData<BabyBearBlake3>) -> Self {
            Self::new()
        }
    }

    impl Clone for BabyBearBlake3 {
        fn clone(&self) -> Self {
            Self::new()
        }
    }

    impl BabyBearBlake3 {
        pub fn new() -> Self {
            let byte_hash = ByteHash {};
            let field_hash = FieldHash::new(byte_hash);

            let compress = MyCompress::new(byte_hash);

            let val_mmcs = ValMmcs::new(field_hash, compress);

            let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

            let dft = Dft {};

            let num_queries = match std::env::var("FRI_QUERIES") {
                Ok(value) => value.parse().unwrap(),
                Err(_) => 100,
            };
            let fri_config = FriConfig {
                log_blowup: 1,
                num_queries,
                proof_of_work_bits: 16,
                mmcs: challenge_mmcs,
            };
            let pcs = Pcs::new(LOG_DEGREE_BOUND, dft, val_mmcs, fri_config);

            Self { pcs }
        }
    }

    impl Default for BabyBearBlake3 {
        fn default() -> Self {
            Self::new()
        }
    }

    impl StarkGenericConfig for BabyBearBlake3 {
        type Val = Val;
        type Challenge = Challenge;

        type Domain = <Pcs as p3_commit::Pcs<Challenge, Challenger>>::Domain;

        type Pcs = Pcs;
        type Challenger = Challenger;

        fn pcs(&self) -> &Self::Pcs {
            &self.pcs
        }

        fn challenger(&self) -> Self::Challenger {
            let byte_hash = ByteHash {};
            Challenger::from_hasher(vec![], byte_hash)
        }
    }
}
