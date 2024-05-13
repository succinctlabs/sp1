use std::fs::File;
use std::io;
use std::io::{Seek, Write};
use web_time::Instant;

pub use baby_bear_blake3::BabyBearBlake3;
use p3_challenger::CanObserve;
use p3_field::PrimeField32;
use serde::de::DeserializeOwned;
use serde::Serialize;
use size::Size;
use thiserror::Error;

use crate::air::MachineAir;
use crate::io::{SP1PublicValues, SP1Stdin};
use crate::lookup::InteractionBuilder;
use crate::runtime::ExecutionError;
use crate::runtime::{ExecutionRecord, ShardingConfig};
use crate::stark::DebugConstraintBuilder;
use crate::stark::MachineProof;
use crate::stark::ProverConstraintFolder;
use crate::stark::StarkVerifyingKey;
use crate::stark::Val;
use crate::stark::VerifierConstraintFolder;
use crate::stark::{Com, PcsProverData, RiscvAir, ShardProof, StarkProvingKey, UniConfig};
use crate::stark::{MachineRecord, StarkMachine};
use crate::utils::env;
use crate::{
    runtime::{Program, Runtime},
    stark::StarkGenericConfig,
    stark::{LocalProver, OpeningProof, ShardMainData},
};

const LOG_DEGREE_BOUND: usize = 31;

#[derive(Error, Debug)]
pub enum SP1CoreProverError {
    #[error("failed to execute program: {0}")]
    ExecutionError(ExecutionError),
    #[error("io error: {0}")]
    IoError(io::Error),
    #[error("serialization error: {0}")]
    SerializationError(bincode::Error),
}

pub fn prove_simple<SC: StarkGenericConfig>(
    config: SC,
    runtime: Runtime,
) -> Result<MachineProof<SC>, SP1CoreProverError>
where
    SC::Challenger: Clone,
    OpeningProof<SC>: Send + Sync,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    ShardMainData<SC>: Serialize + DeserializeOwned,
    <SC as StarkGenericConfig>::Val: PrimeField32,
{
    // Setup the machine.
    let machine = RiscvAir::machine(config);
    let (pk, _) = machine.setup(runtime.program.as_ref());

    // Prove the program.
    let mut challenger = machine.config().challenger();
    let proving_start = Instant::now();
    let proof = machine.prove::<LocalProver<_, _>>(&pk, runtime.record, &mut challenger);
    let proving_duration = proving_start.elapsed().as_millis();
    let nb_bytes = bincode::serialize(&proof).unwrap().len();

    // Print the summary.
    tracing::info!(
        "summary: cycles={}, e2e={}, khz={:.2}, proofSize={}",
        runtime.state.global_clk,
        proving_duration,
        (runtime.state.global_clk as f64 / proving_duration as f64),
        Size::from_bytes(nb_bytes),
    );

    Ok(proof)
}

pub fn prove<SC: StarkGenericConfig + Send + Sync>(
    program: Program,
    stdin: &SP1Stdin,
    config: SC,
) -> Result<(MachineProof<SC>, Vec<u8>), SP1CoreProverError>
where
    SC::Challenger: Clone,
    OpeningProof<SC>: Send + Sync,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    ShardMainData<SC>: Serialize + DeserializeOwned,
    <SC as StarkGenericConfig>::Val: PrimeField32,
{
    let proving_start = Instant::now();

    // Execute the program.
    let mut runtime = Runtime::new(program.clone());
    runtime.write_vecs(&stdin.buffer);
    for proof in stdin.proofs.iter() {
        runtime.write_proof(proof.0.clone(), proof.1.clone());
    }

    // Setup the machine.
    let machine = RiscvAir::machine(config);
    let (pk, vk) = machine.setup(runtime.program.as_ref());

    // If we don't need to batch, we can just run the program normally and prove it.
    if env::shard_batch_size() == 0 {
        // Execute the runtime and collect all the events..
        runtime.run().map_err(SP1CoreProverError::ExecutionError)?;

        // If debugging is enabled, we will also debug the constraints.
        #[cfg(feature = "debug")]
        {
            let mut challenger = machine.config().challenger();
            machine.debug_constraints(&pk, runtime.record.clone(), &mut challenger);
        }

        // Generate the proof and return the proof and public values.
        let public_values = std::mem::take(&mut runtime.state.public_values_stream);
        let proof = prove_simple(machine.config().clone(), runtime)?;
        return Ok((proof, public_values));
    }

    // Execute the program, saving checkpoints at the start of every `shard_batch_size` cycle range.
    let mut checkpoints = Vec::new();
    let (public_values_stream, public_values) = loop {
        // Execute the runtime until we reach a checkpoint.
        let (checkpoint, done) = runtime
            .execute_state()
            .map_err(SP1CoreProverError::ExecutionError)?;

        // Save the checkpoint to a temp file.
        let mut tempfile = tempfile::tempfile().map_err(SP1CoreProverError::IoError)?;
        let mut writer = std::io::BufWriter::new(&mut tempfile);
        bincode::serialize_into(&mut writer, &checkpoint)
            .map_err(SP1CoreProverError::SerializationError)?;
        writer.flush().map_err(SP1CoreProverError::IoError)?;
        drop(writer);
        tempfile
            .seek(std::io::SeekFrom::Start(0))
            .map_err(SP1CoreProverError::IoError)?;
        checkpoints.push(tempfile);

        // If we've reached the final checkpoint, break out of the loop.
        if done {
            break (
                std::mem::take(&mut runtime.state.public_values_stream),
                runtime.record.public_values,
            );
        }
    };

    // For each checkpoint, generate events, shard them, commit shards, and observe in challenger.
    let sharding_config = ShardingConfig::default();
    let mut shard_main_datas = Vec::new();
    let mut challenger = machine.config().challenger();
    vk.observe_into(&mut challenger);
    for checkpoint_file in checkpoints.iter_mut() {
        let mut record = trace_checkpoint(program.clone(), checkpoint_file);
        record.public_values = public_values;
        reset_seek(&mut *checkpoint_file);

        // Shard the record into shards.
        let checkpoint_shards =
            tracing::info_span!("shard").in_scope(|| machine.shard(record, &sharding_config));

        // Commit to each shard.
        let (commitments, commit_data) = tracing::info_span!("commit")
            .in_scope(|| LocalProver::commit_shards(&machine, &checkpoint_shards));
        shard_main_datas.push(commit_data);

        // Observe the commitments.
        for (commitment, shard) in commitments.into_iter().zip(checkpoint_shards.iter()) {
            challenger.observe(commitment);
            challenger.observe_slice(&shard.public_values::<SC::Val>()[0..machine.num_pv_elts()]);
        }
    }

    // For each checkpoint, generate events and shard again, then prove the shards.
    let mut shard_proofs = Vec::<ShardProof<SC>>::new();
    for mut checkpoint_file in checkpoints.into_iter() {
        let checkpoint_shards = {
            let mut events = trace_checkpoint(program.clone(), &checkpoint_file);
            events.public_values = public_values;
            reset_seek(&mut checkpoint_file);
            tracing::debug_span!("shard").in_scope(|| machine.shard(events, &sharding_config))
        };
        let mut checkpoint_proofs = checkpoint_shards
            .into_iter()
            .map(|shard| {
                let config = machine.config();
                let shard_data =
                    LocalProver::commit_main(config, &machine, &shard, shard.index() as usize);

                let chip_ordering = shard_data.chip_ordering.clone();
                let ordered_chips = machine
                    .shard_chips_ordered(&chip_ordering)
                    .collect::<Vec<_>>()
                    .to_vec();
                LocalProver::prove_shard(
                    config,
                    &pk,
                    &ordered_chips,
                    shard_data,
                    &mut challenger.clone(),
                )
            })
            .collect::<Vec<_>>();
        shard_proofs.append(&mut checkpoint_proofs);
    }
    let proof = MachineProof::<SC> { shard_proofs };

    // Print the summary.
    let proving_time = proving_start.elapsed().as_secs_f64();
    tracing::info!(
        "summary: cycles={}, e2e={}, khz={:.2}, proofSize={}",
        runtime.state.global_clk,
        proving_time,
        (runtime.state.global_clk as f64 / proving_time as f64),
        bincode::serialize(&proof).unwrap().len(),
    );

    Ok((proof, public_values_stream))
}

/// Runs a program and returns the public values stream.
pub fn run_test_io(
    program: Program,
    inputs: SP1Stdin,
) -> Result<SP1PublicValues, crate::stark::MachineVerificationError<BabyBearPoseidon2>> {
    let runtime = tracing::info_span!("runtime.run(...)").in_scope(|| {
        let mut runtime = Runtime::new(program);
        runtime.write_vecs(&inputs.buffer);
        runtime.run().unwrap();
        runtime
    });
    let public_values = SP1PublicValues::from(&runtime.state.public_values_stream);
    let _ = run_test_core(runtime)?;
    Ok(public_values)
}

pub fn run_test(
    program: Program,
) -> Result<
    crate::stark::MachineProof<BabyBearPoseidon2>,
    crate::stark::MachineVerificationError<BabyBearPoseidon2>,
> {
    let runtime = tracing::info_span!("runtime.run(...)").in_scope(|| {
        let mut runtime = Runtime::new(program);
        runtime.run().unwrap();
        runtime
    });
    run_test_core(runtime)
}

#[allow(unused_variables)]
pub fn run_test_core(
    runtime: Runtime,
) -> Result<
    crate::stark::MachineProof<BabyBearPoseidon2>,
    crate::stark::MachineVerificationError<BabyBearPoseidon2>,
> {
    let config = BabyBearPoseidon2::new();
    let machine = RiscvAir::machine(config);
    let (pk, vk) = machine.setup(runtime.program.as_ref());

    let record = runtime.record;
    run_test_machine(record, machine, pk, vk)
}

#[allow(unused_variables)]
pub fn run_test_machine<SC, A>(
    record: A::Record,
    machine: StarkMachine<SC, A>,
    pk: StarkProvingKey<SC>,
    vk: StarkVerifyingKey<SC>,
) -> Result<crate::stark::MachineProof<SC>, crate::stark::MachineVerificationError<SC>>
where
    A: MachineAir<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + Air<InteractionBuilder<Val<SC>>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>
        + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>,
    SC: StarkGenericConfig,
    SC::Val: p3_field::PrimeField32,
    SC::Challenger: Clone,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    OpeningProof<SC>: Send + Sync,
    ShardMainData<SC>: Serialize + DeserializeOwned,
{
    #[cfg(feature = "debug")]
    {
        let mut challenger_clone = machine.config().challenger();
        let record_clone = record.clone();
        machine.debug_constraints(&pk, record_clone, &mut challenger_clone);
    }
    let stats = record.stats().clone();
    let cycles = stats.get("cpu_events").unwrap();

    let start = Instant::now();
    let mut challenger = machine.config().challenger();
    let proof = machine.prove::<LocalProver<SC, A>>(&pk, record, &mut challenger);
    let time = start.elapsed().as_millis();
    let nb_bytes = bincode::serialize(&proof).unwrap().len();

    let mut challenger = machine.config().challenger();
    machine.verify(&vk, &proof, &mut challenger)?;

    tracing::info!(
        "summary: cycles={}, e2e={}, khz={:.2}, proofSize={}",
        cycles,
        time,
        (*cycles as f64 / time as f64),
        Size::from_bytes(nb_bytes),
    );

    Ok(proof)
}

fn trace_checkpoint(program: Program, file: &File) -> ExecutionRecord {
    let mut reader = std::io::BufReader::new(file);
    let state = bincode::deserialize_from(&mut reader).expect("failed to deserialize state");
    let mut runtime = Runtime::recover(program.clone(), state);
    let (events, _) =
        tracing::debug_span!("runtime.trace").in_scope(|| runtime.execute_record().unwrap());
    events
}

fn reset_seek(file: &mut File) {
    file.seek(std::io::SeekFrom::Start(0))
        .expect("failed to seek to start of tempfile");
}

#[cfg(debug_assertions)]
#[cfg(not(doctest))]
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
#[cfg(not(doctest))]
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

    use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
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

    pub type Perm = Poseidon2<Val, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>;
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

    pub fn my_perm() -> Perm {
        const ROUNDS_F: usize = 8;
        const ROUNDS_P: usize = 13;
        let mut round_constants = RC_16_30.to_vec();
        let internal_start = ROUNDS_F / 2;
        let internal_end = (ROUNDS_F / 2) + ROUNDS_P;
        let internal_round_constants = round_constants
            .drain(internal_start..internal_end)
            .map(|vec| vec[0])
            .collect::<Vec<_>>();
        let external_round_constants = round_constants;
        Perm::new(
            ROUNDS_F,
            external_round_constants,
            Poseidon2ExternalMatrixGeneral,
            ROUNDS_P,
            internal_round_constants,
            DiffusionMatrixBabyBear,
        )
    }

    pub fn default_fri_config() -> FriConfig<ChallengeMmcs> {
        let perm = my_perm();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let challenge_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress));
        let num_queries = match std::env::var("FRI_QUERIES") {
            Ok(value) => value.parse().unwrap(),
            Err(_) => 100,
        };
        FriConfig {
            log_blowup: 1,
            num_queries,
            proof_of_work_bits: 16,
            mmcs: challenge_mmcs,
        }
    }

    pub fn compressed_fri_config() -> FriConfig<ChallengeMmcs> {
        let perm = my_perm();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let challenge_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress));
        let num_queries = match std::env::var("FRI_QUERIES") {
            Ok(value) => value.parse().unwrap(),
            Err(_) => 33,
        };
        FriConfig {
            log_blowup: 3,
            num_queries,
            proof_of_work_bits: 16,
            mmcs: challenge_mmcs,
        }
    }

    enum BabyBearPoseidon2Type {
        Default,
        Compressed,
    }

    #[derive(Deserialize)]
    #[serde(from = "std::marker::PhantomData<BabyBearPoseidon2>")]
    pub struct BabyBearPoseidon2 {
        pub perm: Perm,
        pcs: Pcs,
        config_type: BabyBearPoseidon2Type,
    }

    impl BabyBearPoseidon2 {
        pub fn new() -> Self {
            let perm = my_perm();
            let hash = MyHash::new(perm.clone());
            let compress = MyCompress::new(perm.clone());
            let val_mmcs = ValMmcs::new(hash, compress);
            let dft = Dft {};
            let fri_config = default_fri_config();
            let pcs = Pcs::new(27, dft, val_mmcs, fri_config);
            Self {
                pcs,
                perm,
                config_type: BabyBearPoseidon2Type::Default,
            }
        }

        pub fn compressed() -> Self {
            let perm = my_perm();
            let hash = MyHash::new(perm.clone());
            let compress = MyCompress::new(perm.clone());
            let val_mmcs = ValMmcs::new(hash, compress);
            let dft = Dft {};
            let fri_config = compressed_fri_config();
            let pcs = Pcs::new(27, dft, val_mmcs, fri_config);
            Self {
                pcs,
                perm,
                config_type: BabyBearPoseidon2Type::Compressed,
            }
        }
    }

    impl Clone for BabyBearPoseidon2 {
        fn clone(&self) -> Self {
            match self.config_type {
                BabyBearPoseidon2Type::Default => Self::new(),
                BabyBearPoseidon2Type::Compressed => Self::compressed(),
            }
        }
    }

    impl Default for BabyBearPoseidon2 {
        fn default() -> Self {
            Self::new()
        }
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
