use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    num::NonZero,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use hashbrown::HashSet;
use lru::LruCache;
use serde::{Deserialize, Serialize};
use slop_air::BaseAir;
use slop_algebra::AbstractField;
use slop_basefold::FriConfig;
use sp1_core_executor::MAX_PROGRAM_SIZE;
use sp1_core_machine::{
    bytes::columns::NUM_BYTE_PREPROCESSED_COLS, program::NUM_PROGRAM_PREPROCESSED_COLS,
    range::columns::NUM_RANGE_PREPROCESSED_COLS, riscv::RiscvAir,
};
use sp1_hypercube::{
    air::MachineAir,
    log2_ceil_usize,
    prover::{CoreProofShape, DefaultTraceGenerator, ProverSemaphore, TraceGenerator},
    Chip, HashableKey, Machine, MachineShape, SP1PcsProofInner, SP1VerifyingKey,
};
use sp1_primitives::{
    fri_params::{core_fri_config, CORE_LOG_BLOWUP},
    SP1Field, SP1GlobalContext,
};
use sp1_prover_types::ArtifactClient;
use sp1_recursion_circuit::{
    dummy::{dummy_shard_proof, dummy_vk},
    machine::{
        SP1CompressWithVKeyWitnessValues, SP1MerkleProofWitnessValues, SP1NormalizeWitnessValues,
        SP1ShapedWitnessValues,
    },
};
use sp1_recursion_compiler::config::InnerConfig;
use sp1_recursion_executor::{
    shape::RecursionShape, RecursionAirEventCount, RecursionProgram, DIGEST_SIZE,
};
use sp1_recursion_machine::chips::{
    alu_base::BaseAluChip,
    alu_ext::ExtAluChip,
    mem::{MemoryConstChip, MemoryVarChip},
    poseidon2_helper::{
        convert::ConvertChip, linear::Poseidon2LinearLayerChip, sbox::Poseidon2SBoxChip,
    },
    poseidon2_wide::Poseidon2WideChip,
    prefix_sum_checks::PrefixSumChecksChip,
    public_values::PublicValuesChip,
    select::SelectChip,
};
use sp1_verifier::compressed::RECURSION_MAX_LOG_ROW_COUNT;
use thiserror::Error;
use tokio::task::JoinSet;

use crate::{
    components::{SP1ProverComponents, CORE_LOG_STACKING_HEIGHT},
    recursion::{
        compose_program_from_input, deferred_program_from_input, dummy_compose_input,
        dummy_deferred_input, normalize_program_from_input, recursive_verifier,
        shrink_program_from_input,
    },
    worker::{AirProverWorker, RecursionVkWorker},
    CompressAir, CORE_MAX_LOG_ROW_COUNT,
};

pub const DEFAULT_ARITY: usize = 4;

/// The shape of the "normalize" program, which proves the correct execution for the verifier of a
/// single core shard proof.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct SP1NormalizeInputShape {
    pub proof_shapes: Vec<CoreProofShape<SP1Field, RiscvAir<SP1Field>>>,
    pub max_log_row_count: usize,
    pub log_blowup: usize,
    pub log_stacking_height: usize,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub enum SP1RecursionProgramShape {
    // The program that verifies a core shard proof.
    Normalize(CoreProofShape<SP1Field, RiscvAir<SP1Field>>),
    // Compose(arity) is the program that verifies a batch of Normalize proofs of size arity.
    Compose(usize),
    // The deferred proof program.
    Deferred,
    // The shrink program that verifies the the root of the recursion tree.
    Shrink,
}

const PADDED_ELEMENT_THRESHOLD: u64 =
    sp1_core_executor::ELEMENT_THRESHOLD + (1 << CORE_LOG_STACKING_HEIGHT);

#[derive(Debug, Error)]
pub enum VkBuildError {
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Bincode(#[from] bincode::Error),
}

impl SP1NormalizeInputShape {
    pub fn dummy_input(
        &self,
        vk: SP1VerifyingKey,
    ) -> SP1NormalizeWitnessValues<SP1GlobalContext, SP1PcsProofInner> {
        let shard_proofs = self
            .proof_shapes
            .iter()
            .map(|core_shape| {
                dummy_shard_proof(
                    core_shape.shard_chips.clone(),
                    self.max_log_row_count,
                    core_fri_config(),
                    self.log_stacking_height,
                    &[core_shape.preprocessed_multiple, core_shape.main_multiple],
                    &[core_shape.preprocessed_padding_cols, core_shape.main_padding_cols],
                )
            })
            .collect::<Vec<_>>();

        SP1NormalizeWitnessValues {
            vk: vk.vk,
            shard_proofs,
            is_complete: false,
            vk_root: [SP1Field::zero(); DIGEST_SIZE],
            reconstruct_deferred_digest: [SP1Field::zero(); 8],
            num_deferred_proofs: SP1Field::zero(),
        }
    }
}

pub struct SP1NormalizeCache {
    lru: Arc<Mutex<LruCache<SP1NormalizeInputShape, Arc<RecursionProgram<SP1Field>>>>>,
    total_calls: AtomicUsize,
    hits: AtomicUsize,
}

impl SP1NormalizeCache {
    pub fn new(size: usize) -> Self {
        let size = NonZero::new(size).expect("size must be non-zero");
        let lru = LruCache::new(size);
        let lru = Arc::new(Mutex::new(lru));
        Self { lru, total_calls: AtomicUsize::new(0), hits: AtomicUsize::new(0) }
    }

    pub fn get(&self, shape: &SP1NormalizeInputShape) -> Option<Arc<RecursionProgram<SP1Field>>> {
        self.total_calls.fetch_add(1, Ordering::Relaxed);
        if let Some(program) = self.lru.lock().unwrap().get(shape).cloned() {
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(program)
        } else {
            None
        }
    }

    pub fn push(&self, shape: SP1NormalizeInputShape, program: Arc<RecursionProgram<SP1Field>>) {
        self.lru.lock().unwrap().push(shape, program);
    }

    pub fn stats(&self) -> (usize, usize, f64) {
        (
            self.total_calls.load(Ordering::Relaxed),
            self.hits.load(Ordering::Relaxed),
            self.hits.load(Ordering::Relaxed) as f64
                / self.total_calls.load(Ordering::Relaxed) as f64,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SP1RecursionProofShape {
    pub shape: RecursionShape<SP1Field>,
}

impl Default for SP1RecursionProofShape {
    fn default() -> Self {
        Self::compress_proof_shape_from_arity(DEFAULT_ARITY).unwrap()
    }
}

impl SP1RecursionProofShape {
    pub fn compress_proof_shape_from_arity(arity: usize) -> Option<Self> {
        match arity {
            DEFAULT_ARITY => {
                let file = include_bytes!("../compress_shape.json");
                serde_json::from_slice(file).ok().or_else(|| {
                    tracing::warn!("Failed to load compress_shape.json, using default shape.");
                    // This is not a well-tuned shape, but is likely to be big enough even if
                    // relatively substantial changes are made to the verifier.
                    Some(SP1RecursionProofShape {
                        shape: [
                            (
                                CompressAir::<SP1Field>::MemoryConst(MemoryConstChip::default()),
                                600_000usize.next_multiple_of(32),
                            ),
                            (
                                CompressAir::<SP1Field>::MemoryVar(MemoryVarChip::default()),
                                500_000usize.next_multiple_of(32),
                            ),
                            (
                                CompressAir::<SP1Field>::BaseAlu(BaseAluChip),
                                500_000usize.next_multiple_of(32),
                            ),
                            (
                                CompressAir::<SP1Field>::ExtAlu(ExtAluChip),
                                850_000usize.next_multiple_of(32),
                            ),
                            (
                                CompressAir::<SP1Field>::Poseidon2Wide(Poseidon2WideChip),
                                150_448usize.next_multiple_of(32),
                            ),
                            (
                                CompressAir::<SP1Field>::PrefixSumChecks(PrefixSumChecksChip),
                                275_440usize.next_multiple_of(32),
                            ),
                            (
                                CompressAir::<SP1Field>::Select(SelectChip),
                                800_000usize.next_multiple_of(32),
                            ),
                            (CompressAir::<SP1Field>::PublicValues(PublicValuesChip), 16usize),
                        ]
                        .into_iter()
                        .collect(),
                    })
                })
            }
            _ => None,
        }
    }

    pub fn dummy_input(
        &self,
        arity: usize,
        height: usize,
        chips: BTreeSet<Chip<SP1Field, CompressAir<SP1Field>>>,
        max_log_row_count: usize,
        fri_config: FriConfig<SP1Field>,
        log_stacking_height: usize,
    ) -> SP1CompressWithVKeyWitnessValues<SP1PcsProofInner> {
        let dummy_vk = dummy_vk();

        let preprocessed_multiple = chips
            .iter()
            .map(|chip| self.shape.height(chip).unwrap() * chip.preprocessed_width())
            .sum::<usize>()
            .div_ceil(1 << log_stacking_height);

        let main_multiple = chips
            .iter()
            .map(|chip| self.shape.height(chip).unwrap() * chip.width())
            .sum::<usize>()
            .div_ceil(1 << log_stacking_height);

        let preprocessed_padding_cols = ((preprocessed_multiple * (1 << log_stacking_height))
            - chips
                .iter()
                .map(|chip| self.shape.height(chip).unwrap() * chip.preprocessed_width())
                .sum::<usize>())
        .div_ceil(1 << max_log_row_count)
        .max(1);

        let main_padding_cols = ((main_multiple * (1 << log_stacking_height))
            - chips
                .iter()
                .map(|chip| self.shape.height(chip).unwrap() * chip.width())
                .sum::<usize>())
        .div_ceil(1 << max_log_row_count)
        .max(1);

        let dummy_proof = dummy_shard_proof(
            chips,
            max_log_row_count,
            fri_config,
            log_stacking_height,
            &[preprocessed_multiple, main_multiple],
            &[preprocessed_padding_cols, main_padding_cols],
        );

        let vks_and_proofs =
            (0..arity).map(|_| (dummy_vk.clone(), dummy_proof.clone())).collect::<Vec<_>>();

        SP1CompressWithVKeyWitnessValues {
            compress_val: SP1ShapedWitnessValues { vks_and_proofs, is_complete: false },
            merkle_val: SP1MerkleProofWitnessValues::dummy(arity, height),
        }
    }

    pub async fn check_compatibility(
        &self,
        program: Arc<RecursionProgram<SP1Field>>,
        machine: Machine<SP1Field, CompressAir<SP1Field>>,
    ) -> bool {
        // Generate the preprocessed traces to get the heights.
        let trace_generator = DefaultTraceGenerator::new(machine);
        let setup_permits = ProverSemaphore::new(1);
        let preprocessed_traces = trace_generator
            .generate_preprocessed_traces(program, RECURSION_MAX_LOG_ROW_COUNT, setup_permits)
            .await;

        let mut is_compatible = true;
        for (chip, trace) in preprocessed_traces.preprocessed_traces.into_iter() {
            let real_height = trace.num_real_entries();
            let expected_height = self.shape.height_of_name(&chip).unwrap();
            if real_height > expected_height {
                tracing::warn!(
                    "program is incompatible with shape: {} > {} for chip {}",
                    real_height,
                    expected_height,
                    chip
                );
                is_compatible = false;
            }
        }
        is_compatible
    }

    #[allow(dead_code)]
    async fn max_arity<C: SP1ProverComponents>(
        &self,
        vk_verification: bool,
        height: usize,
    ) -> usize {
        let mut arity = 0;
        let compress_verifier = C::compress_verifier();
        let recursive_compress_verifier =
            recursive_verifier::<_, _, InnerConfig>(compress_verifier.shard_verifier());
        for possible_arity in 1.. {
            let input = dummy_compose_input(&compress_verifier, self, possible_arity, height);
            let program =
                compose_program_from_input(&recursive_compress_verifier, vk_verification, &input);
            let program = Arc::new(program);
            let is_compatible =
                self.check_compatibility(program, compress_verifier.machine().clone()).await;
            if !is_compatible {
                break;
            }
            arity = possible_arity;
        }
        arity
    }
}

pub async fn build_vk_map<A: ArtifactClient, C: SP1ProverComponents + 'static>(
    dummy: bool,
    num_compiler_workers: usize,
    num_setup_workers: usize,
    indices: Option<Vec<usize>>,
    max_arity: usize,
    merkle_tree_height: usize,
    vk_worker: Arc<RecursionVkWorker<C>>,
) -> (BTreeSet<[SP1Field; DIGEST_SIZE]>, Vec<usize>) {
    let recursion_permits = vk_worker.recursion_permits.clone();
    let recursion_prover = vk_worker.recursion_prover.clone();
    let shrink_prover = vk_worker.shrink_prover.clone();
    if dummy {
        let dummy_set = dummy_vk_map::<C>().into_keys().collect();
        return (dummy_set, vec![]);
    }

    // Setup the channels.
    let (vk_tx, mut vk_rx) =
        tokio::sync::mpsc::unbounded_channel::<(usize, [SP1Field; DIGEST_SIZE])>();
    let (shape_tx, shape_rx) =
        tokio::sync::mpsc::channel::<(usize, SP1RecursionProgramShape)>(num_compiler_workers);
    let (program_tx, program_rx) = tokio::sync::mpsc::channel(num_setup_workers);
    let (panic_tx, mut panic_rx) = tokio::sync::mpsc::unbounded_channel();

    // Setup the mutexes.
    let shape_rx = Arc::new(tokio::sync::Mutex::new(shape_rx));
    let program_rx = Arc::new(tokio::sync::Mutex::new(program_rx));

    // Generate all the possible shape inputs we encounter in recursion. This may span normalize,
    // compose (of any arity), deferred, shrink, etc.
    let all_shapes = create_all_input_shapes(C::core_verifier().machine().shape(), max_arity);

    let num_shapes = all_shapes.len();

    let height = if indices.is_some() { merkle_tree_height } else { log2_ceil_usize(num_shapes) };

    let indices_set = indices.map(|indices| indices.into_iter().collect::<HashSet<_>>());

    let vk_map_size = indices_set.as_ref().map(|indices| indices.len()).unwrap_or(num_shapes);

    let mut set = JoinSet::new();

    // Initialize compiler workers.
    for _ in 0..num_compiler_workers {
        let program_tx = program_tx.clone();
        let shape_rx = shape_rx.clone();
        let panic_tx = panic_tx.clone();
        set.spawn(async move {
            while let Some((i, shape)) = shape_rx.lock().await.recv().await {
                // eprintln!("shape: {:?}", shape);
                let compress_verifier = C::compress_verifier();
                let recursive_compress_verifier =
                    recursive_verifier::<_, _, InnerConfig>(compress_verifier.shard_verifier());
                // Spawn on another thread to handle panics.
                let program_thread = tokio::spawn(async move {
                    let reduce_shape =
                        SP1RecursionProofShape::compress_proof_shape_from_arity(max_arity);
                    match shape {
                        SP1RecursionProgramShape::Normalize(shape_clone) => {
                            let normalize_shape = SP1NormalizeInputShape {
                                proof_shapes: vec![shape_clone],
                                max_log_row_count: CORE_MAX_LOG_ROW_COUNT,
                                log_blowup: CORE_LOG_BLOWUP,
                                log_stacking_height: CORE_LOG_STACKING_HEIGHT as usize,
                            };
                            let dummy_vk = dummy_vk();
                            let core_verifier = C::core_verifier();
                            let recursive_core_verifier = recursive_verifier::<_, _, InnerConfig>(
                                core_verifier.shard_verifier(),
                            );
                            let witness =
                                normalize_shape.dummy_input(SP1VerifyingKey { vk: dummy_vk });
                            let mut program =
                                normalize_program_from_input(&recursive_core_verifier, &witness);
                            program.shape =
                                Some(reduce_shape.clone().expect("max arity not supported").shape);
                            (Arc::new(program), false)
                        }
                        SP1RecursionProgramShape::Compose(arity) => {
                            let dummy_input = dummy_compose_input(
                                &compress_verifier,
                                &SP1RecursionProofShape::compress_proof_shape_from_arity(max_arity)
                                    .expect("max arity not supported"),
                                arity,
                                height,
                            );

                            let mut program = compose_program_from_input(
                                &recursive_compress_verifier,
                                true,
                                &dummy_input,
                            );
                            program.shape =
                                Some(reduce_shape.clone().expect("max arity not supported").shape);
                            (Arc::new(program), false)
                        }
                        SP1RecursionProgramShape::Deferred => {
                            let dummy_input = dummy_deferred_input(
                                &C::compress_verifier(),
                                &reduce_shape.clone().expect("max arity not supported"),
                                height,
                            );
                            let mut program = deferred_program_from_input(
                                &recursive_compress_verifier,
                                true,
                                &dummy_input,
                            );

                            program.shape =
                                Some(reduce_shape.clone().expect("max arity not supported").shape);

                            (Arc::new(program), false)
                        }
                        SP1RecursionProgramShape::Shrink => {
                            let dummy_input = dummy_compose_input(
                                &C::compress_verifier(),
                                &reduce_shape.clone().expect("max arity not supported"),
                                1,
                                height,
                            );
                            let program = shrink_program_from_input(
                                &recursive_compress_verifier,
                                true,
                                &dummy_input,
                            );

                            (Arc::new(program), true)
                        }
                    }
                });
                match program_thread.await {
                    Ok((program, is_shrink)) => {
                        program_tx.send((i, program, is_shrink)).await.unwrap()
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Program generation failed for shape {}, with error: {:?}",
                            i,
                            e
                        );
                        panic_tx.send(i).unwrap();
                    }
                }
            }
        });
    }

    let recursion_prover = recursion_prover.clone();
    // Initialize setup workers.
    for _ in 0..num_setup_workers {
        let vk_tx = vk_tx.clone();
        let program_rx = program_rx.clone();
        let prover = recursion_prover.clone();
        let recursion_permits = recursion_permits.clone();
        let shrink_prover = shrink_prover.clone();
        set.spawn(async move {
            let mut done = 0;
            while let Some((i, program, is_shrink)) = program_rx.lock().await.recv().await {
                let prover = prover.clone();
                let shrink_prover = shrink_prover.clone();
                let recursion_permits = recursion_permits.clone();
                let vk_thread = tokio::spawn(async move {
                    if is_shrink {
                        shrink_prover.setup(program).await
                    } else {
                        prover.setup(program, recursion_permits.clone()).await.1
                    }
                });
                let vk = vk_thread.await.unwrap();
                done += 1;

                let vk_digest = vk.hash_koalabear();

                tracing::info!(
                    "program {} = {:?}, {}% done",
                    i,
                    vk_digest,
                    done * 100 / vk_map_size
                );
                vk_tx.send((i, vk_digest)).unwrap();
            }
        });
    }

    // Generate shapes and send them to the compiler workers.
    let subset_shapes = all_shapes
        .into_iter()
        .enumerate()
        .filter(|(i, _)| indices_set.as_ref().map(|set| set.contains(i)).unwrap_or(true))
        .collect::<Vec<_>>();

    for (i, shape) in subset_shapes.iter() {
        shape_tx.send((*i, shape.clone())).await.unwrap();
    }

    drop(shape_tx);
    drop(program_tx);
    drop(vk_tx);
    drop(panic_tx);

    set.join_all().await;

    let mut vk_map = BTreeMap::new();
    while let Some((i, vk)) = vk_rx.recv().await {
        vk_map.insert(i, vk);
    }

    let mut panic_indices = vec![];
    while let Some(i) = panic_rx.recv().await {
        panic_indices.push(i);
    }
    for (i, shape) in subset_shapes {
        if panic_indices.contains(&i) {
            tracing::info!("panic shape {}: {:?}", i, shape);
        }
    }

    // Build vk_set in lexicographic order.
    let vk_set: BTreeSet<[SP1Field; DIGEST_SIZE]> = vk_map.into_values().collect();

    (vk_set, panic_indices)
}

fn max_main_multiple_for_preprocessed_multiple(preprocessed_multiple: usize) -> usize {
    (PADDED_ELEMENT_THRESHOLD - preprocessed_multiple as u64 * (1 << CORE_LOG_STACKING_HEIGHT))
        .div_ceil(1 << CORE_LOG_STACKING_HEIGHT as u64) as usize
}

pub fn create_all_input_shapes(
    core_shape: &MachineShape<SP1Field, RiscvAir<SP1Field>>,
    max_arity: usize,
) -> Vec<SP1RecursionProgramShape> {
    let (max_preprocessed_multiple, _, capacity) = normalize_program_parameter_space();
    let max_num_padding_cols =
        ((1 << CORE_LOG_STACKING_HEIGHT) as usize).div_ceil(1 << CORE_MAX_LOG_ROW_COUNT);

    let mut result: Vec<SP1RecursionProgramShape> = Vec::with_capacity(capacity);
    for preprocessed_multiple in 1..=max_preprocessed_multiple {
        for main_multiple in 1..=max_main_multiple_for_preprocessed_multiple(preprocessed_multiple)
        {
            for main_padding_cols in 1..=max_num_padding_cols {
                for preprocessed_padding_cols in 1..=max_num_padding_cols {
                    for cluster in &core_shape.chip_clusters {
                        result.push(SP1RecursionProgramShape::Normalize(CoreProofShape {
                            shard_chips: cluster.clone(),
                            preprocessed_multiple,
                            main_multiple,
                            preprocessed_padding_cols,
                            main_padding_cols,
                        }));
                    }
                }
            }
        }
    }

    // Add the compose shapes for each arity.
    for arity in 1..=max_arity {
        result.push(SP1RecursionProgramShape::Compose(arity));
    }

    // Add the deferred shape.
    result.push(SP1RecursionProgramShape::Deferred);
    // Add the shrink shape.
    result.push(SP1RecursionProgramShape::Shrink);
    result
}

pub fn normalize_program_parameter_space() -> (usize, usize, usize) {
    let max_preprocessed_multiple = (MAX_PROGRAM_SIZE * NUM_PROGRAM_PREPROCESSED_COLS
        + (1 << 17) * NUM_RANGE_PREPROCESSED_COLS
        + (1 << 16) * NUM_BYTE_PREPROCESSED_COLS)
        .div_ceil(1 << CORE_LOG_STACKING_HEIGHT);
    let max_main_multiple =
        (PADDED_ELEMENT_THRESHOLD).div_ceil(1 << CORE_LOG_STACKING_HEIGHT) as usize;

    let num_shapes = (0..=max_preprocessed_multiple)
        .map(max_main_multiple_for_preprocessed_multiple)
        .sum::<usize>();

    (max_preprocessed_multiple, max_main_multiple, num_shapes)
}

pub fn dummy_vk_map<C: SP1ProverComponents>() -> BTreeMap<[SP1Field; DIGEST_SIZE], usize> {
    create_all_input_shapes(C::core_verifier().machine().shape(), DEFAULT_ARITY)
        .iter()
        .enumerate()
        .map(|(i, _)| ([SP1Field::from_canonical_usize(i); DIGEST_SIZE], i))
        .collect()
}

pub fn max_count(a: RecursionAirEventCount, b: RecursionAirEventCount) -> RecursionAirEventCount {
    use std::cmp::max;
    RecursionAirEventCount {
        mem_const_events: max(a.mem_const_events, b.mem_const_events),
        mem_var_events: max(a.mem_var_events, b.mem_var_events),
        base_alu_events: max(a.base_alu_events, b.base_alu_events),
        ext_alu_events: max(a.ext_alu_events, b.ext_alu_events),
        ext_felt_conversion_events: max(a.ext_felt_conversion_events, b.ext_felt_conversion_events),
        poseidon2_wide_events: max(a.poseidon2_wide_events, b.poseidon2_wide_events),
        poseidon2_linear_layer_events: max(
            a.poseidon2_linear_layer_events,
            b.poseidon2_linear_layer_events,
        ),
        poseidon2_sbox_events: max(a.poseidon2_sbox_events, b.poseidon2_sbox_events),
        select_events: max(a.select_events, b.select_events),
        prefix_sum_checks_events: max(a.prefix_sum_checks_events, b.prefix_sum_checks_events),
        commit_pv_hash_events: max(a.commit_pv_hash_events, b.commit_pv_hash_events),
    }
}

pub fn create_test_shape(
    cluster: &BTreeSet<Chip<SP1Field, RiscvAir<SP1Field>>>,
) -> SP1NormalizeInputShape {
    let preprocessed_multiple = (MAX_PROGRAM_SIZE * NUM_PROGRAM_PREPROCESSED_COLS
        + (1 << 17) * NUM_RANGE_PREPROCESSED_COLS
        + (1 << 16) * NUM_BYTE_PREPROCESSED_COLS)
        .div_ceil(1 << CORE_LOG_STACKING_HEIGHT);
    let main_multiple = (PADDED_ELEMENT_THRESHOLD).div_ceil(1 << CORE_LOG_STACKING_HEIGHT) as usize;
    let num_padding_cols =
        ((1 << CORE_LOG_STACKING_HEIGHT) as usize).div_ceil(1 << CORE_MAX_LOG_ROW_COUNT);
    SP1NormalizeInputShape {
        proof_shapes: vec![CoreProofShape {
            shard_chips: cluster.clone(),
            preprocessed_multiple,
            main_multiple,
            preprocessed_padding_cols: num_padding_cols,
            main_padding_cols: num_padding_cols,
        }],
        max_log_row_count: CORE_MAX_LOG_ROW_COUNT,
        log_stacking_height: CORE_LOG_STACKING_HEIGHT as usize,
        log_blowup: CORE_LOG_BLOWUP,
    }
}

pub fn build_recursion_count_from_shape(
    shape: &RecursionShape<SP1Field>,
) -> RecursionAirEventCount {
    RecursionAirEventCount {
        mem_const_events: shape
            .height(&CompressAir::<SP1Field>::MemoryConst(MemoryConstChip::default()))
            .unwrap(),
        mem_var_events: shape
            .height(&CompressAir::<SP1Field>::MemoryVar(MemoryVarChip::<SP1Field, 2>::default()))
            .unwrap()
            * 2,
        base_alu_events: shape.height(&CompressAir::<SP1Field>::BaseAlu(BaseAluChip)).unwrap(),
        ext_alu_events: shape.height(&CompressAir::<SP1Field>::ExtAlu(ExtAluChip)).unwrap(),
        ext_felt_conversion_events: shape
            .height(&CompressAir::<SP1Field>::ExtFeltConvert(ConvertChip))
            .unwrap_or(0),
        poseidon2_wide_events: shape
            .height(&CompressAir::<SP1Field>::Poseidon2Wide(Poseidon2WideChip))
            .unwrap_or(0),
        poseidon2_linear_layer_events: shape
            .height(&CompressAir::<SP1Field>::Poseidon2LinearLayer(Poseidon2LinearLayerChip))
            .unwrap_or(0),
        poseidon2_sbox_events: shape
            .height(&CompressAir::<SP1Field>::Poseidon2SBox(Poseidon2SBoxChip))
            .unwrap_or(0),
        select_events: shape.height(&CompressAir::<SP1Field>::Select(SelectChip)).unwrap(),
        prefix_sum_checks_events: shape
            .height(&CompressAir::<SP1Field>::PrefixSumChecks(PrefixSumChecksChip))
            .unwrap_or(0),
        commit_pv_hash_events: shape
            .height(&CompressAir::<SP1Field>::PublicValues(PublicValuesChip))
            .unwrap(),
    }
}

pub fn build_shape_from_recursion_air_event_count(
    event_count: &RecursionAirEventCount,
) -> SP1RecursionProofShape {
    let &RecursionAirEventCount {
        mem_const_events,
        mem_var_events,
        base_alu_events,
        ext_alu_events,
        poseidon2_wide_events,
        select_events,
        prefix_sum_checks_events,
        commit_pv_hash_events,
        ..
    } = event_count;
    let chips_and_heights = vec![
        (CompressAir::<SP1Field>::MemoryConst(MemoryConstChip::default()), mem_const_events),
        (
            CompressAir::<SP1Field>::MemoryVar(MemoryVarChip::<SP1Field, 2>::default()),
            mem_var_events / 2,
        ),
        (CompressAir::<SP1Field>::BaseAlu(BaseAluChip), base_alu_events),
        (CompressAir::<SP1Field>::ExtAlu(ExtAluChip), ext_alu_events),
        (CompressAir::<SP1Field>::Poseidon2Wide(Poseidon2WideChip), poseidon2_wide_events),
        (CompressAir::<SP1Field>::Select(SelectChip), select_events),
        (CompressAir::<SP1Field>::PrefixSumChecks(PrefixSumChecksChip), prefix_sum_checks_events),
        (CompressAir::<SP1Field>::PublicValues(PublicValuesChip), commit_pv_hash_events),
    ];
    SP1RecursionProofShape { shape: chips_and_heights.into_iter().collect() }
}

#[cfg(test)]
mod tests {
    use anyhow::Context;

    use crate::{
        recursion::normalize_program_from_input, worker::SP1LightNode, CpuSP1ProverComponents,
    };
    #[cfg(feature = "experimental")]
    use sp1_core_executor::SP1Context;

    use sp1_core_machine::utils::setup_logger;
    use sp1_recursion_executor::RecursionAirEventCount;

    use super::*;

    #[tokio::test]
    #[ignore = "should be invoked specifically"]
    async fn test_max_arity() {
        setup_logger();
        let client = SP1LightNode::new().await;

        let vk_verification = client.inner().vk_verification();
        let allowed_vk_height = client.inner().allowed_vk_height();

        let reduce_shape = SP1RecursionProofShape::compress_proof_shape_from_arity(DEFAULT_ARITY)
            .expect("default arity shape should be valid");

        let arity = reduce_shape
            .max_arity::<CpuSP1ProverComponents>(vk_verification, allowed_vk_height)
            .await;

        tracing::info!("arity: {}", arity);
    }

    #[derive(Debug, Error)]
    enum ShapeError {
        #[error("Expected arity to be {DEFAULT_ARITY}, found {_0}")]
        WrongArity(usize),
        #[error(
            "Expected the arity {DEFAULT_ARITY} shape to be large enough
                to accommodate all core shard proof shapes."
        )]
        CoreShapesTooLarge,
        #[error("Expected height of chip {_0} to be a multiple of 32")]
        ChipHeightNotMultipleOf32(String),
        #[error("Expected the shape to be minimal")]
        ShapeNotMinimal,
        #[error("Public values chip height is not 16")]
        PublicValuesChipHeightNot16,
    }

    #[tokio::test]
    async fn test_core_shape_fit() -> Result<(), anyhow::Error> {
        setup_logger();
        let elf = test_artifacts::FIBONACCI_ELF;
        let client = SP1LightNode::new().await;
        // let prover = SP1ProverBuilder::new().without_recursion_vks().build().await;
        let vk = client.setup(&elf).await?;

        let context =
            "Shape is not valid. To fix: From sp1-wip directory, run `cargo test --release -p sp1-prover --features experimental -- test_find_recursion_shape --include-ignored`";

        let machine = RiscvAir::<SP1Field>::machine();
        let chip_clusters = &machine.shape().chip_clusters;
        let mut max_cluster_count = RecursionAirEventCount::default();

        let core_verifier = CpuSP1ProverComponents::core_verifier();
        let recursive_core_verifier =
            recursive_verifier::<SP1GlobalContext, _, InnerConfig>(core_verifier.shard_verifier());

        for cluster in chip_clusters {
            let shape = create_test_shape(cluster);
            let program = normalize_program_from_input(
                &recursive_core_verifier,
                &shape.dummy_input(vk.clone()),
            );
            max_cluster_count = max_count(max_cluster_count, program.event_counts);
        }

        let vk_verification = client.inner().vk_verification();
        let allowed_vk_height = client.inner().allowed_vk_height();

        tracing::info!("max_cluster_count: {:?}", max_cluster_count);

        let reduce_shape =
            SP1RecursionProofShape::compress_proof_shape_from_arity(DEFAULT_ARITY).unwrap();
        let arity = reduce_shape
            .max_arity::<CpuSP1ProverComponents>(vk_verification, allowed_vk_height)
            .await;
        if arity != DEFAULT_ARITY {
            return Err(ShapeError::WrongArity(arity)).context(context);
        }

        let arity_4_count = build_recursion_count_from_shape(&reduce_shape.shape);
        let combined_count = max_count(max_cluster_count, arity_4_count);

        let max_cluster_shape = build_shape_from_recursion_air_event_count(&max_cluster_count);
        if combined_count != arity_4_count {
            return Err(ShapeError::CoreShapesTooLarge).context(context);
        }

        for (chip, height) in (&reduce_shape.shape).into_iter() {
            if chip != "PublicValues" {
                if !height.is_multiple_of(32) {
                    return Err(ShapeError::ChipHeightNotMultipleOf32(chip.clone()))
                        .context(context);
                }
                let mut new_reduce_shape = reduce_shape.clone();

                new_reduce_shape.shape.insert_with_name(chip, height - 32);

                if !(new_reduce_shape
                    .max_arity::<CpuSP1ProverComponents>(vk_verification, allowed_vk_height)
                    .await
                    < DEFAULT_ARITY
                    || new_reduce_shape.shape.height_of_name(chip).unwrap()
                        < max_cluster_shape
                            .shape
                            .height_of_name(chip)
                            .unwrap()
                            .next_multiple_of(32))
                {
                    return Err(ShapeError::ShapeNotMinimal).context(context);
                }
            } else if *height != 16 {
                return Err(ShapeError::PublicValuesChipHeightNot16).context(context);
            }
        }
        Ok(())
    }

    #[cfg(feature = "experimental")]
    use serial_test::serial;

    #[tokio::test]
    #[serial]
    #[cfg(feature = "experimental")]
    async fn test_build_vk_map() {
        use std::fs::File;

        use either::Either;

        use sp1_core_machine::io::SP1Stdin;
        use sp1_prover_types::network_base_types::ProofMode;
        use sp1_verifier::SP1Proof;

        use crate::worker::{cpu_worker_builder, SP1LocalNodeBuilder};

        setup_logger();

        // Use a temporary directory for the vk_map file to avoid conflicts
        let temp_dir = std::env::temp_dir();
        let vk_map_path = temp_dir.join("vk_map.bin");

        // Clean up any existing file from previous runs
        let _ = std::fs::remove_file(&vk_map_path);

        let node = SP1LocalNodeBuilder::from_worker_client_builder(cpu_worker_builder())
            .build()
            .await
            .unwrap();

        let elf = test_artifacts::FIBONACCI_ELF;

        // Make a proof to get proof shapes to populate the vk map with.
        let vk = node.setup(&elf).await.expect("Failed to setup");

        let proof = node
            .prove_with_mode(&elf, SP1Stdin::default(), SP1Context::default(), ProofMode::Core)
            .await
            .expect("Failed to prove");

        // Create all circuit shapes.
        let shapes = create_all_input_shapes(
            CpuSP1ProverComponents::core_verifier().shard_verifier().machine().shape(),
            DEFAULT_ARITY,
        );

        // Determine the indices in `shapes` of the shapes appear in the proof.
        let mut shape_indices = vec![];

        let core_proof = match proof.proof {
            SP1Proof::Core(proof) => proof,
            _ => panic!("Expected core proof"),
        };

        for proof in &core_proof {
            let shape = SP1RecursionProgramShape::Normalize(
                CpuSP1ProverComponents::core_verifier().shape_from_proof(proof),
            );

            shape_indices.push(shapes.iter().position(|s| s == &shape).unwrap());
        }

        let shape_indices =
            shape_indices.into_iter().chain(shapes.len() - 12..shapes.len()).collect::<Vec<_>>();

        let result = node.build_vks(Some(Either::Left(shape_indices)), 4).await.unwrap();

        let vk_map_path = temp_dir.join("vk_map.bin");

        // Create the file to store the vk map.
        let mut file = File::create(vk_map_path.clone()).unwrap();

        bincode::serialize_into(&mut file, &result.vk_map).unwrap();

        // Build a new prover that performs the vk verification check using the built vk map.
        let node = SP1LocalNodeBuilder::from_worker_client_builder(
            cpu_worker_builder().with_vk_map_path(vk_map_path.to_str().unwrap().to_string()),
        )
        .build()
        .await
        .unwrap();

        tracing::info!("Rebuilt prover with vk map.");

        // Make a proof with the vks checked.
        let proof = node
            .prove_with_mode(
                &elf,
                SP1Stdin::default(),
                SP1Context::default(),
                ProofMode::Compressed,
            )
            .await
            .expect("Failed to prove");

        node.verify(&vk, &proof.proof).unwrap();

        std::fs::remove_file(vk_map_path).unwrap();
    }

    #[tokio::test]
    #[ignore = "should be invoked for shape tuning"]
    async fn test_find_recursion_shape() {
        setup_logger();
        let elf = test_artifacts::FIBONACCI_ELF;
        let client = SP1LightNode::new().await;
        let vk = client.setup(&elf).await.unwrap();

        let machine = RiscvAir::<SP1Field>::machine();
        let chip_clusters = &machine.shape().chip_clusters;
        let allowed_vk_height = client.inner().allowed_vk_height();
        let vk_verification = client.inner().vk_verification();

        let verifier = CpuSP1ProverComponents::compress_verifier();
        let dummy_input =
            |current_shape: &SP1RecursionProofShape| -> SP1CompressWithVKeyWitnessValues<SP1PcsProofInner> {
                dummy_compose_input(&verifier, current_shape, DEFAULT_ARITY, allowed_vk_height)
            };
        let core_verifier = CpuSP1ProverComponents::core_verifier();
        let recursive_core_verifier =
            recursive_verifier::<SP1GlobalContext, _, InnerConfig>(core_verifier.shard_verifier());

        let recursive_compress_verifier =
            recursive_verifier::<SP1GlobalContext, _, InnerConfig>(verifier.shard_verifier());
        let compose_program =
            |input: &SP1CompressWithVKeyWitnessValues<SP1PcsProofInner>| -> Arc<RecursionProgram<SP1Field>> {
                Arc::new(compose_program_from_input(
                    &recursive_compress_verifier,
                    vk_verification,
                    input,
                ))
            };

        // Find the recursion proof shape that fits the normalize programs verifying all core
        // shards.
        let mut max_cluster_count = RecursionAirEventCount::default();

        for cluster in chip_clusters {
            let shape = create_test_shape(cluster);
            let program = normalize_program_from_input(
                &recursive_core_verifier,
                &shape.dummy_input(vk.clone()),
            );
            max_cluster_count = max_count(max_cluster_count, program.event_counts);
        }

        // Iterate on this shape until the compose program verifying DEFAULT_ARITY proofs of shape
        // `current_shape` can be proved using `current_shape`.
        let mut current_shape = build_shape_from_recursion_air_event_count(&max_cluster_count);
        let trace_generator =
            DefaultTraceGenerator::new(CompressAir::<SP1Field>::compress_machine());
        loop {
            // Create DEFAULT_ARITY dummy proofs of shape `current_shape`
            let input = dummy_input(&current_shape);
            // Compile the program that verifies those `DEFAULT_ARITY` proofs.
            let program = compose_program(&input);
            let setup_permits = ProverSemaphore::new(1);
            // The preprocessed traces contain the information of the minimum required table heights
            // to prove the compose program.
            let preprocessed_traces = trace_generator
                .generate_preprocessed_traces(program, RECURSION_MAX_LOG_ROW_COUNT, setup_permits)
                .await;

            // Check if the `current_shape` heights are insufficient.
            let updated_key_values = preprocessed_traces
                .preprocessed_traces
                .into_iter()
                .filter_map(|(chip, trace)| {
                    let real_height = trace.num_real_entries();
                    let expected_height = current_shape.shape.height_of_name(&chip).unwrap();

                    if real_height > expected_height {
                        tracing::warn!(
                            "Insufficient height for chip {}: expected {}, got {}",
                            chip,
                            expected_height,
                            real_height
                        );
                        Some((chip, real_height))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();

            // If no need to update the chip heights, `current_shape` is good enough.
            if updated_key_values.is_empty() {
                break;
            }
            // Otherwise, update the heights in `current_shape` and repeat the loop.
            for (chip, real_height) in updated_key_values {
                current_shape.shape.insert_with_name(&chip, real_height);
            }
        }

        // Write the shape to a file.
        let shape = SP1RecursionProofShape {
            shape: RecursionShape::new(
                current_shape
                    .shape
                    .into_iter()
                    .map(|(chip, height)| {
                        let new_height = if chip == "PublicValues" {
                            height
                        } else {
                            height.next_multiple_of(32)
                        };
                        (chip, new_height)
                    })
                    .collect(),
            ),
        };

        let mut file = std::fs::File::create("compress_shape.json").unwrap();
        serde_json::to_writer_pretty(&mut file, &shape).unwrap();
    }
}
