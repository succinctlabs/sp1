//! A minimal machine exercising the third (global) committed trace round: one mixed chip with
//! preprocessed + global + main columns, and one global-only chip with no main columns.

use std::{borrow::BorrowMut, mem::MaybeUninit};

use hashbrown::HashMap;
use slop_air::{Air, BaseAir, GlobalBuilder, PairBuilder};
use slop_algebra::{AbstractField, PrimeField32};
use slop_challenger::IopCtx;
use slop_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::Program;
use sp1_hypercube::{
    air::{
        AirInteraction, InteractionScope, MachineAir, PublicValues, SP1AirBuilder,
        POSEIDON_NUM_WORDS,
    },
    InteractionKind, MachineRecord, PROOF_MAX_NUM_PVS,
};

use crate::utils::zeroed_f_vec;

/// The fixed trace height of the mixed chip (and its preprocessed trace).
pub const MIXED_CHIP_HEIGHT: usize = 64;

/// The fixed trace height of the global-only chip.
pub const GLOBAL_ONLY_CHIP_HEIGHT: usize = 32;

/// A record for the global-round test machine.
#[derive(Clone, Debug, Default)]
pub struct GlobalTestRecord {
    /// Rows `(a, b)` for the mixed chip; at most [`MIXED_CHIP_HEIGHT`].
    pub mixed_rows: Vec<(u32, u32)>,
    /// Boolean rows for the global-only chip; at most [`GLOBAL_ONLY_CHIP_HEIGHT`].
    pub flag_rows: Vec<u32>,
    /// Corrupt one global trace cell of the global-only chip (a cell only the cross-chip bus
    /// pairs reference), so the proved buses no longer balance.
    pub corrupt_global_cell: bool,
    /// The chunk's previous memory-state root, mirrored into the public values. Shards in one
    /// chunk share it, so it is part of the chunk-invariant transcript prefix.
    pub prev_merkle_root: [u32; POSEIDON_NUM_WORDS],
    /// The chunk's current memory-state root, mirrored into the public values.
    pub merkle_root: [u32; POSEIDON_NUM_WORDS],
    /// The chunk's ordered global-trace commitments (digest base-field elements in `u32` form);
    /// the shared global challenge is derived from them. Empty for a standalone shard.
    pub global_commitments: Vec<[u32; 8]>,
}

impl GlobalTestRecord {
    /// Record the chunk's ordered global-trace commitments (mirrors `ExecutionRecord`).
    fn set_global_commitments<GC: IopCtx>(&mut self, commitments: &[GC::Digest]) {
        self.global_commitments = commitments
            .iter()
            .map(|digest| {
                let elements = GC::digest_to_elements(digest);
                std::array::from_fn(|i| elements[i].as_canonical_u32())
            })
            .collect();
    }
}

impl MachineRecord for GlobalTestRecord {
    fn stats(&self) -> HashMap<String, usize> {
        let mut map = HashMap::new();
        map.insert("num_mixed_rows".to_string(), self.mixed_rows.len());
        map.insert("num_flag_rows".to_string(), self.flag_rows.len());
        map
    }

    fn append(&mut self, other: &mut Self) {
        self.mixed_rows.append(&mut other.mixed_rows);
        self.flag_rows.append(&mut other.flag_rows);
    }

    fn public_values<F: AbstractField>(&self) -> Vec<F> {
        let mut values = vec![F::zero(); PROOF_MAX_NUM_PVS];
        let pv: &mut PublicValues<[F; 4], [F; 3], [F; 4], F> = values.as_mut_slice().borrow_mut();
        pv.prev_merkle_root = self.prev_merkle_root.map(F::from_canonical_u32);
        pv.merkle_root = self.merkle_root.map(F::from_canonical_u32);
        values
    }

    fn eval_public_values<AB: SP1AirBuilder>(_builder: &mut AB) {}

    fn interactions_in_public_values() -> Vec<InteractionKind> {
        vec![]
    }

    fn global_challenge_input<GC: IopCtx>(&self) -> Option<Vec<GC::Digest>> {
        if self.global_commitments.is_empty() {
            return None;
        }
        Some(
            self.global_commitments
                .iter()
                .map(|limbs| {
                    let elements: [GC::F; 8] =
                        std::array::from_fn(|i| GC::F::from_canonical_u32(limbs[i]));
                    GC::digest_from_elements(&elements)
                })
                .collect(),
        )
    }
}

/// A chip with preprocessed, global, and main columns: `main = [a, b]`,
/// `global = [a, b * prep, is_bus_row]`, with the preprocessed column fixed to `row + 1`. The
/// first [`GLOBAL_ONLY_CHIP_HEIGHT`] rows (`is_bus_row == 1`) send `(global[0], global[1])` on
/// a Global-scope and on a Local-scope bus, both received by [`GlobalOnlyChip`].
#[derive(Clone, Debug, Default)]
pub struct MixedGlobalChip;

const MIXED_MAIN_COLS: usize = 2;
const MIXED_GLOBAL_COLS: usize = 3;

impl<F> BaseAir<F> for MixedGlobalChip {
    fn width(&self) -> usize {
        MIXED_MAIN_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for MixedGlobalChip {
    type Record = GlobalTestRecord;
    type Program = Program;

    fn name(&self) -> &'static str {
        "MixedGlobal"
    }

    fn num_rows(&self, _input: &Self::Record) -> Option<usize> {
        Some(MIXED_CHIP_HEIGHT)
    }

    fn preprocessed_width(&self) -> usize {
        1
    }

    fn preprocessed_num_rows(&self, _program: &Self::Program) -> Option<usize> {
        Some(MIXED_CHIP_HEIGHT)
    }

    fn generate_preprocessed_trace(&self, _program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let values =
            (0..MIXED_CHIP_HEIGHT).map(|i| F::from_canonical_usize(i + 1)).collect::<Vec<_>>();
        Some(RowMajorMatrix::new(values, 1))
    }

    fn generate_trace(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
    ) -> RowMajorMatrix<F> {
        assert!(input.mixed_rows.len() <= MIXED_CHIP_HEIGHT);
        let mut values = zeroed_f_vec(MIXED_CHIP_HEIGHT * MIXED_MAIN_COLS);
        for (i, (a, b)) in input.mixed_rows.iter().enumerate() {
            values[MIXED_MAIN_COLS * i] = F::from_canonical_u32(*a);
            values[MIXED_MAIN_COLS * i + 1] = F::from_canonical_u32(*b);
        }
        RowMajorMatrix::new(values, MIXED_MAIN_COLS)
    }

    fn generate_trace_into(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _buffer: &mut [MaybeUninit<F>],
    ) {
        unimplemented!("use generate_trace");
    }

    fn global_width(&self) -> usize {
        MIXED_GLOBAL_COLS
    }

    fn generate_global_trace_into(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        buffer: &mut [MaybeUninit<F>],
    ) {
        assert_eq!(buffer.len(), MIXED_CHIP_HEIGHT * MIXED_GLOBAL_COLS);
        for (i, cell) in buffer.iter_mut().enumerate() {
            let (row, col) = (i / MIXED_GLOBAL_COLS, i % MIXED_GLOBAL_COLS);
            let value = match input.mixed_rows.get(row) {
                Some((a, _)) if col == 0 => F::from_canonical_u32(*a),
                Some((_, b)) if col == 1 => {
                    F::from_canonical_u32(*b) * F::from_canonical_usize(row + 1)
                }
                Some(_) => F::from_bool(row < GLOBAL_ONLY_CHIP_HEIGHT),
                None => F::zero(),
            };
            cell.write(value);
        }
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.mixed_rows.is_empty()
    }
}

impl<AB> Air<AB> for MixedGlobalChip
where
    AB: SP1AirBuilder + PairBuilder + GlobalBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let main_local = main.row_slice(0);
        let global = builder.global();
        let global_local = global.row_slice(0);
        let preprocessed = builder.preprocessed();
        let preprocessed_local = preprocessed.row_slice(0);

        // The global columns are bound to the main and preprocessed columns.
        builder.assert_eq(global_local[0], main_local[0]);
        builder.assert_eq(global_local[1], main_local[1] * preprocessed_local[0]);
        builder.assert_bool(global_local[2]);

        // A self-balancing interaction pair, so the machine has a (trivially balanced) LogUp
        // argument.
        let values = vec![main_local[0].into()];
        builder.send(
            AirInteraction::new(values.clone(), main_local[1].into(), InteractionKind::Byte),
            InteractionScope::Local,
        );
        builder.receive(
            AirInteraction::new(values, main_local[1].into(), InteractionKind::Byte),
            InteractionScope::Local,
        );

        // Cross-chip bus pairs routed through the global columns, received by the global-only
        // chip: one Global-scope, one Local-scope (the `MemoryLocal` pattern — a Local-scope
        // interaction referencing global columns).
        let bus_values = vec![global_local[0].into(), global_local[1].into()];
        builder.send(
            AirInteraction::new(
                bus_values.clone(),
                global_local[2].into(),
                InteractionKind::Memory,
            ),
            InteractionScope::Global,
        );
        builder.send(
            AirInteraction::new(bus_values, global_local[2].into(), InteractionKind::LeafHash),
            InteractionScope::Local,
        );
    }
}

/// A chip with only global columns (`width() == 0`), mirroring `MemoryLocal`'s layout:
/// `global = [flag, v0, v1]`, where `(v0, v1)` mirror the mixed chip's bus tuples and every
/// row receives them on the Global-scope and the Local-scope bus.
#[derive(Clone, Debug, Default)]
pub struct GlobalOnlyChip;

const GLOBAL_ONLY_GLOBAL_COLS: usize = 3;

impl<F> BaseAir<F> for GlobalOnlyChip {
    fn width(&self) -> usize {
        0
    }
}

impl<F: PrimeField32> MachineAir<F> for GlobalOnlyChip {
    type Record = GlobalTestRecord;
    type Program = Program;

    fn name(&self) -> &'static str {
        "GlobalOnly"
    }

    fn num_rows(&self, _input: &Self::Record) -> Option<usize> {
        Some(GLOBAL_ONLY_CHIP_HEIGHT)
    }

    fn generate_trace_into(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _buffer: &mut [MaybeUninit<F>],
    ) {
        unimplemented!("the chip has no main trace");
    }

    fn generate_dependencies(&self, _input: &Self::Record, _output: &mut Self::Record) {}

    fn global_width(&self) -> usize {
        GLOBAL_ONLY_GLOBAL_COLS
    }

    fn generate_global_trace_into(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        buffer: &mut [MaybeUninit<F>],
    ) {
        assert!(input.flag_rows.len() <= GLOBAL_ONLY_CHIP_HEIGHT);
        assert_eq!(buffer.len(), GLOBAL_ONLY_CHIP_HEIGHT * GLOBAL_ONLY_GLOBAL_COLS);
        for (i, cell) in buffer.iter_mut().enumerate() {
            let (row, col) = (i / GLOBAL_ONLY_GLOBAL_COLS, i % GLOBAL_ONLY_GLOBAL_COLS);
            // `(v0, v1)` mirror the tuples the mixed chip sends on its bus rows.
            let mut value = match col {
                0 => input.flag_rows.get(row).map_or(F::zero(), |f| F::from_canonical_u32(*f)),
                1 => {
                    input.mixed_rows.get(row).map_or(F::zero(), |(a, _)| F::from_canonical_u32(*a))
                }
                _ => input.mixed_rows.get(row).map_or(F::zero(), |(_, b)| {
                    F::from_canonical_u32(*b) * F::from_canonical_usize(row + 1)
                }),
            };
            // A corrupted, otherwise-unconstrained cell that only the bus pairs reference.
            if input.corrupt_global_cell && row == 0 && col == 1 {
                value += F::one();
            }
            cell.write(value);
        }
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.flag_rows.is_empty()
    }
}

impl<AB> Air<AB> for GlobalOnlyChip
where
    AB: SP1AirBuilder + GlobalBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let global = builder.global();
        let global_local = global.row_slice(0);

        builder.assert_bool(global_local[0]);

        // Receive the mixed chip's bus tuples, on both scopes. The constant multiplicity on
        // padded rows is handled by the padded-row (geq) adjustment of the GKR.
        let bus_values = vec![global_local[1].into(), global_local[2].into()];
        builder.receive(
            AirInteraction::new(bus_values.clone(), AB::Expr::one(), InteractionKind::Memory),
            InteractionScope::Global,
        );
        builder.receive(
            AirInteraction::new(bus_values, AB::Expr::one(), InteractionKind::LeafHash),
            InteractionScope::Local,
        );
    }
}

/// The AIR enum for the global-round test machine.
#[derive(Debug)]
pub enum GlobalTestAir {
    /// The mixed preprocessed + global + main chip.
    Mixed(MixedGlobalChip),
    /// The global-only chip.
    GlobalOnly(GlobalOnlyChip),
}

impl<F> BaseAir<F> for GlobalTestAir {
    fn width(&self) -> usize {
        match self {
            Self::Mixed(chip) => <MixedGlobalChip as BaseAir<F>>::width(chip),
            Self::GlobalOnly(chip) => <GlobalOnlyChip as BaseAir<F>>::width(chip),
        }
    }
}

impl<F: PrimeField32> MachineAir<F> for GlobalTestAir {
    type Record = GlobalTestRecord;
    type Program = Program;

    fn name(&self) -> &'static str {
        match self {
            Self::Mixed(chip) => <MixedGlobalChip as MachineAir<F>>::name(chip),
            Self::GlobalOnly(chip) => <GlobalOnlyChip as MachineAir<F>>::name(chip),
        }
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        match self {
            Self::Mixed(chip) => MachineAir::<F>::num_rows(chip, input),
            Self::GlobalOnly(chip) => MachineAir::<F>::num_rows(chip, input),
        }
    }

    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Mixed(chip) => MachineAir::<F>::preprocessed_width(chip),
            Self::GlobalOnly(chip) => MachineAir::<F>::preprocessed_width(chip),
        }
    }

    fn preprocessed_num_rows(&self, program: &Self::Program) -> Option<usize> {
        match self {
            Self::Mixed(chip) => MachineAir::<F>::preprocessed_num_rows(chip, program),
            Self::GlobalOnly(chip) => MachineAir::<F>::preprocessed_num_rows(chip, program),
        }
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Mixed(chip) => MachineAir::<F>::generate_preprocessed_trace(chip, program),
            Self::GlobalOnly(chip) => MachineAir::<F>::generate_preprocessed_trace(chip, program),
        }
    }

    fn generate_trace(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        match self {
            Self::Mixed(chip) => chip.generate_trace(input, output),
            Self::GlobalOnly(chip) => chip.generate_trace(input, output),
        }
    }

    fn generate_trace_into(
        &self,
        input: &Self::Record,
        output: &mut Self::Record,
        buffer: &mut [MaybeUninit<F>],
    ) {
        match self {
            Self::Mixed(chip) => chip.generate_trace_into(input, output, buffer),
            Self::GlobalOnly(chip) => chip.generate_trace_into(input, output, buffer),
        }
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        match self {
            Self::Mixed(chip) => MachineAir::<F>::generate_dependencies(chip, input, output),
            Self::GlobalOnly(chip) => MachineAir::<F>::generate_dependencies(chip, input, output),
        }
    }

    fn global_width(&self) -> usize {
        match self {
            Self::Mixed(chip) => MachineAir::<F>::global_width(chip),
            Self::GlobalOnly(chip) => MachineAir::<F>::global_width(chip),
        }
    }

    fn generate_global_trace_into(
        &self,
        input: &Self::Record,
        output: &mut Self::Record,
        buffer: &mut [MaybeUninit<F>],
    ) {
        match self {
            Self::Mixed(chip) => chip.generate_global_trace_into(input, output, buffer),
            Self::GlobalOnly(chip) => chip.generate_global_trace_into(input, output, buffer),
        }
    }

    fn included(&self, shard: &Self::Record) -> bool {
        match self {
            Self::Mixed(chip) => MachineAir::<F>::included(chip, shard),
            Self::GlobalOnly(chip) => MachineAir::<F>::included(chip, shard),
        }
    }
}

impl<AB> Air<AB> for GlobalTestAir
where
    AB: SP1AirBuilder + PairBuilder + GlobalBuilder,
{
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Mixed(chip) => chip.eval(builder),
            Self::GlobalOnly(chip) => chip.eval(builder),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{borrow::Borrow, sync::Arc};

    use slop_algebra::AbstractField;
    use slop_basefold::FriConfig;
    use slop_challenger::{CanObserve, IopCtx};
    use slop_multilinear::{MleEval, Point};
    use sp1_core_executor::{Instruction, Opcode, Program};
    use sp1_hypercube::{
        air::{MachineAir, PublicValues},
        beta_seed_dim_for_scope, observe_global_challenge,
        prover::{simple_prover, AirProver, CpuShardProver, ProverSemaphore, SP1InnerPcsProver},
        pv_interaction_max_arity, Chip, InnerSC, Machine, MachineProof, MachineShape,
        MachineVerifyingKey, SP1Pcs, SP1PcsProofInner, ShardProof, ShardVerifier,
    };
    use sp1_primitives::{SP1Field, SP1GlobalContext};

    use super::*;
    use crate::riscv::RiscvAir;

    type F = SP1Field;
    type EF = <SP1GlobalContext as IopCtx>::EF;

    fn global_test_machine() -> Machine<F, GlobalTestAir> {
        let chips = vec![
            Chip::new(GlobalTestAir::Mixed(MixedGlobalChip)),
            Chip::new(GlobalTestAir::GlobalOnly(GlobalOnlyChip)),
        ];
        let shape = MachineShape::all(&chips);
        // The two memory roots (16 field elements) are the only non-zero public values.
        Machine::new(chips, 2 * POSEIDON_NUM_WORDS, shape)
    }

    fn test_program() -> Program {
        Program::new(vec![Instruction::new(Opcode::ADD, 0, 0, 0, false, true)], 0, 0)
    }

    fn test_record() -> GlobalTestRecord {
        GlobalTestRecord {
            mixed_rows: (0..MIXED_CHIP_HEIGHT as u32).map(|i| (3 * i + 7, i + 11)).collect(),
            flag_rows: (0..GLOBAL_ONLY_CHIP_HEIGHT as u32).map(|i| i % 2).collect(),
            corrupt_global_cell: false,
            ..Default::default()
        }
    }

    async fn prove_record(
        record: GlobalTestRecord,
    ) -> (
        sp1_hypercube::MachineVerifyingKey<SP1GlobalContext>,
        sp1_hypercube::ShardProof<SP1GlobalContext, sp1_hypercube::SP1PcsProofInner>,
        ShardVerifier<SP1GlobalContext, sp1_hypercube::InnerSC<GlobalTestAir>>,
    ) {
        let machine = global_test_machine();
        assert!(machine.has_global_round());
        assert_eq!(machine.num_commitment_rounds(), 3);

        let verifier = ShardVerifier::from_basefold_parameters(
            FriConfig::default_fri_config(),
            21,
            22,
            machine,
        );
        let prover = simple_prover(verifier.clone());

        let (pk, vk) = prover.setup(Arc::new(test_program())).await;
        let pk = unsafe { pk.into_inner() };
        let proof = prover.prove_shard(pk, record).await;
        (vk, proof, verifier)
    }

    async fn prove_test_record() -> (
        sp1_hypercube::MachineVerifyingKey<SP1GlobalContext>,
        sp1_hypercube::ShardProof<SP1GlobalContext, sp1_hypercube::SP1PcsProofInner>,
        ShardVerifier<SP1GlobalContext, sp1_hypercube::InnerSC<GlobalTestAir>>,
    ) {
        prove_record(test_record()).await
    }

    fn verify(
        vk: &sp1_hypercube::MachineVerifyingKey<SP1GlobalContext>,
        proof: sp1_hypercube::ShardProof<SP1GlobalContext, sp1_hypercube::SP1PcsProofInner>,
        verifier: &ShardVerifier<SP1GlobalContext, sp1_hypercube::InnerSC<GlobalTestAir>>,
    ) -> Result<(), String> {
        let machine_verifier = sp1_hypercube::MachineVerifier::new(verifier.clone());
        machine_verifier
            .verify(vk, &MachineProof { shard_proofs: vec![proof] })
            .map_err(|e| e.to_string())
    }

    #[tokio::test]
    async fn test_global_round_prove_verify() {
        crate::utils::setup_logger();
        let (vk, proof, verifier) = prove_test_record().await;

        // The proof carries the global commitment and per-chip global openings.
        assert!(proof.global_commitment.is_some());
        let mixed_opening = &proof.opened_values.chips["MixedGlobal"];
        assert_eq!(mixed_opening.preprocessed.local.len(), 1);
        assert_eq!(mixed_opening.global.local.len(), 3);
        assert_eq!(mixed_opening.main.local.len(), 2);
        let global_only_opening = &proof.opened_values.chips["GlobalOnly"];
        assert_eq!(global_only_opening.preprocessed.local.len(), 0);
        assert_eq!(global_only_opening.global.local.len(), 3);
        assert_eq!(global_only_opening.main.local.len(), 0);

        // The record balances the Global-scope bus and there are no global-scope public-value
        // interactions, so the exposed global cumulative sum is zero.
        assert_eq!(proof.global_cumulative_sum, Some(EF::zero()));

        verify(&vk, proof, &verifier).expect("proof with a global round should verify");
    }

    /// A corrupted global opening must fail verification.
    #[tokio::test]
    async fn test_global_round_corrupt_global_opening() {
        let (vk, mut proof, verifier) = prove_test_record().await;
        let opening = proof.opened_values.chips.get_mut("MixedGlobal").unwrap();
        opening.global.local[0] += <SP1GlobalContext as slop_challenger::IopCtx>::EF::one();
        assert!(
            verify(&vk, proof, &verifier).is_err(),
            "corrupting a global opening must fail verification"
        );
    }

    /// A corrupted global-only chip opening must fail verification.
    #[tokio::test]
    async fn test_global_round_corrupt_global_only_opening() {
        let (vk, mut proof, verifier) = prove_test_record().await;
        let opening = proof.opened_values.chips.get_mut("GlobalOnly").unwrap();
        opening.global.local[0] += <SP1GlobalContext as slop_challenger::IopCtx>::EF::one();
        assert!(
            verify(&vk, proof, &verifier).is_err(),
            "corrupting the global-only chip's opening must fail verification"
        );
    }

    /// A wrong global commitment must fail verification.
    #[tokio::test]
    async fn test_global_round_wrong_global_commitment() {
        let (vk, mut proof, verifier) = prove_test_record().await;
        proof.global_commitment = Some([F::zero(); 8]);
        assert!(
            verify(&vk, proof, &verifier).is_err(),
            "a wrong global commitment must fail verification"
        );
    }

    /// A missing global commitment must fail verification.
    #[tokio::test]
    async fn test_global_round_missing_global_commitment() {
        let (vk, mut proof, verifier) = prove_test_record().await;
        proof.global_commitment = None;
        assert!(
            verify(&vk, proof, &verifier).is_err(),
            "a missing global commitment must fail verification"
        );
    }

    /// A tampered global cumulative sum (a proof output) must fail verification: the verifier
    /// binds it to the value recomputed from the observed output layer.
    #[tokio::test]
    async fn test_global_round_corrupt_global_cumulative_sum() {
        let (vk, mut proof, verifier) = prove_test_record().await;
        proof.global_cumulative_sum = Some(proof.global_cumulative_sum.unwrap() + EF::one());
        assert!(
            verify(&vk, proof, &verifier).is_err(),
            "a tampered global cumulative sum must fail verification"
        );

        let (vk, mut proof, verifier) = prove_test_record().await;
        proof.global_cumulative_sum = None;
        assert!(
            verify(&vk, proof, &verifier).is_err(),
            "a missing global cumulative sum must fail verification"
        );
    }

    /// A corrupted global trace cell that only the bus pairs reference: the Local-scope bus
    /// (which references global columns, like `MemoryLocal`) no longer balances, so the
    /// honestly-generated proof of the corrupted record must fail verification.
    #[tokio::test]
    async fn test_global_round_corrupted_global_trace_cell() {
        let record = GlobalTestRecord { corrupt_global_cell: true, ..test_record() };
        let (vk, proof, verifier) = prove_record(record).await;

        // The Global-scope bus is also unbalanced, so the exposed sum is nonzero.
        assert_ne!(proof.global_cumulative_sum, Some(EF::zero()));

        assert!(
            verify(&vk, proof, &verifier).is_err(),
            "a corrupted global trace cell must fail verification"
        );
    }

    /// A corrupted global trace evaluation in the GKR openings must fail verification (the
    /// openings are bound to the committed traces through the zerocheck opening batch).
    #[tokio::test]
    async fn test_global_round_corrupt_gkr_global_opening() {
        let (vk, mut proof, verifier) = prove_test_record().await;
        let openings =
            proof.logup_gkr_proof.logup_evaluations.chip_openings.get_mut("MixedGlobal").unwrap();
        let mut evals = openings.global_trace_evaluations.to_vec();
        evals[0] += EF::one();
        openings.global_trace_evaluations = MleEval::from(evals);
        assert!(
            verify(&vk, proof, &verifier).is_err(),
            "a corrupted GKR global trace evaluation must fail verification"
        );
    }

    /// A verifier deriving a different global challenge pair (by folding in commitments the
    /// prover never bound) must reject the proof.
    #[tokio::test]
    async fn test_global_round_mismatched_global_challenge_tuple() {
        let (vk, proof, verifier) = prove_test_record().await;

        // The proof was proved standalone (no chunk commitments). A verifier that instead observes
        // the hash of some commitments takes a transcript the prover never did, so it
        // derives a different challenge pair and the GKR check fails.
        let wrong_commitments =
            vec![proof.global_commitment.expect("a core shard has a global commitment")];
        let mut challenger = verifier.challenger();
        vk.observe_into(&mut challenger);
        assert!(
            verifier
                .verify_shard_with_global_commitments(
                    &vk,
                    &proof,
                    Some(&wrong_commitments),
                    &mut challenger,
                )
                .is_err(),
            "a mismatched global challenge tuple must fail verification"
        );

        // Sanity: the same proof verifies under the matching (standalone) derivation.
        let mut challenger = verifier.challenger();
        vk.observe_into(&mut challenger);
        verifier
            .verify_shard(&vk, &proof, &mut challenger)
            .expect("the proof verifies under the matching derivation");
    }

    /// A CPU shard prover that lets the test stamp the chunk's commitments onto the record (the
    /// simple prover always proves standalone).
    type SeamProver = CpuShardProver<
        SP1GlobalContext,
        SP1Pcs<SP1GlobalContext>,
        SP1InnerPcsProver,
        GlobalTestAir,
    >;

    /// Setup and prove `record`, deriving the global challenge pair from `commitments` (the
    /// chunk's ordered commitments, or `None` to prove it standalone).
    async fn prove_with_commitments(
        prover: &SeamProver,
        program: Arc<Program>,
        mut record: GlobalTestRecord,
        commitments: Option<&[<SP1GlobalContext as IopCtx>::Digest]>,
    ) -> (MachineVerifyingKey<SP1GlobalContext>, ShardProof<SP1GlobalContext, SP1PcsProofInner>)
    {
        if let Some(commitments) = commitments {
            record.set_global_commitments::<SP1GlobalContext>(commitments);
        }
        let (vk, proof, _permit) =
            prover.setup_and_prove_shard(program, record, None, ProverSemaphore::new(1)).await;
        (vk, proof)
    }

    /// Re-derive the global challenge pair a shard was proved with, replaying the verifier's
    /// transcript up to the derivation (vk, then the chunk-invariant memory roots).
    fn derive_global_challenge(
        verifier: &ShardVerifier<SP1GlobalContext, InnerSC<GlobalTestAir>>,
        vk: &MachineVerifyingKey<SP1GlobalContext>,
        proof: &ShardProof<SP1GlobalContext, SP1PcsProofInner>,
        commitments: Option<&[<SP1GlobalContext as IopCtx>::Digest]>,
    ) -> (EF, Point<EF>) {
        let mut challenger = verifier.challenger();
        vk.observe_into(&mut challenger);
        // The roots are base-field elements, so observing each one is transcript-identical to the
        // verifier's `observe_constant_length_extension_slice` over the same subset.
        let pv: &PublicValues<[F; 4], [F; 3], [F; 4], F> = proof.public_values.as_slice().borrow();
        for &element in pv.prev_merkle_root.iter().chain(&pv.merkle_root) {
            challenger.observe(element);
        }
        let beta_seed_dim = beta_seed_dim_for_scope(
            verifier.machine().chips().iter(),
            InteractionScope::Global,
            pv_interaction_max_arity::<GlobalTestRecord>(),
        );
        observe_global_challenge::<SP1GlobalContext>(commitments, beta_seed_dim, &mut challenger)
    }

    /// Two shards of one chunk, sharing the chunk's commitments, each derive the identical global
    /// challenge pair, verify under those commitments, and their global cumulative sums cancel to
    /// zero.
    #[tokio::test]
    async fn test_global_round_chunk_shared_seam() {
        crate::utils::setup_logger();
        let verifier = ShardVerifier::from_basefold_parameters(
            FriConfig::default_fri_config(),
            21,
            22,
            global_test_machine(),
        );
        let prover = SeamProver::new(verifier.clone());
        let program = Arc::new(test_program());

        // Two distinct shards of one chunk: they share the chunk-invariant memory roots but have
        // different traces, so their global commitments differ.
        let make_record = |a_mul: u32, a_add: u32| GlobalTestRecord {
            mixed_rows: (0..MIXED_CHIP_HEIGHT as u32)
                .map(|i| (a_mul * i + a_add, i + 11))
                .collect(),
            flag_rows: (0..GLOBAL_ONLY_CHIP_HEIGHT as u32).map(|i| i % 2).collect(),
            corrupt_global_cell: false,
            prev_merkle_root: std::array::from_fn(|i| i as u32 + 1),
            merkle_root: std::array::from_fn(|i| i as u32 + 101),
            global_commitments: Vec::new(),
        };
        let records = [make_record(3, 7), make_record(5, 13)];

        // Harvest each shard's global commitment (deterministic, challenge-independent) by proving
        // it standalone.
        let mut commitments = Vec::new();
        for record in records.clone() {
            let (_, proof) = prove_with_commitments(&prover, program.clone(), record, None).await;
            commitments
                .push(proof.global_commitment.expect("a core shard has a global commitment"));
        }
        // The shards differ, so the chunk's commitment hash genuinely folds two distinct digests.
        assert_ne!(commitments[0], commitments[1]);

        // Prove both shards under the chunk's shared commitments.
        let mut vks = Vec::new();
        let mut proofs = Vec::new();
        for record in records.clone() {
            let (vk, proof) =
                prove_with_commitments(&prover, program.clone(), record, Some(&commitments)).await;
            vks.push(vk);
            proofs.push(proof);
        }

        // The in-proof global commitment matches the harvested one (the commit is deterministic).
        for (proof, commitment) in proofs.iter().zip(commitments.iter()) {
            assert_eq!(proof.global_commitment.as_ref(), Some(commitment));
        }

        // Every shard of the chunk derives the identical global challenge pair.
        let challenge0 =
            derive_global_challenge(&verifier, &vks[0], &proofs[0], Some(&commitments));
        let challenge1 =
            derive_global_challenge(&verifier, &vks[1], &proofs[1], Some(&commitments));
        assert_eq!(
            challenge0, challenge1,
            "shards of one chunk must share the global challenge pair"
        );

        // Each shard verifies under the shared commitments, and the per-shard global sums cancel.
        let mut sum = EF::zero();
        for (vk, proof) in vks.iter().zip(proofs.iter()) {
            let mut challenger = verifier.challenger();
            vk.observe_into(&mut challenger);
            verifier
                .verify_shard_with_global_commitments(
                    vk,
                    proof,
                    Some(&commitments),
                    &mut challenger,
                )
                .expect("a chunk shard must verify under the shared commitments");
            sum += proof.global_cumulative_sum.expect("a core shard exposes a global sum");
        }
        assert_eq!(sum, EF::zero(), "the chunk's global cumulative sums must cancel to zero");

        let mut challenger = verifier.challenger();
        vks[0].observe_into(&mut challenger);
        assert!(
            verifier
                .verify_shard_with_global_commitments(
                    &vks[0],
                    &proofs[0],
                    Some(&commitments[0..1]),
                    &mut challenger,
                )
                .is_err(),
            "the wrong commitments must fail verification"
        );
    }

    /// Every chip cluster of the core machine must contain at least one chip with global
    /// columns: the prover commits a global round for every core shard.
    #[test]
    fn test_riscv_clusters_contain_global_chip() {
        let machine = RiscvAir::<F>::machine();
        assert!(machine.has_global_round());
        assert_eq!(machine.num_commitment_rounds(), 3);
        for cluster in &machine.shape().chip_clusters {
            assert!(
                cluster.iter().any(|chip| chip.global_width() > 0),
                "cluster {:?} has no chip with global columns",
                cluster.iter().map(MachineAir::<F>::name).collect::<Vec<_>>(),
            );
        }
    }
}
