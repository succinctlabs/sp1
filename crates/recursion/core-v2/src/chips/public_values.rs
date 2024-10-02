use std::borrow::{Borrow, BorrowMut};

use p3_air::{Air, AirBuilder, BaseAir, PairBuilder};
use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_machine::utils::pad_rows_fixed;
use sp1_derive::AlignedBorrow;
use sp1_stark::air::MachineAir;

use crate::{
    air::{RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS},
    builder::SP1RecursionAirBuilder,
    runtime::{Instruction, RecursionProgram},
    ExecutionRecord,
};

use crate::DIGEST_SIZE;

use super::mem::MemoryAccessCols;

pub const NUM_PUBLIC_VALUES_COLS: usize = core::mem::size_of::<PublicValuesCols<u8>>();
pub const NUM_PUBLIC_VALUES_PREPROCESSED_COLS: usize =
    core::mem::size_of::<PublicValuesPreprocessedCols<u8>>();

pub(crate) const PUB_VALUES_LOG_HEIGHT: usize = 4;

#[derive(Default)]
pub struct PublicValuesChip;

/// The preprocessed columns for the CommitPVHash instruction.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct PublicValuesPreprocessedCols<T: Copy> {
    pub pv_idx: [T; DIGEST_SIZE],
    pub pv_mem: MemoryAccessCols<T>,
}

/// The cols for a CommitPVHash invocation.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct PublicValuesCols<T: Copy> {
    pub pv_element: T,
}

impl<F> BaseAir<F> for PublicValuesChip {
    fn width(&self) -> usize {
        NUM_PUBLIC_VALUES_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for PublicValuesChip {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "PublicValues".to_string()
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PUBLIC_VALUES_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_PUBLIC_VALUES_PREPROCESSED_COLS]> = Vec::new();
        let commit_pv_hash_instrs = program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::CommitPublicValues(instr) = instruction {
                    Some(instr)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if commit_pv_hash_instrs.len() != 1 {
            tracing::warn!("Expected exactly one CommitPVHash instruction.");
        }

        // We only take 1 commit pv hash instruction, since our air only checks for one public
        // values hash.
        for instr in commit_pv_hash_instrs.iter().take(1) {
            for (i, addr) in instr.pv_addrs.digest.iter().enumerate() {
                let mut row = [F::zero(); NUM_PUBLIC_VALUES_PREPROCESSED_COLS];
                let cols: &mut PublicValuesPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                cols.pv_idx[i] = F::one();
                cols.pv_mem = MemoryAccessCols { addr: *addr, mult: F::neg_one() };
                rows.push(row);
            }
        }

        // Pad the preprocessed rows to 8 rows.
        // gpu code breaks for small traces
        pad_rows_fixed(
            &mut rows,
            || [F::zero(); NUM_PUBLIC_VALUES_PREPROCESSED_COLS],
            Some(PUB_VALUES_LOG_HEIGHT),
        );

        let trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect(),
            NUM_PUBLIC_VALUES_PREPROCESSED_COLS,
        );
        Some(trace)
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        if input.commit_pv_hash_events.len() != 1 {
            tracing::warn!("Expected exactly one CommitPVHash event.");
        }

        let mut rows: Vec<[F; NUM_PUBLIC_VALUES_COLS]> = Vec::new();

        // We only take 1 commit pv hash instruction, since our air only checks for one public
        // values hash.
        for event in input.commit_pv_hash_events.iter().take(1) {
            for element in event.public_values.digest.iter() {
                let mut row = [F::zero(); NUM_PUBLIC_VALUES_COLS];
                let cols: &mut PublicValuesCols<F> = row.as_mut_slice().borrow_mut();

                cols.pv_element = *element;
                rows.push(row);
            }
        }

        // Pad the trace to 8 rows.
        pad_rows_fixed(
            &mut rows,
            || [F::zero(); NUM_PUBLIC_VALUES_COLS],
            Some(PUB_VALUES_LOG_HEIGHT),
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect(), NUM_PUBLIC_VALUES_COLS)
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<AB> Air<AB> for PublicValuesChip
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &PublicValuesCols<AB::Var> = (*local).borrow();
        let prepr = builder.preprocessed();
        let local_prepr = prepr.row_slice(0);
        let local_prepr: &PublicValuesPreprocessedCols<AB::Var> = (*local_prepr).borrow();
        let pv = builder.public_values();
        let pv_elms: [AB::Expr; RECURSIVE_PROOF_NUM_PV_ELTS] =
            core::array::from_fn(|i| pv[i].into());
        let public_values: &RecursionPublicValues<AB::Expr> = pv_elms.as_slice().borrow();

        // Constrain mem read for the public value element.
        builder.send_single(local_prepr.pv_mem.addr, local.pv_element, local_prepr.pv_mem.mult);

        for (i, pv_elm) in public_values.digest.iter().enumerate() {
            // Ensure that the public value element is the same for all rows within a fri fold
            // invocation.
            builder.when(local_prepr.pv_idx[i]).assert_eq(pv_elm.clone(), local.pv_element);
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use sp1_core_machine::utils::setup_logger;

    use sp1_stark::{air::MachineAir, StarkGenericConfig};
    use std::{array, borrow::Borrow};

    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;

    use crate::{
        air::{RecursionPublicValues, NUM_PV_ELMS_TO_HASH, RECURSIVE_PROOF_NUM_PV_ELTS},
        chips::public_values::PublicValuesChip,
        machine::tests::run_recursion_test_machines,
        runtime::{instruction as instr, ExecutionRecord},
        stark::BabyBearPoseidon2Outer,
        CommitPublicValuesEvent, MemAccessKind, RecursionProgram, DIGEST_SIZE,
    };

    #[test]
    fn prove_babybear_circuit_public_values() {
        setup_logger();
        type SC = BabyBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut random_felt = move || -> F { F::from_canonical_u32(rng.gen_range(0..1 << 16)) };
        let random_pv_elms: [F; RECURSIVE_PROOF_NUM_PV_ELTS] = array::from_fn(|_| random_felt());
        let addr = 0u32;
        let public_values_a: [u32; RECURSIVE_PROOF_NUM_PV_ELTS] =
            array::from_fn(|i| i as u32 + addr);

        let mut instructions = Vec::new();
        // Allocate the memory for the public values hash.

        for i in 0..RECURSIVE_PROOF_NUM_PV_ELTS {
            let mult = (NUM_PV_ELMS_TO_HASH..NUM_PV_ELMS_TO_HASH + DIGEST_SIZE).contains(&i);
            instructions.push(instr::mem_block(
                MemAccessKind::Write,
                mult as u32,
                public_values_a[i],
                random_pv_elms[i].into(),
            ));
        }
        let public_values_a: &RecursionPublicValues<u32> = public_values_a.as_slice().borrow();
        instructions.push(instr::commit_public_values(public_values_a));

        let program = RecursionProgram { instructions, ..Default::default() };

        run_recursion_test_machines(program);
    }

    #[test]
    fn generate_public_values_circuit_trace() {
        type F = BabyBear;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let random_felts: [F; RECURSIVE_PROOF_NUM_PV_ELTS] =
            array::from_fn(|_| F::from_canonical_u32(rng.gen_range(0..1 << 16)));
        let random_public_values: &RecursionPublicValues<F> = random_felts.as_slice().borrow();

        let shard = ExecutionRecord {
            commit_pv_hash_events: vec![CommitPublicValuesEvent {
                public_values: *random_public_values,
            }],
            ..Default::default()
        };
        let chip = PublicValuesChip;
        let trace: RowMajorMatrix<F> = chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }
}
