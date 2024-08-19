use core::borrow::Borrow;
use itertools::Itertools;
use p3_air::{Air, AirBuilder, BaseAir, PairBuilder};
use p3_field::{Field, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_machine::utils::pad_to_power_of_two;
use sp1_derive::AlignedBorrow;
use sp1_stark::air::MachineAir;
use std::{borrow::BorrowMut, iter::zip};

use crate::{builder::SP1RecursionAirBuilder, *};

pub const NUM_BASE_ALU_ENTRIES_PER_ROW: usize = 8;

#[derive(Default)]
pub struct BaseAluChip {}

pub const NUM_BASE_ALU_COLS: usize = core::mem::size_of::<BaseAluCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BaseAluCols<F: Copy> {
    pub values: [BaseAluValueCols<F>; NUM_BASE_ALU_ENTRIES_PER_ROW],
}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BaseAluValueCols<F: Copy> {
    pub vals: BaseAluIo<F>,
}

pub const NUM_BASE_ALU_PREPROCESSED_COLS: usize =
    core::mem::size_of::<BaseAluPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BaseAluPreprocessedCols<F: Copy> {
    pub accesses: [BaseAluAccessCols<F>; NUM_BASE_ALU_ENTRIES_PER_ROW],
}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BaseAluAccessCols<F: Copy> {
    pub addrs: BaseAluIo<Address<F>>,
    pub is_add: F,
    pub is_sub: F,
    pub is_mul: F,
    pub is_div: F,
    pub mult: F,
}

impl<F: Field> BaseAir<F> for BaseAluChip {
    fn width(&self) -> usize {
        NUM_BASE_ALU_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for BaseAluChip {
    type Record = ExecutionRecord<F>;

    type Program = crate::RecursionProgram<F>;

    fn name(&self) -> String {
        "BaseAlu".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_BASE_ALU_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let rows = program
            .instructions
            .iter()
            .filter_map(|instruction| {
                let Instruction::BaseAlu(BaseAluInstr { opcode, mult, addrs }) = instruction else {
                    return None;
                };
                let mut access = BaseAluAccessCols {
                    addrs: addrs.to_owned(),
                    is_add: F::from_bool(false),
                    is_sub: F::from_bool(false),
                    is_mul: F::from_bool(false),
                    is_div: F::from_bool(false),
                    mult: mult.to_owned(),
                };
                let target_flag = match opcode {
                    BaseAluOpcode::AddF => &mut access.is_add,
                    BaseAluOpcode::SubF => &mut access.is_sub,
                    BaseAluOpcode::MulF => &mut access.is_mul,
                    BaseAluOpcode::DivF => &mut access.is_div,
                };
                *target_flag = F::from_bool(true);

                Some(access)
            })
            .chunks(NUM_BASE_ALU_ENTRIES_PER_ROW)
            .into_iter()
            .map(|row_accesses| {
                let mut row = [F::zero(); NUM_BASE_ALU_PREPROCESSED_COLS];
                let cols: &mut BaseAluPreprocessedCols<_> = row.as_mut_slice().borrow_mut();
                for (cell, access) in zip(&mut cols.accesses, row_accesses) {
                    *cell = access;
                }
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_BASE_ALU_PREPROCESSED_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_BASE_ALU_PREPROCESSED_COLS, F>(&mut trace.values);

        Some(trace)
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn generate_trace(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let rows = input
            .base_alu_events
            .chunks(NUM_BASE_ALU_ENTRIES_PER_ROW)
            .map(|row_events| {
                let mut row = [F::zero(); NUM_BASE_ALU_COLS];
                let cols: &mut BaseAluCols<_> = row.as_mut_slice().borrow_mut();
                for (cell, &vals) in zip(&mut cols.values, row_events) {
                    *cell = BaseAluValueCols { vals };
                }

                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_BASE_ALU_COLS);

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_BASE_ALU_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<AB> Air<AB> for BaseAluChip
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &BaseAluCols<AB::Var> = (*local).borrow();
        let prep = builder.preprocessed();
        let prep_local = prep.row_slice(0);
        let prep_local: &BaseAluPreprocessedCols<AB::Var> = (*prep_local).borrow();

        for (value, access) in zip(local.values, prep_local.accesses) {
            let BaseAluValueCols { vals: BaseAluIo { out, in1, in2 } } = value;

            // Check exactly one flag is enabled.
            let is_real = access.is_add + access.is_sub + access.is_mul + access.is_div;
            builder.assert_bool(is_real.clone());

            builder.when(access.is_add).assert_eq(in1 + in2, out);
            builder.when(access.is_sub).assert_eq(in1, in2 + out);
            builder.when(access.is_mul).assert_eq(in1 * in2, out);
            builder.when(access.is_div).assert_eq(in1, in2 * out);

            builder.receive_single(access.addrs.in1, in1, is_real.clone());

            builder.receive_single(access.addrs.in2, in2, is_real);

            builder.send_single(access.addrs.out, out, access.mult);
        }
    }
}

#[cfg(test)]
mod tests {
    use machine::tests::run_recursion_test_machines;
    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;

    use rand::{rngs::StdRng, Rng, SeedableRng};
    use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, StarkGenericConfig};

    use super::*;

    use crate::runtime::instruction as instr;

    #[test]
    fn generate_trace() {
        type F = BabyBear;

        let shard = ExecutionRecord {
            base_alu_events: vec![BaseAluIo { out: F::one(), in1: F::one(), in2: F::one() }],
            ..Default::default()
        };
        let chip = BaseAluChip::default();
        let trace: RowMajorMatrix<F> = chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    pub fn four_ops() {
        type SC = BabyBearPoseidon2;
        type F = <SC as StarkGenericConfig>::Val;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut random_felt = move || -> F { rng.sample(rand::distributions::Standard) };
        let mut addr = 0;

        let instructions = (0..1000)
            .flat_map(|_| {
                let quot = random_felt();
                let in2 = random_felt();
                let in1 = in2 * quot;
                let alloc_size = 6;
                let a = (0..alloc_size).map(|x| x + addr).collect::<Vec<_>>();
                addr += alloc_size;
                [
                    instr::mem_single(MemAccessKind::Write, 4, a[0], in1),
                    instr::mem_single(MemAccessKind::Write, 4, a[1], in2),
                    instr::base_alu(BaseAluOpcode::AddF, 1, a[2], a[0], a[1]),
                    instr::mem_single(MemAccessKind::Read, 1, a[2], in1 + in2),
                    instr::base_alu(BaseAluOpcode::SubF, 1, a[3], a[0], a[1]),
                    instr::mem_single(MemAccessKind::Read, 1, a[3], in1 - in2),
                    instr::base_alu(BaseAluOpcode::MulF, 1, a[4], a[0], a[1]),
                    instr::mem_single(MemAccessKind::Read, 1, a[4], in1 * in2),
                    instr::base_alu(BaseAluOpcode::DivF, 1, a[5], a[0], a[1]),
                    instr::mem_single(MemAccessKind::Read, 1, a[5], quot),
                ]
            })
            .collect::<Vec<Instruction<F>>>();

        let program = RecursionProgram { instructions, ..Default::default() };

        run_recursion_test_machines(program);
    }
}
