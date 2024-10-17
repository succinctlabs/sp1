use core::borrow::Borrow;
use p3_air::{Air, BaseAir, PairBuilder};
use p3_field::{extension::BinomiallyExtendable, Field, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::*;
use sp1_core_machine::utils::next_power_of_two;
use sp1_derive::AlignedBorrow;
use sp1_stark::air::{ExtensionAirBuilder, MachineAir};
use std::{borrow::BorrowMut, iter::zip};

use crate::{builder::SP1RecursionAirBuilder, *};

pub const NUM_EXT_ALU_ENTRIES_PER_ROW: usize = 4;

#[derive(Default)]
pub struct ExtAluChip;

pub const NUM_EXT_ALU_COLS: usize = core::mem::size_of::<ExtAluCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExtAluCols<F: Copy> {
    pub values: [ExtAluValueCols<F>; NUM_EXT_ALU_ENTRIES_PER_ROW],
}
const NUM_EXT_ALU_VALUE_COLS: usize = core::mem::size_of::<ExtAluValueCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExtAluValueCols<F: Copy> {
    pub vals: ExtAluIo<Block<F>>,
}

pub const NUM_EXT_ALU_PREPROCESSED_COLS: usize = core::mem::size_of::<ExtAluPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExtAluPreprocessedCols<F: Copy> {
    pub accesses: [ExtAluAccessCols<F>; NUM_EXT_ALU_ENTRIES_PER_ROW],
}

pub const NUM_EXT_ALU_ACCESS_COLS: usize = core::mem::size_of::<ExtAluAccessCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExtAluAccessCols<F: Copy> {
    pub addrs: ExtAluIo<Address<F>>,
    pub is_add: F,
    pub is_sub: F,
    pub is_mul: F,
    pub is_div: F,
    pub mult: F,
}

impl<F: Field> BaseAir<F> for ExtAluChip {
    fn width(&self) -> usize {
        NUM_EXT_ALU_COLS
    }
}

impl<F: PrimeField32 + BinomiallyExtendable<D>> MachineAir<F> for ExtAluChip {
    type Record = ExecutionRecord<F>;

    type Program = crate::RecursionProgram<F>;

    fn name(&self) -> String {
        "ExtAlu".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_EXT_ALU_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        // Allocating an intermediate `Vec` is faster.
        let instrs = program
            .instructions
            .iter() // Faster than using `rayon` for some reason. Maybe vectorization?
            .filter_map(|instruction| match instruction {
                Instruction::ExtAlu(x) => Some(x),
                _ => None,
            })
            .collect::<Vec<_>>();

        let nb_rows = instrs.len().div_ceil(NUM_EXT_ALU_ENTRIES_PER_ROW);
        let fixed_log2_rows = program.fixed_log2_rows(self);
        let padded_nb_rows = match fixed_log2_rows {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(nb_rows, None),
        };
        let mut values = vec![F::zero(); padded_nb_rows * NUM_EXT_ALU_PREPROCESSED_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = instrs.len() * NUM_EXT_ALU_ACCESS_COLS;
        values[..populate_len].par_chunks_mut(NUM_EXT_ALU_ACCESS_COLS).zip_eq(instrs).for_each(
            |(row, instr)| {
                let ExtAluInstr { opcode, mult, addrs } = instr;
                let access: &mut ExtAluAccessCols<_> = row.borrow_mut();
                *access = ExtAluAccessCols {
                    addrs: addrs.to_owned(),
                    is_add: F::from_bool(false),
                    is_sub: F::from_bool(false),
                    is_mul: F::from_bool(false),
                    is_div: F::from_bool(false),
                    mult: mult.to_owned(),
                };
                let target_flag = match opcode {
                    ExtAluOpcode::AddE => &mut access.is_add,
                    ExtAluOpcode::SubE => &mut access.is_sub,
                    ExtAluOpcode::MulE => &mut access.is_mul,
                    ExtAluOpcode::DivE => &mut access.is_div,
                };
                *target_flag = F::from_bool(true);
            },
        );

        // Convert the trace to a row major matrix.
        Some(RowMajorMatrix::new(values, NUM_EXT_ALU_PREPROCESSED_COLS))
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn generate_trace(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = &input.ext_alu_events;
        let nb_rows = events.len().div_ceil(NUM_EXT_ALU_ENTRIES_PER_ROW);
        let fixed_log2_rows = input.fixed_log2_rows(self);
        let padded_nb_rows = match fixed_log2_rows {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(nb_rows, None),
        };
        let mut values = vec![F::zero(); padded_nb_rows * NUM_EXT_ALU_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = events.len() * NUM_EXT_ALU_VALUE_COLS;
        values[..populate_len].par_chunks_mut(NUM_EXT_ALU_VALUE_COLS).zip_eq(events).for_each(
            |(row, &vals)| {
                let cols: &mut ExtAluValueCols<_> = row.borrow_mut();
                *cols = ExtAluValueCols { vals };
            },
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_EXT_ALU_COLS)
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<AB> Air<AB> for ExtAluChip
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &ExtAluCols<AB::Var> = (*local).borrow();
        let prep = builder.preprocessed();
        let prep_local = prep.row_slice(0);
        let prep_local: &ExtAluPreprocessedCols<AB::Var> = (*prep_local).borrow();

        for (
            ExtAluValueCols { vals },
            ExtAluAccessCols { addrs, is_add, is_sub, is_mul, is_div, mult },
        ) in zip(local.values, prep_local.accesses)
        {
            let in1 = vals.in1.as_extension::<AB>();
            let in2 = vals.in2.as_extension::<AB>();
            let out = vals.out.as_extension::<AB>();

            // Check exactly one flag is enabled.
            let is_real = is_add + is_sub + is_mul + is_div;
            builder.assert_bool(is_real.clone());

            builder.when(is_add).assert_ext_eq(in1.clone() + in2.clone(), out.clone());
            builder.when(is_sub).assert_ext_eq(in1.clone(), in2.clone() + out.clone());
            builder.when(is_mul).assert_ext_eq(in1.clone() * in2.clone(), out.clone());
            builder.when(is_div).assert_ext_eq(in1, in2 * out);

            // Read the inputs from memory.
            builder.receive_block(addrs.in1, vals.in1, is_real.clone());

            builder.receive_block(addrs.in2, vals.in2, is_real);

            // Write the output to memory.
            builder.send_block(addrs.out, vals.out, mult);
        }
    }
}

#[cfg(test)]
mod tests {
    use machine::tests::run_recursion_test_machines;
    use p3_baby_bear::BabyBear;
    use p3_field::{extension::BinomialExtensionField, AbstractExtensionField, AbstractField};
    use p3_matrix::dense::RowMajorMatrix;

    use rand::{rngs::StdRng, Rng, SeedableRng};
    use sp1_stark::StarkGenericConfig;
    use stark::BabyBearPoseidon2Outer;

    use super::*;

    use crate::runtime::instruction as instr;

    #[test]
    fn generate_trace() {
        type F = BabyBear;

        let shard = ExecutionRecord {
            ext_alu_events: vec![ExtAluIo {
                out: F::one().into(),
                in1: F::one().into(),
                in2: F::one().into(),
            }],
            ..Default::default()
        };
        let chip = ExtAluChip;
        let trace: RowMajorMatrix<F> = chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    pub fn four_ops() {
        type SC = BabyBearPoseidon2Outer;
        type F = <SC as StarkGenericConfig>::Val;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut random_extfelt = move || {
            let inner: [F; 4] = core::array::from_fn(|_| rng.sample(rand::distributions::Standard));
            BinomialExtensionField::<F, D>::from_base_slice(&inner)
        };
        let mut addr = 0;

        let instructions = (0..1000)
            .flat_map(|_| {
                let quot = random_extfelt();
                let in2 = random_extfelt();
                let in1 = in2 * quot;
                let alloc_size = 6;
                let a = (0..alloc_size).map(|x| x + addr).collect::<Vec<_>>();
                addr += alloc_size;
                [
                    instr::mem_ext(MemAccessKind::Write, 4, a[0], in1),
                    instr::mem_ext(MemAccessKind::Write, 4, a[1], in2),
                    instr::ext_alu(ExtAluOpcode::AddE, 1, a[2], a[0], a[1]),
                    instr::mem_ext(MemAccessKind::Read, 1, a[2], in1 + in2),
                    instr::ext_alu(ExtAluOpcode::SubE, 1, a[3], a[0], a[1]),
                    instr::mem_ext(MemAccessKind::Read, 1, a[3], in1 - in2),
                    instr::ext_alu(ExtAluOpcode::MulE, 1, a[4], a[0], a[1]),
                    instr::mem_ext(MemAccessKind::Read, 1, a[4], in1 * in2),
                    instr::ext_alu(ExtAluOpcode::DivE, 1, a[5], a[0], a[1]),
                    instr::mem_ext(MemAccessKind::Read, 1, a[5], quot),
                ]
            })
            .collect::<Vec<Instruction<F>>>();

        let program = RecursionProgram { instructions, ..Default::default() };

        run_recursion_test_machines(program);
    }
}
