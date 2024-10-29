use core::borrow::Borrow;
use p3_air::{Air, BaseAir, PairBuilder};
use p3_field::AbstractField;
use p3_field::{Field, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::*;
use sp1_core_machine::utils::next_power_of_two;
use sp1_derive::AlignedBorrow;
use sp1_stark::air::MachineAir;
use std::borrow::BorrowMut;

use crate::{builder::SP1RecursionAirBuilder, *};

#[derive(Default)]
pub struct SelectChip;

pub const SELECT_COLS: usize = core::mem::size_of::<SelectCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct SelectCols<F: Copy> {
    pub vals: SelectIo<F>,
}

pub const SELECT_PREPROCESSED_COLS: usize = core::mem::size_of::<SelectPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct SelectPreprocessedCols<F: Copy> {
    pub is_real: F,
    pub addrs: SelectIo<Address<F>>,
    pub mult1: F,
    pub mult2: F,
}

impl<F: Field> BaseAir<F> for SelectChip {
    fn width(&self) -> usize {
        SELECT_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for SelectChip {
    type Record = ExecutionRecord<F>;

    type Program = crate::RecursionProgram<F>;

    fn name(&self) -> String {
        "Select".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        SELECT_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let instrs = program
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instruction::Select(x) => Some(x),
                _ => None,
            })
            .collect::<Vec<_>>();

        let nb_rows = instrs.len();
        let fixed_log2_rows = program.fixed_log2_rows(self);
        let padded_nb_rows = match fixed_log2_rows {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(nb_rows, None),
        };
        let mut values = vec![F::zero(); padded_nb_rows * SELECT_PREPROCESSED_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = instrs.len() * SELECT_PREPROCESSED_COLS;
        values[..populate_len].par_chunks_mut(SELECT_PREPROCESSED_COLS).zip_eq(instrs).for_each(
            |(row, instr)| {
                let SelectInstr { addrs, mult1, mult2 } = instr;
                let access: &mut SelectPreprocessedCols<_> = row.borrow_mut();
                *access = SelectPreprocessedCols {
                    is_real: F::one(),
                    addrs: addrs.to_owned(),
                    mult1: mult1.to_owned(),
                    mult2: mult2.to_owned(),
                };
            },
        );

        // Convert the trace to a row major matrix.
        Some(RowMajorMatrix::new(values, SELECT_PREPROCESSED_COLS))
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn generate_trace(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = &input.select_events;
        let nb_rows = events.len();
        let fixed_log2_rows = input.fixed_log2_rows(self);
        let padded_nb_rows = match fixed_log2_rows {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(nb_rows, None),
        };
        let mut values = vec![F::zero(); padded_nb_rows * SELECT_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = events.len() * SELECT_COLS;
        values[..populate_len].par_chunks_mut(SELECT_COLS).zip_eq(events).for_each(
            |(row, &vals)| {
                let cols: &mut SelectCols<_> = row.borrow_mut();
                *cols = SelectCols { vals };
            },
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, SELECT_COLS)
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<AB> Air<AB> for SelectChip
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &SelectCols<AB::Var> = (*local).borrow();
        let prep = builder.preprocessed();
        let prep_local = prep.row_slice(0);
        let prep_local: &SelectPreprocessedCols<AB::Var> = (*prep_local).borrow();

        builder.receive_single(prep_local.addrs.bit, local.vals.bit, prep_local.is_real);
        builder.receive_single(prep_local.addrs.in1, local.vals.in1, prep_local.is_real);
        builder.receive_single(prep_local.addrs.in2, local.vals.in2, prep_local.is_real);
        builder.send_single(prep_local.addrs.out1, local.vals.out1, prep_local.mult1);
        builder.send_single(prep_local.addrs.out2, local.vals.out2, prep_local.mult2);
        builder.assert_eq(
            local.vals.out1,
            local.vals.bit * local.vals.in2 + (AB::Expr::one() - local.vals.bit) * local.vals.in1,
        );
        builder.assert_eq(
            local.vals.out2,
            local.vals.bit * local.vals.in1 + (AB::Expr::one() - local.vals.bit) * local.vals.in2,
        );
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
            select_events: vec![
                SelectIo {
                    bit: F::one(),
                    out1: F::from_canonical_u32(5),
                    out2: F::from_canonical_u32(3),
                    in1: F::from_canonical_u32(3),
                    in2: F::from_canonical_u32(5),
                },
                SelectIo {
                    bit: F::zero(),
                    out1: F::from_canonical_u32(5),
                    out2: F::from_canonical_u32(3),
                    in1: F::from_canonical_u32(5),
                    in2: F::from_canonical_u32(3),
                },
            ],
            ..Default::default()
        };
        let chip = SelectChip;
        let trace: RowMajorMatrix<F> = chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }

    #[test]
    pub fn prove_select() {
        type SC = BabyBearPoseidon2;
        type F = <SC as StarkGenericConfig>::Val;

        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let mut addr = 0;

        let instructions = (0..1000)
            .flat_map(|_| {
                let in1: F = rng.sample(rand::distributions::Standard);
                let in2: F = rng.sample(rand::distributions::Standard);
                let bit = F::from_bool(rng.gen_bool(0.5));
                assert_eq!(bit * (bit - F::one()), F::zero());

                let (out1, out2) = if bit == F::one() { (in2, in1) } else { (in1, in2) };
                let alloc_size = 5;
                let a = (0..alloc_size).map(|x| x + addr).collect::<Vec<_>>();
                addr += alloc_size;
                [
                    instr::mem_single(MemAccessKind::Write, 1, a[0], bit),
                    instr::mem_single(MemAccessKind::Write, 1, a[3], in1),
                    instr::mem_single(MemAccessKind::Write, 1, a[4], in2),
                    instr::select(1, 1, a[0], a[1], a[2], a[3], a[4]),
                    instr::mem_single(MemAccessKind::Read, 1, a[1], out1),
                    instr::mem_single(MemAccessKind::Read, 1, a[2], out2),
                ]
            })
            .collect::<Vec<Instruction<F>>>();

        let program = RecursionProgram { instructions, ..Default::default() };

        run_recursion_test_machines(program);
    }
}
