use std::{
    array,
    borrow::{Borrow, BorrowMut},
    cmp::max,
    ops::Deref,
};

use crate::{
    builder::SP1RecursionAirBuilder,
    chips::{alu_base::BaseAluChip, alu_ext::ExtAluChip},
    ExecutionRecord, ExtAluInstr, ExtAluOpcode, D,
};
use crate::{chips::poseidon2_skinny::Poseidon2SkinnyChip, Instruction};
use itertools::Itertools;
use p3_air::{Air, BaseAir, PairBuilder};
use p3_field::AbstractField;
use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_maybe_rayon::prelude::ParallelSliceMut;
use sp1_core_machine::utils::{next_power_of_two, pad_rows_fixed};
use sp1_derive::AlignedBorrow;
use sp1_stark::air::MachineAir;

use super::{
    alu_base::{BaseAluCols, BaseAluPreprocessedCols, NUM_BASE_ALU_PREPROCESSED_COLS},
    alu_ext::{
        ExtAluAccessCols, ExtAluCols, ExtAluPreprocessedCols, NUM_EXT_ALU_ACCESS_COLS,
        NUM_EXT_ALU_ENTRIES_PER_ROW, NUM_EXT_ALU_PREPROCESSED_COLS,
    },
    poseidon2_skinny::{
        columns::{preprocessed::Poseidon2PreprocessedCols, Poseidon2},
        trace::PREPROCESSED_POSEIDON2_WIDTH,
    },
};

pub const NUM_MULTI_COLS: usize = core::mem::size_of::<MultiCols<u8>>();
pub const NUM_MULTI_PREPROCESSED_COLS: usize = core::mem::size_of::<MultiPreprocessedCols<u8>>();

#[derive(Default)]
pub struct MultiChip;

impl MultiChip {
    fn p2_skinny_width<T>() -> usize {
        <Poseidon2SkinnyChip<9> as BaseAir<T>>::width(&Poseidon2SkinnyChip::default())
    }

    fn ext_alu_width<T>() -> usize {
        <ExtAluChip as BaseAir<T>>::width(&ExtAluChip { pad: true })
    }

    fn base_alu_width<T>() -> usize {
        <BaseAluChip as BaseAir<T>>::width(&BaseAluChip { pad: true })
    }
}

impl<F> BaseAir<F> for MultiChip {
    fn width(&self) -> usize {
        let p2_skinny_width = Self::p2_skinny_width::<F>();
        let ext_alu_width = Self::ext_alu_width::<F>();
        let base_alu_width = Self::base_alu_width::<F>();

        max(max(p2_skinny_width, ext_alu_width), base_alu_width) + NUM_MULTI_COLS
    }
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct MultiCols<T: Copy> {
    pub _marker: T,
}

fn preprocessed_width() -> usize {
    3 + max(PREPROCESSED_POSEIDON2_WIDTH, NUM_EXT_ALU_PREPROCESSED_COLS)
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct MultiPreprocessedCols<T: Copy> {
    pub is_p2_skinny: T,
    pub is_ext_alu: T,
    pub is_base_alu: T,
}

impl<F: PrimeField32 + BinomiallyExtendable<D>> MachineAir<F> for MultiChip {
    type Record = ExecutionRecord<F>;

    type Program = crate::RecursionProgram<F>;

    fn name(&self) -> String {
        "Multi".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        max(NUM_EXT_ALU_PREPROCESSED_COLS, PREPROCESSED_POSEIDON2_WIDTH) + 3
    }

    fn generate_preprocessed_trace(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let p2_skinny_chip = Poseidon2SkinnyChip::<9> { pad: false };
        let ext_alu_chip = ExtAluChip { pad: false };
        let base_alu_chip = BaseAluChip { pad: false };

        let p2_skinny_trace = p2_skinny_chip.generate_preprocessed_trace(program).unwrap();
        let mut ext_alu_trace = ext_alu_chip.generate_preprocessed_trace(program).unwrap();
        let mut base_alu_trace = base_alu_chip.generate_preprocessed_trace(program).unwrap();

        let p2_skinny_trace_height = p2_skinny_trace.height();
        let ext_alu_trace_height = ext_alu_trace.height();
        let base_alu_trace_height = base_alu_trace.height();

        let num_columns = preprocessed_width();

        let mut rows = p2_skinny_trace
            .clone()
            .rows_mut()
            .chain(ext_alu_trace.rows_mut())
            .chain(base_alu_trace.rows_mut())
            .enumerate()
            .map(|(i, instruction_row)| {
                let process_p2_skinny = i < p2_skinny_trace_height;
                let process_ext_alu =
                    !process_p2_skinny && i < ext_alu_trace_height + p2_skinny_trace_height;
                let process_base_alu = !process_p2_skinny
                    && !process_ext_alu
                    && i < base_alu_trace_height + ext_alu_trace_height + p2_skinny_trace_height;

                let mut row = vec![F::zero(); num_columns];
                // println!("instruction_row.len(): {}", instruction_row.len());
                // println!("NUM_MULTI_PREPROCESSED_COLS: {}", NUM_MULTI_PREPROCESSED_COLS);
                // println!("NUM_EXT_ALU_PREPROCESSED_COLS: {}", NUM_EXT_ALU_PREPROCESSED_COLS);
                // println!("PREPROCESSED_POSEIDON2_WIDTH: {}", PREPROCESSED_POSEIDON2_WIDTH);
                row[NUM_MULTI_PREPROCESSED_COLS
                    ..NUM_MULTI_PREPROCESSED_COLS + instruction_row.len()]
                    .copy_from_slice(instruction_row);

                let multi_cols: &mut MultiPreprocessedCols<_> =
                    row[0..NUM_MULTI_PREPROCESSED_COLS].borrow_mut();
                if process_p2_skinny {
                    multi_cols.is_p2_skinny = F::one();
                } else if process_ext_alu {
                    multi_cols.is_ext_alu = F::one();
                } else if process_base_alu {
                    multi_cols.is_base_alu = F::one();
                }

                row
            })
            .collect_vec();

        // Pad the trace to a power of two.
        pad_rows_fixed(&mut rows, || vec![F::zero(); num_columns], None);

        println!("preprocessed rows.len(): {}", rows.len());

        // Convert the trace to a row major matrix.
        Some(RowMajorMatrix::new(rows.into_iter().flatten().collect(), num_columns))
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn generate_trace(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        let p2_skinny_chip = Poseidon2SkinnyChip::<9> { pad: false };
        let ext_alu_chip = ExtAluChip { pad: false };
        let base_alu_chip = BaseAluChip { pad: false };

        let p2_skinny_trace = p2_skinny_chip.generate_trace(input, output);
        let mut ext_alu_trace = ext_alu_chip.generate_trace(input, output);
        let mut base_alu_trace = base_alu_chip.generate_trace(input, output);

        let num_columns = <MultiChip as BaseAir<F>>::width(self);

        let mut rows = p2_skinny_trace
            .clone()
            .rows_mut()
            .chain(ext_alu_trace.rows_mut())
            .chain(base_alu_trace.rows_mut())
            .enumerate()
            .map(|(i, instruction_row)| {
                let mut row = vec![F::zero(); num_columns];
                row[0..instruction_row.len()].copy_from_slice(instruction_row);
                row
            })
            .collect_vec();

        // Pad the trace to a power of two.
        pad_rows_fixed(&mut rows, || vec![F::zero(); num_columns], None);

        println!("main rows.len(): {}", rows.len());

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect(), num_columns)
    }

    fn included(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<AB> Air<AB> for MultiChip
where
    AB: SP1RecursionAirBuilder + PairBuilder,
    AB::Var: 'static,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let prep = builder.preprocessed();
        let (prep_local, prep_next) = (prep.row_slice(0), prep.row_slice(1));

        let local_p2_skinny_slice = &local[0..Self::p2_skinny_width::<AB::Var>()];
        let local_p2_skinny: &Poseidon2<AB::Var> = local_p2_skinny_slice.borrow();
        let next_p2_skinny_slice = &next[0..Self::p2_skinny_width::<AB::Var>()];
        let next_p2_skinny: &Poseidon2<AB::Var> = next_p2_skinny_slice.borrow();

        let local_ext_alu_slice = &local[0..Self::ext_alu_width::<AB::Var>()];
        let local_ext_alu: &ExtAluCols<AB::Var> = local_ext_alu_slice.borrow();

        let local_base_alu_slice = &local[0..Self::base_alu_width::<AB::Var>()];
        let local_base_alu: &BaseAluCols<AB::Var> = local_base_alu_slice.borrow();

        let prep_p2_skinny_slice =
            &prep_local[NUM_MULTI_COLS..NUM_MULTI_COLS + PREPROCESSED_POSEIDON2_WIDTH];
        let prep_p2_skinny: &Poseidon2PreprocessedCols<AB::Var> = prep_p2_skinny_slice.borrow();

        let prep_ext_alu_slice =
            &prep_local[NUM_MULTI_COLS..NUM_MULTI_COLS + NUM_EXT_ALU_PREPROCESSED_COLS];
        let prep_ext_alu: &ExtAluPreprocessedCols<AB::Var> = prep_ext_alu_slice.borrow();

        let prep_base_alu_slice =
            &prep_local[NUM_MULTI_COLS..NUM_MULTI_COLS + NUM_BASE_ALU_PREPROCESSED_COLS];
        let prep_base_alu: &BaseAluPreprocessedCols<AB::Var> = prep_base_alu_slice.borrow();

        // let local_multi_cols: &MultiCols<AB::Var> = (*local).borrow();
        let prep_multi_cols: &MultiPreprocessedCols<AB::Var> = (*prep_local).borrow();

        builder.assert_bool(prep_multi_cols.is_p2_skinny);
        builder.assert_bool(prep_multi_cols.is_ext_alu);

        let p2_skinny_chip = Poseidon2SkinnyChip::<9>::default();
        let ext_alu_chip = ExtAluChip::default();
        let base_alu_chip = BaseAluChip::default();

        p2_skinny_chip.eval_p2_skinny(builder, local_p2_skinny, prep_p2_skinny, next_p2_skinny);
        ext_alu_chip.eval_ext_alu(builder, local_ext_alu, prep_ext_alu);
        base_alu_chip.eval_base_alu(builder, local_base_alu, prep_base_alu);

        let mut one = AB::Expr::one();
        let mut expr = AB::Expr::one();
        for i in 0..9 {
            expr *= one.clone();
        }
        builder.assert_eq(expr.clone(), expr);

        // builder.when(prep_multi_cols.is_p2_skinny).eval_p2_skinny(builder, local_p2_skinny, prep_p2_skinny);
        // builder.when(prep_multi_cols.is_ext_alu).eval_ext_alu(builder, local_ext_alu, prep_ext_alu);
    }
}
