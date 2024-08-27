use std::{
    array,
    borrow::{Borrow, BorrowMut},
    cmp::max,
    ops::Deref,
};

use itertools::Itertools;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_machine::utils::pad_rows_fixed;
use sp1_derive::AlignedBorrow;
use sp1_stark::air::{BaseAirBuilder, MachineAir};

use crate::{
    air::{MultiBuilder, SP1RecursionAirBuilder},
    fri_fold::{FriFoldChip, FriFoldCols},
    poseidon2_wide::{columns::Poseidon2, Poseidon2WideChip, WIDTH},
    runtime::{ExecutionRecord, RecursionProgram},
};

pub const NUM_MULTI_COLS: usize = core::mem::size_of::<MultiCols<u8>>();

#[derive(Default)]
pub struct MultiChip<const DEGREE: usize> {
    pub fixed_log2_rows: Option<usize>,
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct MultiCols<T: Copy> {
    pub is_fri_fold: T,

    /// Rows that needs to receive a fri_fold syscall.
    pub fri_fold_receive_table: T,
    /// Rows that needs to access memory.
    pub fri_fold_memory_access: T,

    pub is_poseidon2: T,

    /// A flag column to indicate whether the row is the first poseidon2 row.
    pub poseidon2_first_row: T,
    /// A flag column to indicate whether the row is the last poseidon2 row.
    pub poseidon2_last_row: T,

    /// Similar for Fri_fold.
    pub fri_fold_last_row: T,

    /// Rows that needs to receive a poseidon2 syscall.
    pub poseidon2_receive_table: T,
    /// Hash/Permute state entries that needs to access memory.  This is for the the first half of
    /// the permute state.
    pub poseidon2_1st_half_memory_access: [T; WIDTH / 2],
    /// Flag to indicate if all of the second half of a compress state needs to access memory.
    pub poseidon2_2nd_half_memory_access: T,
    /// Rows that need to send a range check.
    pub poseidon2_send_range_check: T,
}

impl<F, const DEGREE: usize> BaseAir<F> for MultiChip<DEGREE> {
    fn width(&self) -> usize {
        let fri_fold_width = Self::fri_fold_width::<F>();
        let poseidon2_width = Self::poseidon2_width::<F>();

        max(fri_fold_width, poseidon2_width) + NUM_MULTI_COLS
    }
}

impl<F: PrimeField32, const DEGREE: usize> MachineAir<F> for MultiChip<DEGREE> {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "Multi".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        output: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let fri_fold_chip = FriFoldChip::<DEGREE> { fixed_log2_rows: None, pad: false };
        let poseidon2 = Poseidon2WideChip::<DEGREE> { fixed_log2_rows: None, pad: false };
        let fri_fold_trace = fri_fold_chip.generate_trace(input, output);
        let mut poseidon2_trace = poseidon2.generate_trace(input, output);

        let fri_fold_height = fri_fold_trace.height();
        let poseidon2_height = poseidon2_trace.height();

        let num_columns = <MultiChip<DEGREE> as BaseAir<F>>::width(self);

        let mut rows = fri_fold_trace
            .clone()
            .rows_mut()
            .chain(poseidon2_trace.rows_mut())
            .enumerate()
            .map(|(i, instruction_row)| {
                let process_fri_fold = i < fri_fold_trace.height();

                let mut row = vec![F::zero(); num_columns];
                row[NUM_MULTI_COLS..NUM_MULTI_COLS + instruction_row.len()]
                    .copy_from_slice(instruction_row);

                if process_fri_fold {
                    let multi_cols: &mut MultiCols<F> = row[0..NUM_MULTI_COLS].borrow_mut();
                    multi_cols.is_fri_fold = F::one();

                    let fri_fold_cols: &FriFoldCols<F> = (*instruction_row).borrow();
                    multi_cols.fri_fold_receive_table =
                        FriFoldChip::<DEGREE>::do_receive_table(fri_fold_cols);
                    multi_cols.fri_fold_memory_access =
                        FriFoldChip::<DEGREE>::do_memory_access(fri_fold_cols);
                    if i == fri_fold_trace.height() - 1 {
                        multi_cols.fri_fold_last_row = F::one();
                    }
                } else {
                    let multi_cols: &mut MultiCols<F> = row[0..NUM_MULTI_COLS].borrow_mut();
                    multi_cols.is_poseidon2 = F::one();

                    let poseidon2_cols = Poseidon2WideChip::<DEGREE>::convert::<F>(instruction_row);
                    multi_cols.poseidon2_receive_table =
                        poseidon2_cols.control_flow().is_syscall_row;
                    multi_cols.poseidon2_1st_half_memory_access =
                        array::from_fn(|i| poseidon2_cols.memory().memory_slot_used[i]);
                    multi_cols.poseidon2_2nd_half_memory_access =
                        poseidon2_cols.control_flow().is_compress;
                    multi_cols.poseidon2_send_range_check = poseidon2_cols.control_flow().is_absorb;

                    // The first row of the poseidon2 trace has index fri_fold_trace.height()
                    multi_cols.poseidon2_first_row = F::from_bool(i == fri_fold_height);
                    multi_cols.poseidon2_last_row =
                        F::from_bool(i == fri_fold_height + poseidon2_height - 1);
                }

                row
            })
            .collect_vec();

        // Pad the trace to a power of two.
        pad_rows_fixed(&mut rows, || vec![F::zero(); num_columns], self.fixed_log2_rows);

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect(), num_columns)
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }
}

impl<AB, const DEGREE: usize> Air<AB> for MultiChip<DEGREE>
where
    AB: SP1RecursionAirBuilder,
    AB::Var: 'static,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));

        let local_slice: &[<AB as p3_air::AirBuilder>::Var] = &local;
        let next_slice: &[<AB as p3_air::AirBuilder>::Var] = &next;
        let local_multi_cols: &MultiCols<AB::Var> = local_slice[0..NUM_MULTI_COLS].borrow();
        let next_multi_cols: &MultiCols<AB::Var> = next_slice[0..NUM_MULTI_COLS].borrow();

        // Dummy constraints to normalize to DEGREE.
        let lhs = (0..DEGREE).map(|_| local_multi_cols.is_poseidon2.into()).product::<AB::Expr>();
        let rhs = (0..DEGREE).map(|_| local_multi_cols.is_poseidon2.into()).product::<AB::Expr>();
        builder.assert_eq(lhs, rhs);

        let next_is_real = next_multi_cols.is_fri_fold + next_multi_cols.is_poseidon2;
        let local_is_real = local_multi_cols.is_fri_fold + local_multi_cols.is_poseidon2;

        // Assert that is_fri_fold and is_poseidon2 are bool and that at most one is set.
        builder.assert_bool(local_multi_cols.is_fri_fold);
        builder.assert_bool(local_multi_cols.is_poseidon2);
        builder.assert_bool(local_is_real.clone());

        // Constrain the flags to be boolean.
        builder.assert_bool(local_multi_cols.poseidon2_first_row);
        builder.assert_bool(local_multi_cols.poseidon2_last_row);
        builder.assert_bool(local_multi_cols.fri_fold_last_row);

        // Constrain that the flags are computed correctly.
        builder.when_transition().assert_eq(
            local_multi_cols.is_fri_fold * (AB::Expr::one() - next_multi_cols.is_fri_fold),
            local_multi_cols.fri_fold_last_row,
        );
        builder
            .when_last_row()
            .assert_eq(local_multi_cols.is_fri_fold, local_multi_cols.fri_fold_last_row);
        builder
            .when_first_row()
            .assert_eq(local_multi_cols.is_poseidon2, local_multi_cols.poseidon2_first_row);
        builder.when_transition().assert_eq(
            next_multi_cols.poseidon2_first_row,
            local_multi_cols.is_fri_fold * next_multi_cols.is_poseidon2,
        );
        builder.when_transition().assert_eq(
            local_multi_cols.is_poseidon2 * (AB::Expr::one() - next_multi_cols.is_poseidon2),
            local_multi_cols.poseidon2_last_row,
        );
        builder
            .when_last_row()
            .assert_eq(local_multi_cols.is_poseidon2, local_multi_cols.poseidon2_last_row);

        // Fri fold requires that it's rows are contiguous, since each invocation spans multiple
        // rows and it's AIR checks for consistencies among them.  The following constraints
        // enforce that all the fri fold rows are first, then the posiedon2 rows, and
        // finally any padded (non-real) rows.

        // First verify that all real rows are contiguous.
        builder.when_transition().when_not(local_is_real.clone()).assert_zero(next_is_real.clone());

        // Next, verify that all fri fold rows are before the poseidon2 rows within the real rows
        // section.
        builder
            .when_transition()
            .when(next_is_real)
            .when(local_multi_cols.is_poseidon2)
            .assert_one(next_multi_cols.is_poseidon2);

        let mut sub_builder = MultiBuilder::new(
            builder,
            local_multi_cols.is_fri_fold.into(),
            builder.is_first_row(),
            local_multi_cols.fri_fold_last_row.into(),
            next_multi_cols.is_fri_fold.into(),
        );

        let local_fri_fold_cols = Self::fri_fold(&local);
        let next_fri_fold_cols = Self::fri_fold(&next);

        sub_builder.assert_eq(
            local_multi_cols.is_fri_fold
                * FriFoldChip::<DEGREE>::do_memory_access::<AB::Var>(&local_fri_fold_cols),
            local_multi_cols.fri_fold_memory_access,
        );
        sub_builder.assert_eq(
            local_multi_cols.is_fri_fold
                * FriFoldChip::<DEGREE>::do_receive_table::<AB::Var>(&local_fri_fold_cols),
            local_multi_cols.fri_fold_receive_table,
        );

        let fri_fold_chip = FriFoldChip::<DEGREE>::default();
        fri_fold_chip.eval_fri_fold(
            &mut sub_builder,
            &local_fri_fold_cols,
            &next_fri_fold_cols,
            local_multi_cols.fri_fold_receive_table,
            local_multi_cols.fri_fold_memory_access,
        );

        let mut sub_builder = MultiBuilder::new(
            builder,
            local_multi_cols.is_poseidon2.into(),
            local_multi_cols.poseidon2_first_row.into(),
            local_multi_cols.poseidon2_last_row.into(),
            next_multi_cols.is_poseidon2.into(),
        );

        let poseidon2_columns = MultiChip::<DEGREE>::poseidon2(local_slice);
        sub_builder.assert_eq(
            local_multi_cols.is_poseidon2 * poseidon2_columns.control_flow().is_syscall_row,
            local_multi_cols.poseidon2_receive_table,
        );
        local_multi_cols.poseidon2_1st_half_memory_access.iter().enumerate().for_each(
            |(i, mem_access)| {
                sub_builder.assert_eq(
                    local_multi_cols.is_poseidon2 * poseidon2_columns.memory().memory_slot_used[i],
                    *mem_access,
                );
            },
        );

        sub_builder.assert_eq(
            local_multi_cols.is_poseidon2 * poseidon2_columns.control_flow().is_compress,
            local_multi_cols.poseidon2_2nd_half_memory_access,
        );

        sub_builder.assert_eq(
            local_multi_cols.is_poseidon2 * poseidon2_columns.control_flow().is_absorb,
            local_multi_cols.poseidon2_send_range_check,
        );

        let poseidon2_chip = Poseidon2WideChip::<DEGREE>::default();
        poseidon2_chip.eval_poseidon2(
            &mut sub_builder,
            poseidon2_columns.as_ref(),
            MultiChip::<DEGREE>::poseidon2(next_slice).as_ref(),
            local_multi_cols.poseidon2_receive_table,
            local_multi_cols.poseidon2_1st_half_memory_access,
            local_multi_cols.poseidon2_2nd_half_memory_access,
            local_multi_cols.poseidon2_send_range_check,
        );
    }
}

impl<const DEGREE: usize> MultiChip<DEGREE> {
    fn fri_fold_width<T>() -> usize {
        <FriFoldChip<DEGREE> as BaseAir<T>>::width(&FriFoldChip::<DEGREE>::default())
    }

    fn fri_fold<T: Copy>(row: &dyn Deref<Target = [T]>) -> FriFoldCols<T> {
        let row_slice: &[T] = row;
        let fri_fold_width = Self::fri_fold_width::<T>();
        let fri_fold_cols: &FriFoldCols<T> =
            (row_slice[NUM_MULTI_COLS..NUM_MULTI_COLS + fri_fold_width]).borrow();

        *fri_fold_cols
    }

    fn poseidon2_width<T>() -> usize {
        <Poseidon2WideChip<DEGREE> as BaseAir<T>>::width(&Poseidon2WideChip::<DEGREE>::default())
    }

    fn poseidon2<'a, T>(row: impl Deref<Target = [T]>) -> Box<dyn Poseidon2<'a, T> + 'a>
    where
        T: Copy + 'a,
    {
        let row_slice: &[T] = &row;
        let poseidon2_width = Self::poseidon2_width::<T>();

        Poseidon2WideChip::<DEGREE>::convert::<T>(
            &row_slice[NUM_MULTI_COLS..NUM_MULTI_COLS + poseidon2_width],
        )
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
    use p3_matrix::{dense::RowMajorMatrix, Matrix};
    use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
    use sp1_core_machine::utils::{uni_stark_prove, uni_stark_verify};
    use sp1_stark::{air::MachineAir, baby_bear_poseidon2::BabyBearPoseidon2, StarkGenericConfig};

    use crate::{
        multi::MultiChip, poseidon2_wide::tests::generate_test_execution_record,
        runtime::ExecutionRecord,
    };

    #[test]
    #[ignore]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::compressed();
        let mut challenger = config.challenger();

        let chip = MultiChip::<9> { fixed_log2_rows: None };

        let input_exec = generate_test_execution_record(false);
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&input_exec, &mut ExecutionRecord::<BabyBear>::default());
        println!("trace dims is width: {:?}, height: {:?}", trace.width(), trace.height());

        let start = Instant::now();
        let proof = uni_stark_prove(&config, &chip, &mut challenger, trace);
        let duration = start.elapsed().as_secs_f64();
        println!("proof duration = {:?}", duration);

        let mut challenger: p3_challenger::DuplexChallenger<
            BabyBear,
            Poseidon2<BabyBear, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>,
            16,
            8,
        > = config.challenger();
        let start = Instant::now();
        uni_stark_verify(&config, &chip, &mut challenger, &proof)
            .expect("expected proof to be valid");

        let duration = start.elapsed().as_secs_f64();
        println!("verify duration = {:?}", duration);
    }
}
