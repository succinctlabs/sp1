use std::borrow::{Borrow, BorrowMut};

use itertools::Itertools;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_core::air::{BaseAirBuilder, MachineAir};
use sp1_core::utils::pad_rows_fixed;
use sp1_derive::AlignedBorrow;

use crate::air::{MultiBuilder, SP1RecursionAirBuilder};
use crate::fri_fold::{FriFoldChip, FriFoldCols};
use crate::poseidon2::{Poseidon2Chip, Poseidon2Cols};
use crate::runtime::{ExecutionRecord, RecursionProgram};

pub const NUM_MULTI_COLS: usize = core::mem::size_of::<MultiCols<u8>>();

#[derive(Default)]
pub struct MultiChip<const DEGREE: usize> {
    pub fixed_log2_rows: Option<usize>,
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct MultiCols<T: Copy> {
    pub instruction: InstructionSpecificCols<T>,

    pub is_fri_fold: T,
    pub fri_fold_receive_table: T,
    pub fri_fold_memory_access: T,

    pub is_poseidon2: T,
    pub poseidon2_receive_table: T,
    pub poseidon2_memory_access: T,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub union InstructionSpecificCols<T: Copy> {
    fri_fold: FriFoldCols<T>,
    poseidon2: Poseidon2Cols<T>,
}

impl<F, const DEGREE: usize> BaseAir<F> for MultiChip<DEGREE> {
    fn width(&self) -> usize {
        NUM_MULTI_COLS
    }
}

impl<F: PrimeField32, const DEGREE: usize> MachineAir<F> for MultiChip<DEGREE> {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "Multi".to_string()
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        output: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let fri_fold_chip = FriFoldChip::<3>::default();
        let poseidon2 = Poseidon2Chip::default();
        let fri_fold_trace = fri_fold_chip.generate_trace(input, output);
        let mut poseidon2_trace = poseidon2.generate_trace(input, output);

        let mut rows = fri_fold_trace
            .clone()
            .rows_mut()
            .chain(poseidon2_trace.rows_mut())
            .enumerate()
            .map(|(i, instruction_row)| {
                let mut row = [F::zero(); NUM_MULTI_COLS];
                row[0..instruction_row.len()].copy_from_slice(instruction_row);
                let cols: &mut MultiCols<F> = row.as_mut_slice().borrow_mut();
                if i < fri_fold_trace.height() {
                    cols.is_fri_fold = F::one();

                    let fri_fold_cols = *cols.fri_fold();
                    cols.fri_fold_receive_table =
                        FriFoldChip::<3>::do_receive_table(&fri_fold_cols);
                    cols.fri_fold_memory_access =
                        FriFoldChip::<3>::do_memory_access(&fri_fold_cols);
                } else {
                    cols.is_poseidon2 = F::one();

                    let poseidon2_cols = *cols.poseidon2();
                    cols.poseidon2_receive_table = Poseidon2Chip::do_receive_table(&poseidon2_cols);
                    cols.poseidon2_memory_access = Poseidon2Chip::do_memory_access(&poseidon2_cols);
                }
                row
            })
            .collect_vec();

        // Pad the trace to a power of two.
        pad_rows_fixed(
            &mut rows,
            || [F::zero(); NUM_MULTI_COLS],
            self.fixed_log2_rows,
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect(), NUM_MULTI_COLS)
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }
}

impl<AB, const DEGREE: usize> Air<AB> for MultiChip<DEGREE>
where
    AB: SP1RecursionAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &MultiCols<AB::Var> = (*local).borrow();
        let next: &MultiCols<AB::Var> = (*next).borrow();

        // Add some dummy constraints to compress the interactions.
        let mut expr = local.is_fri_fold * local.is_fri_fold;
        for _ in 0..(DEGREE - 2) {
            expr *= local.is_fri_fold.into();
        }
        builder.assert_eq(expr.clone(), expr.clone());

        let next_is_real = next.is_fri_fold + next.is_poseidon2;
        let local_is_real = local.is_fri_fold + local.is_poseidon2;

        // Assert that is_fri_fold and is_poseidon2 are bool and that at most one is set.
        builder.assert_bool(local.is_fri_fold);
        builder.assert_bool(local.is_poseidon2);
        builder.assert_bool(local_is_real.clone());

        // Fri fold requires that it's rows are contiguous, since each invocation spans multiple rows
        // and it's AIR checks for consistencies among them.  The following constraints enforce that
        // all the fri fold rows are first, then the posiedon2 rows, and finally any padded (non-real) rows.

        // First verify that all real rows are contiguous.
        builder.when_first_row().assert_one(local_is_real.clone());
        builder
            .when_transition()
            .when_not(local_is_real.clone())
            .assert_zero(next_is_real.clone());

        // Next, verify that all fri fold rows are before the poseidon2 rows within the real rows section.
        builder.when_first_row().assert_one(local.is_fri_fold);
        builder
            .when_transition()
            .when(next_is_real)
            .when(local.is_poseidon2)
            .assert_one(next.is_poseidon2);

        let mut sub_builder =
            MultiBuilder::new(builder, local.is_fri_fold.into(), next.is_fri_fold.into());

        let fri_columns_local = local.fri_fold();
        sub_builder.assert_eq(
            local.is_fri_fold * FriFoldChip::<3>::do_memory_access::<AB::Var>(fri_columns_local),
            local.fri_fold_memory_access,
        );
        sub_builder.assert_eq(
            local.is_fri_fold * FriFoldChip::<3>::do_receive_table::<AB::Var>(fri_columns_local),
            local.fri_fold_receive_table,
        );

        let fri_fold_chip = FriFoldChip::<3>::default();
        fri_fold_chip.eval_fri_fold(
            &mut sub_builder,
            local.fri_fold(),
            next.fri_fold(),
            local.fri_fold_receive_table,
            local.fri_fold_memory_access,
        );

        let mut sub_builder =
            MultiBuilder::new(builder, local.is_poseidon2.into(), next.is_poseidon2.into());

        let poseidon2_columns = local.poseidon2();
        sub_builder.assert_eq(
            local.is_poseidon2 * Poseidon2Chip::do_receive_table::<AB::Var>(poseidon2_columns),
            local.poseidon2_receive_table,
        );
        sub_builder.assert_eq(
            local.is_poseidon2
                * Poseidon2Chip::do_memory_access::<AB::Var, AB::Expr>(poseidon2_columns),
            local.poseidon2_memory_access,
        );

        let poseidon2_chip = Poseidon2Chip::default();
        poseidon2_chip.eval_poseidon2(
            &mut sub_builder,
            local.poseidon2(),
            next.poseidon2(),
            local.poseidon2_receive_table,
            local.poseidon2_memory_access.into(),
        );
    }
}
// SAFETY: Each view is a valid interpretation of the underlying array.
impl<T: Copy> MultiCols<T> {
    pub fn fri_fold(&self) -> &FriFoldCols<T> {
        unsafe { &self.instruction.fri_fold }
    }

    pub fn poseidon2(&self) -> &Poseidon2Cols<T> {
        unsafe { &self.instruction.poseidon2 }
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use std::time::Instant;

    use p3_baby_bear::BabyBear;
    use p3_baby_bear::DiffusionMatrixBabyBear;
    use p3_field::AbstractField;
    use p3_matrix::{dense::RowMajorMatrix, Matrix};
    use p3_poseidon2::Poseidon2;
    use p3_poseidon2::Poseidon2ExternalMatrixGeneral;
    use sp1_core::stark::StarkGenericConfig;
    use sp1_core::utils::inner_perm;
    use sp1_core::{
        air::MachineAir,
        utils::{uni_stark_prove, uni_stark_verify, BabyBearPoseidon2},
    };

    use crate::multi::MultiChip;
    use crate::{poseidon2::Poseidon2Event, runtime::ExecutionRecord};
    use p3_symmetric::Permutation;

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::compressed();
        let mut challenger = config.challenger();

        let chip = MultiChip::<5> {
            fixed_log2_rows: None,
        };

        let test_inputs = (0..16)
            .map(|i| [BabyBear::from_canonical_u32(i); 16])
            .collect_vec();

        let gt: Poseidon2<
            BabyBear,
            Poseidon2ExternalMatrixGeneral,
            DiffusionMatrixBabyBear,
            16,
            7,
        > = inner_perm();

        let expected_outputs = test_inputs
            .iter()
            .map(|input| gt.permute(*input))
            .collect::<Vec<_>>();

        let mut input_exec = ExecutionRecord::<BabyBear>::default();
        for (input, output) in test_inputs.into_iter().zip_eq(expected_outputs) {
            input_exec
                .poseidon2_events
                .push(Poseidon2Event::dummy_from_input(input, output));
        }
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&input_exec, &mut ExecutionRecord::<BabyBear>::default());
        println!(
            "trace dims is width: {:?}, height: {:?}",
            trace.width(),
            trace.height()
        );

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
