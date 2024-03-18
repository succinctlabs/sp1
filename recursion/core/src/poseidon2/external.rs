use core::borrow::Borrow;
use core::mem::size_of;
use p3_air::AirBuilder;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use sp1_core::air::{MachineAir, SP1AirBuilder};
use sp1_core::utils::pad_to_power_of_two;
use sp1_core::utils::poseidon2_instance::RC_16_30_U32;
use sp1_derive::AlignedBorrow;
use std::borrow::BorrowMut;
use tracing::instrument;

use crate::runtime::ExecutionRecord;

use super::{apply_m_4, matmul_internal, MATRIX_DIAG_16_BABYBEAR_U32};

/// The number of main trace columns for `AddChip`.
pub const NUM_POSEIDON2_COLS: usize = size_of::<Poseidon2Cols<u8>>();

/// The width of the permutation.
pub const WIDTH: usize = 16;

/// A chip that implements addition for the opcode ADD.
#[derive(Default)]
pub struct Poseidon2Chip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2Cols<T> {
    pub input: [T; WIDTH],
    pub rounds: [T; 31],
    pub add_rc: [T; WIDTH],
    pub sbox_deg_3: [T; WIDTH],
    pub sbox_deg_7: [T; WIDTH],
    pub output: [T; WIDTH],
    pub is_initial: T,
    pub is_internal: T,
    pub is_external: T,
}

impl<F: PrimeField32> MachineAir<F> for Poseidon2Chip {
    type Record = ExecutionRecord<F>;

    fn name(&self) -> String {
        "Poseidon2".to_string()
    }

    #[instrument(name = "generate poseidon2 trace", level = "debug", skip_all)]
    fn generate_trace(
        &self,
        _: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let mut input = [F::one(); WIDTH];
        let rows = (0..128)
            .map(|i| {
                let mut row = [F::zero(); NUM_POSEIDON2_COLS];
                let cols: &mut Poseidon2Cols<F> = row.as_mut_slice().borrow_mut();
                cols.input = input;

                let r = i % 31;
                let rounds_f = 8;
                let rounds_p = 22;
                let rounds = rounds_f + rounds_p;
                let rounds_f_beginning = rounds_f / 2;
                let p_end = rounds_f_beginning + rounds_p;

                cols.rounds[r] = F::one();
                let is_initial_layer = r == 0;
                let is_external_layer = r != 0
                    && (((r - 1) < rounds_f_beginning) || (p_end <= (r - 1) && (r - 1) < rounds));

                if is_initial_layer {
                    // Mark the selector as initial.
                    cols.is_initial = F::one();

                    // Don't apply the round constants.
                    cols.add_rc.copy_from_slice(&cols.input);
                } else if is_external_layer {
                    // Mark the selector as external.
                    cols.is_external = F::one();

                    // Apply the round constants.
                    for j in 0..WIDTH {
                        cols.add_rc[j] =
                            cols.input[j] + F::from_wrapped_u32(RC_16_30_U32[r - 1][j]);
                    }
                } else {
                    // Mark the selector as internal.
                    cols.is_internal = F::one();

                    // Apply the round constants only on the first element.
                    cols.add_rc.copy_from_slice(&cols.input);
                    cols.add_rc[0] = cols.input[0] + F::from_wrapped_u32(RC_16_30_U32[r - 1][0]);
                };

                // Apply the sbox.
                for j in 0..WIDTH {
                    cols.sbox_deg_3[j] = cols.add_rc[j] * cols.add_rc[j] * cols.add_rc[j];
                    cols.sbox_deg_7[j] = cols.sbox_deg_3[j] * cols.sbox_deg_3[j] * cols.add_rc[j];
                }

                // What state to use for the linear layer.
                let mut state = if is_initial_layer {
                    cols.add_rc
                } else if is_external_layer {
                    cols.sbox_deg_7
                } else {
                    let mut state = cols.add_rc;
                    state[0] = cols.sbox_deg_7[0];
                    state
                };

                // Apply either the external or internal linear layer.
                if cols.is_initial == F::one() || cols.is_external == F::one() {
                    for j in (0..WIDTH).step_by(4) {
                        apply_m_4(&mut state[j..j + 4]);
                    }
                    let sums: [F; 4] = core::array::from_fn(|k| {
                        (0..WIDTH).step_by(4).map(|j| state[j + k]).sum::<F>()
                    });
                    for j in 0..WIDTH {
                        state[j] += sums[j % 4];
                    }
                } else if cols.is_internal == F::one() {
                    let matmul_constants: [F; WIDTH] = MATRIX_DIAG_16_BABYBEAR_U32
                        .iter()
                        .map(|x| F::from_wrapped_u32(*x))
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap();
                    matmul_internal(&mut state, matmul_constants);
                }

                // Copy the state to the output.
                cols.output.copy_from_slice(&state);

                input = cols.output;

                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_POSEIDON2_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_POSEIDON2_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }
}

impl<F> BaseAir<F> for Poseidon2Chip {
    fn width(&self) -> usize {
        NUM_POSEIDON2_COLS
    }
}

impl<AB> Air<AB> for Poseidon2Chip
where
    AB: SP1AirBuilder,
{
    #[allow(clippy::needless_range_loop)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &Poseidon2Cols<AB::Var> = main.row_slice(0).borrow();

        let rounds_f = 8;
        let rounds_p = 22;
        let rounds = rounds_f + rounds_p;

        // Convert the u32 round constants to field elements.
        let constants: [[AB::F; WIDTH]; 30] = RC_16_30_U32
            .iter()
            .map(|round| round.map(AB::F::from_wrapped_u32))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Apply the round constants.
        //
        // Initial Layer: Don't apply the round constants.
        // External Layers: Apply the round constants.
        // Internal Layers: Only apply the round constants to the first element.
        for i in 0..WIDTH {
            let mut result: AB::Expr = local.input[i].into();
            for r in 0..rounds {
                if i == 0 {
                    result += local.rounds[r + 1]
                        * constants[r][i]
                        * (local.is_external + local.is_internal);
                } else {
                    result += local.rounds[r + 1] * constants[r][i] * local.is_external;
                }
            }
            builder.assert_eq(result, local.add_rc[i]);
        }

        // Apply the sbox.
        //
        // To differentiate between external and internal layers, we use a masking operation
        // to only apply the state change to the first element for internal layers.
        for i in 0..WIDTH {
            let sbox_deg_3 = local.add_rc[i] * local.add_rc[i] * local.add_rc[i];
            builder.assert_eq(sbox_deg_3, local.sbox_deg_3[i]);
            let sbox_deg_7 = local.sbox_deg_3[i] * local.sbox_deg_3[i] * local.add_rc[i];
            builder.assert_eq(sbox_deg_7, local.sbox_deg_7[i]);
        }
        let sbox_result: [AB::Expr; WIDTH] = local
            .sbox_deg_7
            .iter()
            .enumerate()
            .map(|(i, x)| {
                // The masked first result of the sbox.
                //
                // Initial Layer: Pass through the result of the round constant layer.
                // External Layer: Pass through the result of the sbox layer.
                // Internal Layer: Pass through the result of the sbox layer.
                if i == 0 {
                    local.is_initial * local.add_rc[i] + (AB::Expr::one() - local.is_initial) * *x
                }
                // The masked result of the rest of the sbox.
                //
                // Initial layer: Pass through the result of the round constant layer.
                // External layer: Pass through the result of the sbox layer.
                // Internal layer: Pass through the result of the round constant layer.
                else {
                    (local.is_initial + local.is_internal) * local.add_rc[i]
                        + (AB::Expr::one() - (local.is_initial + local.is_internal)) * *x
                }
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // EXTERNAL LAYER + INITIAL LAYER
        {
            // First, we apply M_4 to each consecutive four elements of the state.
            // In Appendix B's terminology, this replaces each x_i with x_i'.
            let mut state: [AB::Expr; WIDTH] = sbox_result.clone();
            for i in (0..WIDTH).step_by(4) {
                apply_m_4(&mut state[i..i + 4]);
            }

            // Now, we apply the outer circulant matrix (to compute the y_i values).
            //
            // We first precompute the four sums of every four elements.
            let sums: [AB::Expr; 4] = core::array::from_fn(|k| {
                (0..WIDTH)
                    .step_by(4)
                    .map(|j| state[j + k].clone())
                    .sum::<AB::Expr>()
            });

            // The formula for each y_i involves 2x_i' term and x_j' terms for each j that equals i mod 4.
            // In other words, we can add a single copy of x_i' to the appropriate one of our precomputed sums.
            for i in 0..WIDTH {
                state[i] += sums[i % 4].clone();
                builder
                    .when(local.is_external + local.is_initial)
                    .assert_eq(state[i].clone(), local.output[i]);
            }
        }

        // INTERNAL LAYER
        {
            // Use a simple matrix multiplication as the permutation.
            let mut state: [AB::Expr; WIDTH] = sbox_result.clone();
            let matmul_constants: [<<AB as AirBuilder>::Expr as AbstractField>::F; WIDTH] =
                MATRIX_DIAG_16_BABYBEAR_U32
                    .iter()
                    .map(|x| <<AB as AirBuilder>::Expr as AbstractField>::F::from_wrapped_u32(*x))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
            matmul_internal(&mut state, matmul_constants);
            for i in 0..WIDTH {
                builder
                    .when(local.is_internal)
                    .assert_eq(state[i].clone(), local.output[i]);
            }
        }

        // Range check all flags.
        for i in 0..local.rounds.len() {
            builder.assert_bool(local.rounds[i]);
        }
        builder.assert_bool(local.is_initial);
        builder.assert_bool(local.is_external);
        builder.assert_bool(local.is_internal);
        builder.assert_bool(local.is_initial + local.is_external + local.is_internal);

        // Constrain the initial flag.
        builder.assert_eq(local.is_initial, local.rounds[0]);

        // Constrain the external flag.
        let is_external_first_half = (0..4).map(|i| local.rounds[i + 1].into()).sum::<AB::Expr>();
        let is_external_second_half = (26..30)
            .map(|i| local.rounds[i + 1].into())
            .sum::<AB::Expr>();
        builder.assert_eq(
            local.is_external,
            is_external_first_half + is_external_second_half,
        );

        // Constrain the internal flag.
        let is_internal = (4..26)
            .map(|i| local.rounds[i + 1].into())
            .sum::<AB::Expr>();
        builder.assert_eq(local.is_internal, is_internal);
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::BorrowMut;

    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_poseidon2::{DiffusionMatrixBabybear, Poseidon2};
    use p3_symmetric::Permutation;
    use sp1_core::{
        air::MachineAir,
        utils::{poseidon2_instance::RC_16_30, uni_stark_prove, BabyBearPoseidon2, StarkUtils},
    };

    use crate::poseidon2::external::WIDTH;
    use crate::{poseidon2::external::Poseidon2Chip, runtime::ExecutionRecord};

    use super::{Poseidon2Cols, NUM_POSEIDON2_COLS};

    #[test]
    fn generate_trace() {
        let chip = Poseidon2Chip;
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(
            &ExecutionRecord::<BabyBear>::default(),
            &mut ExecutionRecord::<BabyBear>::default(),
        );
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new();
        let mut challenger = config.challenger();

        let chip = Poseidon2Chip;
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(
            &ExecutionRecord::<BabyBear>::default(),
            &mut ExecutionRecord::<BabyBear>::default(),
        );

        let gt: Poseidon2<BabyBear, DiffusionMatrixBabybear, 16, 7> =
            Poseidon2::new(8, 22, RC_16_30.to_vec(), DiffusionMatrixBabybear);
        let input = [BabyBear::one(); WIDTH];
        let output = gt.permute(input);

        let mut row: [BabyBear; NUM_POSEIDON2_COLS] = trace.values
            [NUM_POSEIDON2_COLS * 30..(NUM_POSEIDON2_COLS) * 31]
            .try_into()
            .unwrap();
        let cols: &mut Poseidon2Cols<BabyBear> = row.as_mut_slice().borrow_mut();
        assert_eq!(cols.output, output);

        uni_stark_prove(&config, &chip, &mut challenger, trace);
    }
}
