use core::borrow::Borrow;
use core::mem::size_of;
use std::borrow::BorrowMut;
use p3_air::{Air, BaseAir};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_core::air::{MachineAir, SP1AirBuilder};
use sp1_core::utils::pad_to_power_of_two;
use sp1_derive::AlignedBorrow;
use sp1_primitives::RC_16_30_U32;
use tracing::instrument;

use crate::poseidon2::{apply_m_4, external_linear_layer, internal_linear_layer};
use crate::runtime::{ExecutionRecord, RecursionProgram};

/// The number of main trace columns for `AddChip`.
pub const NUM_POSEIDON2_WIDE_COLS: usize = size_of::<Poseidon2WideCols<u8>>();

/// The width of the permutation.
pub const WIDTH: usize = 16;

pub const NUM_EXTERNAL_ROUNDS: usize = 8;
pub const NUM_INTERNAL_ROUNDS: usize = 22;
pub const NUM_ROUNDS: usize = NUM_EXTERNAL_ROUNDS + NUM_INTERNAL_ROUNDS;

/// A chip that implements addition for the opcode ADD.
#[derive(Default)]
pub struct Poseidon2WideChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2WideCols<T> {
    pub input: [T; WIDTH],
    pub output: [T; WIDTH],
    pub external_rounds: [Poseidon2WideExternalRoundCols<T>; NUM_EXTERNAL_ROUNDS],
    pub internal_rounds: [Poseidon2WideInternalRoundCols<T>; NUM_INTERNAL_ROUNDS],
}

// Columns required for external rounds
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
struct Poseidon2WideExternalRoundCols<T> {
    state: [T; WIDTH],
    sbox_deg_3: [T; WIDTH],
    sbox_deg_7: [T; WIDTH],
}

// Columns required for internal rounds
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
struct Poseidon2WideInternalRoundCols<T> {
    state: [T; WIDTH],
    sbox_deg_3: T,
    sbox_deg_7: T,
}

impl<F: PrimeField32> MachineAir<F> for Poseidon2WideChip {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "Poseidon2Wide".to_string()
    }

    #[instrument(name = "generate poseidon2 wide trace", level = "debug", skip_all)]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        for event in &input.poseidon2_events {
            let mut row = [F::zero(); NUM_POSEIDON2_WIDE_COLS];
            let cols: &mut Poseidon2WideCols<F> = row.as_mut_slice().borrow_mut();

            cols.input = event.input;

            // apply initial round
            external_linear_layer(&cols.input, &mut cols.external_rounds[0].state);

            // apply first half of external rounds 
            for r in 0..NUM_EXTERNAL_ROUNDS / 2 {
                Self::generate_external_round(cols, r);
            }

            // apply internal rounds
            for r in 0..NUM_INTERNAL_ROUNDS {
                Self::generate_internal_round(cols, r);
            }

            // apply second half of external rounds
            for r in NUM_EXTERNAL_ROUNDS / 2..NUM_EXTERNAL_ROUNDS {
                Self::generate_external_round(cols, r);
            }

            rows.push(row);
        }

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_POSEIDON2_WIDE_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_POSEIDON2_WIDE_COLS, F>(&mut trace.values);

        // println!(
        //     "poseidon2 wide trace dims is width: {:?}, height: {:?}",
        //     trace.width(),
        //     trace.height()
        // );

        trace
    }

    fn included(&self, record: &Self::Record) -> bool {
        !record.poseidon2_events.is_empty()
    }
}

impl Poseidon2WideChip {
    fn generate_external_round<F: PrimeField32>(cols: &mut Poseidon2WideCols<F>, r: usize) {
        let round_cols = cols.external_rounds[r].borrow();

        // rc
        // we don't need columns for the result of adding rc since the constraint is 
        // degree 1, so we can absorb this into the constraint for the x^3 part of the sbox
        let mut add_rc = round_cols.state.clone();
        for j in 0..WIDTH {
            add_rc[j] += F::from_wrapped_u32(RC_16_30_U32[r][j]);
        }

        // sbox
        for j in 0..WIDTH {
            round_cols.sbox_deg_3[j] = add_rc[j] * add_rc[j] * add_rc[j];
            round_cols.sbox_deg_7[j] = round_cols.sbox_deg_3[j] * round_cols.sbox_deg_3[j] * add_rc[j];
        }

        // write output of the round directly into the next state,
        // or the output if this is the last round
        let next_state_cols = if r == (NUM_EXTERNAL_ROUNDS / 2) - 1 {
            &mut cols.internal_rounds[0].state
        } else if r == NUM_EXTERNAL_ROUNDS - 1 {
            &mut cols.output
        } else {
            &mut cols.external_rounds[r + 1].state
        };

        // apply linear layer
        external_linear_layer(&round_cols.sbox_deg_7, next_state_cols);
    }

    fn generate_internal_round<F: PrimeField32>(cols: &mut Poseidon2WideCols<F>, r: usize) {
        let round_cols = cols.internal_rounds[r].borrow();

        // rc
        // we don't need columns for the result of adding rc since the constraint is 
        // degree 1, so we can absorb this into the constraint for the x^3 part of the sbox
        let add_rc = round_cols.state[0] + F::from_wrapped_u32(RC_16_30_U32[r][0]);

        // sbox
        round_cols.sbox_deg_3 = add_rc * add_rc * add_rc;
        round_cols.sbox_deg_7 = round_cols.sbox_deg_3 * round_cols.sbox_deg_3 * add_rc;

        // write output of the round directly into the next state,
        let next_state_cols = if r == NUM_INTERNAL_ROUNDS - 1 {
            &mut cols.external_rounds[NUM_EXTERNAL_ROUNDS / 2].state
        } else {
            &mut cols.internal_rounds[r + 1].state
        };

        // apply linear layer
        let mut linear_layer_input = round_cols.state.clone();
        linear_layer_input[0] = round_cols.sbox_deg_7;
        internal_linear_layer(&linear_layer_input, next_state_cols);
    }
}

impl<F> BaseAir<F> for Poseidon2WideChip {
    fn width(&self) -> usize {
        NUM_POSEIDON2_WIDE_COLS
    }
}

impl<AB> Air<AB> for Poseidon2WideChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Poseidon2WideCols s<AB::Var> = (*local).borrow();

        builder.assert_eq(
            local.dummy_cols[0] * local.dummy_cols[0] * local.dummy_cols[0],
            local.dummy_cols[0] * local.dummy_cols[0] * local.dummy_cols[0],
        );

        // let rounds_f = 8;
        // let rounds_p = 22;
        // let rounds = rounds_f + rounds_p;

        // // Convert the u32 round constants to field elements.
        // let constants: [[AB::F; WIDTH]; 30] = RC_16_30_U32
        //     .iter()
        //     .map(|round| round.map(AB::F::from_wrapped_u32))
        //     .collect::<Vec<_>>()
        //     .try_into()
        //     .unwrap();

        // // Apply the round constants.
        // //
        // // Initial Layer: Don't apply the round constants.
        // // External Layers: Apply the round constants.
        // // Internal Layers: Only apply the round constants to the first element.
        // for i in 0..WIDTH {
        //     let mut result: AB::Expr = local.input[i].into();
        //     for r in 0..rounds {
        //         if i == 0 {
        //             result += local.rounds[r + 1]
        //                 * constants[r][i]
        //                 * (local.is_external + local.is_internal);
        //         } else {
        //             result += local.rounds[r + 1] * constants[r][i] * local.is_external;
        //         }
        //     }
        //     builder.assert_eq(result, local.add_rc[i]);
        // }

        // // Apply the sbox.
        // //
        // // To differentiate between external and internal layers, we use a masking operation
        // // to only apply the state change to the first element for internal layers.
        // for i in 0..WIDTH {
        //     let sbox_deg_3 = local.add_rc[i] * local.add_rc[i] * local.add_rc[i];
        //     builder.assert_eq(sbox_deg_3, local.sbox_deg_3[i]);
        //     let sbox_deg_7 = local.sbox_deg_3[i] * local.sbox_deg_3[i] * local.add_rc[i];
        //     builder.assert_eq(sbox_deg_7, local.sbox_deg_7[i]);
        // }
        // let sbox_result: [AB::Expr; WIDTH] = local
        //     .sbox_deg_7
        //     .iter()
        //     .enumerate()
        //     .map(|(i, x)| {
        //         // The masked first result of the sbox.
        //         //
        //         // Initial Layer: Pass through the result of the round constant layer.
        //         // External Layer: Pass through the result of the sbox layer.
        //         // Internal Layer: Pass through the result of the sbox layer.
        //         if i == 0 {
        //             local.is_initial * local.add_rc[i] + (AB::Expr::one() - local.is_initial) * *x
        //         }
        //         // The masked result of the rest of the sbox.
        //         //
        //         // Initial layer: Pass through the result of the round constant layer.
        //         // External layer: Pass through the result of the sbox layer.
        //         // Internal layer: Pass through the result of the round constant layer.
        //         else {
        //             (local.is_initial + local.is_internal) * local.add_rc[i]
        //                 + (AB::Expr::one() - (local.is_initial + local.is_internal)) * *x
        //         }
        //     })
        //     .collect::<Vec<_>>()
        //     .try_into()
        //     .unwrap();

        // // EXTERNAL LAYER + INITIAL LAYER
        // {
        //     // First, we apply M_4 to each consecutive four elements of the state.
        //     // In Appendix B's terminology, this replaces each x_i with x_i'.
        //     let mut state: [AB::Expr; WIDTH] = sbox_result.clone();
        //     for i in (0..WIDTH).step_by(4) {
        //         apply_m_4(&mut state[i..i + 4]);
        //     }

        //     // Now, we apply the outer circulant matrix (to compute the y_i values).
        //     //
        //     // We first precompute the four sums of every four elements.
        //     let sums: [AB::Expr; 4] = core::array::from_fn(|k| {
        //         (0..WIDTH)
        //             .step_by(4)
        //             .map(|j| state[j + k].clone())
        //             .sum::<AB::Expr>()
        //     });

        //     // The formula for each y_i involves 2x_i' term and x_j' terms for each j that equals i mod 4.
        //     // In other words, we can add a single copy of x_i' to the appropriate one of our precomputed sums.
        //     for i in 0..WIDTH {
        //         state[i] += sums[i % 4].clone();
        //         builder
        //             .when(local.is_external + local.is_initial)
        //             .assert_eq(state[i].clone(), local.output[i]);
        //     }
        // }

        // // INTERNAL LAYER
        // {
        //     // Use a simple matrix multiplication as the permutation.
        //     let mut state: [AB::Expr; WIDTH] = sbox_result.clone();
        //     let matmul_constants: [<<AB as AirBuilder>::Expr as AbstractField>::F; WIDTH] =
        //         MATRIX_DIAG_16_BABYBEAR_U32
        //             .iter()
        //             .map(|x| <<AB as AirBuilder>::Expr as AbstractField>::F::from_wrapped_u32(*x))
        //             .collect::<Vec<_>>()
        //             .try_into()
        //             .unwrap();
        //     matmul_internal(&mut state, matmul_constants);
        //     for i in 0..WIDTH {
        //         builder
        //             .when(local.is_internal)
        //             .assert_eq(state[i].clone(), local.output[i]);
        //     }
        // }

        // // Range check all flags.
        // for i in 0..local.rounds.len() {
        //     builder.assert_bool(local.rounds[i]);
        // }
        // builder.assert_bool(local.is_initial);
        // builder.assert_bool(local.is_external);
        // builder.assert_bool(local.is_internal);
        // builder.assert_bool(local.is_initial + local.is_external + local.is_internal);

        // // Constrain the initial flag.
        // builder.assert_eq(local.is_initial, local.rounds[0]);

        // // Constrain the external flag.
        // let is_external_first_half = (0..4).map(|i| local.rounds[i + 1].into()).sum::<AB::Expr>();
        // let is_external_second_half = (26..30)
        //     .map(|i| local.rounds[i + 1].into())
        //     .sum::<AB::Expr>();
        // builder.assert_eq(
        //     local.is_external,
        //     is_external_first_half + is_external_second_half,
        // );

        // // Constrain the internal flag.
        // let is_internal = (4..26)
        //     .map(|i| local.rounds[i + 1].into())
        //     .sum::<AB::Expr>();
        // builder.assert_eq(local.is_internal, is_internal);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;
    use sp1_core::stark::StarkGenericConfig;
    use sp1_core::utils::{uni_stark_verify, BabyBearPoseidon2Inner};
    use sp1_core::{air::MachineAir, utils::uni_stark_prove};

    use crate::poseidon2::Poseidon2Event;
    use crate::poseidon2_wide::external::WIDTH;
    use crate::{poseidon2_wide::external::Poseidon2WideChip, runtime::ExecutionRecord};

    #[test]
    fn generate_trace() {
        let chip = Poseidon2WideChip;
        let mut input_exec = ExecutionRecord::<BabyBear>::default();
        for _i in 0..108173 {
            input_exec.poseidon2_events.push(Poseidon2Event {
                input: [BabyBear::one(); WIDTH],
            });
        }
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&input_exec, &mut ExecutionRecord::<BabyBear>::default());
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2Inner::new();
        let mut challenger = config.challenger();

        let chip = Poseidon2WideChip;

        let mut input_exec = ExecutionRecord::<BabyBear>::default();
        for _i in 0..108173 {
            input_exec.poseidon2_events.push(Poseidon2Event {
                input: [BabyBear::one(); WIDTH],
            });
        }
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&input_exec, &mut ExecutionRecord::<BabyBear>::default());

        let start = Instant::now();
        let proof = uni_stark_prove(&config, &chip, &mut challenger, trace);
        let duration = start.elapsed().as_secs_f64();
        println!("proof duration = {:?}", duration);

        let mut challenger = config.challenger();
        let start = Instant::now();
        uni_stark_verify(&config, &chip, &mut challenger, &proof).unwrap();
        let duration = start.elapsed().as_secs_f64();
        println!("verify duration = {:?}", duration);
    }
}
