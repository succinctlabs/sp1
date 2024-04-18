use core::borrow::Borrow;
use core::mem::size_of;
use p3_air::{Air, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_core::air::{MachineAir, SP1AirBuilder};
use sp1_core::utils::pad_to_power_of_two;
use sp1_derive::AlignedBorrow;
use sp1_primitives::RC_16_30_U32;
use std::borrow::BorrowMut;
use tracing::instrument;

use crate::poseidon2_wide::{external_linear_layer, internal_linear_layer};
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
    external_rounds: [Poseidon2WideExternalRoundCols<T>; NUM_EXTERNAL_ROUNDS],
    internal_rounds: Poseidon2WideInternalRoundsCols<T>,
}

// Columns required for external rounds
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
struct Poseidon2WideExternalRoundCols<T> {
    state: [T; WIDTH],
    sbox_deg_3: [T; WIDTH],
}

// Columns required for a chunk of 3 internal rounds
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
struct Poseidon2WideInternalRoundsCols<T> {
    state: [T; WIDTH],
    s0: [T; NUM_INTERNAL_ROUNDS - 1],
    sbox_deg_3: [T; NUM_INTERNAL_ROUNDS],
}

// Columns required for internal rounds
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
struct Poseidon2WideLastInternalRoundCols<T> {
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
                let next_state = Self::generate_external_round(cols, r);

                if r == NUM_EXTERNAL_ROUNDS / 2 - 1 {
                    cols.internal_rounds.state = next_state;
                } else {
                    cols.external_rounds[r + 1].state = next_state;
                }
            }

            // apply internal rounds
            cols.external_rounds[NUM_EXTERNAL_ROUNDS / 2].state =
                Self::generate_internal_rounds(cols);

            // apply second half of external rounds
            for r in NUM_EXTERNAL_ROUNDS / 2..NUM_EXTERNAL_ROUNDS {
                let next_state = Self::generate_external_round(cols, r);
                if r == NUM_EXTERNAL_ROUNDS - 1 {
                    cols.output = next_state;
                } else {
                    cols.external_rounds[r + 1].state = next_state;
                }
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
    fn generate_external_round<F: PrimeField32>(
        cols: &mut Poseidon2WideCols<F>,
        r: usize,
    ) -> [F; WIDTH] {
        let linear_layer_input = {
            let round_cols = cols.external_rounds[r].borrow_mut();

            // rc
            // we don't need columns for the result of adding rc since the constraint is
            // degree 1, so we can absorb this into the constraint for the x^3 part of the sbox
            let round = if r < NUM_EXTERNAL_ROUNDS / 2 {
                r
            } else {
                r + NUM_INTERNAL_ROUNDS
            };
            let mut add_rc = round_cols.state;
            for i in 0..WIDTH {
                add_rc[i] += F::from_wrapped_u32(RC_16_30_U32[round][i]);
            }

            // sbox
            let mut sbox_deg_7 = [F::zero(); WIDTH];
            for i in 0..WIDTH {
                round_cols.sbox_deg_3[i] = add_rc[i] * add_rc[i] * add_rc[i];
                sbox_deg_7[i] = round_cols.sbox_deg_3[i] * round_cols.sbox_deg_3[i] * add_rc[i];
            }

            sbox_deg_7
        };

        // apply linear layer
        let mut next_state = [F::zero(); WIDTH];
        external_linear_layer(&linear_layer_input, &mut next_state);
        next_state
    }

    fn generate_internal_rounds<F: PrimeField32>(cols: &mut Poseidon2WideCols<F>) -> [F; WIDTH] {
        let cols = cols.internal_rounds.borrow_mut();
        let mut state = cols.state;
        for r in 0..NUM_INTERNAL_ROUNDS {
            // rc
            let round = r + NUM_EXTERNAL_ROUNDS / 2;
            let add_rc = state[0] + F::from_wrapped_u32(RC_16_30_U32[round][0]);

            // sbox
            cols.sbox_deg_3[r] = add_rc * add_rc * add_rc;
            let sbox_deg_7 = cols.sbox_deg_3[r] * cols.sbox_deg_3[r] * add_rc;

            // linear layer
            let mut linear_layer_input = state;
            linear_layer_input[0] = sbox_deg_7;

            internal_linear_layer(&linear_layer_input, &mut state);

            if r < NUM_INTERNAL_ROUNDS - 1 {
                cols.s0[r] = state[0];
            }
        }

        state
    }

    fn build_external_round<AB: SP1AirBuilder>(
        builder: &mut AB,
        cols: &Poseidon2WideCols<AB::Var>,
        r: usize,
    ) {
        let round_cols = cols.external_rounds[r];

        // rc
        // we don't need columns for the result of adding rc since the constraint is
        // degree 1, so we can absorb this into the constraint for the x^3 part of the sbox
        let round = if r < NUM_EXTERNAL_ROUNDS / 2 {
            r
        } else {
            r + NUM_INTERNAL_ROUNDS
        };
        let add_rc: [AB::Expr; WIDTH] = core::array::from_fn(|i| {
            round_cols.state[i].into() + AB::Expr::from_canonical_u32(RC_16_30_U32[round][i])
        });

        // sbox
        let mut sbox_deg_7: [AB::Expr; WIDTH] = core::array::from_fn(|_| AB::Expr::zero());
        for i in 0..WIDTH {
            let sbox_deg_3 = add_rc[i].clone() * add_rc[i].clone() * add_rc[i].clone();
            builder.assert_eq(round_cols.sbox_deg_3[i], sbox_deg_3);

            let sbox_deg_3 = round_cols.sbox_deg_3[i];
            sbox_deg_7[i] = sbox_deg_3 * sbox_deg_3 * add_rc[i].clone();
        }

        // linear layer
        let mut linear_layer_output: [AB::Expr; WIDTH] = core::array::from_fn(|_| AB::Expr::zero());
        external_linear_layer(&sbox_deg_7, &mut linear_layer_output);

        let next_state_cols = if r == NUM_EXTERNAL_ROUNDS / 2 - 1 {
            &cols.internal_rounds.state
        } else if r == NUM_EXTERNAL_ROUNDS - 1 {
            &cols.output
        } else {
            &cols.external_rounds[r + 1].state
        };
        for i in 0..WIDTH {
            builder.assert_eq(next_state_cols[i], linear_layer_output[i].clone());
        }
    }

    fn build_internal_rounds<AB: SP1AirBuilder>(
        builder: &mut AB,
        cols: &Poseidon2WideCols<AB::Var>,
    ) {
        let round_cols = &cols.internal_rounds;
        let mut state: [AB::Expr; WIDTH] = core::array::from_fn(|i| round_cols.state[i].into());
        for r in 0..NUM_INTERNAL_ROUNDS {
            // rc
            let round = r + NUM_EXTERNAL_ROUNDS / 2;
            let add_rc = if r == 0 {
                state[0].clone()
            } else {
                round_cols.s0[r - 1].into()
            } + AB::Expr::from_wrapped_u32(RC_16_30_U32[round][0]);

            let sbox_deg_3 = add_rc.clone() * add_rc.clone() * add_rc.clone();
            builder.assert_eq(round_cols.sbox_deg_3[r], sbox_deg_3);

            // we don't need a separate constraint here because the linear layer is degree 1
            // if this isn't the last round, this is constrained by the constraint below for s0
            // if this is the last round, this is constrained by the constraint where we set the
            // and the constraint
            let sbox_deg_7 =
                round_cols.sbox_deg_3[r].into() * round_cols.sbox_deg_3[r].into() * add_rc.clone();

            // linear layer
            let mut linear_layer_input = state.clone();
            linear_layer_input[0] = sbox_deg_7.clone();
            internal_linear_layer(&linear_layer_input, &mut state);

            if r < NUM_INTERNAL_ROUNDS - 1 {
                builder.assert_eq(round_cols.s0[r], state[0].clone());
            }
        }

        for i in 0..WIDTH {
            builder.assert_eq(
                cols.external_rounds[NUM_EXTERNAL_ROUNDS / 2].state[i],
                state[i].clone(),
            )
        }
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
        let cols = main.row_slice(0);
        let cols: &Poseidon2WideCols<AB::Var> = (*cols).borrow();

        // initial round
        let initial_round_output = {
            let input: [AB::Expr; WIDTH] = core::array::from_fn(|i| cols.input[i].into());
            let mut output: [AB::Expr; WIDTH] = core::array::from_fn(|_| AB::Expr::zero());
            external_linear_layer(&input, &mut output);
            output
        };
        for i in 0..WIDTH {
            builder.assert_eq(
                cols.external_rounds[0].state[i],
                initial_round_output[i].clone(),
            );
        }

        // first half of external rounds
        for r in 0..NUM_EXTERNAL_ROUNDS / 2 {
            Self::build_external_round(builder, cols, r);
        }

        // internal rounds
        Self::build_internal_rounds(builder, cols);

        // second half of external rounds
        for r in NUM_EXTERNAL_ROUNDS / 2..NUM_EXTERNAL_ROUNDS {
            Self::build_external_round(builder, cols, r);
        }
    }
}

#[cfg(test)]
mod tests {
    use core::borrow::Borrow;
    use std::time::Instant;

    use itertools::Itertools;
    use p3_baby_bear::{BabyBear, DiffusionMatrixBabybear};
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::Matrix;
    use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
    use p3_symmetric::Permutation;
    use sp1_core::air::MachineAir;
    use sp1_core::stark::StarkGenericConfig;
    use sp1_core::utils::{inner_perm, uni_stark_prove, uni_stark_verify, BabyBearPoseidon2Inner};

    use crate::poseidon2::Poseidon2Event;
    use crate::poseidon2_wide::external::{Poseidon2WideCols, WIDTH};
    use crate::{poseidon2_wide::external::Poseidon2WideChip, runtime::ExecutionRecord};

    #[test]
    fn generate_trace() {
        let chip = Poseidon2WideChip;
        let test_inputs = vec![
            [BabyBear::from_canonical_u32(1); WIDTH],
            [BabyBear::from_canonical_u32(2); WIDTH],
            [BabyBear::from_canonical_u32(3); WIDTH],
            [BabyBear::from_canonical_u32(4); WIDTH],
        ];

        let gt: Poseidon2<
            BabyBear,
            Poseidon2ExternalMatrixGeneral,
            DiffusionMatrixBabybear,
            16,
            7,
        > = inner_perm();

        let expected_outputs = test_inputs
            .iter()
            .map(|input| gt.permute(*input))
            .collect::<Vec<_>>();

        let mut input_exec = ExecutionRecord::<BabyBear>::default();
        for input in test_inputs.iter().cloned() {
            input_exec.poseidon2_events.push(Poseidon2Event { input });
        }

        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&input_exec, &mut ExecutionRecord::<BabyBear>::default());

        assert_eq!(trace.height(), test_inputs.len());
        for (i, expected_output) in expected_outputs.iter().enumerate() {
            let row = trace.row(i).collect_vec();
            let cols: &Poseidon2WideCols<BabyBear> = row.as_slice().borrow();
            println!("{:?}", cols.output);
            assert_eq!(expected_output, &cols.output);
        }
    }

    // test proving 2^10 permuations
    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2Inner::new();
        let mut challenger = config.challenger();

        let chip = Poseidon2WideChip;

        let test_inputs = (0..4)
            .map(|i| [BabyBear::from_canonical_u32(i); WIDTH])
            .collect_vec();

        let mut input_exec = ExecutionRecord::<BabyBear>::default();
        for input in test_inputs.iter().cloned() {
            input_exec.poseidon2_events.push(Poseidon2Event { input });
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

        let mut challenger = config.challenger();
        let start = Instant::now();
        uni_stark_verify(&config, &chip, &mut challenger, &proof)
            .expect("expected proof to be valid");

        let duration = start.elapsed().as_secs_f64();
        println!("verify duration = {:?}", duration);
    }
}
