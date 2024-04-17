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
    internal_rounds: [Poseidon2WideInternalRoundCols<T>; NUM_INTERNAL_ROUNDS],
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
            println!("linear layer applied: {:?}", cols.external_rounds[0].state);

            // apply first half of external rounds
            for r in 0..NUM_EXTERNAL_ROUNDS / 2 {
                let next_state = Self::generate_external_round(cols, r);
                println!("curr state: {:?}", cols.external_rounds[r].state);

                if r == NUM_EXTERNAL_ROUNDS / 2 - 1 {
                    cols.internal_rounds[0].state = next_state;
                } else {
                    cols.external_rounds[r + 1].state = next_state;
                }
            }

            // apply internal rounds
            for r in 0..NUM_INTERNAL_ROUNDS {
                let next_state = Self::generate_internal_round(cols, r);
                println!("curr state: {:?}", cols.internal_rounds[r].state);

                if r == NUM_INTERNAL_ROUNDS - 1 {
                    cols.external_rounds[NUM_EXTERNAL_ROUNDS / 2].state = next_state;
                } else {
                    cols.internal_rounds[r + 1].state = next_state;
                }
            }

            // apply second half of external rounds
            for r in NUM_EXTERNAL_ROUNDS / 2..NUM_EXTERNAL_ROUNDS {
                let next_state = Self::generate_external_round(cols, r);
                println!("curr state: {:?}", cols.external_rounds[r].state);
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
        let round = if r < NUM_EXTERNAL_ROUNDS / 2 {
            r
        } else {
            r + NUM_INTERNAL_ROUNDS
        };

        let linear_layer_input = {
            let round_cols = cols.external_rounds[r].borrow_mut();

            // rc
            // we don't need columns for the result of adding rc since the constraint is
            // degree 1, so we can absorb this into the constraint for the x^3 part of the sbox
            let mut add_rc = round_cols.state;
            for j in 0..WIDTH {
                add_rc[j] += F::from_wrapped_u32(RC_16_30_U32[round][j]);
            }

            // sbox
            for j in 0..WIDTH {
                round_cols.sbox_deg_3[j] = add_rc[j] * add_rc[j] * add_rc[j];
                round_cols.sbox_deg_7[j] =
                    round_cols.sbox_deg_3[j] * round_cols.sbox_deg_3[j] * add_rc[j];
            }

            round_cols.sbox_deg_7
        };

        // apply linear layer
        let mut next_state = [F::zero(); WIDTH];
        external_linear_layer(&linear_layer_input, &mut next_state);
        next_state
    }

    fn generate_internal_round<F: PrimeField32>(
        cols: &mut Poseidon2WideCols<F>,
        r: usize,
    ) -> [F; WIDTH] {
        let round = r + NUM_EXTERNAL_ROUNDS / 2;
        let linear_layer_input = {
            let round_cols = cols.internal_rounds[r].borrow_mut();

            // rc
            // we don't need columns for the result of adding rc since the constraint is
            // degree 1, so we can absorb this into the constraint for the x^3 part of the sbox
            let add_rc = round_cols.state[0] + F::from_wrapped_u32(RC_16_30_U32[round][0]);

            // sbox
            round_cols.sbox_deg_3 = add_rc * add_rc * add_rc;
            round_cols.sbox_deg_7 = round_cols.sbox_deg_3 * round_cols.sbox_deg_3 * add_rc;

            let mut res = round_cols.state;
            res[0] = round_cols.sbox_deg_7;
            res
        };

        // apply linear layer
        let mut next_state = [F::zero(); WIDTH];
        internal_linear_layer(&linear_layer_input, &mut next_state);
        next_state
    }

    fn build_external_round<AB: SP1AirBuilder>(
        builder: &mut AB,
        cols: &Poseidon2WideCols<AB::Var>,
        r: usize,
    ) {
        let round_cols = cols.external_rounds[r].borrow();

        // convert the u32 round constants to field elements.
        let constants: [[AB::F; WIDTH]; 30] = RC_16_30_U32
            .iter()
            .map(|round| round.map(AB::F::from_wrapped_u32))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // rc
        // we don't need columns for the result of adding rc since the constraint is
        // degree 1, so we can absorb this into the constraint for the x^3 part of the sbox
        let mut add_rc: [AB::Expr; WIDTH] = core::array::from_fn(|_| AB::Expr::zero());
        for i in 0..WIDTH {
            add_rc[i] = round_cols.state[i].into() + constants[r][i];
        }

        // sbox
        let mut sbox_deg_7: [AB::Expr; WIDTH] = core::array::from_fn(|_| AB::Expr::zero());
        for i in 0..WIDTH {
            let sbox_deg_3 = add_rc[i].clone() * add_rc[i].clone() * add_rc[i].clone();
            sbox_deg_7[i] = sbox_deg_3.clone() * sbox_deg_3.clone() * add_rc[i].clone();

            builder.assert_eq(round_cols.sbox_deg_3[i], sbox_deg_3);
            builder.assert_eq(round_cols.sbox_deg_7[i], sbox_deg_7[i].clone());
        }

        // linear layer
        let mut linear_layer_output: [AB::Expr; WIDTH] = core::array::from_fn(|_| AB::Expr::zero());
        external_linear_layer(&sbox_deg_7, &mut linear_layer_output);

        let next_state_cols = if r == (NUM_EXTERNAL_ROUNDS / 2) - 1 {
            &cols.internal_rounds[0].state
        } else if r == NUM_EXTERNAL_ROUNDS - 1 {
            &cols.output
        } else {
            &cols.external_rounds[r + 1].state
        };
        for i in 0..WIDTH {
            builder.assert_eq(linear_layer_output[i].clone(), next_state_cols[i]);
        }
    }

    fn build_internal_round<AB: SP1AirBuilder>(
        builder: &mut AB,
        cols: &Poseidon2WideCols<AB::Var>,
        r: usize,
    ) {
        let round_cols = cols.internal_rounds[r].borrow();

        // rc
        // we don't need columns for the result of adding rc since the constraint is
        // degree 1, so we can absorb this into the constraint for the x^3 part of the sbox
        let add_rc: AB::Expr = round_cols.state[0] + AB::Expr::from_wrapped_u32(RC_16_30_U32[r][0]);

        // sbox
        let sbox_deg_3 = add_rc.clone() * add_rc.clone() * add_rc.clone();
        let sbox_deg_7 = sbox_deg_3.clone() * sbox_deg_3.clone() * add_rc.clone();

        builder.assert_eq(round_cols.sbox_deg_3, sbox_deg_3);
        builder.assert_eq(round_cols.sbox_deg_7, sbox_deg_7.clone());

        // apply linear layer
        let linear_layer_input: [AB::Expr; WIDTH] = core::array::from_fn(|i| match i {
            0 => sbox_deg_7.clone(),
            _ => round_cols.state[i].into(),
        });
        let mut linear_layer_output: [AB::Expr; WIDTH] = core::array::from_fn(|_| AB::Expr::zero());
        internal_linear_layer(&linear_layer_input, &mut linear_layer_output);

        let next_state_cols = if r == NUM_INTERNAL_ROUNDS - 1 {
            &cols.external_rounds[NUM_EXTERNAL_ROUNDS / 2].state
        } else {
            &cols.internal_rounds[r + 1].state
        };
        for i in 0..WIDTH {
            builder.assert_eq(linear_layer_output[i].clone(), next_state_cols[i]);
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
        for r in 0..NUM_INTERNAL_ROUNDS {
            Self::build_internal_round(builder, cols, r);
        }

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
    use sp1_core::stark::StarkGenericConfig;
    use sp1_core::utils::{inner_perm, uni_stark_verify, BabyBearPoseidon2Inner};
    use sp1_core::{air::MachineAir, utils::uni_stark_prove};
    use sp1_primitives::poseidon2_hash;

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

    #[test]
    fn prove_babybear() {
        // let config = BabyBearPoseidon2Inner::new();
        // let mut challenger = config.challenger();

        // let chip = Poseidon2WideChip;

        // let mut input_exec = ExecutionRecord::<BabyBear>::default();
        // for _i in 0..108173 {
        //     input_exec.poseidon2_events.push(Poseidon2Event {
        //         input: [BabyBear::one(); WIDTH],
        //     });
        // }
        // let trace: RowMajorMatrix<BabyBear> =
        //     chip.generate_trace(&input_exec, &mut ExecutionRecord::<BabyBear>::default());

        // let start = Instant::now();
        // let proof = uni_stark_prove(&config, &chip, &mut challenger, trace);
        // let duration = start.elapsed().as_secs_f64();
        // println!("proof duration = {:?}", duration);

        // let mut challenger = config.challenger();
        // let start = Instant::now();
        // uni_stark_verify(&config, &chip, &mut challenger, &proof).unwrap();
        // let duration = start.elapsed().as_secs_f64();
        // println!("verify duration = {:?}", duration);
    }
}
