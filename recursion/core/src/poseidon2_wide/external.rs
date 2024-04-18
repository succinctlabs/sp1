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
pub const NUM_INTERNAL_ROUND_CHUNKS: usize = 7;
pub const NUM_LAST_INTERNAL_ROUNDS: usize = 1;
pub const INTERNAL_ROUND_CHUNK_SIZE: usize = 3;
pub const NUM_INTERNAL_ROUNDS: usize =
    NUM_INTERNAL_ROUND_CHUNKS * INTERNAL_ROUND_CHUNK_SIZE + NUM_LAST_INTERNAL_ROUNDS;
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
    internal_round_chunks: [Poseidon2WideInternalRoundChunkCols<T>; NUM_INTERNAL_ROUND_CHUNKS],
    last_internal_rounds: [Poseidon2WideLastInternalRoundCols<T>; NUM_LAST_INTERNAL_ROUNDS],
}

// Columns required for external rounds
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
struct Poseidon2WideExternalRoundCols<T> {
    state: [T; WIDTH],
    sbox_deg_3: [T; WIDTH],
    sbox_deg_7: [T; WIDTH],
}

// Columns required for a chunk of 3 internal rounds
#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
struct Poseidon2WideInternalRoundChunkCols<T> {
    state: [T; WIDTH],
    state_accs: [T; 2],
    sbox_deg_3: [T; 3],
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
                    cols.internal_round_chunks[0].state = next_state;
                } else {
                    cols.external_rounds[r + 1].state = next_state;
                }
            }

            // apply internal rounds
            // first, we do 7 chunks of 3 internal rounds
            // then, we do the last internal round
            for chunk in 0..NUM_INTERNAL_ROUND_CHUNKS {
                let next_state = Self::generate_internal_round_chunk(cols, chunk);
                if chunk == NUM_INTERNAL_ROUND_CHUNKS - 1 {
                    cols.last_internal_rounds[0].state = next_state;
                } else {
                    cols.internal_round_chunks[chunk + 1].state = next_state;
                }
            }
            for r in 0..NUM_LAST_INTERNAL_ROUNDS {
                let next_state = Self::generate_last_internal_round(cols, r);
                if r == NUM_LAST_INTERNAL_ROUNDS - 1 {
                    cols.external_rounds[NUM_EXTERNAL_ROUNDS / 2].state = next_state;
                } else {
                    cols.last_internal_rounds[r + 1].state = next_state;
                }
            }

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
            for i in 0..WIDTH {
                round_cols.sbox_deg_3[i] = add_rc[i] * add_rc[i] * add_rc[i];
                round_cols.sbox_deg_7[i] =
                    round_cols.sbox_deg_3[i] * round_cols.sbox_deg_3[i] * add_rc[i];
            }

            round_cols.sbox_deg_7
        };

        // apply linear layer
        let mut next_state = [F::zero(); WIDTH];
        external_linear_layer(&linear_layer_input, &mut next_state);
        next_state
    }

    fn generate_internal_round_chunk<F: PrimeField32>(
        cols: &mut Poseidon2WideCols<F>,
        chunk: usize,
    ) -> [F; WIDTH] {
        let chunk_cols = &mut cols.internal_round_chunks[chunk];
        let mut state = chunk_cols.state;
        for i in 0..INTERNAL_ROUND_CHUNK_SIZE {
            // rc
            let round = chunk * INTERNAL_ROUND_CHUNK_SIZE + i + NUM_EXTERNAL_ROUNDS / 2;
            let add_rc = state[0] + F::from_wrapped_u32(RC_16_30_U32[round][0]);

            // sbox
            chunk_cols.sbox_deg_3[i] = add_rc * add_rc * add_rc;
            let sbox_deg_7 = chunk_cols.sbox_deg_3[i] * chunk_cols.sbox_deg_3[i] * add_rc;

            // linear layer
            let mut linear_layer_input = state;
            linear_layer_input[0] = sbox_deg_7;

            internal_linear_layer(&linear_layer_input, &mut state);

            if i < INTERNAL_ROUND_CHUNK_SIZE - 1 {
                chunk_cols.state_accs[i] = state[0];
            }
        }

        state
    }

    fn generate_last_internal_round<F: PrimeField32>(
        cols: &mut Poseidon2WideCols<F>,
        r: usize,
    ) -> [F; WIDTH] {
        let linear_layer_input = {
            let round_cols = &mut cols.last_internal_rounds[r];

            // rc
            // we don't need columns for the result of adding rc since the constraint is
            // degree 1, so we can absorb this into the constraint for the x^3 part of the sbox
            let round =
                r + NUM_INTERNAL_ROUND_CHUNKS * INTERNAL_ROUND_CHUNK_SIZE + NUM_EXTERNAL_ROUNDS / 2;
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
        for i in 0..WIDTH {
            let sbox_deg_3 = add_rc[i].clone() * add_rc[i].clone() * add_rc[i].clone();
            builder.assert_eq(round_cols.sbox_deg_3[i], sbox_deg_3);

            let sbox_deg_3 = round_cols.sbox_deg_3[i];
            let sbox_deg_7 = sbox_deg_3 * sbox_deg_3 * add_rc[i].clone();
            builder.assert_eq(round_cols.sbox_deg_7[i], sbox_deg_7);
        }

        // linear layer
        let linear_layer_input: [AB::Expr; WIDTH] =
            core::array::from_fn(|i| round_cols.sbox_deg_7[i].into());
        let mut linear_layer_output: [AB::Expr; WIDTH] = core::array::from_fn(|_| AB::Expr::zero());
        external_linear_layer(&linear_layer_input, &mut linear_layer_output);

        let next_state_cols = if r == (NUM_EXTERNAL_ROUNDS / 2) - 1 {
            &cols.internal_round_chunks[0].state
        } else if r == NUM_EXTERNAL_ROUNDS - 1 {
            &cols.output
        } else {
            &cols.external_rounds[r + 1].state
        };
        for i in 0..WIDTH {
            builder.assert_eq(linear_layer_output[i].clone(), next_state_cols[i]);
        }
    }

    fn build_internal_round_chunk<AB: SP1AirBuilder>(
        builder: &mut AB,
        cols: &Poseidon2WideCols<AB::Var>,
        chunk: usize,
    ) {
        let chunk_cols = &cols.internal_round_chunks[chunk];

        let mut state: [AB::Expr; WIDTH] = core::array::from_fn(|i| chunk_cols.state[i].into());
        for i in 0..INTERNAL_ROUND_CHUNK_SIZE {
            // rc
            let round = chunk * INTERNAL_ROUND_CHUNK_SIZE + i + NUM_EXTERNAL_ROUNDS / 2;
            let add_rc = if i == 0 {
                chunk_cols.state[0].into()
            } else {
                chunk_cols.state_accs[i - 1].into()
            } + AB::Expr::from_wrapped_u32(RC_16_30_U32[round][0]);

            // sbox
            let sbox_deg_3 = add_rc.clone() * add_rc.clone() * add_rc.clone();
            builder.assert_eq(chunk_cols.sbox_deg_3[i], sbox_deg_3);

            let sbox_deg_3 = chunk_cols.sbox_deg_3[i];
            let sbox_deg_7 = sbox_deg_3 * sbox_deg_3 * add_rc.clone();

            // apply linear layer
            let linear_layer_input: [AB::Expr; WIDTH] = core::array::from_fn(|j| {
                if j == 0 {
                    sbox_deg_7.clone()
                } else {
                    state[j].clone()
                }
            });
            let mut linear_layer_output: [AB::Expr; WIDTH] =
                core::array::from_fn(|_| AB::Expr::zero());
            internal_linear_layer(&linear_layer_input, &mut linear_layer_output);

            if i < INTERNAL_ROUND_CHUNK_SIZE - 1 {
                builder.assert_eq(chunk_cols.state_accs[i], linear_layer_output[0].clone());
            }

            state = linear_layer_output;
        }

        let next_state_cols = if chunk == NUM_INTERNAL_ROUND_CHUNKS - 1 {
            &cols.last_internal_rounds[0].state
        } else {
            &cols.internal_round_chunks[chunk + 1].state
        };

        for i in 0..WIDTH {
            builder.assert_eq(state[i].clone(), next_state_cols[i]);
        }
    }

    fn build_last_internal_round<AB: SP1AirBuilder>(
        builder: &mut AB,
        cols: &Poseidon2WideCols<AB::Var>,
        r: usize,
    ) {
        let round_cols = cols.last_internal_rounds[r].borrow();

        // rc
        // we don't need columns for the result of adding rc since the constraint is
        // degree 1, so we can absorb this into the constraint for the x^3 part of the sbox
        let round =
            r + NUM_INTERNAL_ROUND_CHUNKS * INTERNAL_ROUND_CHUNK_SIZE + NUM_EXTERNAL_ROUNDS / 2;
        let add_rc: AB::Expr =
            round_cols.state[0] + AB::Expr::from_wrapped_u32(RC_16_30_U32[round][0]);

        // sbox
        let sbox_deg_3 = add_rc.clone() * add_rc.clone() * add_rc.clone();
        builder.assert_eq(round_cols.sbox_deg_3, sbox_deg_3);

        let sbox_deg_3 = round_cols.sbox_deg_3;
        let sbox_deg_7 = sbox_deg_3 * sbox_deg_3 * add_rc.clone();
        builder.assert_eq(round_cols.sbox_deg_7, sbox_deg_7);

        // apply linear layer
        let linear_layer_input: [AB::Expr; WIDTH] = core::array::from_fn(|i| match i {
            0 => round_cols.sbox_deg_7.into(),
            _ => round_cols.state[i].into(),
        });
        let mut linear_layer_output: [AB::Expr; WIDTH] = core::array::from_fn(|_| AB::Expr::zero());
        internal_linear_layer(&linear_layer_input, &mut linear_layer_output);

        let next_state_cols = if r == NUM_LAST_INTERNAL_ROUNDS - 1 {
            &cols.external_rounds[NUM_EXTERNAL_ROUNDS / 2].state
        } else {
            &cols.last_internal_rounds[r + 1].state
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
        // first we do 7 chunks of 3 internal rounds
        // then we do the last internal round
        for chunk in 0..NUM_INTERNAL_ROUND_CHUNKS {
            Self::build_internal_round_chunk(builder, cols, chunk);
        }
        for r in 0..NUM_LAST_INTERNAL_ROUNDS {
            Self::build_last_internal_round(builder, cols, r);
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

    use itertools::Itertools;
    use p3_baby_bear::{BabyBear, DiffusionMatrixBabybear};
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::Matrix;
    use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
    use p3_symmetric::Permutation;
    use sp1_core::air::MachineAir;
    use sp1_core::utils::inner_perm;

    use crate::poseidon2::Poseidon2Event;
    use crate::poseidon2_wide::external::{Poseidon2WideCols, WIDTH};
    use crate::{poseidon2_wide::external::Poseidon2WideChip, runtime::ExecutionRecord};

    #[cfg(release)]
    use sp1_core::utils::{uni_stark_prove, uni_stark_verify, BabyBearPoseidon2Inner};

    #[cfg(release)]
    use sp1_core::stark::StarkGenericConfig;

    #[cfg(release)]
    use std::time::Instant;

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
    #[cfg(release)]
    fn prove_babybear() {
        let config = BabyBearPoseidon2Inner::new();
        let mut challenger = config.challenger();

        let chip = Poseidon2WideChip;

        let test_inputs = (0..1024)
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
