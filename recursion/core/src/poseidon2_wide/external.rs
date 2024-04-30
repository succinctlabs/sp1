use crate::poseidon2_wide::columns::{
    Poseidon2Cols, Poseidon2Columns, Poseidon2SboxCols, NUM_POSEIDON2_COLS, NUM_POSEIDON2_SBOX_COLS,
};
use crate::runtime::Opcode;
use core::borrow::Borrow;
use p3_air::{Air, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_core::air::{BaseAirBuilder, MachineAir, SP1AirBuilder};
use sp1_core::utils::pad_to_power_of_two;
use sp1_primitives::RC_16_30_U32;
use tracing::instrument;

use crate::air::SP1RecursionAirBuilder;
use crate::memory::MemoryCols;

use crate::poseidon2_wide::{external_linear_layer, internal_linear_layer};
use crate::runtime::{ExecutionRecord, RecursionProgram};

use super::columns::Poseidon2MemCols;

/// The width of the permutation.
pub const WIDTH: usize = 16;

pub const NUM_EXTERNAL_ROUNDS: usize = 8;
pub const NUM_INTERNAL_ROUNDS: usize = 13;
pub const NUM_ROUNDS: usize = NUM_EXTERNAL_ROUNDS + NUM_INTERNAL_ROUNDS;

/// A chip that implements addition for the opcode ADD.
#[derive(Default)]
pub struct Poseidon2WideChip<const DEGREE: usize>;

impl<F: PrimeField32, const DEGREE: usize> MachineAir<F> for Poseidon2WideChip<DEGREE> {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        format!("Poseidon2Wide {}", DEGREE)
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    #[instrument(name = "generate poseidon2 wide trace", level = "debug", skip_all)]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        println!("Nb poseidon2 events: {:?}", input.poseidon2_events.len());

        let use_sbox_3 = DEGREE < 7;
        let num_columns = if use_sbox_3 {
            NUM_POSEIDON2_SBOX_COLS
        } else {
            NUM_POSEIDON2_COLS
        };

        for event in &input.poseidon2_events {
            let mut row = Vec::new();
            row.resize(num_columns, F::zero());

            let mut cols = if use_sbox_3 {
                let cols: &Poseidon2SboxCols<F> = row.as_slice().borrow();
                Poseidon2Columns::Wide(*cols)
            } else {
                let cols: &Poseidon2Cols<F> = row.as_slice().borrow();
                Poseidon2Columns::Narrow(*cols)
            };

            {
                let memory = cols.get_memory_mut();
                memory.timestamp = event.clk;
                memory.dst = event.dst;
                memory.left = event.left;
                memory.right = event.right;
                memory.is_real = F::one();

                // Apply the initial round.
                for i in 0..WIDTH {
                    memory.input[i].populate(&event.input_records[i]);
                }

                for i in 0..WIDTH {
                    memory.output[i].populate(&event.result_records[i]);
                }
            }

            let external_state_0 = cols.get_external_state_mut(0);
            *external_state_0 = event.input;
            external_linear_layer(external_state_0);

            // Apply the first half of external rounds.
            for r in 0..NUM_EXTERNAL_ROUNDS / 2 {
                let next_state = populate_external_round(&mut cols, r);

                if r == NUM_EXTERNAL_ROUNDS / 2 - 1 {
                    *cols.get_internal_state_mut() = next_state;
                } else {
                    *cols.get_external_state_mut(r + 1) = next_state;
                }
            }

            // Apply the internal rounds.
            *cols.get_external_state_mut(NUM_EXTERNAL_ROUNDS / 2) =
                populate_internal_rounds(&mut cols);

            // Apply the second half of external rounds.
            for r in NUM_EXTERNAL_ROUNDS / 2..NUM_EXTERNAL_ROUNDS {
                let next_state = populate_external_round(&mut cols, r);
                if r == NUM_EXTERNAL_ROUNDS - 1 {
                    // Do nothing, since we set the cols.output by populating the output records
                    // after this loop.
                    for i in 0..WIDTH {
                        assert_eq!(event.result_records[i].value[0], next_state[i]);
                    }
                } else {
                    *cols.get_external_state_mut(r + 1) = next_state;
                }
            }

            rows.push(row);
        }

        // Convert the trace to a row major matrix.
        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), num_columns);

        // Pad the trace to a power of two.
        pad_to_power_of_two::<F>(num_columns, &mut trace.values);

        #[cfg(debug_assertions)]
        println!(
            "poseidon2 wide trace dims is width: {:?}, height: {:?}",
            trace.width(),
            trace.height()
        );

        trace
    }

    fn included(&self, record: &Self::Record) -> bool {
        !record.poseidon2_events.is_empty()
    }
}

fn populate_external_round<F: PrimeField32>(
    cols: &mut Poseidon2Columns<F>,
    r: usize,
) -> [F; WIDTH] {
    let mut state = {
        let round_state = cols.get_external_state_mut(r);

        // Add round constants.
        //
        // Optimization: Since adding a constant is a degree 1 operation, we can avoid adding
        // columns for it, and instead include it in the constraint for the x^3 part of the sbox.
        let round = if r < NUM_EXTERNAL_ROUNDS / 2 {
            r
        } else {
            r + NUM_INTERNAL_ROUNDS
        };
        for i in 0..WIDTH {
            round_state[i] += F::from_wrapped_u32(RC_16_30_U32[round][i]);
        }

        // Apply the sboxes.
        // Optimization: since the linear layer that comes after the sbox is degree 1, we can
        // avoid adding columns for the result of the sbox, and instead include the x^3 -> x^7
        // part of the sbox in the constraint for the linear layer
        let mut sbox_deg_7: [F; 16] = [F::zero(); WIDTH];
        let mut sbox_deg_3: [F; 16] = [F::zero(); WIDTH];
        for i in 0..WIDTH {
            sbox_deg_3[i] = round_state[i] * round_state[i] * round_state[i];
            sbox_deg_7[i] = sbox_deg_3[i] * sbox_deg_3[i] * round_state[i];
        }

        if let Some(sbox) = cols.get_external_sbox_mut(r) {
            *sbox = sbox_deg_3;
        }

        sbox_deg_7
    };

    // Apply the linear layer.
    external_linear_layer(&mut state);
    state
}

fn populate_internal_rounds<F: PrimeField32>(cols: &mut Poseidon2Columns<F>) -> [F; WIDTH] {
    let mut s0: [F; NUM_INTERNAL_ROUNDS - 1] = [F::zero(); NUM_INTERNAL_ROUNDS - 1];
    let mut sbox_deg_3: [F; NUM_INTERNAL_ROUNDS] = [F::zero(); NUM_INTERNAL_ROUNDS];

    let state = {
        let state = cols.get_internal_state_mut();
        for r in 0..NUM_INTERNAL_ROUNDS {
            // Add the round constant to the 0th state element.
            // Optimization: Since adding a constant is a degree 1 operation, we can avoid adding
            // columns for it, just like for external rounds.
            let round = r + NUM_EXTERNAL_ROUNDS / 2;
            let add_rc = state[0] + F::from_wrapped_u32(RC_16_30_U32[round][0]);

            // Apply the sboxes.
            // Optimization: since the linear layer that comes after the sbox is degree 1, we can
            // avoid adding columns for the result of the sbox, just like for external rounds.
            sbox_deg_3[r] = add_rc * add_rc * add_rc;
            let sbox_deg_7 = sbox_deg_3[r] * sbox_deg_3[r] * add_rc;

            // Apply the linear layer.
            state[0] = sbox_deg_7;
            internal_linear_layer(state);

            // Optimization: since we're only applying the sbox to the 0th state element, we only
            // need to have columns for the 0th state element at every step. This is because the
            // linear layer is degree 1, so all state elements at the end can be expressed as a
            // degree-3 polynomial of the state at the beginning of the internal rounds and the 0th
            // state element at rounds prior to the current round
            if r < NUM_INTERNAL_ROUNDS - 1 {
                s0[r] = state[0];
            }
        }

        *state
    };

    *cols.get_internal_s0_mut() = s0;
    if let Some(sbox) = cols.get_internal_sbox_mut() {
        *sbox = sbox_deg_3;
    }

    state
}

fn eval_external_round<AB: SP1AirBuilder>(
    builder: &mut AB,
    cols: &Poseidon2Columns<AB::Var>,
    r: usize,
    is_real: AB::Var,
) {
    let external_state = cols.get_external_state(r);

    // Add the round constants.
    let round = if r < NUM_EXTERNAL_ROUNDS / 2 {
        r
    } else {
        r + NUM_INTERNAL_ROUNDS
    };
    let add_rc: [AB::Expr; WIDTH] = core::array::from_fn(|i| {
        external_state[i].into() + is_real * AB::F::from_wrapped_u32(RC_16_30_U32[round][i])
    });

    // Apply the sboxes.
    // See `populate_external_round` for why we don't have columns for the sbox output here.
    let mut sbox_deg_7: [AB::Expr; WIDTH] = core::array::from_fn(|_| AB::Expr::zero());
    let mut sbox_deg_3: [AB::Expr; WIDTH] = core::array::from_fn(|_| AB::Expr::zero());
    let expected_sbox_deg_3 = cols.get_external_sbox(r);
    for i in 0..WIDTH {
        sbox_deg_3[i] = add_rc[i].clone() * add_rc[i].clone() * add_rc[i].clone();
        sbox_deg_7[i] = sbox_deg_3[i].clone() * sbox_deg_3[i].clone() * add_rc[i].clone();
        if let Some(expected) = expected_sbox_deg_3 {
            builder.assert_eq(expected[i], sbox_deg_3[i].clone());
        }
    }

    // Apply the linear layer.
    let mut state = sbox_deg_7;
    external_linear_layer(&mut state);

    let next_state_cols = if r == NUM_EXTERNAL_ROUNDS / 2 - 1 {
        cols.get_internal_state()
    } else if r == NUM_EXTERNAL_ROUNDS - 1 {
        let memory = cols.get_memory();
        &core::array::from_fn(|i| *memory.output[i].value())
    } else {
        cols.get_external_state(r + 1)
    };
    for i in 0..WIDTH {
        builder.assert_eq(next_state_cols[i], state[i].clone());
    }
}

fn eval_internal_rounds<AB: SP1AirBuilder>(
    builder: &mut AB,
    cols: &Poseidon2Columns<AB::Var>,
    is_real: AB::Var,
) {
    let state = &cols.get_internal_state();
    let s0 = cols.get_internal_s0();
    let sbox_3 = cols.get_internal_sbox();
    let mut state: [AB::Expr; WIDTH] = core::array::from_fn(|i| state[i].into());
    for r in 0..NUM_INTERNAL_ROUNDS {
        // Add the round constant.
        let round = r + NUM_EXTERNAL_ROUNDS / 2;
        let add_rc = if r == 0 {
            state[0].clone()
        } else {
            s0[r - 1].into()
        } + is_real * AB::Expr::from_wrapped_u32(RC_16_30_U32[round][0]);

        let mut sbox_deg_3 = add_rc.clone() * add_rc.clone() * add_rc.clone();
        if let Some(expected) = sbox_3 {
            builder.assert_eq(expected[r], sbox_deg_3);
            sbox_deg_3 = expected[r].into();
        }

        // See `populate_internal_rounds` for why we don't have columns for the sbox output here.
        let sbox_deg_7 = sbox_deg_3.clone() * sbox_deg_3 * add_rc.clone();

        // Apply the linear layer.
        // See `populate_internal_rounds` for why we don't have columns for the new state here.
        state[0] = sbox_deg_7.clone();
        internal_linear_layer(&mut state);

        if r < NUM_INTERNAL_ROUNDS - 1 {
            builder.assert_eq(s0[r], state[0].clone());
        }
    }

    let external_state = cols.get_external_state(NUM_EXTERNAL_ROUNDS / 2);
    for i in 0..WIDTH {
        builder.assert_eq(external_state[i], state[i].clone())
    }
}

impl<F, const DEGREE: usize> BaseAir<F> for Poseidon2WideChip<DEGREE> {
    fn width(&self) -> usize {
        let use_sbox_3 = DEGREE < 7;
        if use_sbox_3 {
            NUM_POSEIDON2_SBOX_COLS
        } else {
            NUM_POSEIDON2_COLS
        }
    }
}

fn eval_mem<AB: SP1RecursionAirBuilder>(builder: &mut AB, local: &Poseidon2MemCols<AB::Var>) {
    // Evaluate all of the memory.
    for i in 0..WIDTH {
        let input_addr = if i < WIDTH / 2 {
            local.left + AB::F::from_canonical_usize(i)
        } else {
            local.right + AB::F::from_canonical_usize(i - WIDTH / 2)
        };

        builder.recursion_eval_memory_access_single(
            local.timestamp,
            input_addr,
            &local.input[i],
            local.is_real,
        );

        let output_addr = local.dst + AB::F::from_canonical_usize(i);
        builder.recursion_eval_memory_access_single(
            local.timestamp + AB::F::from_canonical_usize(1),
            output_addr,
            &local.output[i],
            local.is_real,
        );
    }

    // Constraint that the operands are sent from the CPU table.
    let operands: [AB::Expr; 4] = [
        local.timestamp.into(),
        local.dst.into(),
        local.left.into(),
        local.right.into(),
    ];
    builder.receive_table(
        Opcode::Poseidon2Compress.as_field::<AB::F>(),
        &operands,
        local.is_real,
    );
}

impl<AB, const DEGREE: usize> Air<AB> for Poseidon2WideChip<DEGREE>
where
    AB: SP1RecursionAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let use_sbox_3 = DEGREE < 7;
        let main = builder.main();
        let cols = main.row_slice(0);
        let cols = if use_sbox_3 {
            let cols: &Poseidon2SboxCols<AB::Var> = (*cols).borrow();
            Poseidon2Columns::Wide(*cols)
        } else {
            let cols: &Poseidon2Cols<AB::Var> = (*cols).borrow();
            Poseidon2Columns::Narrow(*cols)
        };

        let memory = cols.get_memory();
        eval_mem(builder, memory);

        // Dummy constraints to normalize to DEGREE.
        let lhs = (0..DEGREE)
            .map(|_| memory.is_real.into())
            .product::<AB::Expr>();
        let rhs = (0..DEGREE)
            .map(|_| memory.is_real.into())
            .product::<AB::Expr>();
        builder.assert_eq(lhs, rhs);

        // Apply the initial round.
        let initial_round_output = {
            let mut initial_round_output: [AB::Expr; WIDTH] =
                core::array::from_fn(|i| (*memory.input[i].value()).into());
            external_linear_layer(&mut initial_round_output);
            initial_round_output
        };
        let state_expr: [AB::Expr; WIDTH] = core::array::from_fn(|i| {
            let state = cols.get_external_state(0);
            state[i].into()
        });
        builder
            .when(memory.is_real)
            .assert_all_eq(state_expr, initial_round_output);

        // Apply the first half of external rounds.
        for r in 0..NUM_EXTERNAL_ROUNDS / 2 {
            eval_external_round(builder, &cols, r, memory.is_real);
        }

        // Apply the internal rounds.
        eval_internal_rounds(builder, &cols, memory.is_real);

        // Apply the second half of external rounds.
        for r in NUM_EXTERNAL_ROUNDS / 2..NUM_EXTERNAL_ROUNDS {
            eval_external_round(builder, &cols, r, memory.is_real);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use crate::poseidon2::Poseidon2Event;
    use crate::poseidon2_wide::external::WIDTH;
    use crate::{poseidon2_wide::external::Poseidon2WideChip, runtime::ExecutionRecord};
    use itertools::Itertools;
    use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::Matrix;
    use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
    use p3_symmetric::Permutation;
    use sp1_core::air::MachineAir;
    use sp1_core::stark::StarkGenericConfig;
    use sp1_core::utils::{inner_perm, uni_stark_prove, uni_stark_verify, BabyBearPoseidon2Inner};

    /// A test generating a trace for a single permutation that checks that the output is correct
    #[test]
    fn generate_trace() {
        const DEGREE: usize = 3;

        let chip = Poseidon2WideChip::<DEGREE>;
        let test_inputs = vec![
            [BabyBear::from_canonical_u32(1); WIDTH],
            [BabyBear::from_canonical_u32(2); WIDTH],
            [BabyBear::from_canonical_u32(3); WIDTH],
            [BabyBear::from_canonical_u32(4); WIDTH],
        ];

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
        for (input, output) in test_inputs.clone().into_iter().zip_eq(expected_outputs) {
            input_exec
                .poseidon2_events
                .push(Poseidon2Event::dummy_from_input(input, output));
        }

        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&input_exec, &mut ExecutionRecord::<BabyBear>::default());

        assert_eq!(trace.height(), test_inputs.len());
    }

    #[test]
    fn poseidon2_wide_prove_babybear() {
        let config = BabyBearPoseidon2Inner::new();
        let mut challenger = config.challenger();

        let chip = Poseidon2WideChip::<3>;

        let test_inputs = (0..1000)
            .map(|i| [BabyBear::from_canonical_u32(i); WIDTH])
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

        let mut challenger = config.challenger();
        let start = Instant::now();
        uni_stark_verify(&config, &chip, &mut challenger, &proof)
            .expect("expected proof to be valid");

        let duration = start.elapsed().as_secs_f64();
        println!("verify duration = {:?}", duration);
    }
}
