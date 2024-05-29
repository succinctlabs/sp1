use core::borrow::Borrow;
use core::mem::size_of;
use p3_air::AirBuilder;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_matrix::Matrix;
use sp1_core::air::{BaseAirBuilder, ExtensionAirBuilder, SP1AirBuilder};
use sp1_primitives::RC_16_30_U32;
use std::ops::Add;

use crate::air::{RecursionInteractionAirBuilder, RecursionMemoryAirBuilder};
use crate::memory::MemoryCols;
use crate::poseidon2_wide::{apply_m_4, internal_linear_layer};
use crate::runtime::Opcode;

use super::columns::Poseidon2Cols;

/// The number of main trace columns for `AddChip`.
pub const NUM_POSEIDON2_COLS: usize = size_of::<Poseidon2Cols<u8>>();

/// The width of the permutation.
pub const WIDTH: usize = 16;

/// A chip that implements addition for the opcode ADD.
#[derive(Default)]
pub struct Poseidon2Chip {
    pub fixed_log2_rows: Option<usize>,
}

impl<F> BaseAir<F> for Poseidon2Chip {
    fn width(&self) -> usize {
        NUM_POSEIDON2_COLS
    }
}

impl Poseidon2Chip {
    pub fn eval_poseidon2<AB: BaseAirBuilder + ExtensionAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Poseidon2Cols<AB::Var>,
        next: &Poseidon2Cols<AB::Var>,
        receive_table: AB::Var,
        memory_access: AB::Expr,
    ) {
        const NUM_ROUNDS_F: usize = 8;
        const NUM_ROUNDS_P: usize = 13;
        const ROUNDS_F_1_BEGINNING: usize = 2; // Previous rounds are memory read and initial.
        const ROUNDS_P_BEGINNING: usize = ROUNDS_F_1_BEGINNING + NUM_ROUNDS_F / 2;
        const ROUNDS_P_END: usize = ROUNDS_P_BEGINNING + NUM_ROUNDS_P;
        const ROUND_F_2_END: usize = ROUNDS_P_END + NUM_ROUNDS_F / 2;

        let is_memory_read = local.rounds[0];
        let is_initial = local.rounds[1];

        // First half of the external rounds.
        let mut is_external_layer = (ROUNDS_F_1_BEGINNING..ROUNDS_P_BEGINNING)
            .map(|i| local.rounds[i].into())
            .sum::<AB::Expr>();

        // Second half of the external rounds.
        is_external_layer += (ROUNDS_P_END..ROUND_F_2_END)
            .map(|i| local.rounds[i].into())
            .sum::<AB::Expr>();
        let is_internal_layer = (ROUNDS_P_BEGINNING..ROUNDS_P_END)
            .map(|i| local.rounds[i].into())
            .sum::<AB::Expr>();
        let is_memory_write = local.rounds[local.rounds.len() - 1];

        self.eval_mem(
            builder,
            local,
            next,
            is_memory_read,
            is_memory_write,
            memory_access,
        );

        self.eval_computation(
            builder,
            local,
            next,
            is_initial.into(),
            is_external_layer.clone(),
            is_internal_layer.clone(),
            NUM_ROUNDS_F + NUM_ROUNDS_P + 1,
        );

        self.eval_syscall(builder, local, receive_table);

        // Range check all flags.
        for i in 0..local.rounds.len() {
            builder.assert_bool(local.rounds[i]);
        }
        builder.assert_bool(
            is_memory_read + is_initial + is_external_layer + is_internal_layer + is_memory_write,
        );
    }

    fn eval_mem<AB: BaseAirBuilder + ExtensionAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Poseidon2Cols<AB::Var>,
        next: &Poseidon2Cols<AB::Var>,
        is_memory_read: AB::Var,
        is_memory_write: AB::Var,
        memory_access: AB::Expr,
    ) {
        let memory_access_cols = local.round_specific_cols.memory_access();
        builder
            .when(is_memory_read)
            .assert_eq(local.left_input, memory_access_cols.addr_first_half);
        builder
            .when(is_memory_read)
            .assert_eq(local.right_input, memory_access_cols.addr_second_half);

        builder
            .when(is_memory_write)
            .assert_eq(local.dst_input, memory_access_cols.addr_first_half);
        builder.when(is_memory_write).assert_eq(
            local.dst_input + AB::F::from_canonical_usize(WIDTH / 2),
            memory_access_cols.addr_second_half,
        );

        for i in 0..WIDTH {
            let addr = if i < WIDTH / 2 {
                memory_access_cols.addr_first_half + AB::Expr::from_canonical_usize(i)
            } else {
                memory_access_cols.addr_second_half + AB::Expr::from_canonical_usize(i - WIDTH / 2)
            };
            builder.recursion_eval_memory_access_single(
                local.clk + AB::Expr::one() * is_memory_write,
                addr,
                &memory_access_cols.mem_access[i],
                memory_access.clone(),
            );
        }

        // For the memory read round, need to connect the memory val to the input of the next
        // computation round.
        let next_computation_col = next.round_specific_cols.computation();
        for i in 0..WIDTH {
            builder.when_transition().when(is_memory_read).assert_eq(
                *memory_access_cols.mem_access[i].value(),
                next_computation_col.input[i],
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_computation<AB: BaseAirBuilder + ExtensionAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Poseidon2Cols<AB::Var>,
        next: &Poseidon2Cols<AB::Var>,
        is_initial: AB::Expr,
        is_external_layer: AB::Expr,
        is_internal_layer: AB::Expr,
        rounds: usize,
    ) {
        let computation_cols = local.round_specific_cols.computation();

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
            let mut result: AB::Expr = computation_cols.input[i].into();
            for r in 0..rounds {
                if i == 0 {
                    result += local.rounds[r + 2]
                        * constants[r][i]
                        * (is_external_layer.clone() + is_internal_layer.clone());
                } else {
                    result += local.rounds[r + 2] * constants[r][i] * is_external_layer.clone();
                }
            }
            builder
                .when(is_initial.clone() + is_external_layer.clone() + is_internal_layer.clone())
                .assert_eq(result, computation_cols.add_rc[i]);
        }

        // Apply the sbox.
        //
        // To differentiate between external and internal layers, we use a masking operation
        // to only apply the state change to the first element for internal layers.
        for i in 0..WIDTH {
            let sbox_deg_3 = computation_cols.add_rc[i]
                * computation_cols.add_rc[i]
                * computation_cols.add_rc[i];
            let sbox_deg_7 = sbox_deg_3.clone() * sbox_deg_3.clone() * computation_cols.add_rc[i];
            builder
                .when(is_initial.clone() + is_external_layer.clone() + is_internal_layer.clone())
                .assert_eq(sbox_deg_7, computation_cols.sbox_deg_7[i]);
        }
        let sbox_result: [AB::Expr; WIDTH] = computation_cols
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
                    is_initial.clone() * computation_cols.add_rc[i]
                        + (is_external_layer.clone() + is_internal_layer.clone()) * *x
                }
                // The masked result of the rest of the sbox.
                //
                // Initial layer: Pass through the result of the round constant layer.
                // External layer: Pass through the result of the sbox layer.
                // Internal layer: Pass through the result of the round constant layer.
                else {
                    (is_initial.clone() + is_internal_layer.clone()) * computation_cols.add_rc[i]
                        + (is_external_layer.clone()) * *x
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
                    .when(is_external_layer.clone() + is_initial.clone())
                    .assert_eq(state[i].clone(), computation_cols.output[i]);
            }
        }

        // INTERNAL LAYER
        {
            // Use a simple matrix multiplication as the permutation.
            let mut state: [AB::Expr; WIDTH] = sbox_result.clone();
            internal_linear_layer(&mut state);
            builder
                .when(is_internal_layer.clone())
                .assert_all_eq(state.clone(), computation_cols.output);
        }

        // Assert that the round's output values are equal the the next round's input values.  For the
        // last computation round, assert athat the output values are equal to the output memory values.
        let next_row_computation = next.round_specific_cols.computation();
        let next_row_memory_access = next.round_specific_cols.memory_access();
        for i in 0..WIDTH {
            let next_round_value = builder.if_else(
                local.rounds[22],
                *next_row_memory_access.mem_access[i].value(),
                next_row_computation.input[i],
            );

            builder
                .when_transition()
                .when(is_initial.clone() + is_external_layer.clone() + is_internal_layer.clone())
                .assert_eq(computation_cols.output[i], next_round_value);
        }
    }

    fn eval_syscall<AB: BaseAirBuilder + ExtensionAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Poseidon2Cols<AB::Var>,
        receive_table: AB::Var,
    ) {
        // Constraint that the operands are sent from the CPU table.
        let operands: [AB::Expr; 4] = [
            local.clk.into(),
            local.dst_input.into(),
            local.left_input.into(),
            local.right_input.into(),
        ];
        builder.receive_table(
            Opcode::Poseidon2Compress.as_field::<AB::F>(),
            &operands,
            receive_table,
        );
    }

    pub const fn do_receive_table<T: Copy>(local: &Poseidon2Cols<T>) -> T {
        local.rounds[0]
    }

    pub fn do_memory_access<T: Copy + Add<T, Output = Output>, Output>(
        local: &Poseidon2Cols<T>,
    ) -> Output {
        local.rounds[0] + local.rounds[23]
    }
}

impl<AB> Air<AB> for Poseidon2Chip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Poseidon2Cols<AB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &Poseidon2Cols<AB::Var> = (*next).borrow();

        self.eval_poseidon2::<AB>(
            builder,
            local,
            next,
            Self::do_receive_table::<AB::Var>(local),
            Self::do_memory_access::<AB::Var, AB::Expr>(local),
        );
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use std::borrow::Borrow;
    use std::time::Instant;
    use zkhash::ark_ff::UniformRand;

    use p3_baby_bear::BabyBear;
    use p3_baby_bear::DiffusionMatrixBabyBear;
    use p3_matrix::{dense::RowMajorMatrix, Matrix};
    use p3_poseidon2::Poseidon2;
    use p3_poseidon2::Poseidon2ExternalMatrixGeneral;
    use sp1_core::stark::StarkGenericConfig;
    use sp1_core::utils::inner_perm;
    use sp1_core::{
        air::MachineAir,
        utils::{uni_stark_prove, uni_stark_verify, BabyBearPoseidon2},
    };

    use crate::{
        poseidon2::{Poseidon2Chip, Poseidon2Event},
        runtime::ExecutionRecord,
    };
    use p3_symmetric::Permutation;

    use super::Poseidon2Cols;

    const ROWS_PER_PERMUTATION: usize = 24;

    #[test]
    fn generate_trace() {
        let chip = Poseidon2Chip {
            fixed_log2_rows: None,
        };

        let rng = &mut rand::thread_rng();

        let test_inputs: Vec<[BabyBear; 16]> = (0..16)
            .map(|_| core::array::from_fn(|_| BabyBear::rand(rng)))
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
        for (input, output) in test_inputs.into_iter().zip_eq(expected_outputs.clone()) {
            input_exec
                .poseidon2_events
                .push(Poseidon2Event::dummy_from_input(input, output));
        }

        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&input_exec, &mut ExecutionRecord::<BabyBear>::default());

        for (i, expected_output) in expected_outputs.iter().enumerate() {
            let row = trace.row(ROWS_PER_PERMUTATION * (i + 1) - 2).collect_vec();
            let cols: &Poseidon2Cols<BabyBear> = row.as_slice().borrow();
            let computation_cols = cols.round_specific_cols.computation();
            assert_eq!(expected_output, &computation_cols.output);
        }
    }

    fn prove_babybear(inputs: Vec<[BabyBear; 16]>, outputs: Vec<[BabyBear; 16]>) {
        let mut input_exec = ExecutionRecord::<BabyBear>::default();
        for (input, output) in inputs.into_iter().zip_eq(outputs) {
            input_exec
                .poseidon2_events
                .push(Poseidon2Event::dummy_from_input(input, output));
        }

        let chip = Poseidon2Chip {
            fixed_log2_rows: None,
        };
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&input_exec, &mut ExecutionRecord::<BabyBear>::default());
        println!(
            "trace dims is width: {:?}, height: {:?}",
            trace.width(),
            trace.height()
        );

        let start = Instant::now();
        let config = BabyBearPoseidon2::compressed();
        let mut challenger = config.challenger();
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

    #[test]
    fn prove_babybear_success() {
        let rng = &mut rand::thread_rng();

        let test_inputs: Vec<[BabyBear; 16]> = (0..16)
            .map(|_| core::array::from_fn(|_| BabyBear::rand(rng)))
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

        prove_babybear(test_inputs, expected_outputs)
    }

    #[test]
    #[should_panic]
    fn prove_babybear_failure() {
        let rng = &mut rand::thread_rng();
        let test_inputs: Vec<[BabyBear; 16]> = (0..16)
            .map(|_| core::array::from_fn(|_| BabyBear::rand(rng)))
            .collect_vec();

        let bad_outputs: Vec<[BabyBear; 16]> = (0..16)
            .map(|_| core::array::from_fn(|_| BabyBear::rand(rng)))
            .collect_vec();

        prove_babybear(test_inputs, bad_outputs)
    }
}
