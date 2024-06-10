use crate::poseidon2::Poseidon2Event;
// use crate::poseidon2_wide::columns::{
//     Poseidon2ColType, Poseidon2ColTypeMut, Poseidon2Cols, Poseidon2SBoxCols, NUM_POSEIDON2_COLS,
//     NUM_POSEIDON2_SBOX_COLS,
// };
use crate::runtime::Opcode;
use core::borrow::Borrow;
use p3_air::{Air, BaseAir};
use p3_field::{AbstractField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_core::air::{BaseAirBuilder, MachineAir, SP1AirBuilder};
use sp1_core::utils::pad_rows_fixed;
use sp1_primitives::RC_16_30_U32;
use std::borrow::BorrowMut;
use tracing::instrument;

use crate::air::SP1RecursionAirBuilder;
use crate::memory::{MemoryCols, MemoryReadSingleCols, MemoryReadWriteSingleCols};

use crate::poseidon2_wide::{external_linear_layer, internal_linear_layer};
use crate::runtime::{ExecutionRecord, RecursionProgram};

use super::columns::{
    Poseidon2Cols, Poseidon2CompressInput, Poseidon2Permutation, NUM_POSEIDON2_COLS,
};

/// The width of the permutation.
pub const WIDTH: usize = 16;

pub const NUM_EXTERNAL_ROUNDS: usize = 8;
pub const NUM_INTERNAL_ROUNDS: usize = 13;
pub const NUM_ROUNDS: usize = NUM_EXTERNAL_ROUNDS + NUM_INTERNAL_ROUNDS;

/// A chip that implements addition for the opcode ADD.
#[derive(Default)]
pub struct Poseidon2WideChip<const DEGREE: usize> {
    pub fixed_log2_rows: Option<usize>,
}

impl<F: PrimeField32, const DEGREE: usize> MachineAir<F> for Poseidon2WideChip<DEGREE> {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        format!("Poseidon2Wide {}", DEGREE)
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    #[instrument(name = "generate poseidon2 wide trace", level = "debug", skip_all, fields(rows = input.poseidon2_events.len()))]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        let num_columns = NUM_POSEIDON2_COLS;

        for event in &input.poseidon2_events {
            match event {
                Poseidon2Event::Compress(compress_event) => {
                    let mut input_row = vec![F::zero(); NUM_POSEIDON2_COLS];

                    let cols: &mut Poseidon2Cols<F> = input_row.as_mut_slice().borrow_mut();
                    cols.is_compress = F::one();
                    cols.is_syscall = F::one();
                    cols.is_input = F::one();

                    let input_cols = cols.syscall_input.compress_mut();
                    input_cols.clk = compress_event.clk;
                    input_cols.dst_ptr = compress_event.dst;
                    input_cols.left_ptr = compress_event.left;
                    input_cols.right_ptr = compress_event.right;

                    let compress_cols = cols.cols.compress_mut();

                    // Apply the initial round.
                    for i in 0..WIDTH {
                        compress_cols.input[i].populate(&compress_event.input_records[i]);
                    }

                    let p2_perm_cols = &mut compress_cols.permutation_cols;

                    p2_perm_cols.external_rounds_state[0] = compress_event.input;
                    external_linear_layer(&mut p2_perm_cols.external_rounds_state[0]);

                    // Apply the first half of external rounds.
                    for r in 0..NUM_EXTERNAL_ROUNDS / 2 {
                        let next_state = populate_external_round(p2_perm_cols, r);

                        if r == NUM_EXTERNAL_ROUNDS / 2 - 1 {
                            p2_perm_cols.internal_rounds_state = next_state;
                        } else {
                            p2_perm_cols.external_rounds_state[r + 1] = next_state;
                        }
                    }

                    // Apply the internal rounds.
                    p2_perm_cols.external_rounds_state[NUM_EXTERNAL_ROUNDS / 2] =
                        populate_internal_rounds(p2_perm_cols);

                    // Apply the second half of external rounds.
                    for r in NUM_EXTERNAL_ROUNDS / 2..NUM_EXTERNAL_ROUNDS {
                        let next_state = populate_external_round(p2_perm_cols, r);
                        if r == NUM_EXTERNAL_ROUNDS - 1 {
                            for i in 0..WIDTH {
                                p2_perm_cols.output_state[i] = next_state[i];
                                assert_eq!(
                                    compress_event.result_records[i].value[0],
                                    next_state[i]
                                );
                            }
                        } else {
                            p2_perm_cols.external_rounds_state[r + 1] = next_state;
                        }
                    }

                    rows.push(input_row);

                    let mut output_row = vec![F::zero(); NUM_POSEIDON2_COLS];
                    let cols: &mut Poseidon2Cols<F> = output_row.as_mut_slice().borrow_mut();
                    cols.is_compress = F::one();
                    let output_cols = cols.cols.output_mut();

                    for i in 0..WIDTH {
                        output_cols.output_memory[i].populate(&compress_event.result_records[i]);
                    }
                }

                Poseidon2Event::Absorb(_) | Poseidon2Event::Finalize(_) => {
                    todo!();
                } // Poseidon2Event::Absorb(absorb_event) => {
                  //     cols.is_absorb = F::one();

                  //     let input_cols = cols.syscall_input.absorb_mut();
                  //     input_cols.clk = absorb_event.clk;
                  //     input_cols.input_ptr = absorb_event.input_ptr;
                  //     input_cols.len = F::from_canonical_usize(absorb_event.input_len);
                  //     input_cols.hash_num = absorb_event.hash_num;
                  // }

                  // Poseidon2Event::Finalize(finalize_event) => {
                  //     cols.is_finalize = F::one();

                  //     let input_cols = cols.syscall_input.finalize_mut();
                  //     input_cols.clk = finalize_event.clk;
                  //     input_cols.hash_num = finalize_event.hash_num;
                  //     input_cols.output_ptr = finalize_event.output_ptr;
                  // }
            }

            //     for i in 0..WIDTH {
            //         memory.output[i].populate(&event.result_records[i]);
            //     }
        }

        // Pad the trace to a power of two.
        pad_rows_fixed(
            &mut rows,
            || vec![F::zero(); num_columns],
            self.fixed_log2_rows,
        );

        // Convert the trace to a row major matrix.
        let trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), num_columns);

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
    p2_perm_cols: &mut Poseidon2Permutation<F>,
    r: usize,
) -> [F; WIDTH] {
    let mut state = {
        let round_state: &mut [F; WIDTH] = p2_perm_cols.external_rounds_state[r].borrow_mut();

        // Add round constants.
        //
        // Optimization: Since adding a constant is a degree 1 operation, we can avoid adding
        // columns for it, and instead include it in the constraint for the x^3 part of the sbox.
        let round = if r < NUM_EXTERNAL_ROUNDS / 2 {
            r
        } else {
            r + NUM_INTERNAL_ROUNDS
        };
        let mut add_rc = *round_state;
        for i in 0..WIDTH {
            add_rc[i] += F::from_wrapped_u32(RC_16_30_U32[round][i]);
        }

        // Apply the sboxes.
        // Optimization: since the linear layer that comes after the sbox is degree 1, we can
        // avoid adding columns for the result of the sbox, and instead include the x^3 -> x^7
        // part of the sbox in the constraint for the linear layer
        let mut sbox_deg_7: [F; 16] = [F::zero(); WIDTH];
        let mut sbox_deg_3: [F; 16] = [F::zero(); WIDTH];
        for i in 0..WIDTH {
            sbox_deg_3[i] = add_rc[i] * add_rc[i] * add_rc[i];
            sbox_deg_7[i] = sbox_deg_3[i] * sbox_deg_3[i] * add_rc[i];
        }

        p2_perm_cols.external_rounds_sbox[r] = sbox_deg_3;

        sbox_deg_7
    };

    // Apply the linear layer.
    external_linear_layer(&mut state);
    state
}

fn populate_internal_rounds<F: PrimeField32>(
    p2_perm_cols: &mut Poseidon2Permutation<F>,
) -> [F; WIDTH] {
    let mut state: [F; WIDTH] = p2_perm_cols.internal_rounds_state;
    let mut sbox_deg_3: [F; NUM_INTERNAL_ROUNDS] = [F::zero(); NUM_INTERNAL_ROUNDS];
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
        internal_linear_layer(&mut state);

        // Optimization: since we're only applying the sbox to the 0th state element, we only
        // need to have columns for the 0th state element at every step. This is because the
        // linear layer is degree 1, so all state elements at the end can be expressed as a
        // degree-3 polynomial of the state at the beginning of the internal rounds and the 0th
        // state element at rounds prior to the current round
        if r < NUM_INTERNAL_ROUNDS - 1 {
            p2_perm_cols.internal_rounds_s0[r] = state[0];
        }
    }

    let ret_state = state;

    p2_perm_cols.internal_rounds_sbox = sbox_deg_3;

    ret_state
}

fn eval_external_round<AB: SP1AirBuilder>(
    builder: &mut AB,
    perm_cols: &Poseidon2Permutation<AB::Var>,
    r: usize,
    is_real: AB::Expr,
) {
    let external_state = perm_cols.external_rounds_state[r];

    // Add the round constants.
    let round = if r < NUM_EXTERNAL_ROUNDS / 2 {
        r
    } else {
        r + NUM_INTERNAL_ROUNDS
    };
    let add_rc: [AB::Expr; WIDTH] = core::array::from_fn(|i| {
        external_state[i].into() + is_real.clone() * AB::F::from_wrapped_u32(RC_16_30_U32[round][i])
    });

    // Apply the sboxes.
    // See `populate_external_round` for why we don't have columns for the sbox output here.
    let mut sbox_deg_7: [AB::Expr; WIDTH] = core::array::from_fn(|_| AB::Expr::zero());
    let mut sbox_deg_3: [AB::Expr; WIDTH] = core::array::from_fn(|_| AB::Expr::zero());
    for i in 0..WIDTH {
        sbox_deg_3[i] = add_rc[i].clone() * add_rc[i].clone() * add_rc[i].clone();

        builder.assert_eq(
            perm_cols.external_rounds_sbox[r][i].into(),
            sbox_deg_3[i].clone(),
        );

        sbox_deg_7[i] = sbox_deg_3[i].clone() * sbox_deg_3[i].clone() * add_rc[i].clone();
    }

    // Apply the linear layer.
    let mut state = sbox_deg_7;
    external_linear_layer(&mut state);

    let next_state_cols = if r == NUM_EXTERNAL_ROUNDS / 2 - 1 {
        perm_cols.internal_rounds_state
    } else if r == NUM_EXTERNAL_ROUNDS - 1 {
        perm_cols.output_state
    } else {
        perm_cols.external_rounds_state[r + 1]
    };
    for i in 0..WIDTH {
        builder.assert_eq(next_state_cols[i], state[i].clone());
    }
}

fn eval_internal_rounds<AB: SP1AirBuilder>(
    builder: &mut AB,
    perm_cols: &Poseidon2Permutation<AB::Var>,
    is_real: AB::Expr,
) {
    let state = &perm_cols.internal_rounds_state;
    let s0 = perm_cols.internal_rounds_s0;
    let mut state: [AB::Expr; WIDTH] = core::array::from_fn(|i| state[i].into());
    for r in 0..NUM_INTERNAL_ROUNDS {
        // Add the round constant.
        let round = r + NUM_EXTERNAL_ROUNDS / 2;
        let add_rc = if r == 0 {
            state[0].clone()
        } else {
            s0[r - 1].into()
        } + is_real.clone() * AB::Expr::from_wrapped_u32(RC_16_30_U32[round][0]);

        let sbox_deg_3 = add_rc.clone() * add_rc.clone() * add_rc.clone();
        builder.assert_eq(perm_cols.internal_rounds_sbox[r], sbox_deg_3.clone());

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

    let external_state = perm_cols.external_rounds_state[NUM_EXTERNAL_ROUNDS / 2];
    for i in 0..WIDTH {
        builder.assert_eq(external_state[i], state[i].clone())
    }
}

impl<F, const DEGREE: usize> BaseAir<F> for Poseidon2WideChip<DEGREE> {
    fn width(&self) -> usize {
        NUM_POSEIDON2_COLS
    }
}

fn eval_mem<AB: SP1RecursionAirBuilder>(
    builder: &mut AB,
    syscall_params: &Poseidon2CompressInput<AB::Var>,
    input: &[MemoryReadSingleCols<AB::Var>; WIDTH],
    output: &[MemoryReadWriteSingleCols<AB::Var>; WIDTH],
    is_syscall: AB::Var,
    is_input: AB::Var,
) {
    // Evaluate all of the memory.
    for i in 0..WIDTH {
        let input_addr = if i < WIDTH / 2 {
            syscall_params.left_ptr + AB::F::from_canonical_usize(i)
        } else {
            syscall_params.right_ptr + AB::F::from_canonical_usize(i - WIDTH / 2)
        };

        builder.recursion_eval_memory_access_single(
            syscall_params.clk,
            input_addr,
            &input[i],
            is_input,
        );

        let output_addr = syscall_params.dst_ptr + AB::F::from_canonical_usize(i);
        builder.recursion_eval_memory_access_single(
            syscall_params.clk + AB::F::from_canonical_usize(1),
            output_addr,
            &output[i],
            AB::Expr::one() - is_input,
        );
    }

    // Constraint that the operands are sent from the CPU table.
    let operands: [AB::Expr; 4] = [
        syscall_params.clk.into(),
        syscall_params.dst_ptr.into(),
        syscall_params.left_ptr.into(),
        syscall_params.right_ptr.into(),
    ];
    builder.receive_table(
        Opcode::Poseidon2Compress.as_field::<AB::F>(),
        &operands,
        is_syscall,
    );
}

impl<AB, const DEGREE: usize> Air<AB> for Poseidon2WideChip<DEGREE>
where
    AB: SP1RecursionAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        let local = main.row_slice(0);
        let local: &Poseidon2Cols<AB::Var> = (*local).borrow();

        let syscall_input = local.syscall_input.compress();
        let compress_cols = local.cols.compress();
        let output_cols = local.cols.output();

        let is_real = local.is_absorb + local.is_compress + local.is_finalize;
        let is_syscall = local.is_syscall;
        let is_input = local.is_input;
        let do_perm = local.is_compress * is_syscall;

        eval_mem(
            builder,
            syscall_input,
            &compress_cols.input,
            &output_cols.output_memory,
            is_syscall,
            is_input,
        );

        // // Apply the initial round.
        // let initial_round_output = {
        //     let mut initial_round_output: [AB::Expr; WIDTH] =
        //         core::array::from_fn(|i| (*compress_cols.input[i].value()).into());
        //     external_linear_layer(&mut initial_round_output);
        //     initial_round_output
        // };
        // let external_round_0_state: [AB::Expr; WIDTH] = core::array::from_fn(|i| {
        //     let state = compress_cols.permutation_cols.external_rounds_state[0];
        //     state[i].into()
        // });
        // builder
        //     .when(do_perm.clone())
        //     .assert_all_eq(external_round_0_state.clone(), initial_round_output);

        // // Apply the first half of external rounds.
        // for r in 0..NUM_EXTERNAL_ROUNDS / 2 {
        //     eval_external_round(builder, &compress_cols.permutation_cols, r, do_perm.clone());
        // }

        // // Apply the internal rounds.
        // eval_internal_rounds(builder, &compress_cols.permutation_cols, do_perm.clone());

        // // Apply the second half of external rounds.
        // for r in NUM_EXTERNAL_ROUNDS / 2..NUM_EXTERNAL_ROUNDS {
        //     eval_external_round(builder, &compress_cols.permutation_cols, r, do_perm.clone());
        // }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use crate::poseidon2::{Poseidon2CompressEvent, Poseidon2Event};
    use crate::poseidon2_wide::external::WIDTH;
    use crate::{poseidon2_wide::external::Poseidon2WideChip, runtime::ExecutionRecord};
    use itertools::Itertools;
    use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
    use p3_symmetric::Permutation;
    use sp1_core::air::MachineAir;
    use sp1_core::stark::StarkGenericConfig;
    use sp1_core::utils::{inner_perm, uni_stark_prove, uni_stark_verify, BabyBearPoseidon2};
    use zkhash::ark_ff::UniformRand;

    fn generate_trace_degree<const DEGREE: usize>() {
        let chip = Poseidon2WideChip::<DEGREE> {
            fixed_log2_rows: None,
        };

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
            input_exec.poseidon2_events.push(Poseidon2Event::Compress(
                Poseidon2CompressEvent::dummy_from_input(input, output),
            ));
        }

        // Generate trace will assert for the expected outputs.
        chip.generate_trace(&input_exec, &mut ExecutionRecord::<BabyBear>::default());
    }

    /// A test generating a trace for a single permutation that checks that the output is correct
    #[test]
    fn generate_trace() {
        generate_trace_degree::<3>();
        // generate_trace_degree::<7>();
    }

    fn poseidon2_wide_prove_babybear_degree<const DEGREE: usize>(
        inputs: Vec<[BabyBear; 16]>,
        outputs: Vec<[BabyBear; 16]>,
    ) {
        let chip = Poseidon2WideChip::<DEGREE> {
            fixed_log2_rows: None,
        };
        let mut input_exec = ExecutionRecord::<BabyBear>::default();
        for (input, output) in inputs.into_iter().zip_eq(outputs) {
            input_exec.poseidon2_events.push(Poseidon2Event::Compress(
                Poseidon2CompressEvent::dummy_from_input(input, output),
            ));
        }
        let trace: RowMajorMatrix<BabyBear> =
            chip.generate_trace(&input_exec, &mut ExecutionRecord::<BabyBear>::default());

        let config = BabyBearPoseidon2::compressed();
        let mut challenger = config.challenger();

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

    #[test]
    fn poseidon2_wide_prove_babybear_success() {
        let rng = &mut rand::thread_rng();

        let test_inputs: Vec<[BabyBear; 16]> = (0..1000)
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

        poseidon2_wide_prove_babybear_degree::<3>(test_inputs.clone(), expected_outputs.clone());
        // poseidon2_wide_prove_babybear_degree::<7>(test_inputs, expected_outputs);
    }

    #[test]
    #[should_panic]
    fn poseidon2_wide_prove_babybear_failure() {
        let rng = &mut rand::thread_rng();

        let test_inputs = (0..1000)
            .map(|i| [BabyBear::from_canonical_u32(i); WIDTH])
            .collect_vec();

        let bad_outputs: Vec<[BabyBear; 16]> = (0..1000)
            .map(|_| core::array::from_fn(|_| BabyBear::rand(rng)))
            .collect_vec();

        poseidon2_wide_prove_babybear_degree::<3>(test_inputs.clone(), bad_outputs.clone());
        // poseidon2_wide_prove_babybear_degree::<7>(test_inputs, bad_outputs);
    }
}
