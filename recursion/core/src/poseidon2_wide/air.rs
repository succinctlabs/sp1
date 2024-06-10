use std::{array, borrow::Borrow};

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_matrix::Matrix;
use sp1_core::air::{BaseAirBuilder, SP1AirBuilder};
use sp1_primitives::RC_16_30_U32;

use crate::{
    air::SP1RecursionAirBuilder,
    memory::{MemoryCols, MemoryReadSingleCols, MemoryReadWriteSingleCols},
    runtime::Opcode,
};

use super::{
    columns::{Poseidon2Cols, Poseidon2CompressInput, Poseidon2Permutation, NUM_POSEIDON2_COLS},
    external_linear_layer, internal_linear_layer, Poseidon2WideChip, NUM_EXTERNAL_ROUNDS,
    NUM_INTERNAL_ROUNDS, WIDTH,
};

fn eval_external_round<AB: SP1AirBuilder>(
    builder: &mut AB,
    perm_cols: &Poseidon2Permutation<AB::Var>,
    r: usize,
    do_perm: AB::Var,
) {
    let external_state = perm_cols.external_rounds_state[r];

    // Add the round constants.
    let round = if r < NUM_EXTERNAL_ROUNDS / 2 {
        r
    } else {
        r + NUM_INTERNAL_ROUNDS
    };
    let add_rc: [AB::Expr; WIDTH] = core::array::from_fn(|i| {
        external_state[i].into() + do_perm * AB::F::from_wrapped_u32(RC_16_30_U32[round][i])
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

        sbox_deg_7[i] = perm_cols.external_rounds_sbox[r][i]
            * perm_cols.external_rounds_sbox[r][i]
            * add_rc[i].clone();
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
    do_perm: AB::Var,
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
        } + do_perm * AB::Expr::from_wrapped_u32(RC_16_30_U32[round][0]);

        let sbox_deg_3 = add_rc.clone() * add_rc.clone() * add_rc.clone();
        builder.assert_eq(perm_cols.internal_rounds_sbox[r], sbox_deg_3.clone());

        // See `populate_internal_rounds` for why we don't have columns for the sbox output here.
        let sbox_deg_7 =
            perm_cols.internal_rounds_sbox[r] * perm_cols.internal_rounds_sbox[r] * add_rc.clone();

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

fn eval_control_flow<AB: SP1RecursionAirBuilder>(
    builder: &mut AB,
    local: &Poseidon2Cols<AB::Var>,
    next: &Poseidon2Cols<AB::Var>,
) {
    builder.assert_bool(local.is_compress);
    builder.assert_bool(local.is_absorb);
    builder.assert_bool(local.is_finalize);
    builder.assert_bool(local.is_compress + local.is_absorb + local.is_finalize);

    builder.assert_bool(local.is_syscall);
    builder.assert_bool(local.is_input);
    builder.assert_bool(local.do_perm);

    // Ensure the first row is real and is a syscall row.
    builder
        .when_first_row()
        .assert_one(local.is_compress + local.is_absorb + local.is_finalize);
    builder.when_first_row().assert_one(local.is_syscall);

    let mut transition_builder = builder.when_transition();
    let mut compress_builder = transition_builder.when(local.is_compress);
    let mut compress_syscall_builder = compress_builder.when(local.is_syscall);

    compress_syscall_builder.assert_one(local.is_input);
    compress_syscall_builder.assert_one(local.do_perm);

    compress_syscall_builder.assert_one(next.is_compress);
    compress_syscall_builder.assert_zero(next.is_syscall);
    compress_syscall_builder.assert_zero(next.is_input);
    compress_syscall_builder.assert_zero(next.do_perm);

    // Verify that the syscall parameters are copied for all of the rows.
    let local_syscall_input = local.syscall_input.compress();
    let next_syscall_input = next.syscall_input.compress();
    compress_syscall_builder.assert_eq(local_syscall_input.clk, next_syscall_input.clk);
    compress_syscall_builder.assert_eq(local_syscall_input.dst_ptr, next_syscall_input.dst_ptr);
    compress_syscall_builder.assert_eq(local_syscall_input.left_ptr, next_syscall_input.left_ptr);
    compress_syscall_builder.assert_eq(local_syscall_input.right_ptr, next_syscall_input.right_ptr);
}

fn eval_mem<AB: SP1RecursionAirBuilder>(
    builder: &mut AB,
    syscall_params: &Poseidon2CompressInput<AB::Var>,
    input_memory: &[MemoryReadSingleCols<AB::Var>; WIDTH],
    output_memory: &[MemoryReadWriteSingleCols<AB::Var>; WIDTH],
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
            &input_memory[i],
            is_input,
        );

        let output_addr = syscall_params.dst_ptr + AB::F::from_canonical_usize(i);
        builder.recursion_eval_memory_access_single(
            syscall_params.clk + AB::F::from_canonical_usize(1),
            output_addr,
            &output_memory[i],
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

fn eval_perm<AB: SP1RecursionAirBuilder>(
    builder: &mut AB,
    input: [AB::Var; WIDTH],
    perm_cols: &Poseidon2Permutation<AB::Var>,
    do_perm: AB::Var,
) {
    // Apply the initial round.
    let initial_round_output = {
        let mut initial_round_output: [AB::Expr; WIDTH] = core::array::from_fn(|i| input[i].into());
        external_linear_layer(&mut initial_round_output);
        initial_round_output
    };
    let external_round_0_state: [AB::Expr; WIDTH] = core::array::from_fn(|i| {
        let state = perm_cols.external_rounds_state[0];
        state[i].into()
    });
    builder
        .when(do_perm)
        .assert_all_eq(external_round_0_state.clone(), initial_round_output);

    // Apply the first half of external rounds.
    for r in 0..NUM_EXTERNAL_ROUNDS / 2 {
        eval_external_round(builder, perm_cols, r, do_perm);
    }

    // Apply the internal rounds.
    eval_internal_rounds(builder, perm_cols, do_perm);

    // Apply the second half of external rounds.
    for r in NUM_EXTERNAL_ROUNDS / 2..NUM_EXTERNAL_ROUNDS {
        eval_external_round(builder, perm_cols, r, do_perm);
    }
}

impl<AB, const DEGREE: usize> Air<AB> for Poseidon2WideChip<DEGREE>
where
    AB: SP1RecursionAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        let local = main.row_slice(0);
        let local: &Poseidon2Cols<AB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &Poseidon2Cols<AB::Var> = (*next).borrow();

        let syscall_input = local.syscall_input.compress();
        let compress_cols = local.opcode_specific_cols.compress();
        let local_output_cols = local.opcode_specific_cols.output();
        let next_output_cols = next.opcode_specific_cols.output();

        let is_syscall = local.is_syscall;
        let is_input = local.is_input;
        let do_perm = local.do_perm;

        // Check that all the control flow columns are correct.
        eval_control_flow(builder, local, next);

        // Check that all the memory access columns are correct.
        eval_mem(
            builder,
            syscall_input,
            &compress_cols.input,
            &local_output_cols.output_memory,
            is_syscall,
            is_input,
        );

        // Check that the permutation columns are correct.
        let perm_cols = local.permutation_cols;
        eval_perm(
            builder,
            array::from_fn(|i| *compress_cols.input[i].value()),
            &perm_cols,
            do_perm,
        );

        // Check that the permutation output is copied to the next row correctly.
        let next_output: [AB::Var; WIDTH] =
            array::from_fn(|i| *next_output_cols.output_memory[i].value());
        builder
            .when(do_perm)
            .assert_all_eq(perm_cols.output_state, next_output);
    }
}
