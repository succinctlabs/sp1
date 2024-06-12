use std::{array, borrow::Borrow, ops::Deref};

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_matrix::Matrix;
use sp1_core::air::BaseAirBuilder;
use sp1_primitives::RC_16_30_U32;

use crate::{air::SP1RecursionAirBuilder, memory::MemoryCols, runtime::Opcode};

use super::{
    columns::{
        control_flow::ControlFlow, opcode_workspace::OpcodeWorkspace, permutation::Permutation,
        syscall_params::SyscallParams, Poseidon2, Poseidon2Degree3, Poseidon2Degree9,
        NUM_POSEIDON2_DEGREE3_COLS, NUM_POSEIDON2_DEGREE9_COLS,
    },
    external_linear_layer, internal_linear_layer, Poseidon2WideChip, NUM_EXTERNAL_ROUNDS,
    NUM_INTERNAL_ROUNDS, WIDTH,
};

impl<F, const DEGREE: usize> BaseAir<F> for Poseidon2WideChip<DEGREE> {
    fn width(&self) -> usize {
        if DEGREE == 3 {
            NUM_POSEIDON2_DEGREE3_COLS
        } else if DEGREE == 9 {
            NUM_POSEIDON2_DEGREE9_COLS
        } else {
            panic!("Unsupported degree: {}", DEGREE);
        }
    }
}

impl<AB, const DEGREE: usize> Air<AB> for Poseidon2WideChip<DEGREE>
where
    AB: SP1RecursionAirBuilder,
    AB::Var: 'static,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_ptr = Self::convert::<AB>(main.row_slice(0));
        let next_ptr = Self::convert::<AB>(main.row_slice(1));

        // Check that all the control flow columns are correct.
        let local_control_flow = local_ptr.control_flow();
        let next_control_flow = next_ptr.control_flow();
        self.eval_control_flow(builder, local_control_flow, next_control_flow);

        // Check that the syscall columns are correct.
        let local_syscall = local_ptr.syscall_params();
        let next_syscall = next_ptr.syscall_params();
        self.eval_syscall_params(
            builder,
            local_syscall,
            next_syscall,
            local_control_flow.is_compress,
            local_control_flow.is_syscall,
        );

        // Check that all the memory access columns are correct.
        let local_opcode_workspace = local_ptr.opcode_workspace();
        self.eval_mem(
            builder,
            local_syscall,
            local_opcode_workspace,
            local_control_flow.is_input,
            local_control_flow.is_output,
        );

        // Check that the permutation columns are correct.
        let local_perm_cols = local_ptr.permutation();
        self.eval_perm(
            builder,
            array::from_fn(|i| *local_opcode_workspace.compress().input[i].value()),
            local_perm_cols.as_ref(),
            local_control_flow.do_perm,
        );

        // // Check that the permutation output is copied to the next row correctly.
        // let next_opcode_workspace = next_ptr.opcode_workspace();
        // let next_output: [AB::Var; WIDTH] =
        //     array::from_fn(|i| *next_opcode_workspace.output().output_memory[i].value());
        // builder
        //     .when(local_control_flow.do_perm)
        //     .assert_all_eq(*local_perm_cols.output_state(), next_output);
    }
}

impl<'a, const DEGREE: usize> Poseidon2WideChip<DEGREE> {
    fn convert<AB: SP1RecursionAirBuilder>(
        row: impl Deref<Target = [AB::Var]>,
    ) -> Box<dyn Poseidon2<'a, AB::Var> + 'a>
    where
        AB::Var: 'a,
    {
        if DEGREE == 3 {
            let convert: &Poseidon2Degree3<AB::Var> = (*row).borrow();
            Box::new(*convert)
        } else if DEGREE == 9 {
            let convert: &Poseidon2Degree9<AB::Var> = (*row).borrow();
            Box::new(*convert)
        } else {
            panic!("Unsupported degree");
        }
    }

    fn eval_control_flow<AB: SP1RecursionAirBuilder>(
        &self,
        builder: &mut AB,
        local_control_flow: &ControlFlow<AB::Var>,
        next_control_flow: &ControlFlow<AB::Var>,
    ) {
        builder.assert_bool(local_control_flow.is_compress);
        builder.assert_bool(local_control_flow.is_absorb);
        builder.assert_bool(local_control_flow.is_finalize);
        builder.assert_bool(
            local_control_flow.is_compress
                + local_control_flow.is_absorb
                + local_control_flow.is_finalize,
        );

        builder.assert_bool(local_control_flow.is_syscall);
        builder.assert_bool(local_control_flow.is_input);
        builder.assert_bool(local_control_flow.is_output);
        builder.assert_bool(local_control_flow.do_perm);

        // Ensure the first row is real and is a syscall row.
        builder.when_first_row().assert_one(
            local_control_flow.is_compress
                + local_control_flow.is_absorb
                + local_control_flow.is_finalize,
        );
        builder
            .when_first_row()
            .assert_one(local_control_flow.is_syscall);

        let mut transition_builder = builder.when_transition();
        let mut compress_builder = transition_builder.when(local_control_flow.is_compress);
        let mut compress_syscall_builder = compress_builder.when(local_control_flow.is_syscall);

        compress_syscall_builder.assert_one(local_control_flow.is_input);
        compress_syscall_builder.assert_one(local_control_flow.do_perm);

        compress_syscall_builder.assert_one(next_control_flow.is_compress);
        compress_syscall_builder.assert_zero(next_control_flow.is_syscall);
        compress_syscall_builder.assert_zero(next_control_flow.is_input);
        compress_syscall_builder.assert_zero(next_control_flow.do_perm);
    }

    fn eval_syscall_params<AB: SP1RecursionAirBuilder>(
        &self,
        builder: &mut AB,
        local_syscall: &SyscallParams<AB::Var>,
        next_syscall: &SyscallParams<AB::Var>,
        is_compress: AB::Var,
        is_syscall: AB::Var,
    ) {
        // Constraint that the operands are sent from the CPU table.
        let operands = local_syscall.get_raw_params();
        builder.receive_table(
            Opcode::Poseidon2Compress.as_field::<AB::F>(),
            &operands,
            is_syscall,
        );

        let mut transition_builder = builder.when_transition();
        let mut compress_builder = transition_builder.when(is_compress);
        let mut compress_syscall_builder = compress_builder.when(is_syscall);

        // Verify that the syscall parameters are copied for all of the rows.
        let local_syscall_input = local_syscall.compress();
        let next_syscall_input = next_syscall.compress();
        compress_syscall_builder.assert_eq(local_syscall_input.clk, next_syscall_input.clk);
        compress_syscall_builder.assert_eq(local_syscall_input.dst_ptr, next_syscall_input.dst_ptr);
        compress_syscall_builder
            .assert_eq(local_syscall_input.left_ptr, next_syscall_input.left_ptr);
        compress_syscall_builder
            .assert_eq(local_syscall_input.right_ptr, next_syscall_input.right_ptr);
    }

    fn eval_mem<AB: SP1RecursionAirBuilder>(
        &self,
        builder: &mut AB,
        syscall_params: &SyscallParams<AB::Var>,
        opcode_workspace: &OpcodeWorkspace<AB::Var>,
        is_input: AB::Var,
        is_output: AB::Var,
    ) {
        let compress_syscall = syscall_params.compress();

        // Evaluate all of the memory.
        for i in 0..WIDTH {
            let input_addr = if i < WIDTH / 2 {
                compress_syscall.left_ptr + AB::F::from_canonical_usize(i)
            } else {
                compress_syscall.right_ptr + AB::F::from_canonical_usize(i - WIDTH / 2)
            };

            let compress_workspace = opcode_workspace.compress();
            builder.recursion_eval_memory_access_single(
                compress_syscall.clk,
                input_addr,
                &compress_workspace.input[i],
                is_input,
            );

            let output_workspace = opcode_workspace.output();
            let output_addr = compress_syscall.dst_ptr + AB::F::from_canonical_usize(i);
            builder.recursion_eval_memory_access_single(
                compress_syscall.clk + AB::F::from_canonical_usize(1),
                output_addr,
                &output_workspace.output_memory[i],
                is_output,
            );
        }
    }

    fn eval_perm<AB: SP1RecursionAirBuilder>(
        &self,
        builder: &mut AB,
        input: [AB::Var; WIDTH],
        perm_cols: &dyn Permutation<AB::Var>,
        do_perm: AB::Var,
    ) {
        // Apply the initial round.
        let initial_round_output = {
            let mut initial_round_output: [AB::Expr; WIDTH] =
                core::array::from_fn(|i| input[i].into());
            external_linear_layer(&mut initial_round_output);
            initial_round_output
        };
        let external_round_0_state: [AB::Expr; WIDTH] = core::array::from_fn(|i| {
            let state = perm_cols.external_rounds_state()[0];
            state[i].into()
        });

        builder
            .when(do_perm)
            .assert_all_eq(external_round_0_state.clone(), initial_round_output);

        // Apply the first half of external rounds.
        for r in 0..NUM_EXTERNAL_ROUNDS / 2 {
            self.eval_external_round(builder, perm_cols, r, do_perm);
        }

        // Apply the internal rounds.
        self.eval_internal_rounds(builder, perm_cols, do_perm);

        // Apply the second half of external rounds.
        for r in NUM_EXTERNAL_ROUNDS / 2..NUM_EXTERNAL_ROUNDS {
            self.eval_external_round(builder, perm_cols, r, do_perm);
        }
    }

    fn eval_external_round<AB: SP1RecursionAirBuilder>(
        &self,
        builder: &mut AB,
        perm_cols: &dyn Permutation<AB::Var>,
        r: usize,
        do_perm: AB::Var,
    ) {
        let external_state = perm_cols.external_rounds_state()[r];

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
            let calculated_sbox_deg_3 = add_rc[i].clone() * add_rc[i].clone() * add_rc[i].clone();

            if let Some(external_sbox) = perm_cols.external_rounds_sbox() {
                builder.assert_eq(external_sbox[r][i].into(), calculated_sbox_deg_3);
                sbox_deg_3[i] = external_sbox[r][i].into();
            } else {
                sbox_deg_3[i] = calculated_sbox_deg_3;
            }

            sbox_deg_7[i] = sbox_deg_3[i].clone() * sbox_deg_3[i].clone() * add_rc[i].clone();
        }

        // Apply the linear layer.
        let mut state = sbox_deg_7;
        external_linear_layer(&mut state);

        let next_state_cols = if r == NUM_EXTERNAL_ROUNDS / 2 - 1 {
            perm_cols.internal_rounds_state()
        } else if r == NUM_EXTERNAL_ROUNDS - 1 {
            perm_cols.output_state()
        } else {
            &perm_cols.external_rounds_state()[r + 1]
        };
        for i in 0..WIDTH {
            builder.assert_eq(next_state_cols[i], state[i].clone());
        }
    }

    fn eval_internal_rounds<AB: SP1RecursionAirBuilder>(
        &self,
        builder: &mut AB,
        perm_cols: &dyn Permutation<AB::Var>,
        do_perm: AB::Var,
    ) {
        let state = &perm_cols.internal_rounds_state();
        let s0 = perm_cols.internal_rounds_s0();
        let mut state: [AB::Expr; WIDTH] = core::array::from_fn(|i| state[i].into());
        for r in 0..NUM_INTERNAL_ROUNDS {
            // Add the round constant.
            let round = r + NUM_EXTERNAL_ROUNDS / 2;
            let add_rc = if r == 0 {
                state[0].clone()
            } else {
                s0[r - 1].into()
            } + do_perm * AB::Expr::from_wrapped_u32(RC_16_30_U32[round][0]);

            let mut sbox_deg_3 = add_rc.clone() * add_rc.clone() * add_rc.clone();
            if let Some(internal_sbox) = perm_cols.internal_rounds_sbox() {
                builder.assert_eq(internal_sbox[r], sbox_deg_3);
                sbox_deg_3 = internal_sbox[r].into();
            }

            // See `populate_internal_rounds` for why we don't have columns for the sbox output here.
            let sbox_deg_7 = sbox_deg_3.clone() * sbox_deg_3.clone() * add_rc.clone();

            // Apply the linear layer.
            // See `populate_internal_rounds` for why we don't have columns for the new state here.
            state[0] = sbox_deg_7.clone();
            internal_linear_layer(&mut state);

            if r < NUM_INTERNAL_ROUNDS - 1 {
                builder.assert_eq(s0[r], state[0].clone());
            }
        }

        let external_state = perm_cols.external_rounds_state()[NUM_EXTERNAL_ROUNDS / 2];
        for i in 0..WIDTH {
            builder.assert_eq(external_state[i], state[i].clone())
        }
    }
}
