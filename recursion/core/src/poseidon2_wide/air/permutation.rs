use std::array;

use p3_field::AbstractField;
use sp1_primitives::RC_16_30_U32;

use crate::{
    air::SP1RecursionAirBuilder,
    memory::MemoryCols,
    poseidon2_wide::{
        columns::{
            control_flow::ControlFlow, memory::Memory, opcode_workspace::OpcodeWorkspace,
            permutation::Permutation,
        },
        external_linear_layer, internal_linear_layer, Poseidon2WideChip, NUM_EXTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS, WIDTH,
    },
};

impl<const DEGREE: usize> Poseidon2WideChip<DEGREE> {
    pub(crate) fn eval_perm<AB: SP1RecursionAirBuilder>(
        &self,
        builder: &mut AB,
        perm_cols: &dyn Permutation<AB::Var>,
        memory: &Memory<AB::Var>,
        opcode_workspace: &OpcodeWorkspace<AB::Var>,
        control_flow: &ControlFlow<AB::Var>,
    ) {
        // Construct the input array of the permutation.  That array is dependent on the row type.
        // For compress_syscall rows, the input is from the memory access values.  For absorb, the
        // input is the previous state, with select elements being read from the memory access values.
        // For finalize, the input is the previous state.
        let input: [AB::Expr; WIDTH] = array::from_fn(|i| {
            let previous_state = opcode_workspace.absorb().previous_state[i];

            let (compress_input, absorb_input, finalize_input) = if i < WIDTH / 2 {
                let mem_value = *memory.memory_accesses[i].value();

                let compress_input = mem_value;
                let absorb_input =
                    builder.if_else(memory.memory_slot_used[i], mem_value, previous_state);
                let finalize_input = previous_state.into();

                (compress_input, absorb_input, finalize_input)
            } else {
                let compress_input =
                    *opcode_workspace.compress().memory_accesses[i - WIDTH / 2].value();
                let absorb_input = previous_state.into();
                let finalize_input = previous_state.into();

                (compress_input, absorb_input, finalize_input)
            };

            control_flow.is_compress * compress_input
                + control_flow.is_absorb * absorb_input
                + control_flow.is_finalize * finalize_input
        });

        // Apply the initial round.
        let initial_round_output = {
            let mut initial_round_output = input;
            external_linear_layer(&mut initial_round_output);
            initial_round_output
        };
        let external_round_0_state: [AB::Expr; WIDTH] = core::array::from_fn(|i| {
            let state = perm_cols.external_rounds_state()[0];
            state[i].into()
        });

        builder.assert_all_eq(external_round_0_state.clone(), initial_round_output);

        // Apply the first half of external rounds.
        for r in 0..NUM_EXTERNAL_ROUNDS / 2 {
            self.eval_external_round(builder, perm_cols, r);
        }

        // Apply the internal rounds.
        self.eval_internal_rounds(builder, perm_cols);

        // Apply the second half of external rounds.
        for r in NUM_EXTERNAL_ROUNDS / 2..NUM_EXTERNAL_ROUNDS {
            self.eval_external_round(builder, perm_cols, r);
        }
    }

    fn eval_external_round<AB: SP1RecursionAirBuilder>(
        &self,
        builder: &mut AB,
        perm_cols: &dyn Permutation<AB::Var>,
        r: usize,
    ) {
        let external_state = perm_cols.external_rounds_state()[r];

        // Add the round constants.
        let round = if r < NUM_EXTERNAL_ROUNDS / 2 {
            r
        } else {
            r + NUM_INTERNAL_ROUNDS
        };
        let add_rc: [AB::Expr; WIDTH] = core::array::from_fn(|i| {
            external_state[i].into() + AB::F::from_wrapped_u32(RC_16_30_U32[round][i])
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
            perm_cols.perm_output()
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
            } + AB::Expr::from_wrapped_u32(RC_16_30_U32[round][0]);

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
