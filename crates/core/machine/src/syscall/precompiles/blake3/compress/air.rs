use core::borrow::Borrow;
use std::iter::once;

use slop_air::{Air, AirBuilder, BaseAir};
use slop_algebra::AbstractField;
use slop_matrix::Matrix;
use sp1_hypercube::{
    air::{AirInteraction, BaseAirBuilder, InteractionScope},
    InteractionKind, Word,
};

use super::{
    columns::{Blake3CompressCols, NUM_BLAKE3_COMPRESS_COLS},
    Blake3CompressChip, FINALIZE_START, G_INDEX, MSG_SCHEDULE, OPERATION_COUNT, ROUND_COUNT,
    STATE_INIT_START,
};
use crate::{
    air::{SP1CoreAirBuilder, WordAirBuilder},
    operations::{AddrAddOperation, AddU32Operation, FixedRotateRightOperation, XorU32Operation},
};

impl<F> BaseAir<F> for Blake3CompressChip {
    fn width(&self) -> usize {
        NUM_BLAKE3_COMPRESS_COLS
    }
}

impl<AB> Air<AB> for Blake3CompressChip
where
    AB: SP1CoreAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Blake3CompressCols<AB::Var> = (*local).borrow();

        self.eval_flags(builder, local);
        self.eval_memory(builder, local);
        self.eval_g_function(builder, local);
        self.eval_interaction(builder, local);
    }
}

impl Blake3CompressChip {
    /// Constrain phase-selector flags and the index.
    fn eval_flags<AB: SP1CoreAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Blake3CompressCols<AB::Var>,
    ) {
        builder.assert_bool(local.is_real);
        builder.assert_bool(local.is_state_init);
        builder.assert_bool(local.is_msg_read);
        builder.assert_bool(local.is_compute);
        builder.assert_bool(local.is_finalize);

        // Exactly one phase is active on a real row.
        builder.when(local.is_real).assert_one(
            local.is_state_init
                + local.is_msg_read
                + local.is_compute
                + local.is_finalize,
        );

        // phase_idx is one-hot for init/msg_read/finalize rows.
        let mut phase_idx_sum = AB::Expr::zero();
        let mut computed_phase_idx = AB::Expr::zero();
        for i in 0..16 {
            builder.assert_bool(local.phase_idx[i]);
            phase_idx_sum = phase_idx_sum + local.phase_idx[i].into();
            computed_phase_idx = computed_phase_idx
                + local.phase_idx[i] * AB::Expr::from_canonical_u32(i as u32);
        }
        builder
            .when(local.is_state_init + local.is_msg_read + local.is_finalize)
            .assert_one(phase_idx_sum);

        // round is one-hot for compute rows.
        let mut round_sum = AB::Expr::zero();
        let mut computed_round = AB::Expr::zero();
        for r in 0..ROUND_COUNT {
            builder.assert_bool(local.round[r]);
            round_sum = round_sum + local.round[r].into();
            computed_round = computed_round
                + local.round[r] * AB::Expr::from_canonical_u32(r as u32);
        }
        builder.when(local.is_compute).assert_one(round_sum);

        // op is one-hot for compute rows.
        let mut op_sum = AB::Expr::zero();
        let mut computed_op = AB::Expr::zero();
        for o in 0..OPERATION_COUNT {
            builder.assert_bool(local.op[o]);
            op_sum = op_sum + local.op[o].into();
            computed_op = computed_op
                + local.op[o] * AB::Expr::from_canonical_u32(o as u32);
        }
        builder.when(local.is_compute).assert_one(op_sum);

        // On non-compute rows, round and op selectors must be zero.
        // (This enables using round[r]*op[o] as a degree-2 selector without is_compute.)
        let non_compute = local.is_state_init + local.is_msg_read + local.is_finalize;
        for r in 0..ROUND_COUNT {
            builder.when(non_compute.clone()).assert_zero(local.round[r]);
        }
        for o in 0..OPERATION_COUNT {
            builder.when(non_compute.clone()).assert_zero(local.op[o]);
        }

        // The row index: index = phase_start + sub_index.
        let msg_read_start = AB::Expr::from_canonical_u32(16);
        let compute_start = AB::Expr::from_canonical_u32(32);
        let finalize_start = AB::Expr::from_canonical_u32(FINALIZE_START as u32);

        let expected_index = local.is_state_init
            * (AB::Expr::from_canonical_u32(STATE_INIT_START as u32) + computed_phase_idx.clone())
            + local.is_msg_read * (msg_read_start + computed_phase_idx.clone())
            + local.is_compute
                * (compute_start
                    + computed_round * AB::Expr::from_canonical_u32(OPERATION_COUNT as u32)
                    + computed_op)
            + local.is_finalize * (finalize_start + computed_phase_idx);
        builder.when(local.is_real).assert_eq(local.index, expected_index);
    }

    /// Constrain memory accesses for state_init, msg_read, and finalize rows.
    fn eval_memory<AB: SP1CoreAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Blake3CompressCols<AB::Var>,
    ) {
        let is_mem_row = local.is_state_init + local.is_msg_read + local.is_finalize;

        let mem_value_word = Word::extend_half::<AB>(&local.mem_value);

        // clk offset: +0 for state_init, +1 for msg_read, +2 for finalize.
        let clk_offset = local.is_msg_read + local.is_finalize * AB::Expr::from_canonical_u32(2);

        // mem_addr is a witness column (degree 1) holding the effective address for this row.
        let addr: [AB::Expr; 3] = local.mem_addr.map(Into::into);

        builder.eval_memory_access_write(
            local.clk_high,
            local.clk_low.into() + clk_offset,
            &addr,
            local.mem,
            mem_value_word.clone(),
            is_mem_row.clone(),
        );

        // Reads: value must not change.
        builder
            .when(local.is_state_init + local.is_msg_read)
            .assert_word_eq(local.mem.prev_value, mem_value_word.clone());

        // Upper two limbs of memory words must be zero (u32 stored in u64 slot).
        builder.assert_zero(local.mem.prev_value[2]);
        builder.assert_zero(local.mem.prev_value[3]);

        // Constrain address computations.
        let phase_idx_expr: AB::Expr = (0..16usize)
            .map(|i| local.phase_idx[i] * AB::Expr::from_canonical_u32(i as u32))
            .fold(AB::Expr::zero(), |acc, x| acc + x);

        // state_init: addr = state_ptr + phase_idx * 8
        AddrAddOperation::<AB::F>::eval(
            builder,
            Word([
                local.state_ptr[0].into(),
                local.state_ptr[1].into(),
                local.state_ptr[2].into(),
                AB::Expr::zero(),
            ]),
            Word::extend_expr::<AB>(phase_idx_expr.clone() * AB::Expr::from_canonical_u32(8)),
            local.mem_addr_state_init,
            local.is_state_init.into(),
        );
        // Bind mem_addr to the computed state_init address.
        builder.when(local.is_state_init).assert_all_eq(local.mem_addr, local.mem_addr_state_init.value);

        // msg_read: addr = msg_ptr + phase_idx * 8
        AddrAddOperation::<AB::F>::eval(
            builder,
            Word([
                local.msg_ptr[0].into(),
                local.msg_ptr[1].into(),
                local.msg_ptr[2].into(),
                AB::Expr::zero(),
            ]),
            Word::extend_expr::<AB>(phase_idx_expr.clone() * AB::Expr::from_canonical_u32(8)),
            local.mem_addr_msg_read,
            local.is_msg_read.into(),
        );
        // Bind mem_addr to the computed msg_read address.
        builder.when(local.is_msg_read).assert_all_eq(local.mem_addr, local.mem_addr_msg_read.value);

        // finalize: addr = state_ptr + phase_idx * 8
        AddrAddOperation::<AB::F>::eval(
            builder,
            Word([
                local.state_ptr[0].into(),
                local.state_ptr[1].into(),
                local.state_ptr[2].into(),
                AB::Expr::zero(),
            ]),
            Word::extend_expr::<AB>(phase_idx_expr * AB::Expr::from_canonical_u32(8)),
            local.mem_addr_finalize,
            local.is_finalize.into(),
        );
        // Bind mem_addr to the computed finalize address.
        builder.when(local.is_finalize).assert_all_eq(local.mem_addr, local.mem_addr_finalize.value);

        // State init: mem_value must equal state[phase_idx].
        let state_picked_lo: AB::Expr = (0..16)
            .map(|k| local.phase_idx[k] * local.state[k][0])
            .fold(AB::Expr::zero(), |a, b| a + b);
        let state_picked_hi: AB::Expr = (0..16)
            .map(|k| local.phase_idx[k] * local.state[k][1])
            .fold(AB::Expr::zero(), |a, b| a + b);
        builder.when(local.is_state_init).assert_eq(local.mem_value[0], state_picked_lo.clone());
        builder.when(local.is_state_init).assert_eq(local.mem_value[1], state_picked_hi.clone());

        // Msg read: mem_value must equal msg[phase_idx].
        let msg_picked_lo: AB::Expr = (0..16)
            .map(|k| local.phase_idx[k] * local.msg[k][0])
            .fold(AB::Expr::zero(), |a, b| a + b);
        let msg_picked_hi: AB::Expr = (0..16)
            .map(|k| local.phase_idx[k] * local.msg[k][1])
            .fold(AB::Expr::zero(), |a, b| a + b);
        builder.when(local.is_msg_read).assert_eq(local.mem_value[0], msg_picked_lo);
        builder.when(local.is_msg_read).assert_eq(local.mem_value[1], msg_picked_hi);

        // Finalize: mem_value must equal state[phase_idx] (writing state out).
        builder.when(local.is_finalize).assert_eq(local.mem_value[0], state_picked_lo);
        builder.when(local.is_finalize).assert_eq(local.mem_value[1], state_picked_hi);
    }

    /// Constrain the G function computation on compute rows.
    fn eval_g_function<AB: SP1CoreAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Blake3CompressCols<AB::Var>,
    ) {
        // Verify that ga, gb, gc, gd match the current state at G_INDEX positions.
        for o in 0..OPERATION_COUNT {
            let [ai, bi, ci, di] = G_INDEX[o];
            builder.when(local.is_compute * local.op[o]).assert_all_eq(
                local.ga,
                local.state[ai],
            );
            builder.when(local.is_compute * local.op[o]).assert_all_eq(
                local.gb,
                local.state[bi],
            );
            builder.when(local.is_compute * local.op[o]).assert_all_eq(
                local.gc,
                local.state[ci],
            );
            builder.when(local.is_compute * local.op[o]).assert_all_eq(
                local.gd,
                local.state[di],
            );
        }

        // Verify that mx and my match msg at MSG_SCHEDULE indices.
        // round[r] and op[o] are guaranteed zero on non-compute rows (constrained in eval_flags),
        // so sel = round[r] * op[o] is a safe degree-2 selector.
        for r in 0..ROUND_COUNT {
            for o in 0..OPERATION_COUNT {
                let mx_idx = MSG_SCHEDULE[r][2 * o];
                let my_idx = MSG_SCHEDULE[r][2 * o + 1];
                let sel = local.round[r] * local.op[o];
                builder.when(sel.clone()).assert_all_eq(local.mx, local.msg[mx_idx]);
                builder.when(sel).assert_all_eq(local.my, local.msg[my_idx]);
            }
        }

        // G function steps:
        // Step 1: a' = a + b + mx
        AddU32Operation::<AB::F>::eval(
            builder,
            local.ga.map(Into::into),
            local.gb.map(Into::into),
            local.a_add_b,
            local.is_compute.into(),
        );
        AddU32Operation::<AB::F>::eval(
            builder,
            local.a_add_b.value.map(Into::into),
            local.mx.map(Into::into),
            local.a_add_b_add_mx,
            local.is_compute.into(),
        );

        // Step 2: d' = d ^ a'
        let d_xor_a_result = XorU32Operation::<AB::F>::eval_xor_u32(
            builder,
            local.gd.map(Into::into),
            local.a_add_b_add_mx.value.map(Into::into),
            local.d_xor_a,
            local.is_compute,
        );

        // Step 3: d'' = d' rotr 16 — pure limb swap, no extra columns.
        let d_pp = [d_xor_a_result[1].clone(), d_xor_a_result[0].clone()];

        // Step 4: c' = c + d''
        AddU32Operation::<AB::F>::eval(
            builder,
            local.gc.map(Into::into),
            d_pp,
            local.c_add_d,
            local.is_compute.into(),
        );

        // Step 5: b' = b ^ c'
        let _b_xor_c_result = XorU32Operation::<AB::F>::eval_xor_u32(
            builder,
            local.gb.map(Into::into),
            local.c_add_d.value.map(Into::into),
            local.b_xor_c,
            local.is_compute,
        );

        // Constrain b_xor_c_limbs = u16 limbs of b_xor_c.value (bytes → half-words).
        let base = AB::F::from_canonical_u32(256);
        builder.when(local.is_compute).assert_eq(
            local.b_xor_c_limbs[0],
            Into::<AB::Expr>::into(local.b_xor_c.value[0])
                + Into::<AB::Expr>::into(local.b_xor_c.value[1]) * base,
        );
        builder.when(local.is_compute).assert_eq(
            local.b_xor_c_limbs[1],
            Into::<AB::Expr>::into(local.b_xor_c.value[2])
                + Into::<AB::Expr>::into(local.b_xor_c.value[3]) * base,
        );

        // Step 6: b'' = b' rotr 12
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.b_xor_c_limbs,
            12,
            local.b_rotr12,
            local.is_compute,
        );

        // Step 7: a'' = a' + b'' + my
        AddU32Operation::<AB::F>::eval(
            builder,
            local.a_add_b_add_mx.value.map(Into::into),
            local.b_rotr12.value.map(Into::into),
            local.a2_add_b2,
            local.is_compute.into(),
        );
        AddU32Operation::<AB::F>::eval(
            builder,
            local.a2_add_b2.value.map(Into::into),
            local.my.map(Into::into),
            local.a2_add_b2_add_my,
            local.is_compute.into(),
        );

        // Step 8: d''' = d'' ^ a''
        // d'' is the rotr16 of d_xor_a: swap the two u16 limbs.
        // Re-derive d'' from d_xor_a bytes.
        let _d_xor_a2_result = XorU32Operation::<AB::F>::eval_xor_u32(
            builder,
            [
                Into::<AB::Expr>::into(local.d_xor_a.value[2])
                    + Into::<AB::Expr>::into(local.d_xor_a.value[3]) * base,
                Into::<AB::Expr>::into(local.d_xor_a.value[0])
                    + Into::<AB::Expr>::into(local.d_xor_a.value[1]) * base,
            ],
            local.a2_add_b2_add_my.value.map(Into::into),
            local.d_xor_a2,
            local.is_compute,
        );

        // Constrain d_xor_a2_limbs.
        builder.when(local.is_compute).assert_eq(
            local.d_xor_a2_limbs[0],
            Into::<AB::Expr>::into(local.d_xor_a2.value[0])
                + Into::<AB::Expr>::into(local.d_xor_a2.value[1]) * base,
        );
        builder.when(local.is_compute).assert_eq(
            local.d_xor_a2_limbs[1],
            Into::<AB::Expr>::into(local.d_xor_a2.value[2])
                + Into::<AB::Expr>::into(local.d_xor_a2.value[3]) * base,
        );

        // Step 9: d'''' = d''' rotr 8
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.d_xor_a2_limbs,
            8,
            local.d_rotr8,
            local.is_compute,
        );

        // Step 10: c'' = c' + d''''
        AddU32Operation::<AB::F>::eval(
            builder,
            local.c_add_d.value.map(Into::into),
            local.d_rotr8.value.map(Into::into),
            local.c_add_d2,
            local.is_compute.into(),
        );

        // Step 11: b''' = b'' ^ c''
        let _b_xor_c2_result = XorU32Operation::<AB::F>::eval_xor_u32(
            builder,
            local.b_rotr12.value.map(Into::into),
            local.c_add_d2.value.map(Into::into),
            local.b_xor_c2,
            local.is_compute,
        );

        // Constrain b_xor_c2_limbs.
        builder.when(local.is_compute).assert_eq(
            local.b_xor_c2_limbs[0],
            Into::<AB::Expr>::into(local.b_xor_c2.value[0])
                + Into::<AB::Expr>::into(local.b_xor_c2.value[1]) * base,
        );
        builder.when(local.is_compute).assert_eq(
            local.b_xor_c2_limbs[1],
            Into::<AB::Expr>::into(local.b_xor_c2.value[2])
                + Into::<AB::Expr>::into(local.b_xor_c2.value[3]) * base,
        );

        // Step 12: b'''' = b''' rotr 7
        FixedRotateRightOperation::<AB::F>::eval(
            builder,
            local.b_xor_c2_limbs,
            7,
            local.b_rotr7,
            local.is_compute,
        );

        // Constrain next_state: for each op, bind the 4 updated positions to G outputs
        // and the 12 unchanged positions to state[k]. Degree-2 constraints (ok here).
        for o in 0..OPERATION_COUNT {
            let [ai, bi, ci, di] = G_INDEX[o];
            let op_sel = local.op[o];

            // Updated positions.
            builder.when(op_sel).assert_all_eq(local.next_state[ai], local.a2_add_b2_add_my.value);
            builder.when(op_sel).assert_all_eq(local.next_state[bi], local.b_rotr7.value);
            builder.when(op_sel).assert_all_eq(local.next_state[ci], local.c_add_d2.value);
            builder.when(op_sel).assert_all_eq(local.next_state[di], local.d_rotr8.value);

            // Unchanged positions.
            for k in 0..16 {
                if k == ai || k == bi || k == ci || k == di {
                    continue;
                }
                builder.when(op_sel).assert_all_eq(local.next_state[k], local.state[k]);
            }
        }

        // On non-compute rows, next_state is a passthrough of state.
        let non_compute = local.is_state_init + local.is_msg_read + local.is_finalize;
        for k in 0..16 {
            builder.when(non_compute.clone()).assert_all_eq(local.next_state[k], local.state[k]);
        }
    }

    /// Constrain the Blake3Compress interaction (state + msg chaining).
    fn eval_interaction<AB: SP1CoreAirBuilder>(
        &self,
        builder: &mut AB,
        local: &Blake3CompressCols<AB::Var>,
    ) {
        // Receive: the current (state, msg) at index.
        let receive_values: Vec<AB::Expr> = once(local.clk_high.into())
            .chain(once(local.clk_low.into()))
            .chain(local.state_ptr.map(Into::into))
            .chain(local.msg_ptr.map(Into::into))
            .chain(once(local.index.into()))
            .chain(local.state.into_iter().flat_map(|w| w.into_iter()).map(Into::into))
            .chain(local.msg.into_iter().flat_map(|w| w.into_iter()).map(Into::into))
            .collect();
        builder.receive(
            AirInteraction::new(
                receive_values,
                local.is_real.into(),
                InteractionKind::Blake3Compress,
            ),
            InteractionScope::Local,
        );

        // Send: (clk_h, clk_l, sp, mp, index+1, next_state, msg) with is_real multiplicity.
        // On compute rows next_state is the post-G state (constrained in eval_g_function).
        // On non-compute rows next_state == state (passthrough, constrained in eval_g_function).
        let send_values: Vec<AB::Expr> = once(local.clk_high.into())
            .chain(once(local.clk_low.into()))
            .chain(local.state_ptr.map(Into::into))
            .chain(local.msg_ptr.map(Into::into))
            .chain(once(local.index.into() + AB::Expr::one()))
            .chain(local.next_state.into_iter().flat_map(|w| w.into_iter()).map(Into::into))
            .chain(local.msg.into_iter().flat_map(|w| w.into_iter()).map(Into::into))
            .collect();
        builder.send(
            AirInteraction::new(send_values, local.is_real.into(), InteractionKind::Blake3Compress),
            InteractionScope::Local,
        );
    }
}
