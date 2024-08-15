use p3_air::AirBuilder;
use p3_field::AbstractField;
use sp1_stark::air::BaseAirBuilder;

use crate::{
    air::SP1RecursionAirBuilder,
    memory::MemoryCols,
    poseidon2_wide::{
        columns::{
            control_flow::ControlFlow, memory::Memory, opcode_workspace::OpcodeWorkspace,
            syscall_params::SyscallParams,
        },
        Poseidon2WideChip, WIDTH,
    },
};

impl<const DEGREE: usize> Poseidon2WideChip<DEGREE> {
    /// Eval the memory related columns.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn eval_mem<AB: SP1RecursionAirBuilder>(
        &self,
        builder: &mut AB,
        syscall_params: &SyscallParams<AB::Var>,
        local_memory: &Memory<AB::Var>,
        next_memory: &Memory<AB::Var>,
        opcode_workspace: &OpcodeWorkspace<AB::Var>,
        control_flow: &ControlFlow<AB::Var>,
        first_half_memory_access: [AB::Var; WIDTH / 2],
        second_half_memory_access: AB::Var,
    ) {
        let clk = syscall_params.get_raw_params()[0];
        let is_real = control_flow.is_compress + control_flow.is_absorb + control_flow.is_finalize;

        // Constrain the memory flags.
        for i in 0..WIDTH / 2 {
            builder.assert_bool(local_memory.memory_slot_used[i]);

            // The memory slot flag will be used as the memory access multiplicity flag, so we need
            // to ensure that those values are zero for all non real rows.
            builder.when_not(is_real.clone()).assert_zero(local_memory.memory_slot_used[i]);

            // For compress and finalize, all of the slots should be true.
            builder
                .when(control_flow.is_compress + control_flow.is_finalize)
                .assert_one(local_memory.memory_slot_used[i]);

            // For absorb, need to make sure the memory_slots_used is consistent with the
            // start_cursor and end_cursor (i.e. start_cursor + num_consumed);
            self.eval_absorb_memory_slots(builder, control_flow, local_memory, opcode_workspace);
        }

        // Verify the start_addr column.
        {
            // For compress syscall rows, the start_addr should be the param's left ptr.
            builder
                .when(control_flow.is_compress * control_flow.is_syscall_row)
                .assert_eq(syscall_params.compress().left_ptr, local_memory.start_addr);

            // For compress output rows, the start_addr should be the param's dst ptr.
            builder
                .when(control_flow.is_compress_output)
                .assert_eq(syscall_params.compress().dst_ptr, local_memory.start_addr);

            // For absorb syscall rows, the start_addr should initially be from the syscall param's
            // input_ptr, and for subsequent rows, it's incremented by the number of consumed
            // elements.
            builder
                .when(control_flow.is_absorb)
                .when(control_flow.is_syscall_row)
                .assert_eq(syscall_params.absorb().input_ptr, local_memory.start_addr);
            builder.when(control_flow.is_absorb_not_last_row).assert_eq(
                next_memory.start_addr,
                local_memory.start_addr + opcode_workspace.absorb().num_consumed::<AB>(),
            );

            // For finalize syscall rows, the start_addr should be the param's output ptr.
            builder
                .when(control_flow.is_finalize)
                .assert_eq(syscall_params.finalize().output_ptr, local_memory.start_addr);
        }

        // Contrain memory access for the first half of the memory accesses.
        {
            let mut addr: AB::Expr = local_memory.start_addr.into();
            for i in 0..WIDTH / 2 {
                builder.recursion_eval_memory_access_single(
                    clk + control_flow.is_compress_output,
                    addr.clone(),
                    &local_memory.memory_accesses[i],
                    first_half_memory_access[i],
                );

                let compress_syscall_row = control_flow.is_compress * control_flow.is_syscall_row;
                // For read only accesses, assert the value didn't change.
                builder.when(compress_syscall_row + control_flow.is_absorb).assert_eq(
                    *local_memory.memory_accesses[i].prev_value(),
                    *local_memory.memory_accesses[i].value(),
                );

                addr = addr.clone() + local_memory.memory_slot_used[i].into();
            }
        }

        // Contrain memory access for the 2nd half of the memory accesses.
        {
            let compress_workspace = opcode_workspace.compress();

            // Verify the start addr.
            let is_compress_syscall = control_flow.is_compress * control_flow.is_syscall_row;
            builder
                .when(is_compress_syscall.clone())
                .assert_eq(compress_workspace.start_addr, syscall_params.compress().right_ptr);
            builder.when(control_flow.is_compress_output).assert_eq(
                compress_workspace.start_addr,
                syscall_params.compress().dst_ptr + AB::Expr::from_canonical_usize(WIDTH / 2),
            );

            let mut addr: AB::Expr = compress_workspace.start_addr.into();
            for i in 0..WIDTH / 2 {
                builder.recursion_eval_memory_access_single(
                    clk + control_flow.is_compress_output,
                    addr.clone(),
                    &compress_workspace.memory_accesses[i],
                    second_half_memory_access,
                );

                // For read only accesses, assert the value didn't change.
                builder.when(is_compress_syscall.clone()).assert_eq(
                    *compress_workspace.memory_accesses[i].prev_value(),
                    *compress_workspace.memory_accesses[i].value(),
                );

                addr = addr.clone() + AB::Expr::one();
            }
        }
    }

    fn eval_absorb_memory_slots<AB: SP1RecursionAirBuilder>(
        &self,
        builder: &mut AB,
        control_flow: &ControlFlow<AB::Var>,
        local_memory: &Memory<AB::Var>,
        opcode_workspace: &OpcodeWorkspace<AB::Var>,
    ) {
        // To verify that the absorb memory slots are correct, we take the derivative of the memory
        // slots, (e.g. memory_slot_used[i] - memory_slot_used[i - 1]), and assert the
        // following:
        // 1) when start_mem_idx_bitmap[i] == 1 -> derivative == 1
        // 2) when end_mem_idx_bitmap[i + 1] == 1 -> derivative == -1
        // 3) when start_mem_idx_bitmap[i] == 0 and end_mem_idx_bitmap[i + 1] == 0 -> derivative ==
        //    0
        let mut absorb_builder = builder.when(control_flow.is_absorb);

        let start_mem_idx_bitmap = opcode_workspace.absorb().start_mem_idx_bitmap;
        let end_mem_idx_bitmap = opcode_workspace.absorb().end_mem_idx_bitmap;
        for i in 0..WIDTH / 2 {
            let derivative: AB::Expr = if i == 0 {
                local_memory.memory_slot_used[i].into()
            } else {
                local_memory.memory_slot_used[i] - local_memory.memory_slot_used[i - 1]
            };

            let is_start_mem_idx = start_mem_idx_bitmap[i].into();

            let is_previous_end_mem_idx =
                if i == 0 { AB::Expr::zero() } else { end_mem_idx_bitmap[i - 1].into() };

            absorb_builder.when(is_start_mem_idx.clone()).assert_one(derivative.clone());

            absorb_builder
                .when(is_previous_end_mem_idx.clone())
                .assert_zero(derivative.clone() + AB::Expr::one());

            absorb_builder
                .when_not(is_start_mem_idx + is_previous_end_mem_idx)
                .assert_zero(derivative);
        }

        // Verify that all elements of start_mem_idx_bitmap and end_mem_idx_bitmap are bool.
        // Also verify that exactly one of the bits in start_mem_idx_bitmap and end_mem_idx_bitmap
        // is one.
        let mut start_mem_idx_bitmap_sum = AB::Expr::zero();
        start_mem_idx_bitmap.iter().for_each(|bit| {
            absorb_builder.assert_bool(*bit);
            start_mem_idx_bitmap_sum += (*bit).into();
        });
        absorb_builder.assert_one(start_mem_idx_bitmap_sum);

        let mut end_mem_idx_bitmap_sum = AB::Expr::zero();
        end_mem_idx_bitmap.iter().for_each(|bit| {
            absorb_builder.assert_bool(*bit);
            end_mem_idx_bitmap_sum += (*bit).into();
        });
        absorb_builder.assert_one(end_mem_idx_bitmap_sum);

        // Verify correct value of start_mem_idx_bitmap and end_mem_idx_bitmap.
        let start_mem_idx: AB::Expr = start_mem_idx_bitmap
            .iter()
            .enumerate()
            .map(|(i, bit)| AB::Expr::from_canonical_usize(i) * *bit)
            .sum();
        absorb_builder.assert_eq(start_mem_idx, opcode_workspace.absorb().state_cursor);

        let end_mem_idx: AB::Expr = end_mem_idx_bitmap
            .iter()
            .enumerate()
            .map(|(i, bit)| AB::Expr::from_canonical_usize(i) * *bit)
            .sum();

        // When we are not in the last row, end_mem_idx should be zero.
        absorb_builder
            .when_not(opcode_workspace.absorb().is_last_row::<AB>())
            .assert_zero(end_mem_idx.clone() - AB::Expr::from_canonical_usize(7));

        // When we are in the last row, end_mem_idx bitmap should equal last_row_ending_cursor.
        absorb_builder
            .when(opcode_workspace.absorb().is_last_row::<AB>())
            .assert_eq(end_mem_idx, opcode_workspace.absorb().last_row_ending_cursor);
    }
}
