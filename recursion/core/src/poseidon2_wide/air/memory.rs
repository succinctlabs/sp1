use p3_air::AirBuilder;
use p3_field::AbstractField;

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

            // The memory slot flag will be used as the memory access multiplicity flag, so we need to
            // ensure that those values are zero for all non real rows.
            builder
                .when_not(is_real.clone())
                .assert_zero(local_memory.memory_slot_used[i]);

            // For compress and finalize, all of the slots should be true.
            builder
                .when(control_flow.is_compress + control_flow.is_finalize)
                .assert_one(local_memory.memory_slot_used[i]);

            // For absorb, the first n zero columns should equal to state_cursor.  The next m contiguous
            // non zero columns should be equal to the consumed elements.  The rest of the columns should
            // be zero.
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
            // input_ptr, and for subsequent rows, it's incremented by the number of consumed elements.
            builder
                .when(control_flow.is_absorb)
                .when(control_flow.is_syscall_row)
                .assert_eq(syscall_params.absorb().input_ptr, local_memory.start_addr);
            builder.when(control_flow.is_absorb_not_last_row).assert_eq(
                next_memory.start_addr,
                local_memory.start_addr + opcode_workspace.absorb().num_consumed::<AB>(),
            );

            // For finalize syscall rows, the start_addr should be the param's output ptr.
            builder.when(control_flow.is_finalize).assert_eq(
                syscall_params.finalize().output_ptr,
                local_memory.start_addr,
            );
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
                builder
                    .when(compress_syscall_row + control_flow.is_absorb)
                    .assert_eq(
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
            builder.when(is_compress_syscall.clone()).assert_eq(
                compress_workspace.start_addr,
                syscall_params.compress().right_ptr,
            );
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
}
