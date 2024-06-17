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
    pub(crate) fn eval_mem<AB: SP1RecursionAirBuilder>(
        &self,
        builder: &mut AB,
        syscall_params: &SyscallParams<AB::Var>,
        memory: &Memory<AB::Var>,
        opcode_workspace: &OpcodeWorkspace<AB::Var>,
        control_flow: &ControlFlow<AB::Var>,
    ) {
        let clk = syscall_params.get_raw_params()[0];
        let is_real = control_flow.is_compress + control_flow.is_absorb + control_flow.is_finalize;

        // Verify the memory flags.
        for i in 0..WIDTH / 2 {
            builder.assert_bool(memory.memory_slot_used[i]);
            builder
                .when(memory.memory_slot_used[i])
                .assert_one(is_real.clone());

            // For compress and finalize, all of the slots should be true.
            builder
                .when(control_flow.is_compress + control_flow.is_finalize)
                .assert_one(memory.memory_slot_used[i]);

            // For absorb, the index of the first non zero slot should be equal to the state_cursor.
            // The number of sequential non zero slots should be equal to the number of consumed elements.
            // Need to make sure the non zero slots are contiguous.
            // TODO
        }

        // Verify the memory addr.
        builder
            .when(control_flow.is_compress * control_flow.is_syscall_row)
            .assert_eq(syscall_params.compress().left_ptr, memory.start_addr);
        builder
            .when(control_flow.is_compress_output)
            .assert_eq(syscall_params.compress().dst_ptr, memory.start_addr);
        builder
            .when(control_flow.is_absorb * control_flow.is_syscall_row)
            .assert_eq(syscall_params.absorb().input_ptr, memory.start_addr);
        // TODO: Need to handle the case for non syscall compress.
        builder
            .when(control_flow.is_finalize)
            .assert_eq(syscall_params.finalize().output_ptr, memory.start_addr);

        // Evaluate the first half of the memory.
        let mut addr: AB::Expr = memory.start_addr.into();
        for i in 0..WIDTH / 2 {
            builder.recursion_eval_memory_access_single(
                clk + control_flow.is_compress_output,
                addr.clone(),
                &memory.memory_accesses[i],
                memory.memory_slot_used[i],
            );

            // For read only accesses, assert the value didn't change.
            builder
                .when(
                    control_flow.is_compress * control_flow.is_syscall_row + control_flow.is_absorb,
                )
                .assert_eq(
                    *memory.memory_accesses[i].prev_value(),
                    *memory.memory_accesses[i].value(),
                );

            addr = addr.clone() + memory.memory_slot_used[i].into();
        }

        // Evalulate the second half for compress syscall.
        let compress_workspace = opcode_workspace.compress();
        // Verify the start addr.
        builder
            .when(control_flow.is_compress * control_flow.is_syscall_row)
            .assert_eq(
                compress_workspace.start_addr,
                syscall_params.compress().right_ptr,
            );
        builder.when(control_flow.is_compress_output).assert_eq(
            compress_workspace.start_addr,
            syscall_params.compress().dst_ptr + AB::Expr::from_canonical_usize(WIDTH / 2),
        );
        // Evaluate then memory
        let mut addr: AB::Expr = compress_workspace.start_addr.into();
        for i in 0..WIDTH / 2 {
            builder.recursion_eval_memory_access_single(
                clk + control_flow.is_compress_output,
                addr.clone(),
                &compress_workspace.memory_accesses[i],
                control_flow.is_compress,
            );

            builder
                .when(control_flow.is_syscall_row * control_flow.is_compress)
                .assert_eq(
                    *compress_workspace.memory_accesses[i].prev_value(),
                    *compress_workspace.memory_accesses[i].value(),
                );

            addr = addr.clone() + AB::Expr::one();
        }
    }
}
