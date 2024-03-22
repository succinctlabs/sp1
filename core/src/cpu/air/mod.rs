pub mod branch;
pub mod memory;

use core::borrow::Borrow;
use p3_air::Air;
use p3_air::AirBuilder;
use p3_air::BaseAir;
use p3_field::AbstractField;
use p3_matrix::MatrixRowSlices;

use crate::air::{SP1AirBuilder, WordAirBuilder};
use crate::bytes::ByteOpcode;
use crate::cpu::columns::OpcodeSelectorCols;
use crate::cpu::columns::{CpuCols, NUM_CPU_COLS};
use crate::cpu::CpuChip;
use crate::memory::MemoryCols;
use crate::runtime::{MemoryAccessPosition, Opcode};

impl<AB> Air<AB> for CpuChip
where
    AB: SP1AirBuilder,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &CpuCols<AB::Var> = main.row_slice(0).borrow();
        let next: &CpuCols<AB::Var> = main.row_slice(1).borrow();

        // Compute some flags for which type of instruction we are dealing with.
        let is_memory_instruction: AB::Expr = self.is_memory_instruction::<AB>(&local.selectors);
        let is_branch_instruction: AB::Expr = self.is_branch_instruction::<AB>(&local.selectors);
        let is_alu_instruction: AB::Expr = self.is_alu_instruction::<AB>(&local.selectors);

        // Program constraints.
        builder.send_program(local.pc, local.instruction, local.selectors, local.is_real);

        // Load immediates into b and c, if the immediate flags are on.
        builder
            .when(local.selectors.imm_b)
            .assert_word_eq(local.op_b_val(), local.instruction.op_b);
        builder
            .when(local.selectors.imm_c)
            .assert_word_eq(local.op_c_val(), local.instruction.op_c);

        // If they are not immediates, read `b` and `c` from memory.
        builder.constraint_memory_access(
            local.shard,
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::B as u32),
            local.instruction.op_b[0],
            &local.op_b_access,
            AB::Expr::one() - local.selectors.imm_b,
        );
        builder
            .when_not(local.selectors.imm_b)
            .assert_word_eq(local.op_b_val(), *local.op_b_access.prev_value());

        builder.constraint_memory_access(
            local.shard,
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::C as u32),
            local.instruction.op_c[0],
            &local.op_c_access,
            AB::Expr::one() - local.selectors.imm_c,
        );
        builder
            .when_not(local.selectors.imm_c)
            .assert_word_eq(local.op_c_val(), *local.op_c_access.prev_value());

        // Write the `a` or the result to the first register described in the instruction unless
        // we are performing a branch or a store.
        builder.constraint_memory_access(
            local.shard,
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::A as u32),
            local.instruction.op_a[0],
            &local.op_a_access,
            AB::Expr::one() - local.selectors.is_noop - local.selectors.reg_0_write,
        );

        // If we are performing a branch or a store, then the value of `a` is the previous value.
        builder
            .when(is_branch_instruction.clone() + self.is_store_instruction::<AB>(&local.selectors))
            .assert_word_eq(local.op_a_val(), local.op_a_access.prev_value);

        // For operations that require reading from memory (not registers), we need to read the
        // value into the memory columns.
        let memory_columns = local.opcode_specific_columns.memory();
        builder.constraint_memory_access(
            local.shard,
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::Memory as u32),
            memory_columns.addr_aligned,
            &memory_columns.memory_access,
            is_memory_instruction.clone(),
        );

        // Check that reduce(addr_word) == addr_aligned + addr_offset.
        builder
            .when(is_memory_instruction.clone())
            .assert_eq::<AB::Expr, AB::Expr>(
                memory_columns.addr_aligned + memory_columns.addr_offset,
                memory_columns.addr_word.reduce::<AB>(),
            );

        // Check that each addr_word element is a byte.
        builder.slice_range_check_u8(&memory_columns.addr_word.0, is_memory_instruction.clone());

        // Send to the ALU table to verify correct calculation of addr_word.
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            memory_columns.addr_word,
            local.op_b_val(),
            local.op_c_val(),
            is_memory_instruction.clone(),
        );

        // Memory handling.
        self.eval_memory_load::<AB>(builder, local);
        self.eval_memory_store::<AB>(builder, local);

        // Branch instructions.
        self.branch_ops_eval::<AB>(builder, is_branch_instruction.clone(), local, next);

        // Jump instructions.
        self.jump_ops_eval::<AB>(builder, local, next);

        // AUIPC instruction.
        self.auipc_eval(builder, local);

        // ECALL instruction.
        let (num_cycles, _is_halt) = self.ecall_eval(builder, local, next);

        builder.send_alu(
            local.instruction.opcode,
            local.op_a_val(),
            local.op_b_val(),
            local.op_c_val(),
            is_alu_instruction,
        );

        // TODO: update the PC.
        // Verify that the pc increments by 4 for all instructions except branch, jump and halt instructions.
        // The other case is handled by eval_jump, eval_branch and eval_ecall.
        // builder
        //     .when_not(
        //         is_branch_instruction + local.selectors.is_jal + local.selectors.is_jalr + is_halt,
        //     )
        //     .assert_eq(local.pc + AB::Expr::from_canonical_u8(4), next.pc);

        self.shard_clk_eval(builder, local, next, num_cycles);

        // Range checks.
        builder.assert_bool(local.is_real);

        // Dummy constraint of degree 3.
        builder.assert_eq(
            local.pc * local.pc * local.pc,
            local.pc * local.pc * local.pc,
        );
    }
}

impl CpuChip {
    /// Whether the instruction is an ALU instruction.
    pub(crate) fn is_alu_instruction<AB: SP1AirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        opcode_selectors.is_alu.into()
    }

    /// Whether the instruction is an ECALL instruction.
    pub(crate) fn is_ecall_instruction<AB: SP1AirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        opcode_selectors.is_ecall.into()
    }

    /// Constraints related to jump operations.
    pub(crate) fn jump_ops_eval<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
    ) {
        // Get the jump specific columns
        let jump_columns = local.opcode_specific_columns.jump();

        // Verify that the local.pc + 4 is saved in op_a for both jump instructions.
        builder
            .when(local.selectors.is_jal + local.selectors.is_jalr)
            .assert_eq(
                local.op_a_val().reduce::<AB>(),
                local.pc + AB::F::from_canonical_u8(4),
            );

        // Verify that the word form of local.pc is correct for JAL instructions.
        builder
            .when(local.selectors.is_jal)
            .assert_eq(jump_columns.pc.reduce::<AB>(), local.pc);

        // Verify that the word form of next.pc is correct for both jump instructions.
        builder
            .when_transition()
            .when(local.selectors.is_jal + local.selectors.is_jalr)
            .assert_eq(jump_columns.next_pc.reduce::<AB>(), next.pc);

        // Verify that the new pc is calculated correctly for JAL instructions.
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            jump_columns.next_pc,
            jump_columns.pc,
            local.op_b_val(),
            local.selectors.is_jal,
        );

        // Verify that the new pc is calculated correctly for JALR instructions.
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            jump_columns.next_pc,
            local.op_b_val(),
            local.op_c_val(),
            local.selectors.is_jalr,
        );
    }

    /// Constraints related to the AUIPC opcode.
    pub(crate) fn auipc_eval<AB: SP1AirBuilder>(&self, builder: &mut AB, local: &CpuCols<AB::Var>) {
        // Get the auipc specific columns.
        let auipc_columns = local.opcode_specific_columns.auipc();

        // Verify that the word form of local.pc is correct.
        builder
            .when(local.selectors.is_auipc)
            .assert_eq(auipc_columns.pc.reduce::<AB>(), local.pc);

        // Verify that op_a == pc + op_b.
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            local.op_a_val(),
            auipc_columns.pc,
            local.op_b_val(),
            local.selectors.is_auipc,
        );
    }

    /// Constraints related to the ECALL opcode.
    pub(crate) fn ecall_eval<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        _next: &CpuCols<AB::Var>,
    ) -> (AB::Expr, AB::Expr) {
        let is_ecall_instruction = self.is_ecall_instruction::<AB>(&local.selectors);
        // The syscall code is the read-in value of op_a at the start of the instruction.
        let syscall_code = local.op_a_access.prev_value();
        // We interpret the syscall_code as little-endian bytes and interpret each byte as a u8
        // with different information. Read more about the format in runtime::syscall::SyscallCode.
        let syscall_id = syscall_code[0];
        let send_to_table = syscall_code[1]; // Does the syscall have a table that should be sent.
        let num_cycles = syscall_code[2]; // How many extra cycles to increment the clk for the syscall.
        let is_halt = syscall_code[3]; // Whether or not the syscall is a halt.

        // Check that the ecall_mul_send_to_table column is equal to send_to_table * is_ecall_instruction.
        // This is a separate column because it is used as a multiplicity in an interaction which
        // requires degree 1 columns.
        builder.assert_eq(
            send_to_table * is_ecall_instruction.clone(),
            local.ecall_mul_send_to_table,
        );
        builder.send_syscall(
            local.shard,
            local.clk,
            syscall_id,
            local.op_b_val().reduce::<AB>(),
            local.op_c_val().reduce::<AB>(),
            local.ecall_mul_send_to_table,
        );

        // For LWA we assume prover-supplied values. Although to be honest, I'm not 100% sure we need this.
        // builder
        //     .when(local.is_ecall)
        //     .when_not(is_lwa)
        //     .assert_word_eq(local.op_a_val(), local.op_a_access.prev_value);

        // TODO: fill in constraints if the syscall is HALT.
        // For halt instructions, the next pc is 0.
        // builder
        //     .when(is_halt)
        //     .assert_eq(next.pc, AB::Expr::from_canonical_u16(0));
        // // If we're halting and it's a transition, then the next.is_real should be 0.
        // builder
        //     .when_transition()
        //     .when(is_halt)
        //     .assert_eq(next.is_real, AB::Expr::zero());
        // builder.when_first_row().assert_one(local.is_real);
        // We probably need a "halted" flag, this can be "is_noop" that turns on to control "is_real".
        (
            num_cycles * is_ecall_instruction.clone(),
            is_halt * is_ecall_instruction,
        )
    }

    /// Constraints related to the shard and clk.
    ///
    /// This function ensures that all of the shard values are the same and that the clk starts at 0
    /// and is transitioned apporpriately.  It will also check that shard values are within 16 bits
    /// and clk values are within 24 bits.  Those range checks are needed for the memory access
    /// timestamp check, which assumes those values are within 2^24.  See [`MemoryAirBuilder::verify_mem_access_ts`].
    pub(crate) fn shard_clk_eval<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
        num_cycles: AB::Expr,
    ) {
        // Verify that all shard values are the same.
        builder
            .when_transition()
            .when(next.is_real)
            .assert_eq(local.shard, next.shard);

        // Verify that the shard value is within 16 bits.
        builder.send_byte(
            AB::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
            local.shard,
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.is_real,
        );

        // Verify that the first row has a clk value of 0.
        builder.when_first_row().assert_zero(local.clk);
        // Verify that the clk increments are correct.  Most clk increment should be 4, but for some
        // precompiles, there are additional cycles.
        let clk_increment = AB::Expr::from_canonical_u32(4) + num_cycles;
        builder
            .when_transition()
            .when(next.is_real)
            .assert_eq(local.clk + clk_increment, next.clk);

        // Range check that the clk is within 24 bits using it's limb values.
        // First verify that the limb values are correct.
        builder.verify_range_24bits(
            local.clk,
            local.clk_16bit_limb,
            local.clk_8bit_limb,
            local.is_real,
        );
    }
}

impl<F> BaseAir<F> for CpuChip {
    fn width(&self) -> usize {
        NUM_CPU_COLS
    }
}
