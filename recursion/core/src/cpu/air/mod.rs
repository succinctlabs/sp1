mod alu;
mod branch;
mod heap;
mod jump;
mod memory;
mod operands;
mod public_values;
mod system;

use std::borrow::Borrow;

use p3_air::{Air, AirBuilder};
use p3_field::{AbstractField, Field};
use p3_matrix::Matrix;
use sp1_core::air::BaseAirBuilder;

use crate::{
    air::{RecursionPublicValues, SP1RecursionAirBuilder, RECURSIVE_PROOF_NUM_PV_ELTS},
    cpu::{CpuChip, CpuCols},
    memory::MemoryCols,
};

impl<AB, const L: usize> Air<AB> for CpuChip<AB::F, L>
where
    AB: SP1RecursionAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &CpuCols<AB::Var> = (*local).borrow();
        let next: &CpuCols<AB::Var> = (*next).borrow();
        let pv = builder.public_values();
        let pv_elms: [AB::Expr; RECURSIVE_PROOF_NUM_PV_ELTS] =
            core::array::from_fn(|i| pv[i].into());
        let public_values: &RecursionPublicValues<AB::Expr> = pv_elms.as_slice().borrow();

        let zero = AB::Expr::zero();
        let one = AB::Expr::one();

        // Constrain the program.
        builder.send_program(local.pc, local.instruction, local.selectors, local.is_real);

        // Constrain the operands.
        self.eval_operands(builder, local);

        // Constrain memory instructions.
        self.eval_memory(builder, local);

        // Constrain ALU instructions.
        self.eval_alu(builder, local);

        // Constrain branches and jumps and constrain the next pc.
        {
            // Expression for the expected next_pc.  This will be added to in `eval_branch` and `eval_jump`
            // to account for possible jumps and branches.
            let mut next_pc = zero;

            self.eval_branch(builder, local, &mut next_pc);

            self.eval_jump(builder, local, next, &mut next_pc);

            // If the instruction is not a jump or branch instruction, then next pc = pc + 1.
            let not_branch_or_jump = one.clone()
                - self.is_branch_instruction::<AB>(local)
                - self.is_jump_instruction::<AB>(local);
            next_pc += not_branch_or_jump.clone() * (local.pc + one);

            builder
                .when_transition()
                .when(next.is_real)
                .assert_eq(next_pc, next.pc);
        }

        // Constrain the syscalls.
        let send_syscall = local.selectors.is_poseidon
            + local.selectors.is_fri_fold
            + local.selectors.is_exp_reverse_bits_len;

        let operands = [
            local.clk.into(),
            local.a.value()[0].into(),
            local.b.value()[0].into(),
            local.c.value()[0] + local.instruction.offset_imm,
        ];
        builder.send_table(local.instruction.opcode, &operands, send_syscall);

        // Constrain the public values digest.
        self.eval_commit(builder, local, public_values.digest.clone());

        // Constrain the clk.
        self.eval_clk(builder, local, next);

        // Constrain the system instructions (TRAP, HALT).
        self.eval_system_instructions(builder, local, next, public_values);

        // Verify the heap size.
        self.eval_heap_ptr(builder, local);

        // Constrain the is_real_flag.
        self.eval_is_real(builder, local, next);

        // Create a dummy constraint of the given degree to compress the permutation columns.
        let mut expr = local.is_real * local.is_real;
        for _ in 0..(L - 2) {
            expr *= local.is_real.into();
        }
        builder.assert_eq(expr.clone(), expr.clone());
    }
}

impl<F: Field, const L: usize> CpuChip<F, L> {
    /// Eval the clk.
    ///
    /// For all instructions except for FRI fold, the next clk is the current clk + 4.
    /// For FRI fold, the next clk is the current clk + number of FRI_FOLD iterations.  That value
    /// is stored in the `a` operand.
    pub fn eval_clk<AB>(&self, builder: &mut AB, local: &CpuCols<AB::Var>, next: &CpuCols<AB::Var>)
    where
        AB: SP1RecursionAirBuilder,
    {
        builder
            .when_transition()
            .when(next.is_real)
            .when_not(local.selectors.is_fri_fold + local.selectors.is_exp_reverse_bits_len)
            .assert_eq(local.clk.into() + AB::F::from_canonical_u32(4), next.clk);

        builder
            .when_transition()
            .when(next.is_real)
            .when(local.selectors.is_fri_fold)
            .assert_eq(local.clk.into() + local.a.value()[0], next.clk);

        builder
            .when_transition()
            .when(next.is_real)
            .when(local.selectors.is_exp_reverse_bits_len)
            .assert_eq(local.clk.into() + local.c.value()[0], next.clk);
    }

    /// Eval the is_real flag.
    pub fn eval_is_real<AB>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
    ) where
        AB: SP1RecursionAirBuilder,
    {
        builder.assert_bool(local.is_real);

        // First row should be real.
        builder.when_first_row().assert_one(local.is_real);

        // Once rows transition to not real, then they should stay not real.
        builder
            .when_transition()
            .when_not(local.is_real)
            .assert_zero(next.is_real);
    }

    /// Expr to check for alu instructions.
    pub fn is_alu_instruction<AB>(&self, local: &CpuCols<AB::Var>) -> AB::Expr
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        local.selectors.is_add
            + local.selectors.is_sub
            + local.selectors.is_mul
            + local.selectors.is_div
    }

    /// Expr to check for branch instructions.
    pub fn is_branch_instruction<AB>(&self, local: &CpuCols<AB::Var>) -> AB::Expr
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        local.selectors.is_beq + local.selectors.is_bne + local.selectors.is_bneinc
    }

    /// Expr to check for jump instructions.
    pub fn is_jump_instruction<AB>(&self, local: &CpuCols<AB::Var>) -> AB::Expr
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        local.selectors.is_jal + local.selectors.is_jalr
    }

    /// Expr to check for memory instructions.
    pub fn is_memory_instruction<AB>(&self, local: &CpuCols<AB::Var>) -> AB::Expr
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        local.selectors.is_load + local.selectors.is_store
    }

    /// Expr to check for instructions that only read from operand `a`.
    pub fn is_op_a_read_only_instruction<AB>(&self, local: &CpuCols<AB::Var>) -> AB::Expr
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        local.selectors.is_beq
            + local.selectors.is_bne
            + local.selectors.is_fri_fold
            + local.selectors.is_poseidon
            + local.selectors.is_store
            + local.selectors.is_noop
            + local.selectors.is_ext_to_felt
    }

    /// Expr to check for instructions that are commit instructions.
    pub fn is_commit_instruction<AB>(&self, local: &CpuCols<AB::Var>) -> AB::Expr
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        local.selectors.is_commit.into()
    }

    /// Expr to check for system instructions.
    pub fn is_system_instruction<AB>(&self, local: &CpuCols<AB::Var>) -> AB::Expr
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        local.selectors.is_trap + local.selectors.is_halt
    }
}
