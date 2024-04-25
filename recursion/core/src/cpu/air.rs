use core::mem::size_of;
use p3_air::Air;
use p3_air::AirBuilder;
use p3_air::BaseAir;
use p3_field::AbstractField;
use p3_matrix::Matrix;
use sp1_core::air::BinomialExtension;
use sp1_core::air::ExtensionAirBuilder;
use sp1_core::utils::indices_arr;
use std::borrow::Borrow;
use std::mem::transmute;

use super::columns::CpuCols;
use crate::air::{BinomialExtensionUtils, BlockBuilder, SP1RecursionAirBuilder};
use crate::cpu::CpuChip;
use crate::memory::MemoryCols;

pub const NUM_CPU_COLS: usize = size_of::<CpuCols<u8>>();

const fn make_col_map() -> CpuCols<usize> {
    let indices_arr = indices_arr::<NUM_CPU_COLS>();
    unsafe { transmute::<[usize; NUM_CPU_COLS], CpuCols<usize>>(indices_arr) }
}

pub(crate) const CPU_COL_MAP: CpuCols<usize> = make_col_map();

impl<F: Send + Sync> BaseAir<F> for CpuChip<F> {
    fn width(&self) -> usize {
        NUM_CPU_COLS
    }
}

impl<AB> Air<AB> for CpuChip<AB::F>
where
    AB: SP1RecursionAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        // Constraints for the CPU chip.
        //
        // - Constraints for fetching the instruction.
        // - Constraints for incrementing the internal state consisting of the program counter
        //   and the clock.

        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &CpuCols<AB::Var> = (*local).borrow();
        let next: &CpuCols<AB::Var> = (*next).borrow();

        // Increment clk by 4 every cycle..
        builder
            .when_transition()
            .when(next.is_real)
            .assert_eq(local.clk.into() + AB::F::from_canonical_u32(4), next.clk);

        // // Increment pc by 1 every cycle unless it is a branch instruction that is satisfied.
        // builder
        //     .when_transition()
        //     .when(next.is_real * (AB::Expr::one() - (local.is_beq + local.is_bne)))
        //     .assert_eq(local.pc + AB::F::one(), next.pc);
        // builder
        //     .when(local.beq + local.bne)
        //     .assert_eq(next.pc, local.pc + local.c.value()[0]);

        // Connect immediates.
        builder
            .when(local.instruction.imm_b)
            .assert_block_eq::<AB::Var, AB::Var>(*local.b.value(), local.instruction.op_b);
        builder
            .when(local.instruction.imm_c)
            .assert_block_eq::<AB::Var, AB::Var>(*local.c.value(), local.instruction.op_c);

        builder.assert_eq(
            local.is_real * local.is_real * local.is_real,
            local.is_real * local.is_real * local.is_real,
        );

        self.eval_alu(builder, local);

        // Compute if a == b.
        // IsZeroOperation::<AB::F>::eval::<AB>(
        //     builder,
        //     local.a.value[0] - local.b.value()[0],
        //     local.a_eq_b,
        //     local.is_real.into(),
        // );

        // Receive C.
        builder.recursion_eval_memory_access(
            local.clk,
            local.fp.into() + local.instruction.op_c[0].into(),
            &local.c,
            AB::Expr::one() - local.instruction.imm_c.into(),
        );

        // Receive B.
        builder.recursion_eval_memory_access(
            local.clk,
            local.fp.into() + local.instruction.op_b[0].into(),
            &local.b,
            AB::Expr::one() - local.instruction.imm_b.into(),
        );

        // Receive A.
        builder.recursion_eval_memory_access(
            local.clk,
            local.fp.into() + local.instruction.op_a.into(),
            &local.a,
            local.is_real.into(),
        );

        // let mut prog_interaction_vals: Vec<AB::Expr> = vec![local.instruction.opcode.into()];
        // prog_interaction_vals.push(local.instruction.op_a.into());
        // prog_interaction_vals.extend_from_slice(&local.instruction.op_b.map(|x| x.into()).0);
        // prog_interaction_vals.extend_from_slice(&local.instruction.op_c.map(|x| x.into()).0);
        // prog_interaction_vals.push(local.instruction.imm_b.into());
        // prog_interaction_vals.push(local.instruction.imm_c.into());
        // prog_interaction_vals.extend_from_slice(
        //     &local
        //         .selectors
        //         .into_iter()
        //         .map(|x| x.into())
        //         .collect::<Vec<_>>(),
        // );
        // builder.send(AirInteraction::new(
        //     prog_interaction_vals,
        //     local.is_real.into(),
        //     InteractionKind::Program,
        // ));
    }
}

impl<F> CpuChip<F> {
    /// Eval all the ALU operations.
    fn eval_alu<AB>(&self, builder: &mut AB, local: &CpuCols<AB::Var>)
    where
        AB: SP1RecursionAirBuilder<F = F>,
    {
        // Convert register values from Block<Var> to BinomialExtension<Expr>.
        let a_ext: BinomialExtension<AB::Expr> =
            BinomialExtensionUtils::from_block(local.a.value().map(|x| x.into()));
        let b_ext: BinomialExtension<AB::Expr> =
            BinomialExtensionUtils::from_block(local.b.value().map(|x| x.into()));
        let c_ext: BinomialExtension<AB::Expr> =
            BinomialExtensionUtils::from_block(local.c.value().map(|x| x.into()));

        // Flag to check if the instruction is a field operation
        let is_field_op = local.selectors.is_add
            + local.selectors.is_sub
            + local.selectors.is_mul
            + local.selectors.is_div;

        // Verify that the b and c registers are base elements for field operations.
        builder
            .when(is_field_op.clone())
            .assert_is_base_element(b_ext.clone());
        builder
            .when(is_field_op)
            .assert_is_base_element(c_ext.clone());

        // Verify the actual operation.
        builder
            .when(local.selectors.is_add + local.selectors.is_eadd)
            .assert_ext_eq(a_ext.clone(), b_ext.clone() + c_ext.clone());
        builder
            .when(local.selectors.is_sub + local.selectors.is_esub)
            .assert_ext_eq(a_ext.clone(), b_ext.clone() - c_ext.clone());
        builder
            .when(local.selectors.is_mul + local.selectors.is_emul)
            .assert_ext_eq(a_ext.clone(), b_ext.clone() * c_ext.clone());
        // For div operation, we assert that b == a * c (equivalent to a == b / c).
        builder
            .when(local.selectors.is_div + local.selectors.is_ediv)
            .assert_ext_eq(b_ext, a_ext * c_ext);
    }
}
