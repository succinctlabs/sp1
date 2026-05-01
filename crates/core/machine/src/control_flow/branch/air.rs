use std::borrow::Borrow;

use slop_air::{Air, AirBuilder};
use slop_algebra::{AbstractField, Field};
use slop_matrix::Matrix;

use crate::{
    adapter::{
        register::i_type::{ITypeReaderImmutable, ITypeReaderImmutableInput},
        state::{CPUState, CPUStateInput},
    },
    air::{SP1CoreAirBuilder, SP1Operation},
    eval_untrusted_program,
    operations::{LtOperationSigned, LtOperationSignedInput},
    TrustMode, UserMode,
};
use sp1_core_executor::{ByteOpcode, Opcode, CLK_INC, PC_INC};

use super::{BranchChip, BranchColumns};

/// Verifies all the branching related columns.
///
/// It does this in few parts:
/// 1. It verifies that the next pc is correct based on the branching column.  That column is a
///    boolean that indicates whether the branch condition is true.
/// 2. It verifies the correct value of branching based on the opcode and the comparison operation.
impl<AB, M> Air<AB> for BranchChip<M>
where
    AB: SP1CoreAirBuilder,
    AB::Var: Sized,
    M: TrustMode,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &BranchColumns<AB::Var, M> = (*local).borrow();

        // SAFETY: All selectors `is_beq`, `is_bne`, `is_blt`, `is_bge`, `is_bltu`, `is_bgeu` are
        // checked to be boolean. Each "real" row has exactly one selector turned on, as
        // `is_real`, the sum of the six selectors, is boolean. Therefore, the `opcode`
        // matches the corresponding opcode.
        builder.assert_bool(local.is_beq);
        builder.assert_bool(local.is_bne);
        builder.assert_bool(local.is_blt);
        builder.assert_bool(local.is_bge);
        builder.assert_bool(local.is_bltu);
        builder.assert_bool(local.is_bgeu);
        let is_real = local.is_beq
            + local.is_bne
            + local.is_blt
            + local.is_bge
            + local.is_bltu
            + local.is_bgeu;
        builder.assert_bool(is_real.clone());

        let opcode = local.is_beq * Opcode::BEQ.as_field::<AB::F>()
            + local.is_bne * Opcode::BNE.as_field::<AB::F>()
            + local.is_blt * Opcode::BLT.as_field::<AB::F>()
            + local.is_bge * Opcode::BGE.as_field::<AB::F>()
            + local.is_bltu * Opcode::BLTU.as_field::<AB::F>()
            + local.is_bgeu * Opcode::BGEU.as_field::<AB::F>();

        // Compute instruction field constants for each opcode
        let funct3 = local.is_beq * AB::Expr::from_canonical_u8(Opcode::BEQ.funct3().unwrap())
            + local.is_bne * AB::Expr::from_canonical_u8(Opcode::BNE.funct3().unwrap())
            + local.is_blt * AB::Expr::from_canonical_u8(Opcode::BLT.funct3().unwrap())
            + local.is_bge * AB::Expr::from_canonical_u8(Opcode::BGE.funct3().unwrap())
            + local.is_bltu * AB::Expr::from_canonical_u8(Opcode::BLTU.funct3().unwrap())
            + local.is_bgeu * AB::Expr::from_canonical_u8(Opcode::BGEU.funct3().unwrap());
        let funct7 = local.is_beq * AB::Expr::from_canonical_u8(Opcode::BEQ.funct7().unwrap_or(0))
            + local.is_bne * AB::Expr::from_canonical_u8(Opcode::BNE.funct7().unwrap_or(0))
            + local.is_blt * AB::Expr::from_canonical_u8(Opcode::BLT.funct7().unwrap_or(0))
            + local.is_bge * AB::Expr::from_canonical_u8(Opcode::BGE.funct7().unwrap_or(0))
            + local.is_bltu * AB::Expr::from_canonical_u8(Opcode::BLTU.funct7().unwrap_or(0))
            + local.is_bgeu * AB::Expr::from_canonical_u8(Opcode::BGEU.funct7().unwrap_or(0));
        let base_opcode = local.is_beq * AB::Expr::from_canonical_u32(Opcode::BEQ.base_opcode().0)
            + local.is_bne * AB::Expr::from_canonical_u32(Opcode::BNE.base_opcode().0)
            + local.is_blt * AB::Expr::from_canonical_u32(Opcode::BLT.base_opcode().0)
            + local.is_bge * AB::Expr::from_canonical_u32(Opcode::BGE.base_opcode().0)
            + local.is_bltu * AB::Expr::from_canonical_u32(Opcode::BLTU.base_opcode().0)
            + local.is_bgeu * AB::Expr::from_canonical_u32(Opcode::BGEU.base_opcode().0);
        let instr_type = local.is_beq
            * AB::Expr::from_canonical_u32(Opcode::BEQ.instruction_type().0 as u32)
            + local.is_bne * AB::Expr::from_canonical_u32(Opcode::BNE.instruction_type().0 as u32)
            + local.is_blt * AB::Expr::from_canonical_u32(Opcode::BLT.instruction_type().0 as u32)
            + local.is_bge * AB::Expr::from_canonical_u32(Opcode::BGE.instruction_type().0 as u32)
            + local.is_bltu
                * AB::Expr::from_canonical_u32(Opcode::BLTU.instruction_type().0 as u32)
            + local.is_bgeu
                * AB::Expr::from_canonical_u32(Opcode::BGEU.instruction_type().0 as u32);

        // Constrain the state of the CPU.
        // The `next_pc` is constrained by the AIR.
        // The clock is incremented by `8`.
        <CPUState<AB::F> as SP1Operation<AB>>::eval(
            builder,
            CPUStateInput::new(
                local.state,
                local.next_pc.map(Into::into),
                AB::Expr::from_canonical_u32(CLK_INC),
                is_real.clone(),
            ),
        );

        let mut is_trusted: AB::Expr = is_real.clone();

        #[cfg(feature = "mprotect")]
        builder.assert_eq(
            builder.extract_public_values().is_untrusted_programs_enabled,
            AB::Expr::from_bool(!M::IS_TRUSTED),
        );

        if !M::IS_TRUSTED {
            let local = main.row_slice(0);
            let local: &BranchColumns<AB::Var, UserMode> = (*local).borrow();

            let instruction = local.adapter.instruction::<AB>(opcode.clone());

            #[cfg(not(feature = "mprotect"))]
            builder.assert_zero(is_real.clone());

            eval_untrusted_program(
                builder,
                local.state.pc,
                instruction,
                [instr_type, base_opcode, funct3, funct7],
                [local.state.clk_high::<AB>(), local.state.clk_low::<AB>()],
                is_real.clone(),
                local.adapter_cols,
            );

            is_trusted = local.adapter_cols.is_trusted.into();
        }

        // Constrain the program and register reads.
        <ITypeReaderImmutable as SP1Operation<AB>>::eval(
            builder,
            ITypeReaderImmutableInput::new(
                local.state.clk_high::<AB>(),
                local.state.clk_low::<AB>(),
                local.state.pc,
                opcode,
                local.adapter,
                is_real.clone(),
                is_trusted,
            ),
        );

        // SAFETY: `use_signed_comparison` is boolean, since at most one selector is turned on.
        let use_signed_comparison = local.is_blt + local.is_bge;
        <LtOperationSigned<AB::F> as SP1Operation<AB>>::eval(
            builder,
            LtOperationSignedInput::<AB>::new(
                local.adapter.prev_a().map(Into::into),
                local.adapter.b().map(Into::into),
                local.compare_operation,
                use_signed_comparison.clone(),
                is_real.clone(),
            ),
        );

        // From the `LtOperationSigned`, derive whether `a == b`, `a < b`, or `a > b`.
        let is_eq = AB::Expr::one()
            - (local.compare_operation.result.u16_flags[0]
                + local.compare_operation.result.u16_flags[1]
                + local.compare_operation.result.u16_flags[2]
                + local.compare_operation.result.u16_flags[3]);
        let is_less_than = local.compare_operation.result.u16_compare_operation.bit;

        // Constrain the branching column with the comparison results and opcode flags.
        let mut branching: AB::Expr = AB::Expr::zero();
        branching = branching.clone() + local.is_beq * is_eq.clone();
        branching = branching.clone() + local.is_bne * (AB::Expr::one() - is_eq);
        branching =
            branching.clone() + (local.is_bge + local.is_bgeu) * (AB::Expr::one() - is_less_than);
        branching = branching.clone() + (local.is_blt + local.is_bltu) * is_less_than;

        builder.assert_bool(local.is_branching);
        builder.when(is_real.clone()).assert_eq(local.is_branching, branching.clone());

        // Constrain the next_pc using the branching column.
        // Show that if `is_branching` is true, then next_pc == pc + op_c
        // Show that if `is_branching` is false, then next_pc == pc + 4
        let base_inverse = AB::F::from_canonical_u32(1 << 16).inverse();
        let mut carry = AB::Expr::zero();
        for i in 0..4 {
            let pc = if i < 3 { local.state.pc[i].into() } else { AB::Expr::zero() };
            let next_pc = if i < 3 { local.next_pc[i].into() } else { AB::Expr::zero() };
            carry = (carry.clone() + pc + local.adapter.c()[i] - next_pc) * base_inverse;
            builder.when(local.is_branching).assert_bool(carry.clone());
        }

        let mut carry = AB::Expr::zero();
        for i in 0..4 {
            let pc = if i < 3 { local.state.pc[i].into() } else { AB::Expr::zero() };
            let next_pc = if i < 3 { local.next_pc[i].into() } else { AB::Expr::zero() };
            let increment =
                if i == 0 { AB::Expr::from_canonical_u32(PC_INC) } else { AB::Expr::zero() };
            carry = (carry.clone() + pc + increment - next_pc) * base_inverse;
            builder.when(is_real.clone() - local.is_branching).assert_bool(carry.clone());
        }

        // Check that the `next_pc` value is a multiple of 4.
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            local.next_pc[0].into() * AB::F::from_canonical_u32(4).inverse(),
            AB::Expr::from_canonical_u32(14),
            AB::Expr::zero(),
            is_real.clone(),
        );
        builder.slice_range_check_u16(&local.next_pc[1..3], is_real);
    }
}
