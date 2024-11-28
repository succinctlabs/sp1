use std::borrow::Borrow;

use p3_air::Air;
use p3_field::AbstractField;
use p3_matrix::Matrix;
use sp1_core_executor::{events::MemoryAccessPosition, Opcode, Register::X5};
use sp1_stark::{
    air::{InteractionScope, PublicValues, SP1AirBuilder, SP1_PROOF_NUM_PV_ELTS},
    Word,
};

use crate::{
    air::{MemoryAirBuilder, WordAirBuilder},
    memory::MemoryCols,
};

use super::{columns::SyscallInstrColumns, SyscallInstrsChip};

impl<AB> Air<AB> for SyscallInstrsChip
where
    AB: SP1AirBuilder,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &SyscallInstrColumns<AB::Var> = (*local).borrow();
        let next: &SyscallInstrColumns<AB::Var> = (*next).borrow();

        let public_values_slice: [AB::PublicVar; SP1_PROOF_NUM_PV_ELTS] =
            core::array::from_fn(|i| builder.public_values()[i]);
        let public_values: &PublicValues<Word<AB::PublicVar>, AB::PublicVar> =
            public_values_slice.as_slice().borrow();

        builder.assert_bool(local.is_ecall);
        builder.assert_bool(local.is_unimpl);
        let is_real = local.is_ecall + local.is_unimpl;
        builder.assert_bool(is_real.clone());

        let opcode = local.is_ecall * Opcode::ECALL.as_field::<AB::F>()
            + local.is_unimpl * Opcode::UNIMP.as_field::<AB::F>();

        builder.receive_instruction(
            local.pc,
            local.next_pc,
            local.num_extra_cycles,
            opcode,
            *local.op_a_access.value(),
            local.op_b_value,
            local.op_c_value,
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::one(),
            is_real.clone(),
        );

        // Do the memory eval for op_a. For syscall instructions, we need to eval at register X5.
        builder.eval_memory_access(
            local.shard,
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::A as u32),
            AB::Expr::from_canonical_u32(X5 as u32),
            &local.op_a_access,
            local.is_ecall,
        );

        // ECALL instruction.
        self.eval_ecall(builder, local);

        // COMMIT/COMMIT_DEFERRED_PROOFS ecall instruction.
        self.eval_commit(
            builder,
            local,
            public_values.committed_value_digest,
            public_values.deferred_proofs_digest,
        );

        // HALT ecall and UNIMPL instruction.
        self.eval_halt_unimpl(builder, local, next, public_values);
    }
}

impl SyscallInstrsChip {
    /// Constraints related to the ECALL opcode.
    ///
    /// This method will do the following:
    /// 1. Send the syscall to the precompile table, if needed.
    /// 2. Check for valid op_a values.
    pub(crate) fn eval_ecall<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &SyscallInstrColumns<AB::Var>,
    ) {
        // The syscall code is the read-in value of op_a at the start of the instruction.
        let syscall_code = local.op_a_access.prev_value();

        // We interpret the syscall_code as little-endian bytes and interpret each byte as a u8
        // with different information.
        let syscall_id = syscall_code[0];
        let send_to_table = syscall_code[1];

        builder.send_syscall(
            local.shard,
            local.clk,
            local.syscall_nonce,
            syscall_id,
            local.op_b_value,
            local.op_c_value,
            send_to_table,
            InteractionScope::Local,
        );

        // Compute whether this ecall is ENTER_UNCONSTRAINED.
        let is_enter_unconstrained = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id
                    - AB::Expr::from_canonical_u32(SyscallCode::ENTER_UNCONSTRAINED.syscall_id()),
                ecall_cols.is_enter_unconstrained,
                is_ecall_instruction.clone(),
            );
            ecall_cols.is_enter_unconstrained.result
        };

        // Compute whether this ecall is HINT_LEN.
        let is_hint_len = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id - AB::Expr::from_canonical_u32(SyscallCode::HINT_LEN.syscall_id()),
                ecall_cols.is_hint_len,
                is_ecall_instruction.clone(),
            );
            ecall_cols.is_hint_len.result
        };

        // When syscall_id is ENTER_UNCONSTRAINED, the new value of op_a should be 0.
        let zero_word = Word::<AB::F>::from(0);
        builder
            .when(is_ecall_instruction.clone() * is_enter_unconstrained)
            .assert_word_eq(local.op_a_val(), zero_word);

        // When the syscall is not one of ENTER_UNCONSTRAINED or HINT_LEN, op_a shouldn't change.
        builder
            .when(is_ecall_instruction.clone())
            .when_not(is_enter_unconstrained + is_hint_len)
            .assert_word_eq(local.op_a_val(), local.op_a_access.prev_value);

        // Verify value of ecall_range_check_operand column.
        builder.assert_eq(
            local.ecall_range_check_operand,
            is_ecall_instruction
                * (ecall_cols.is_halt.result + ecall_cols.is_commit_deferred_proofs.result),
        );

        // Babybear range check the operand_to_check word.
        BabyBearWordRangeChecker::<AB::F>::range_check::<AB>(
            builder,
            ecall_cols.operand_to_check,
            ecall_cols.operand_range_check_cols,
            local.ecall_range_check_operand.into(),
        );
    }

    /// Constraints related to the COMMIT and COMMIT_DEFERRED_PROOFS instructions.
    pub(crate) fn eval_commit<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        commit_digest: [Word<AB::PublicVar>; PV_DIGEST_NUM_WORDS],
        deferred_proofs_digest: [AB::PublicVar; POSEIDON_NUM_WORDS],
    ) {
        let (is_commit, is_commit_deferred_proofs) =
            self.get_is_commit_related_syscall(builder, local);

        // Get the ecall specific columns.
        let ecall_columns = local.opcode_specific_columns.ecall();

        // Verify the index bitmap.
        let mut bitmap_sum = AB::Expr::zero();
        // They should all be bools.
        for bit in ecall_columns.index_bitmap.iter() {
            builder.when(local.selectors.is_ecall).assert_bool(*bit);
            bitmap_sum = bitmap_sum.clone() + (*bit).into();
        }
        // When the syscall is COMMIT or COMMIT_DEFERRED_PROOFS, there should be one set bit.
        builder
            .when(
                local.selectors.is_ecall * (is_commit.clone() + is_commit_deferred_proofs.clone()),
            )
            .assert_one(bitmap_sum.clone());
        // When it's some other syscall, there should be no set bits.
        builder
            .when(
                local.selectors.is_ecall
                    * (AB::Expr::one() - (is_commit.clone() + is_commit_deferred_proofs.clone())),
            )
            .assert_zero(bitmap_sum);

        // Verify that word_idx corresponds to the set bit in index bitmap.
        for (i, bit) in ecall_columns.index_bitmap.iter().enumerate() {
            builder.when(*bit * local.selectors.is_ecall).assert_eq(
                local.op_b_access.prev_value()[0],
                AB::Expr::from_canonical_u32(i as u32),
            );
        }
        // Verify that the 3 upper bytes of the word_idx are 0.
        for i in 0..3 {
            builder
                .when(
                    local.selectors.is_ecall
                        * (is_commit.clone() + is_commit_deferred_proofs.clone()),
                )
                .assert_eq(local.op_b_access.prev_value()[i + 1], AB::Expr::from_canonical_u32(0));
        }

        // Retrieve the expected public values digest word to check against the one passed into the
        // commit ecall. Note that for the interaction builder, it will not have any digest words,
        // since it's used during AIR compilation time to parse for all send/receives. Since
        // that interaction builder will ignore the other constraints of the air, it is safe
        // to not include the verification check of the expected public values digest word.
        let expected_pv_digest_word =
            builder.index_word_array(&commit_digest, &ecall_columns.index_bitmap);

        let digest_word = local.op_c_access.prev_value();

        // Verify the public_values_digest_word.
        builder
            .when(local.selectors.is_ecall * is_commit)
            .assert_word_eq(expected_pv_digest_word, *digest_word);

        let expected_deferred_proofs_digest_element =
            builder.index_array(&deferred_proofs_digest, &ecall_columns.index_bitmap);

        // Verify that the operand that was range checked is digest_word.
        builder
            .when(local.selectors.is_ecall * is_commit_deferred_proofs.clone())
            .assert_word_eq(*digest_word, ecall_columns.operand_to_check);

        builder
            .when(local.selectors.is_ecall * is_commit_deferred_proofs)
            .assert_eq(expected_deferred_proofs_digest_element, digest_word.reduce::<AB>());
    }

    /// Constraint related to the halt and unimpl instruction.
    pub(crate) fn eval_halt_unimpl<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
        public_values: &PublicValues<Word<AB::PublicVar>, AB::PublicVar>,
    ) {
        let is_halt = self.get_is_halt_syscall(builder, local);

        // If we're halting and it's a transition, then the next.is_real should be 0.
        builder
            .when_transition()
            .when(is_halt.clone() + local.selectors.is_unimpl)
            .assert_zero(next.is_real);

        builder.when(is_halt.clone()).assert_zero(local.next_pc);

        // Verify that the operand that was range checked is op_b.
        let ecall_columns = local.opcode_specific_columns.ecall();
        builder
            .when(is_halt.clone())
            .assert_word_eq(local.op_b_val(), ecall_columns.operand_to_check);

        builder
            .when(is_halt.clone())
            .assert_eq(local.op_b_access.value().reduce::<AB>(), public_values.exit_code);
    }

    /// Returns a boolean expression indicating whether the instruction is a HALT instruction.
    pub(crate) fn get_is_halt_syscall<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
    ) -> AB::Expr {
        let ecall_cols = local.opcode_specific_columns.ecall();
        let is_ecall_instruction = self.is_ecall_instruction::<AB>(&local.selectors);

        // The syscall code is the read-in value of op_a at the start of the instruction.
        let syscall_code = local.op_a_access.prev_value();

        let syscall_id = syscall_code[0];

        // Compute whether this ecall is HALT.
        let is_halt = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id - AB::Expr::from_canonical_u32(SyscallCode::HALT.syscall_id()),
                ecall_cols.is_halt,
                is_ecall_instruction.clone(),
            );
            ecall_cols.is_halt.result
        };

        is_halt * is_ecall_instruction
    }

    /// Returns two boolean expression indicating whether the instruction is a COMMIT or
    /// COMMIT_DEFERRED_PROOFS instruction.
    pub(crate) fn get_is_commit_related_syscall<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
    ) -> (AB::Expr, AB::Expr) {
        let ecall_cols = local.opcode_specific_columns.ecall();

        let is_ecall_instruction = self.is_ecall_instruction::<AB>(&local.selectors);

        // The syscall code is the read-in value of op_a at the start of the instruction.
        let syscall_code = local.op_a_access.prev_value();

        let syscall_id = syscall_code[0];

        // Compute whether this ecall is COMMIT.
        let is_commit = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id - AB::Expr::from_canonical_u32(SyscallCode::COMMIT.syscall_id()),
                ecall_cols.is_commit,
                is_ecall_instruction.clone(),
            );
            ecall_cols.is_commit.result
        };

        // Compute whether this ecall is COMMIT_DEFERRED_PROOFS.
        let is_commit_deferred_proofs = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id
                    - AB::Expr::from_canonical_u32(
                        SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id(),
                    ),
                ecall_cols.is_commit_deferred_proofs,
                is_ecall_instruction.clone(),
            );
            ecall_cols.is_commit_deferred_proofs.result
        };

        (is_commit.into(), is_commit_deferred_proofs.into())
    }

    /// Returns the number of extra cycles from an ECALL instruction.
    pub(crate) fn get_num_extra_ecall_cycles<AB: SP1AirBuilder>(
        &self,
        local: &CpuCols<AB::Var>,
    ) -> AB::Expr {
        let is_ecall_instruction = self.is_ecall_instruction::<AB>(&local.selectors);

        // The syscall code is the read-in value of op_a at the start of the instruction.
        let syscall_code = local.op_a_access.prev_value();

        let num_extra_cycles = syscall_code[2];

        num_extra_cycles * is_ecall_instruction.clone()
    }
}
