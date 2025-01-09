use std::borrow::Borrow;

use p3_air::{Air, AirBuilder};
use p3_field::AbstractField;
use p3_matrix::Matrix;
use sp1_core_executor::{
    events::MemoryAccessPosition, syscalls::SyscallCode, Opcode, Register::X5,
};
use sp1_stark::{
    air::{
        BaseAirBuilder, InteractionScope, PublicValues, SP1AirBuilder, POSEIDON_NUM_WORDS,
        PV_DIGEST_NUM_WORDS, SP1_PROOF_NUM_PV_ELTS,
    },
    Word,
};

use crate::{
    air::{MemoryAirBuilder, WordAirBuilder},
    memory::MemoryCols,
    operations::{BabyBearWordRangeChecker, IsZeroOperation},
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
        let local = main.row_slice(0);
        let local: &SyscallInstrColumns<AB::Var> = (*local).borrow();

        let public_values_slice: [AB::PublicVar; SP1_PROOF_NUM_PV_ELTS] =
            core::array::from_fn(|i| builder.public_values()[i]);
        let public_values: &PublicValues<Word<AB::PublicVar>, AB::PublicVar> =
            public_values_slice.as_slice().borrow();

        // SAFETY: Only `ECALL` opcode can be received in this chip.
        // `is_real` is checked to be boolean, and the `opcode` matches the corresponding opcode.
        builder.assert_bool(local.is_real);

        // Verify that local.is_halt is correct.
        self.eval_is_halt_syscall(builder, local);

        // SAFETY: This checks the following.
        // - `shard`, `clk` are correctly received from the CpuChip
        // - `op_a_0 = 0` enforced, as `op_a = X5` for all ECALL
        // - `op_a_immutable = 0`
        // - `is_memory = 0`
        // - `is_syscall = 1`
        // `next_pc`, `num_extra_cycles`, `op_a_val`, `is_halt` need to be constrained. We outline the checks below.
        // `next_pc` is constrained for the case where `is_halt` is true to be `0` in `eval_is_halt_unimpl`.
        // `next_pc` is constrained for the case where `is_halt` is false to be `pc + 4` in `eval`.
        // `num_extra_cycles` is checked to be equal to the return value of `get_num_extra_ecall_cycles`, in `eval`.
        // `op_a_val` is constrained in `eval_ecall`.
        // `is_halt` is checked to be correct in `eval_is_halt_syscall`.
        builder.receive_instruction(
            local.shard,
            local.clk,
            local.pc,
            local.next_pc,
            local.num_extra_cycles,
            Opcode::ECALL.as_field::<AB::F>(),
            *local.op_a_access.value(),
            local.op_b_value,
            local.op_c_value,
            AB::Expr::zero(), // op_a is always register 5 for ecall instructions.
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::one(),
            local.is_halt,
            local.is_real,
        );

        // If the syscall is not halt, then next_pc should be pc + 4.
        // `next_pc` is constrained for the case where `is_halt` is false to be `pc + 4`
        builder
            .when(local.is_real)
            .when(AB::Expr::one() - local.is_halt)
            .assert_eq(local.next_pc, local.pc + AB::Expr::from_canonical_u32(4));

        // `num_extra_cycles` is checked to be equal to the return value of `get_num_extra_ecall_cycles`
        builder.assert_eq::<AB::Var, AB::Expr>(
            local.num_extra_cycles,
            self.get_num_extra_ecall_cycles::<AB>(local),
        );

        // Do the memory eval for op_a. For syscall instructions, we need to eval at register X5.
        builder.eval_memory_access(
            local.shard,
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::A as u32),
            AB::Expr::from_canonical_u32(X5 as u32),
            &local.op_a_access,
            local.is_real,
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
        self.eval_halt_unimpl(builder, local, public_values);
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

        // SAFETY: Assert that for non real row, the send_to_table value is 0 so that the `send_syscall`
        // interaction is not activated.
        builder.when(AB::Expr::one() - local.is_real).assert_zero(send_to_table);

        builder.send_syscall(
            local.shard,
            local.clk,
            syscall_id,
            local.op_b_value.reduce::<AB>(),
            local.op_c_value.reduce::<AB>(),
            send_to_table,
            InteractionScope::Local,
        );

        // Compute whether this ecall is ENTER_UNCONSTRAINED.
        let is_enter_unconstrained = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id
                    - AB::Expr::from_canonical_u32(SyscallCode::ENTER_UNCONSTRAINED.syscall_id()),
                local.is_enter_unconstrained,
                local.is_real.into(),
            );
            local.is_enter_unconstrained.result
        };

        // Compute whether this ecall is HINT_LEN.
        let is_hint_len = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id - AB::Expr::from_canonical_u32(SyscallCode::HINT_LEN.syscall_id()),
                local.is_hint_len,
                local.is_real.into(),
            );
            local.is_hint_len.result
        };

        // `op_a_val` is constrained.

        // When syscall_id is ENTER_UNCONSTRAINED, the new value of op_a should be 0.
        let zero_word = Word::<AB::F>::from(0);
        builder
            .when(local.is_real)
            .when(is_enter_unconstrained)
            .assert_word_eq(*local.op_a_access.value(), zero_word);

        // When the syscall is not one of ENTER_UNCONSTRAINED or HINT_LEN, op_a shouldn't change.
        builder
            .when(local.is_real)
            .when_not(is_enter_unconstrained + is_hint_len)
            .assert_word_eq(*local.op_a_access.value(), *local.op_a_access.prev_value());

        // SAFETY: This leaves the case where syscall is `HINT_LEN`.
        // In this case, `op_a`'s value can be arbitrary, but it still must be a valid word if `is_real = 1`.
        // This is due to `op_a_val` being connected to the CpuChip.
        // In the CpuChip, `op_a_val` is constrained to be a valid word via `eval_registers`.
        // As this is a syscall for HINT, the value itself being arbitrary is fine, as long as it is a valid word.

        // Verify value of ecall_range_check_operand column.
        // SAFETY: If `is_real = 0`, then `ecall_range_check_operand = 0`.
        // If `is_real = 1`, then `is_halt_check` and `is_commit_deferred_proofs` are constrained.
        // The two results will both be boolean due to `IsZeroOperation`, and both cannot be `1` at the same time.
        // Both of them being `1` will require `syscall_id` being `HALT` and `COMMIT_DEFERRED_PROOFS` at the same time.
        // This implies that if `is_real = 1`, `ecall_range_check_operand` will be correct, and boolean.
        builder.assert_eq(
            local.ecall_range_check_operand,
            local.is_real * (local.is_halt_check.result + local.is_commit_deferred_proofs.result),
        );

        // Babybear range check the operand_to_check word.
        // SAFETY: `ecall_range_check_operand` is boolean, and no interactions can be made in padding rows.
        // `operand_to_check` is already known to be a valid word, as it is either
        // - `op_b_val` in the case of `HALT`
        // - `op_c_val` in the case of `COMMIT_DEFERRED_PROOFS`
        BabyBearWordRangeChecker::<AB::F>::range_check::<AB>(
            builder,
            local.operand_to_check,
            local.operand_range_check_cols,
            local.ecall_range_check_operand.into(),
        );
    }

    /// Constraints related to the COMMIT and COMMIT_DEFERRED_PROOFS instructions.
    pub(crate) fn eval_commit<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &SyscallInstrColumns<AB::Var>,
        commit_digest: [Word<AB::PublicVar>; PV_DIGEST_NUM_WORDS],
        deferred_proofs_digest: [AB::PublicVar; POSEIDON_NUM_WORDS],
    ) {
        let (is_commit, is_commit_deferred_proofs) =
            self.get_is_commit_related_syscall(builder, local);

        // Verify the index bitmap.
        let mut bitmap_sum = AB::Expr::zero();
        // They should all be bools.
        for bit in local.index_bitmap.iter() {
            builder.when(local.is_real).assert_bool(*bit);
            bitmap_sum = bitmap_sum.clone() + (*bit).into();
        }
        // When the syscall is COMMIT or COMMIT_DEFERRED_PROOFS, there should be one set bit.
        builder
            .when(local.is_real)
            .when(is_commit.clone() + is_commit_deferred_proofs.clone())
            .assert_one(bitmap_sum.clone());
        // When it's some other syscall, there should be no set bits.
        builder
            .when(local.is_real)
            .when(AB::Expr::one() - (is_commit.clone() + is_commit_deferred_proofs.clone()))
            .assert_zero(bitmap_sum);

        // Verify that word_idx corresponds to the set bit in index bitmap.
        for (i, bit) in local.index_bitmap.iter().enumerate() {
            builder
                .when(local.is_real)
                .when(*bit)
                .assert_eq(local.op_b_value[0], AB::Expr::from_canonical_u32(i as u32));
        }
        // Verify that the 3 upper bytes of the word_idx are 0.
        for i in 0..3 {
            builder
                .when(local.is_real)
                .when(is_commit.clone() + is_commit_deferred_proofs.clone())
                .assert_zero(local.op_b_value[i + 1]);
        }

        // Retrieve the expected public values digest word to check against the one passed into the
        // commit ecall. Note that for the interaction builder, it will not have any digest words,
        // since it's used during AIR compilation time to parse for all send/receives. Since
        // that interaction builder will ignore the other constraints of the air, it is safe
        // to not include the verification check of the expected public values digest word.
        let expected_pv_digest_word = builder.index_word_array(&commit_digest, &local.index_bitmap);

        let digest_word = local.op_c_value;

        // Verify the public_values_digest_word.
        builder
            .when(local.is_real)
            .when(is_commit.clone())
            .assert_word_eq(expected_pv_digest_word, digest_word);

        let expected_deferred_proofs_digest_element =
            builder.index_array(&deferred_proofs_digest, &local.index_bitmap);

        // Verify that the operand that was range checked is digest_word.
        builder
            .when(local.is_real)
            .when(is_commit_deferred_proofs.clone())
            .assert_word_eq(digest_word, local.operand_to_check);

        builder
            .when(local.is_real)
            .when(is_commit_deferred_proofs.clone())
            .assert_eq(expected_deferred_proofs_digest_element, digest_word.reduce::<AB>());
    }

    /// Constraint related to the halt and unimpl instruction.
    pub(crate) fn eval_halt_unimpl<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &SyscallInstrColumns<AB::Var>,
        public_values: &PublicValues<Word<AB::PublicVar>, AB::PublicVar>,
    ) {
        // `next_pc` is constrained for the case where `is_halt` is true to be `0`
        builder.when(local.is_halt).assert_zero(local.next_pc);

        // Verify that the operand that was range checked is op_b.
        builder.when(local.is_halt).assert_word_eq(local.op_b_value, local.operand_to_check);

        // Check that the `op_b_value` reduced is the `public_values.exit_code`.
        builder
            .when(local.is_halt)
            .assert_eq(local.op_b_value.reduce::<AB>(), public_values.exit_code);
    }

    /// Returns a boolean expression indicating whether the instruction is a HALT instruction.
    pub(crate) fn eval_is_halt_syscall<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &SyscallInstrColumns<AB::Var>,
    ) {
        // `is_halt` is checked to be correct in `eval_is_halt_syscall`.

        // The syscall code is the read-in value of op_a at the start of the instruction.
        let syscall_code = local.op_a_access.prev_value();

        let syscall_id = syscall_code[0];

        // Compute whether this ecall is HALT.
        let is_halt = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id - AB::Expr::from_canonical_u32(SyscallCode::HALT.syscall_id()),
                local.is_halt_check,
                local.is_real.into(),
            );
            local.is_halt_check.result
        };

        // Verify that the is_halt flag is correct.
        // If `is_real = 0`, then `local.is_halt = 0`.
        // If `is_real = 1`, then `is_halt_check.result` will be correct, so `local.is_halt` is correct.
        builder.assert_eq(local.is_halt, is_halt * local.is_real);
    }

    /// Returns two boolean expression indicating whether the instruction is a COMMIT or
    /// COMMIT_DEFERRED_PROOFS instruction.
    pub(crate) fn get_is_commit_related_syscall<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &SyscallInstrColumns<AB::Var>,
    ) -> (AB::Expr, AB::Expr) {
        // The syscall code is the read-in value of op_a at the start of the instruction.
        let syscall_code = local.op_a_access.prev_value();

        let syscall_id = syscall_code[0];

        // Compute whether this ecall is COMMIT.
        let is_commit = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id - AB::Expr::from_canonical_u32(SyscallCode::COMMIT.syscall_id()),
                local.is_commit,
                local.is_real.into(),
            );
            local.is_commit.result
        };

        // Compute whether this ecall is COMMIT_DEFERRED_PROOFS.
        let is_commit_deferred_proofs = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id
                    - AB::Expr::from_canonical_u32(
                        SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id(),
                    ),
                local.is_commit_deferred_proofs,
                local.is_real.into(),
            );
            local.is_commit_deferred_proofs.result
        };

        (is_commit.into(), is_commit_deferred_proofs.into())
    }

    /// Returns the number of extra cycles from an ECALL instruction.
    pub(crate) fn get_num_extra_ecall_cycles<AB: SP1AirBuilder>(
        &self,
        local: &SyscallInstrColumns<AB::Var>,
    ) -> AB::Expr {
        // The syscall code is the read-in value of op_a at the start of the instruction.
        let syscall_code = local.op_a_access.prev_value();

        let num_extra_cycles = syscall_code[2];

        // If `is_real = 0`, then the return value is `0` regardless of `num_extra_cycles`.
        // If `is_real = 1`, then the `op_a_access` will be done, and `num_extra_cycles` will be correct.
        num_extra_cycles * local.is_real
    }
}
