use std::borrow::Borrow;

use itertools::Itertools;
use slop_air::{Air, AirBuilder};
use slop_algebra::AbstractField;
use slop_matrix::Matrix;
use sp1_core_executor::{Opcode, SyscallCode, CLK_INC, HALT_PC};
use sp1_hypercube::{
    air::{
        BaseAirBuilder, InteractionScope, PublicValues, SP1AirBuilder, POSEIDON_NUM_WORDS,
        PV_DIGEST_NUM_WORDS, SP1_PROOF_NUM_PV_ELTS,
    },
    Word,
};

use crate::{
    adapter::{register::r_type::RTypeReader, state::CPUState},
    air::{SP1CoreAirBuilder, SP1Operation, WordAirBuilder},
    operations::{
        IsZeroOperation, IsZeroOperationInput, SP1FieldWordRangeChecker, TrapOperation,
        U16toU8OperationSafe, U16toU8OperationSafeInput,
    },
    TrustMode, UserMode,
};

use super::{columns::SyscallInstrColumns, SyscallInstrsChip};

impl<AB, M> Air<AB> for SyscallInstrsChip<M>
where
    AB: SP1CoreAirBuilder,
    AB::Var: Sized,
    M: TrustMode,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &SyscallInstrColumns<AB::Var, M> = (*local).borrow();

        let public_values_slice: [AB::PublicVar; SP1_PROOF_NUM_PV_ELTS] =
            core::array::from_fn(|i| builder.public_values()[i]);
        let public_values: &PublicValues<
            [AB::PublicVar; 4],
            [AB::PublicVar; 3],
            [AB::PublicVar; 4],
            AB::PublicVar,
        > = public_values_slice.as_slice().borrow();

        // Convert the syscall code to 8 bytes using the safe API.
        let a_input = U16toU8OperationSafeInput::new(
            local.adapter.prev_a().0.map(Into::into),
            local.a_low_bytes,
            local.is_real.into(),
        );
        let a = U16toU8OperationSafe::eval(builder, a_input);

        // SAFETY: Only `ECALL` opcode can be received in this chip.
        // `is_real` is checked to be boolean, and the `opcode` matches the corresponding opcode.
        builder.assert_bool(local.is_real);

        // Verify that local.is_halt is correct.
        self.eval_is_halt_syscall(builder, &a, local);

        // Constrain the state of the CPU.
        // The extra timestamp increment is `256` always.
        // The `next_pc` is constrained in the AIR.
        CPUState::<AB::F>::eval(
            builder,
            local.state,
            local.next_pc.map(Into::into),
            AB::Expr::from_canonical_u32(CLK_INC + 256),
            local.is_real.into(),
        );

        #[allow(unused_variables)]
        {
            let funct3 = AB::Expr::from_canonical_u8(Opcode::ECALL.funct3().unwrap_or(0));
            let funct7 = AB::Expr::from_canonical_u8(Opcode::ECALL.funct7().unwrap_or(0));
            let base_opcode = AB::Expr::from_canonical_u32(Opcode::ECALL.base_opcode().0);
            let instr_type =
                AB::Expr::from_canonical_u32(Opcode::ECALL.instruction_type().0 as u32);
        }

        // Constrain the program and register reads.
        RTypeReader::<AB::F>::eval(
            builder,
            local.state.clk_high::<AB>(),
            local.state.clk_low::<AB>(),
            local.state.pc,
            AB::Expr::from_canonical_u32(Opcode::ECALL as u32),
            local.op_a_value,
            local.adapter,
            local.is_real.into(),
            local.is_real.into(), // is_trusted - syscalls are only for trusted programs
        );
        builder.when(local.is_real).assert_zero(local.adapter.op_a_0);

        #[allow(unused_variables)]
        let (is_sig_return, is_trap, trap_code) = if !M::IS_TRUSTED {
            let local = main.row_slice(0);
            let local: &SyscallInstrColumns<AB::Var, UserMode> = (*local).borrow();
            #[cfg(not(feature = "mprotect"))]
            builder.assert_zero(local.is_real);
            let is_sig_return = self.eval_sig_return(builder, &a, local);
            let (is_trap, trap_code) = self.eval_trap(builder, local);
            builder.assert_bool(local.is_halt + is_sig_return.clone() + is_trap.clone());
            // PAGE_PROTECT ecall instruction.
            self.eval_page_protect(builder, local, &a, public_values.is_untrusted_programs_enabled);
            (is_sig_return, is_trap, trap_code)
        } else {
            (AB::Expr::zero(), AB::Expr::zero(), AB::Expr::zero())
        };

        #[cfg(feature = "mprotect")]
        {
            builder.assert_eq(
                public_values.is_untrusted_programs_enabled,
                AB::Expr::from_bool(!M::IS_TRUSTED),
            );
        }

        #[cfg(not(feature = "mprotect"))]
        let jump: AB::Expr = local.is_halt.into();
        #[cfg(feature = "mprotect")]
        let jump: AB::Expr = local.is_halt.into() + is_sig_return.clone() + is_trap.clone();

        // If the syscall is not halt, then next_pc should be pc + 4.
        // `next_pc` is constrained for the case where `is_halt` is false to be `pc + 4`.
        builder
            .when(local.is_real)
            .when(AB::Expr::one() - jump.clone())
            .assert_eq(local.next_pc[0], local.state.pc[0] + AB::Expr::from_canonical_u32(4));
        builder
            .when(local.is_real)
            .when(AB::Expr::one() - jump.clone())
            .assert_eq(local.next_pc[1], local.state.pc[1]);
        builder
            .when(local.is_real)
            .when(AB::Expr::one() - jump.clone())
            .assert_eq(local.next_pc[2], local.state.pc[2]);

        // ECALL instruction.
        self.eval_ecall(builder, &a, local, trap_code);

        // COMMIT/COMMIT_DEFERRED_PROOFS ecall instruction.
        self.eval_commit(
            builder,
            &a,
            local,
            public_values.commit_syscall,
            public_values.commit_deferred_syscall,
            public_values.committed_value_digest,
            public_values.deferred_proofs_digest,
        );

        // HALT ecall and UNIMPL instruction.
        self.eval_halt_unimpl(builder, local, public_values);
    }
}

impl<M: TrustMode> SyscallInstrsChip<M> {
    /// Constraints related to the ECALL opcode.
    ///
    /// This method will do the following:
    /// 1. Send the syscall to the precompile table, if needed.
    /// 2. Check for valid op_a values.
    pub(crate) fn eval_ecall<AB: SP1CoreAirBuilder>(
        &self,
        builder: &mut AB,
        prev_a_byte: &[AB::Expr; 8],
        local: &SyscallInstrColumns<AB::Var, M>,
        trap_code: AB::Expr,
    ) {
        // We interpret the syscall_code as little-endian bytes and interpret each byte as a u8
        // with different information.
        let syscall_id = prev_a_byte[0].clone();
        let send_to_table = prev_a_byte[1].clone();

        // SAFETY: Assert that for padding rows, the interactions from `send_syscall` and
        // KoalaBearWordRangeChecker do not have non-zero multiplicities.
        builder.when_not(local.is_real).assert_zero(send_to_table.clone());
        builder.when_not(local.is_real).assert_zero(local.is_halt);
        builder.when_not(local.is_real).assert_zero(local.is_commit_deferred_proofs.result);
        builder.when(send_to_table.clone()).assert_zero(local.adapter.b()[3]);
        builder.when(send_to_table.clone()).assert_zero(local.adapter.c()[3]);
        builder.assert_bool(send_to_table.clone());
        if !M::IS_TRUSTED {
            builder.when_not(send_to_table.clone()).assert_zero(trap_code.clone());
        }

        let b_address = [local.adapter.b()[0], local.adapter.b()[1], local.adapter.b()[2]];
        let c_address = [local.adapter.c()[0], local.adapter.c()[1], local.adapter.c()[2]];

        builder.send_syscall(
            local.state.clk_high::<AB>(),
            local.state.clk_low::<AB>(),
            syscall_id.clone(),
            trap_code.clone(),
            b_address,
            c_address,
            send_to_table.clone(),
            InteractionScope::Local,
        );

        // Check if `op_b` and `op_c` are a valid SP1Field words.
        // SAFETY: The multiplicities are zero when `is_real = 0`.
        // `op_b` value is already known to be a valid Word, as it is read from a register.
        SP1FieldWordRangeChecker::<AB::F>::range_check::<AB>(
            builder,
            local.adapter.b().map(Into::into),
            local.op_b_range_check,
            local.is_halt.into(),
        );

        // Check if `op_c` is a valid SP1Field word.
        // `op_c` value is already known to be a valid Word, as it is read from a register.
        SP1FieldWordRangeChecker::<AB::F>::range_check::<AB>(
            builder,
            local.adapter.c().map(Into::into),
            local.op_c_range_check,
            local.is_commit_deferred_proofs.result.into(),
        );

        // Compute whether this ecall is ENTER_UNCONSTRAINED.
        let is_enter_unconstrained = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                IsZeroOperationInput::new(
                    syscall_id.clone()
                        - AB::Expr::from_canonical_u32(
                            SyscallCode::ENTER_UNCONSTRAINED.syscall_id(),
                        ),
                    local.is_enter_unconstrained,
                    local.is_real.into(),
                ),
            );
            local.is_enter_unconstrained.result
        };

        // Compute whether this ecall is HINT_LEN.
        let is_hint_len = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                IsZeroOperationInput::new(
                    syscall_id.clone()
                        - AB::Expr::from_canonical_u32(SyscallCode::HINT_LEN.syscall_id()),
                    local.is_hint_len,
                    local.is_real.into(),
                ),
            );
            local.is_hint_len.result
        };

        // `op_a_val` is constrained.
        // When syscall_id is ENTER_UNCONSTRAINED, the new value of op_a should be 0.
        let zero_word = Word::<AB::F>::from(0u64);
        builder
            .when(local.is_real)
            .when(is_enter_unconstrained)
            .assert_word_eq(local.op_a_value, zero_word);

        // When the syscall is not one of ENTER_UNCONSTRAINED or HINT_LEN, op_a shouldn't change.
        builder
            .when(local.is_real)
            .when_not(is_enter_unconstrained + is_hint_len)
            .assert_word_eq(local.op_a_value, *local.adapter.prev_a());

        // SAFETY: This leaves the case where syscall is `HINT_LEN`.
        // In this case, `op_a`'s value can be arbitrary, but it still must be a valid word.
        // As this is a syscall for HINT, the value itself being arbitrary is fine, as long as it is
        // a valid word.
        builder.slice_range_check_u16(&local.op_a_value.0, local.is_real);
    }

    /// Constraints related to the COMMIT and COMMIT_DEFERRED_PROOFS instructions.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn eval_commit<AB: SP1CoreAirBuilder>(
        &self,
        builder: &mut AB,
        prev_a_byte: &[AB::Expr; 8],
        local: &SyscallInstrColumns<AB::Var, M>,
        commit_syscall: AB::PublicVar,
        commit_deferred_syscall: AB::PublicVar,
        commit_digest: [[AB::PublicVar; 4]; PV_DIGEST_NUM_WORDS],
        deferred_proofs_digest: [AB::PublicVar; POSEIDON_NUM_WORDS],
    ) {
        let (is_commit, is_commit_deferred_proofs) = self.get_is_commit_related_syscall(
            builder,
            prev_a_byte,
            commit_syscall,
            commit_deferred_syscall,
            local,
        );

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
                .assert_eq(local.adapter.b()[0], AB::Expr::from_canonical_u32(i as u32));
        }
        // Verify that the upper limb of the word_idx is 0.
        // SAFETY: Since the limbs are u16s, one can sum them all and test that the sum is zero.
        builder
            .when(local.is_real)
            .when(is_commit.clone() + is_commit_deferred_proofs.clone())
            .assert_zero(local.adapter.b()[1] + local.adapter.b()[2] + local.adapter.b()[3]);

        // Retrieve the expected public values digest word to check against the one passed into the
        // commit ecall. Note that for the interaction builder, it will not have any digest words,
        // since it's used during AIR compilation time to parse for all send/receives. Since
        // that interaction builder will ignore the other constraints of the air, it is safe
        // to not include the verification check of the expected public values digest word.

        // First, get the expected public value digest from the bitmap and public values.
        let mut expected_pv_digest =
            [AB::Expr::zero(), AB::Expr::zero(), AB::Expr::zero(), AB::Expr::zero()];
        for i in 0..4 {
            expected_pv_digest[i] = builder.index_array(
                commit_digest.iter().map(|word| word[i]).collect_vec().as_slice(),
                &local.index_bitmap,
            );
        }
        // Then, combine the bytes into u16 Word form, which will be compared to `op_c` value.
        let expected_pv_digest_word = Word([
            expected_pv_digest[0].clone()
                + expected_pv_digest[1].clone() * AB::F::from_canonical_u32(1 << 8),
            expected_pv_digest[2].clone()
                + expected_pv_digest[3].clone() * AB::F::from_canonical_u32(1 << 8),
            AB::Expr::zero(),
            AB::Expr::zero(),
        ]);

        // Assert that the expected public value digest are valid bytes.
        builder.assert_bool(is_commit.clone());
        for i in 0..4 {
            builder
                .when(is_commit.clone())
                .assert_eq(expected_pv_digest[i].clone(), local.expected_public_values_digest[i]);
        }
        builder.slice_range_check_u8(&local.expected_public_values_digest, is_commit.clone());

        let digest_word: Word<AB::Expr> = local.adapter.c().map(Into::into);

        // Verify the public_values_digest_word.
        builder
            .when(local.is_real)
            .when(is_commit.clone())
            .assert_word_eq(expected_pv_digest_word, digest_word.clone());

        let expected_deferred_proofs_digest_element =
            builder.index_array(&deferred_proofs_digest, &local.index_bitmap);

        builder
            .when(local.is_real)
            .when(is_commit_deferred_proofs.clone())
            .assert_eq(expected_deferred_proofs_digest_element, digest_word.reduce::<AB>());
    }

    /// Constraints on `SIG_RETURN` syscall.
    pub(crate) fn eval_sig_return<AB: SP1CoreAirBuilder>(
        &self,
        builder: &mut AB,
        prev_a_byte: &[AB::Expr; 8],
        local: &SyscallInstrColumns<AB::Var, UserMode>,
    ) -> AB::Expr {
        let syscall_id = prev_a_byte[0].clone();
        let is_sig_return = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                IsZeroOperationInput::new(
                    syscall_id.clone()
                        - AB::Expr::from_canonical_u32(SyscallCode::SIG_RETURN.syscall_id()),
                    local.user_mode_cols.is_sig_return,
                    local.is_real.into(),
                ),
            );
            local.user_mode_cols.is_sig_return.result
        };

        builder.assert_bool(is_sig_return);
        builder.when_not(local.is_real).assert_zero(is_sig_return);

        builder.eval_memory_access_read(
            local.state.clk_high::<AB>(),
            local.state.clk_low::<AB>(),
            &[
                local.adapter.b()[0].into(),
                local.adapter.b()[1].into(),
                local.adapter.b()[2].into(),
            ],
            local.user_mode_cols.next_pc_record,
            is_sig_return,
        );

        let next_pc = local.user_mode_cols.next_pc_record.prev_value;
        builder.when(is_sig_return).assert_eq(local.next_pc[0], next_pc[0]);
        builder.when(is_sig_return).assert_eq(local.next_pc[1], next_pc[1]);
        builder.when(is_sig_return).assert_eq(local.next_pc[2], next_pc[2]);
        builder.when(is_sig_return).assert_zero(next_pc[3]);

        is_sig_return.into()
    }

    /// Constraints on trapping in a syscall.
    pub(crate) fn eval_trap<AB: SP1CoreAirBuilder>(
        &self,
        builder: &mut AB,
        local: &SyscallInstrColumns<AB::Var, UserMode>,
    ) -> (AB::Expr, AB::Expr) {
        let is_not_trap = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                IsZeroOperationInput::new(
                    local.user_mode_cols.trap_code.into(),
                    local.user_mode_cols.is_not_trap,
                    local.is_real.into(),
                ),
            );
            local.user_mode_cols.is_not_trap.result
        };

        builder.assert_bool(is_not_trap);
        builder.when_not(local.is_real).assert_zero(is_not_trap);

        let is_trap = local.is_real.into() - is_not_trap.into();
        builder.assert_bool(is_trap.clone());

        let next_pc = TrapOperation::<AB::F>::eval(
            builder,
            local.user_mode_cols.trap_operation,
            local.state.clk_high::<AB>(),
            local.state.clk_low::<AB>(),
            local.user_mode_cols.trap_code.into(),
            local.state.pc.map(Into::into),
            local.user_mode_cols.addresses,
            is_trap.clone(),
        );

        builder.when(is_trap.clone()).assert_eq(local.next_pc[0], next_pc[0]);
        builder.when(is_trap.clone()).assert_eq(local.next_pc[1], next_pc[1]);
        builder.when(is_trap.clone()).assert_eq(local.next_pc[2], next_pc[2]);

        (is_trap, local.user_mode_cols.trap_code.into())
    }

    /// Constraint related to the halt and unimpl instruction.
    pub(crate) fn eval_halt_unimpl<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &SyscallInstrColumns<AB::Var, M>,
        public_values: &PublicValues<
            [AB::PublicVar; 4],
            [AB::PublicVar; 3],
            [AB::PublicVar; 4],
            AB::PublicVar,
        >,
    ) {
        // `next_pc` is constrained for the case where `is_halt` is true to be `HALT_PC`.
        builder
            .when(local.is_halt)
            .assert_eq(local.next_pc[0], AB::Expr::from_canonical_u64(HALT_PC));
        builder.when(local.is_halt).assert_zero(local.next_pc[1]);
        builder.when(local.is_halt).assert_zero(local.next_pc[2]);

        // Check that the `op_b` value reduced is the `public_values.exit_code`.
        builder
            .when(local.is_halt)
            .assert_eq(local.adapter.b().map(Into::into).reduce::<AB>(), public_values.exit_code);
    }

    pub(crate) fn eval_page_protect<AB: SP1CoreAirBuilder>(
        &self,
        builder: &mut AB,
        local: &SyscallInstrColumns<AB::Var, UserMode>,
        prev_a_byte: &[AB::Expr; 8],
        is_page_protect_active: AB::PublicVar,
    ) {
        let syscall_id = prev_a_byte[0].clone();

        // Compute whether this ecall is mprotect.
        let is_mprotect = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                IsZeroOperationInput::new(
                    syscall_id.clone()
                        - AB::Expr::from_canonical_u32(SyscallCode::MPROTECT.syscall_id()),
                    local.user_mode_cols.is_page_protect,
                    local.is_real.into(),
                ),
            );
            local.user_mode_cols.is_page_protect.result
        };

        builder.when(is_mprotect).assert_one(is_page_protect_active);
    }

    /// Returns a boolean expression indicating whether the instruction is a HALT instruction.
    pub(crate) fn eval_is_halt_syscall<AB: SP1CoreAirBuilder>(
        &self,
        builder: &mut AB,
        prev_a_byte: &[AB::Expr; 8],
        local: &SyscallInstrColumns<AB::Var, M>,
    ) {
        // `is_halt` is checked to be correct in `eval_is_halt_syscall`.
        let syscall_id = prev_a_byte[0].clone();

        // Compute whether this ecall is HALT.
        let is_halt = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                IsZeroOperationInput::new(
                    syscall_id.clone()
                        - AB::Expr::from_canonical_u32(SyscallCode::HALT.syscall_id()),
                    local.is_halt_check,
                    local.is_real.into(),
                ),
            );
            local.is_halt_check.result
        };

        // Verify that the `is_halt` flag is correct.
        // If `is_real = 0`, then `local.is_halt = 0`.
        // If `is_real = 1`, then `is_halt_check.result` is correct, so `local.is_halt` is as well.
        builder.assert_eq(local.is_halt, is_halt * local.is_real);
    }

    /// Returns two boolean expression indicating whether the instruction is a COMMIT or
    /// COMMIT_DEFERRED_PROOFS instruction, and constrain public values based on it.
    pub(crate) fn get_is_commit_related_syscall<AB: SP1CoreAirBuilder>(
        &self,
        builder: &mut AB,
        prev_a_byte: &[AB::Expr; 8],
        commit_syscall: AB::PublicVar,
        commit_deferred_syscall: AB::PublicVar,
        local: &SyscallInstrColumns<AB::Var, M>,
    ) -> (AB::Expr, AB::Expr) {
        let syscall_id = prev_a_byte[0].clone();

        // Compute whether this ecall is COMMIT.
        let is_commit = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                IsZeroOperationInput::new(
                    syscall_id.clone()
                        - AB::Expr::from_canonical_u32(SyscallCode::COMMIT.syscall_id()),
                    local.is_commit,
                    local.is_real.into(),
                ),
            );
            local.is_commit.result
        };

        // Compute whether this ecall is COMMIT_DEFERRED_PROOFS.
        let is_commit_deferred_proofs = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                IsZeroOperationInput::new(
                    syscall_id.clone()
                        - AB::Expr::from_canonical_u32(
                            SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id(),
                        ),
                    local.is_commit_deferred_proofs,
                    local.is_real.into(),
                ),
            );
            local.is_commit_deferred_proofs.result
        };

        // If the `COMMIT` syscall is called in the shard, then `pv.commit_syscall == 1`.
        builder.when(is_commit).assert_one(commit_syscall);
        // If the `COMMIT_DEFERRED_PROOFS` syscall was called, `pv.commit_deferred_syscall == 1`.
        builder.when(is_commit_deferred_proofs).assert_one(commit_deferred_syscall);

        (is_commit.into(), is_commit_deferred_proofs.into())
    }
}
