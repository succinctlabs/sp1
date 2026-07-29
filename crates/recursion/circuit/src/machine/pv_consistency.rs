//! Per-child public-values consistency helpers shared by the chunk and global compress verifiers.

use itertools::Itertools;
use sp1_primitives::SP1Field;
use sp1_recursion_compiler::ir::{Builder, Config, Felt};
use sp1_recursion_executor::RecursionPublicValues;

/// A public-values field shape whose in-circuit equality can be asserted element-wise.
pub(crate) trait CircuitEq<C: Config> {
    fn assert_eq(builder: &mut Builder<C>, a: Self, b: Self);
}

impl<C: Config> CircuitEq<C> for Felt<SP1Field> {
    fn assert_eq(builder: &mut Builder<C>, a: Self, b: Self) {
        builder.assert_felt_eq(a, b);
    }
}

impl<C: Config, const N: usize> CircuitEq<C> for [Felt<SP1Field>; N] {
    fn assert_eq(builder: &mut Builder<C>, a: Self, b: Self) {
        for (a, b) in a.iter().zip_eq(b.iter()) {
            builder.assert_felt_eq(*a, *b);
        }
    }
}

impl<C: Config, const N: usize> CircuitEq<C> for [[Felt<SP1Field>; 4]; N] {
    fn assert_eq(builder: &mut Builder<C>, a: Self, b: Self) {
        for (word_a, word_b) in a.iter().zip_eq(b.iter()) {
            for (a, b) in word_a.iter().zip_eq(word_b.iter()) {
                builder.assert_felt_eq(*a, *b);
            }
        }
    }
}

/// Per-child boundary transition: assert `running` equals this child's start value, then advance
/// `running` to the child's end value (checking "child i's end == child i+1's start").
pub(crate) fn carry_forward<C: Config, T: CircuitEq<C> + Copy>(
    builder: &mut Builder<C>,
    running: &mut T,
    child_start: T,
    child_end: T,
) {
    T::assert_eq(builder, *running, child_start);
    *running = child_end;
}

/// Assert a value that must be identical for every child in the batch.
pub(crate) fn assert_constant<C: Config, T: CircuitEq<C>>(
    builder: &mut Builder<C>,
    running: T,
    value: T,
) {
    T::assert_eq(builder, running, value);
}

/// Seed the fields both compress verifiers chain identically from the first child
pub(crate) fn init_common_boundary(
    out: &mut RecursionPublicValues<Felt<SP1Field>>,
    first: &RecursionPublicValues<Felt<SP1Field>>,
) {
    out.sp1_vk_digest = first.sp1_vk_digest;
    out.proof_nonce = first.proof_nonce;
    out.prev_committed_value_digest = first.prev_committed_value_digest;
    out.committed_value_digest = first.prev_committed_value_digest;
    out.prev_deferred_proofs_digest = first.prev_deferred_proofs_digest;
    out.deferred_proofs_digest = first.prev_deferred_proofs_digest;
    out.prev_deferred_proof = first.prev_deferred_proof;
    out.deferred_proof = first.prev_deferred_proof;
    out.pc_start = first.pc_start;
    out.next_pc = first.pc_start;
    out.start_reconstruct_deferred_digest = first.start_reconstruct_deferred_digest;
    out.end_reconstruct_deferred_digest = first.start_reconstruct_deferred_digest;
    out.prev_exit_code = first.prev_exit_code;
    out.exit_code = first.prev_exit_code;
    out.prev_commit_syscall = first.prev_commit_syscall;
    out.commit_syscall = first.prev_commit_syscall;
    out.prev_commit_deferred_syscall = first.prev_commit_deferred_syscall;
    out.commit_deferred_syscall = first.prev_commit_deferred_syscall;
}

/// Per-child consistency for the fields both compress verifiers chain identically.
pub(crate) fn assert_common_child<C: Config>(
    builder: &mut Builder<C>,
    out: &mut RecursionPublicValues<Felt<SP1Field>>,
    cur: &RecursionPublicValues<Felt<SP1Field>>,
) {
    assert_constant(builder, out.sp1_vk_digest, cur.sp1_vk_digest);
    assert_constant(builder, out.proof_nonce, cur.proof_nonce);
    carry_forward(
        builder,
        &mut out.committed_value_digest,
        cur.prev_committed_value_digest,
        cur.committed_value_digest,
    );
    carry_forward(
        builder,
        &mut out.deferred_proofs_digest,
        cur.prev_deferred_proofs_digest,
        cur.deferred_proofs_digest,
    );
    carry_forward(builder, &mut out.deferred_proof, cur.prev_deferred_proof, cur.deferred_proof);
    carry_forward(builder, &mut out.next_pc, cur.pc_start, cur.next_pc);
    carry_forward(
        builder,
        &mut out.end_reconstruct_deferred_digest,
        cur.start_reconstruct_deferred_digest,
        cur.end_reconstruct_deferred_digest,
    );
    carry_forward(builder, &mut out.exit_code, cur.prev_exit_code, cur.exit_code);
    carry_forward(builder, &mut out.commit_syscall, cur.prev_commit_syscall, cur.commit_syscall);
    carry_forward(
        builder,
        &mut out.commit_deferred_syscall,
        cur.prev_commit_deferred_syscall,
        cur.commit_deferred_syscall,
    );
}
