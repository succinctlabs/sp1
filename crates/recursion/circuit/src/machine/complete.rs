use itertools::Itertools;
use slop_algebra::AbstractField;
use sp1_primitives::SP1Field;
use sp1_recursion_compiler::ir::{Builder, Config, Felt};
use sp1_recursion_executor::RecursionPublicValues;

/// Assertions on recursion public values which represent a complete proof.
///
/// The assertions consist of checking all the expected boundary conditions from a compress proof
/// that represents the end of the recursion tower.
pub(crate) fn assert_complete<C: Config>(
    builder: &mut Builder<C>,
    public_values: &RecursionPublicValues<Felt<SP1Field>>,
    is_complete: Felt<SP1Field>,
) {
    let RecursionPublicValues {
        prev_committed_value_digest,
        prev_deferred_proofs_digest,
        deferred_proofs_digest,
        prev_exit_code,
        next_pc,
        start_reconstruct_deferred_digest,
        end_reconstruct_deferred_digest,
        contains_first_shard,
        prev_chunk_index,
        prev_commit_syscall,
        commit_syscall,
        prev_commit_deferred_syscall,
        commit_deferred_syscall,
        prev_deferred_proof,
        ..
    } = public_values;

    // Assert that the `is_complete` flag is boolean.
    builder.assert_felt_eq(is_complete * (is_complete - SP1Field::one()), SP1Field::zero());

    // Assert the `prev_committed_value_digest` is all zeroes.
    for word in prev_committed_value_digest {
        for limb in word {
            builder.assert_felt_eq(is_complete * *limb, SP1Field::zero());
        }
    }

    // Assert the `prev_deferred_proofs_digest` is all zeroes.
    for limb in prev_deferred_proofs_digest {
        builder.assert_felt_eq(is_complete * *limb, SP1Field::zero());
    }

    // Assert that `next_pc` is equal to the `HALT_PC` (so program execution has completed)
    builder.assert_felt_eq(
        is_complete * (next_pc[0] - SP1Field::from_canonical_u64(sp1_core_executor::HALT_PC)),
        SP1Field::zero(),
    );
    builder.assert_felt_eq(is_complete * next_pc[1], SP1Field::zero());
    builder.assert_felt_eq(is_complete * next_pc[2], SP1Field::zero());

    // Assert that the first shard has been included.
    builder
        .assert_felt_eq(is_complete * (*contains_first_shard - SP1Field::one()), SP1Field::zero());

    // The start reconstruct deferred digest should be zero.
    for start_digest in start_reconstruct_deferred_digest {
        builder.assert_felt_eq(is_complete * *start_digest, SP1Field::zero());
    }

    // The end reconstruct deferred digest should be equal to the deferred proofs digest.
    for (end_digest, deferred_digest) in
        end_reconstruct_deferred_digest.iter().zip_eq(deferred_proofs_digest.iter())
    {
        builder.assert_felt_eq(is_complete * (*end_digest - *deferred_digest), SP1Field::zero());
    }
    // The initial deferred proof index should be equal to zero
    builder.assert_felt_eq(is_complete * *prev_deferred_proof, SP1Field::zero());

    // The initial chunk index should be equal to zero.
    builder.assert_felt_eq(is_complete * *prev_chunk_index, SP1Field::zero());

    // Assert that the starting `prev_exit_code` is equal to 0.
    builder.assert_felt_eq(is_complete * *prev_exit_code, SP1Field::zero());

    // The starting `prev_commit_syscall` must be zero.
    builder.assert_felt_eq(is_complete * *prev_commit_syscall, SP1Field::zero());

    // The starting `prev_commit_deferred_syscall` must be zero.
    builder.assert_felt_eq(is_complete * *prev_commit_deferred_syscall, SP1Field::zero());

    // The final `commit_syscall` must be one.
    builder.assert_felt_eq(is_complete * (*commit_syscall - SP1Field::one()), SP1Field::zero());

    // The final `commit_deferred_syscall` must be one.
    builder.assert_felt_eq(
        is_complete * (*commit_deferred_syscall - SP1Field::one()),
        SP1Field::zero(),
    );
}

/// Assertions on recursion public values which represent a complete chunk (a chunk root).
///
/// When `is_chunk_complete == 1`, the chunk's global interactions must balance and the witnessed
/// commitments hash must equal the finalized reconstructed challenge sponge.
pub(crate) fn assert_chunk_complete<C: Config>(
    builder: &mut Builder<C>,
    public_values: &RecursionPublicValues<Felt<SP1Field>>,
    is_chunk_complete: Felt<SP1Field>,
) {
    let RecursionPublicValues {
        global_cumulative_sum,
        global_commitments_hash,
        start_reconstruct_global_challenge,
        end_reconstruct_global_challenge,
        initial_timestamp,
        prev_shard_index,
        last_shard_index,
        num_merkle_shard,
        num_execution_shard,
        ..
    } = public_values;

    // `is_chunk_complete` is boolean.
    builder.assert_felt_eq(
        is_chunk_complete * (is_chunk_complete - SP1Field::one()),
        SP1Field::zero(),
    );

    // The chunk's global interactions balance under its shared challenge.
    for limb in global_cumulative_sum {
        builder.assert_felt_eq(is_chunk_complete * *limb, SP1Field::zero());
    }

    // The initial reconstruct of global challenge sponge is all zeroes.
    for limb in start_reconstruct_global_challenge {
        builder.assert_felt_eq(is_chunk_complete * *limb, SP1Field::zero());
    }

    // The witnessed `global_commitments_hash` equals the finalized reconstructed sponge.
    for (hash_limb, state_limb) in
        global_commitments_hash.iter().zip(end_reconstruct_global_challenge.iter())
    {
        builder.assert_felt_eq(is_chunk_complete * (*hash_limb - *state_limb), SP1Field::zero());
    }

    // The initial previous shard index must be 0.
    builder.assert_felt_eq(is_chunk_complete * *prev_shard_index, SP1Field::zero());

    // The last shard index should be `num_merkle_shard + num_execution_shard`.
    builder.assert_felt_eq(
        is_chunk_complete * (*last_shard_index - *num_merkle_shard - *num_execution_shard),
        SP1Field::zero(),
    );

    // Assert that the initial timestamp is equal to 1.
    for limb in initial_timestamp[0..3].iter() {
        builder.assert_felt_eq(is_chunk_complete * *limb, SP1Field::zero());
    }
    builder.assert_felt_eq(
        is_chunk_complete * (initial_timestamp[3] - SP1Field::one()),
        SP1Field::zero(),
    );
}
