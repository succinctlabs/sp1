use std::mem::transmute;

use itertools::Itertools;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::AbstractField;

use sp1_core::{
    air::MachineAir,
    stark::{Com, StarkGenericConfig, StarkMachine, StarkVerifyingKey},
};
use sp1_recursion_compiler::ir::{Array, Builder, Config, Felt, Var};
use sp1_recursion_core::{
    air::{RecursionPublicValues, NUM_PV_ELMS_TO_HASH, RECURSIVE_PROOF_NUM_PV_ELTS},
    runtime::DIGEST_SIZE,
};

use crate::{
    challenger::DuplexChallengerVariable,
    fri::TwoAdicMultiplicativeCosetVariable,
    types::VerifyingKeyVariable,
    utils::{assert_challenger_eq_pv, felt2var, get_preprocessed_data},
};

/// Assertions on the public values describing a complete recursive proof state.
///
/// See [SP1Prover::verify] for the verification algorithm of a complete SP1 proof.
pub(crate) fn assert_complete<C: Config>(
    builder: &mut Builder<C>,
    public_values: &RecursionPublicValues<Felt<C::F>>,
    end_reconstruct_challenger: &DuplexChallengerVariable<C>,
) {
    let RecursionPublicValues {
        deferred_proofs_digest,
        next_pc,
        start_shard,
        next_shard,
        start_execution_shard,
        next_execution_shard,
        cumulative_sum,
        start_reconstruct_deferred_digest,
        end_reconstruct_deferred_digest,
        leaf_challenger,
        ..
    } = public_values;

    // Assert that `next_pc` is equal to zero (so program execution has completed)
    builder.assert_felt_eq(*next_pc, C::F::zero());

    // Assert that start shard is equal to 1.
    builder.assert_felt_eq(*start_shard, C::F::one());

    // Assert that the next shard is not equal to one. This guarantees that there is at least one shard.
    builder.assert_felt_ne(*next_shard, C::F::one());

    // Assert that the start execution shard is equal to 1.
    builder.assert_felt_eq(*start_execution_shard, C::F::one());

    // Assert that next shard is not equal to one. This guarantees that there is at least one shard
    // with CPU.
    builder.assert_felt_ne(*next_execution_shard, C::F::one());

    // Assert that the end reconstruct challenger is equal to the leaf challenger.
    assert_challenger_eq_pv(builder, end_reconstruct_challenger, *leaf_challenger);

    // The start reconstruct deffered digest should be zero.
    for start_digest_word in start_reconstruct_deferred_digest {
        builder.assert_felt_eq(*start_digest_word, C::F::zero());
    }

    // The end reconstruct deffered digest should be equal to the deferred proofs digest.
    for (end_digest_word, deferred_digest_word) in end_reconstruct_deferred_digest
        .iter()
        .zip_eq(deferred_proofs_digest.iter())
    {
        builder.assert_felt_eq(*end_digest_word, *deferred_digest_word);
    }

    // Assert that the cumulative sum is zero.
    for b in cumulative_sum.iter() {
        builder.assert_felt_eq(*b, C::F::zero());
    }
}

pub(crate) fn proof_data_from_vk<C: Config, SC, A>(
    builder: &mut Builder<C>,
    vk: &StarkVerifyingKey<SC>,
    machine: &StarkMachine<SC, A>,
) -> VerifyingKeyVariable<C>
where
    SC: StarkGenericConfig<
        Val = C::F,
        Challenge = C::EF,
        Domain = TwoAdicMultiplicativeCoset<C::F>,
    >,
    A: MachineAir<SC::Val>,
    Com<SC>: Into<[SC::Val; DIGEST_SIZE]>,
{
    let mut commitment = builder.dyn_array(DIGEST_SIZE);
    for (i, value) in vk.commit.clone().into().iter().enumerate() {
        builder.set(&mut commitment, i, *value);
    }
    let pc_start: Felt<_> = builder.eval(vk.pc_start);

    let (prep_sorted_indices_val, prep_domains_val) = get_preprocessed_data(machine, vk);

    let mut prep_sorted_indices = builder.dyn_array::<Var<_>>(prep_sorted_indices_val.len());
    let mut prep_domains =
        builder.dyn_array::<TwoAdicMultiplicativeCosetVariable<_>>(prep_domains_val.len());

    for (i, value) in prep_sorted_indices_val.iter().enumerate() {
        builder.set(
            &mut prep_sorted_indices,
            i,
            C::N::from_canonical_usize(*value),
        );
    }

    for (i, value) in prep_domains_val.iter().enumerate() {
        let domain: TwoAdicMultiplicativeCosetVariable<_> = builder.constant(*value);
        builder.set(&mut prep_domains, i, domain);
    }

    VerifyingKeyVariable {
        commitment,
        pc_start,
        preprocessed_sorted_idxs: prep_sorted_indices,
        prep_domains,
    }
}

/// Calculates the digest of the recursion public values.
fn calculate_public_values_digest<C: Config>(
    builder: &mut Builder<C>,
    public_values: &RecursionPublicValues<Felt<C::F>>,
) -> Array<C, Felt<C::F>> {
    let pv_elements: [Felt<_>; RECURSIVE_PROOF_NUM_PV_ELTS] = unsafe { transmute(*public_values) };
    let mut poseidon_inputs = builder.array(NUM_PV_ELMS_TO_HASH);
    for (i, elm) in pv_elements[0..NUM_PV_ELMS_TO_HASH].iter().enumerate() {
        builder.set(&mut poseidon_inputs, i, *elm);
    }
    builder.poseidon2_hash(&poseidon_inputs)
}

/// Verifies the digest of a recursive public values struct.
pub(crate) fn verify_public_values_hash<C: Config>(
    builder: &mut Builder<C>,
    public_values: &RecursionPublicValues<Felt<C::F>>,
) {
    let var_exit_code = felt2var(builder, public_values.exit_code);
    // Check that the public values digest is correct if the exit_code is 0.
    builder.if_eq(var_exit_code, C::N::zero()).then(|builder| {
        let calculated_digest = calculate_public_values_digest(builder, public_values);

        let expected_digest = public_values.digest;
        for (i, expected_elm) in expected_digest.iter().enumerate() {
            let calculated_elm = builder.get(&calculated_digest, i);
            builder.assert_felt_eq(*expected_elm, calculated_elm);
        }
    });
}

/// Register and commits the recursion public values.
pub fn commit_public_values<C: Config>(
    builder: &mut Builder<C>,
    public_values: &RecursionPublicValues<Felt<C::F>>,
) {
    let pv_elements: [Felt<_>; RECURSIVE_PROOF_NUM_PV_ELTS] = unsafe { transmute(*public_values) };
    let pv_elms_no_digest = &pv_elements[0..NUM_PV_ELMS_TO_HASH];

    for value in pv_elms_no_digest.iter() {
        builder.register_public_value(*value);
    }

    // Hash the public values.
    let pv_digest = calculate_public_values_digest(builder, public_values);
    for i in 0..DIGEST_SIZE {
        let digest_element = builder.get(&pv_digest, i);
        builder.commit_public_value(digest_element);
    }
}
