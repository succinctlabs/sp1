use itertools::Itertools;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::AbstractField;

use sp1_core::{
    air::MachineAir,
    stark::{Com, StarkGenericConfig, StarkMachine, StarkVerifyingKey},
};
use sp1_recursion_compiler::ir::{Builder, Config, Felt, Var};
use sp1_recursion_core::{air::RecursionPublicValues, runtime::DIGEST_SIZE};

use crate::{
    challenger::DuplexChallengerVariable,
    fri::TwoAdicMultiplicativeCosetVariable,
    types::VerifyingKeyVariable,
    utils::{assert_challenger_eq_pv, get_preprocessed_data},
};

/// Assertions on the public values describing a complete recursive proof state.
pub(crate) fn assert_complete<C: Config>(
    builder: &mut Builder<C>,
    public_values: &RecursionPublicValues<Felt<C::F>>,
    end_reconstruct_challenger: &DuplexChallengerVariable<C>,
) {
    let RecursionPublicValues {
        deferred_proofs_digest,
        next_pc,
        start_shard,
        cumulative_sum,
        start_reconstruct_deferred_digest,
        end_reconstruct_deferred_digest,
        leaf_challenger,
        ..
    } = public_values;

    // Assert that `end_pc` is equal to zero (so program execution has completed)
    builder.assert_felt_eq(*next_pc, C::F::zero());

    // Assert that the start shard is equal to 1.
    builder.assert_felt_eq(*start_shard, C::F::one());

    // The challenger has been fully verified.

    // The start_reconstruct_challenger should be the same as an empty challenger observing the
    // verifier key and the start pc. This was already verified when verifying the leaf proofs so
    // there is no need to assert it here.

    // Assert that the end reconstruct challenger is equal to the leaf challenger.
    assert_challenger_eq_pv(builder, end_reconstruct_challenger, *leaf_challenger);

    // The deferred digest has been fully reconstructed.

    // The start reconstruct digest should be zero.
    for start_digest_word in start_reconstruct_deferred_digest {
        builder.assert_felt_eq(*start_digest_word, C::F::zero());
    }

    // The end reconstruct digest should be equal to the deferred proofs digest.
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
