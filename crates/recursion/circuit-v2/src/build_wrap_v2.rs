// use std::borrow::Borrow;
// use std::iter::once;

// use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
// use p3_bn254_fr::Bn254Fr;
// use p3_field::extension::BinomialExtensionField;
// use p3_field::AbstractField;

// use sp1_recursion_core_v2::{
//     instruction as instr, machine::RecursionAir, BaseAluOpcode, MemAccessKind, RecursionProgram,
//     Runtime,
// };
// use sp1_recursion_gnark_ffi::PlonkBn254Prover;

// use sp1_core::{
//     air::MachineAir,
//     stark::{ShardCommitment, ShardProof, StarkMachine, StarkVerifyingKey, PROOF_MAX_NUM_PVS},
//     utils::{log2_strict_usize, run_test_machine, setup_logger, BabyBearPoseidon2Inner},
// };
// use sp1_recursion_circuit::{
//     challenger::MultiField32ChallengerVariable,
//     stark::StarkVerifierCircuit,
//     types::OuterDigestVariable,
//     utils::{babybear_bytes_to_bn254, babybears_to_bn254, words_to_bytes},
//     witness::Witnessable,
// };
// use sp1_recursion_compiler::{
//     config::OuterConfig,
//     constraints::{Constraint, ConstraintCompiler},
//     ir::{Builder, Config, Ext, Felt, Usize, Var, Witness},
// };
// use sp1_recursion_core::{air::RecursionPublicValues, stark::config::BabyBearPoseidon2Outer};
// use sp1_recursion_program::types::QuotientDataValues;

use std::borrow::Borrow;

use p3_baby_bear::BabyBear;
use p3_bn254_fr::Bn254Fr;
use p3_field::AbstractField;
use sp1_prover::build::Witnessable;
// use sp1_recursion_circuit::types::OuterDigestVariable;
use sp1_recursion_compiler::{
    config::OuterConfig,
    constraints::{Constraint, ConstraintCompiler},
    ir::{Builder, Config, Ext, Felt, Usize, Var},
};
use sp1_recursion_core_v2::{
    air::RecursionPublicValues,
    // stark::{config::BabyBearPoseidon2Outer, RecursionAir},
};
use sp1_recursion_core_v2::{machine::RecursionAir, stark::config::BabyBearPoseidon2Outer};
use sp1_stark::{air::MachineAir, ShardProof, StarkMachine, StarkVerifyingKey, PROOF_MAX_NUM_PVS};

use crate::{
    challenger::{CanObserveVariable, MultiField32ChallengerVariable},
    stark::StarkVerifier,
    utils::{babybear_bytes_to_bn254, babybears_to_bn254, words_to_bytes},
    witness::Witness,
};

pub const DIGEST_SIZE: usize = 1;

type OuterSC = BabyBearPoseidon2Outer;
type OuterC = OuterConfig;
type OuterDigestVariable<C: Config> = [Var<C::N>; DIGEST_SIZE];

/// A function to build the circuit for the wrap layer using the architecture of core-v2.
pub fn build_wrap_circuit_v2<F, const DEGREE: usize>(
    wrap_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: ShardProof<OuterSC>,
    outer_machine: StarkMachine<BabyBearPoseidon2Outer, RecursionAir<BabyBear, DEGREE, 0>>,
) -> Vec<Constraint>
where
{
    let mut builder = Builder::<OuterConfig>::default();
    let mut challenger = MultiField32ChallengerVariable::new(&mut builder);

    let preprocessed_commit_val: [Bn254Fr; 1] = wrap_vk.commit.into();
    let preprocessed_commit: OuterDigestVariable<OuterC> =
        [builder.eval(preprocessed_commit_val[0])];
    challenger.observe_commitment(&mut builder, preprocessed_commit);
    let pc_start = builder.eval(wrap_vk.pc_start);
    challenger.observe(&mut builder, pc_start);

    let mut witness = Witness::default();
    template_proof.write(&mut witness);
    let proof = template_proof.read(&mut builder);

    let commited_values_digest = Bn254Fr::zero().read(&mut builder);
    builder.commit_commited_values_digest_circuit(commited_values_digest);
    let vkey_hash = Bn254Fr::zero().read(&mut builder);
    builder.commit_vkey_hash_circuit(vkey_hash);

    // Validate public values
    let mut pv_elements = Vec::new();
    for i in 0..PROOF_MAX_NUM_PVS {
        let element = builder.get(&proof.public_values, i);
        pv_elements.push(element);
    }

    let pv: &RecursionPublicValues<_> = pv_elements.as_slice().borrow();

    // TODO: Add back.
    // let one_felt: Felt<_> = builder.constant(BabyBear::one());
    // Proof must be complete. In the reduce program, this will ensure that the SP1 proof has
    // been fully accumulated.
    // builder.assert_felt_eq(pv.is_complete, one_felt);

    // Convert pv.sp1_vk_digest into Bn254
    let pv_vkey_hash = babybears_to_bn254(&mut builder, &pv.sp1_vk_digest);
    // Vkey hash must match the witnessed commited_values_digest that we are committing to.
    builder.assert_var_eq(pv_vkey_hash, vkey_hash);

    // Convert pv.committed_value_digest into Bn254
    let pv_committed_values_digest_bytes: [Felt<_>; 32] =
        words_to_bytes(&pv.committed_value_digest).try_into().unwrap();
    let pv_committed_values_digest: Var<_> =
        babybear_bytes_to_bn254(&mut builder, &pv_committed_values_digest_bytes);

    // // Committed values digest must match the witnessed one that we are committing to.
    builder.assert_var_eq(pv_committed_values_digest, commited_values_digest);

    let chips = outer_machine
        .shard_chips_ordered(&template_proof.chip_ordering)
        .map(|chip| chip.name())
        .collect::<Vec<_>>();

    let sorted_indices = outer_machine
        .chips()
        .iter()
        .map(|chip| template_proof.chip_ordering.get(&chip.name()).copied().unwrap_or(usize::MAX))
        .collect::<Vec<_>>();

    let chip_quotient_data = outer_machine
        .shard_chips_ordered(&template_proof.chip_ordering)
        .map(|chip| {
            let log_quotient_degree = chip.log_quotient_degree();
            QuotientDataValues { log_quotient_degree, quotient_size: 1 << log_quotient_degree }
        })
        .collect();

    let ShardCommitment { main_commit, .. } = &proof.commitment;
    challenger.observe_commitment(&mut builder, *main_commit);
    let pv_slice = proof.public_values.slice(
        &mut builder,
        Usize::Const(0),
        Usize::Const(outer_machine.num_pv_elts()),
    );
    challenger.observe_slice(&mut builder, pv_slice);

    StarkVerifier::<OuterC, OuterSC, _>::verify_shard::<_, DEGREE>(
        &mut builder,
        wrap_vk,
        &outer_machine,
        &mut challenger.clone(),
        &proof,
        chip_quotient_data,
        chips,
        sorted_indices,
    );

    let zero_ext: Ext<_, _> = builder.constant(<OuterConfig as Config>::EF::zero());
    let cumulative_sum: Ext<_, _> = builder.eval(zero_ext);
    for chip in proof.opened_values.chips {
        builder.assign(cumulative_sum, cumulative_sum + chip.cumulative_sum);
    }
    builder.assert_ext_eq(cumulative_sum, zero_ext);

    // TODO: Add back.
    // Verify the public values digest.
    // let calculated_digest = builder.p2_babybear_hash(&pv_elements[0..NUM_PV_ELMS_TO_HASH]);
    // let expected_digest = pv.digest;
    // for (calculated_elm, expected_elm) in calculated_digest.iter().zip(expected_digest.iter())
    //     builder.assert_felt_eq(*expected_elm, *calculated_elm);
    // }

    let mut backend = ConstraintCompiler::<OuterConfig>::default();
    backend.emit(builder.operations)
}
#[cfg(test)]
pub mod tests {

    // use super::{machine_with_all_chips, test_machine};

    // #[test]
    // fn test_build_wrap() {
    //     let machine_maker = || machine_with_all_chips::<9>(3, 3, 3);
    //     test_machine(machine_maker);
    // }
}
