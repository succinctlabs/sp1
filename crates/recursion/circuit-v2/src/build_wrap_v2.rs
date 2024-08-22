use std::borrow::Borrow;

use itertools::Itertools;
use p3_baby_bear::BabyBear;
use p3_bn254_fr::Bn254Fr;
use p3_field::AbstractField;
use p3_fri::TwoAdicFriPcsProof;
use sp1_recursion_compiler::{
    config::OuterConfig,
    constraints::{Constraint, ConstraintCompiler},
    ir::{Builder, Config, Ext, Felt, SymbolicExt, Var},
};
use sp1_recursion_core_v2::{
    air::RecursionPublicValues,
    machine::RecursionAir,
    stark::config::{
        BabyBearPoseidon2Outer, OuterChallenge, OuterChallengeMmcs, OuterFriProof, OuterVal,
        OuterValMmcs,
    },
};
use sp1_stark::{
    AirOpenedValues, ChipOpenedValues, ShardCommitment, ShardOpenedValues, ShardProof,
    StarkMachine, StarkVerifyingKey,
};

use crate::{
    challenger::{CanObserveVariable, MultiField32ChallengerVariable},
    stark::{ShardProofVariable, StarkVerifier},
    utils::{felt_bytes_to_bn254_var, felts_to_bn254_var, words_to_bytes},
    witness::Witnessable,
    BatchOpeningVariable, FriCommitPhaseProofStepVariable, FriProofVariable, FriQueryProofVariable,
    TwoAdicPcsProofVariable, VerifyingKeyVariable,
};

pub const DIGEST_SIZE: usize = 1;

type OuterSC = BabyBearPoseidon2Outer;
type OuterC = OuterConfig;
type OuterDigestVariable = [Var<<OuterC as Config>::N>; DIGEST_SIZE];

/// A function to build the circuit for the final wrap layer using the architecture of core-v2.
///
/// For now, the witnessing logic is not implemented and we just witness via constant proof variables.
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
    let preprocessed_commit: OuterDigestVariable = [builder.eval(preprocessed_commit_val[0])];
    challenger.observe_commitment(&mut builder, preprocessed_commit);
    let pc_start = builder.eval(wrap_vk.pc_start);
    challenger.observe(&mut builder, pc_start);

    // let mut witness = OuterWitness::default();
    // template_proof.write(&mut witness);

    let proof = template_proof.read(&mut builder);
    // let proof = const_shard_proof(&mut builder, &template_proof);

    let commited_values_digest = builder.constant(<C as Config>::N::zero());
    builder.commit_commited_values_digest_circuit(commited_values_digest);
    let vkey_hash = builder.constant(<C as Config>::N::zero());
    builder.commit_vkey_hash_circuit(vkey_hash);

    // Validate public values
    // let mut pv_elements = Vec::new();
    // for i in 0..PROOF_MAX_NUM_PVS {
    //     let element = builder.get(&proof.public_values, i);
    //     pv_elements.push(element);
    // }

    let pv: &RecursionPublicValues<_> = proof.public_values.as_slice().borrow();

    // TODO: Add back.
    // let one_felt: Felt<_> = builder.constant(BabyBear::one());
    // // Proof must be complete. In the reduce program, this will ensure that the SP1 proof has
    // // been fully accumulated.
    // builder.assert_felt_eq(pv.is_complete, one_felt);

    // Convert pv.sp1_vk_digest into Bn254
    let pv_vkey_hash = felts_to_bn254_var(&mut builder, &pv.sp1_vk_digest);
    // Vkey hash must match the witnessed commited_values_digest that we are committing to.
    builder.assert_var_eq(pv_vkey_hash, vkey_hash);

    // Convert pv.committed_value_digest into Bn254
    let pv_committed_values_digest_bytes: [Felt<_>; 32] =
        words_to_bytes(&pv.committed_value_digest).try_into().unwrap();
    let pv_committed_values_digest: Var<_> =
        felt_bytes_to_bn254_var(&mut builder, &pv_committed_values_digest_bytes);

    // // Committed values digest must match the witnessed one that we are committing to.
    builder.assert_var_eq(pv_committed_values_digest, commited_values_digest);

    let ShardCommitment { main_commit, .. } = &proof.commitment;
    challenger.observe_commitment(&mut builder, *main_commit);

    challenger.observe_slice(&mut builder, proof.clone().public_values);

    let StarkVerifyingKey { commit, pc_start, chip_information, chip_ordering } = wrap_vk;

    let wrap_vk = VerifyingKeyVariable {
        commitment: commit
            .into_iter()
            .map(|elem| builder.eval(elem))
            .collect_vec()
            .try_into()
            .unwrap(),
        pc_start: builder.eval(*pc_start),
        chip_information: chip_information.clone(),
        chip_ordering: chip_ordering.clone(),
    };

    StarkVerifier::<OuterC, OuterSC, _>::verify_shard(
        &mut builder,
        &wrap_vk,
        &outer_machine,
        &mut challenger.clone(),
        &proof,
    );

    let zero_ext: Ext<_, _> = builder.constant(<OuterConfig as Config>::EF::zero());
    let cumulative_sum: Ext<_, _> = builder.eval(zero_ext);
    for chip in proof.opened_values.chips {
        builder.assign(cumulative_sum, cumulative_sum + chip.cumulative_sum);
    }
    builder.assert_ext_eq(cumulative_sum, zero_ext);

    // TODO: Add back.
    // Verify the public values digest.
    // let calculated_digest =
    //     builder.p2_circuit_babybear_hash(&proof.public_values[0..NUM_PV_ELMS_TO_HASH]);
    // let expected_digest = pv.digest;
    // for (calculated_elm, expected_elm) in calculated_digest.iter().zip(expected_digest.iter()) {
    //     builder.assert_felt_eq(*expected_elm, *calculated_elm);
    // }

    let mut backend = ConstraintCompiler::<OuterConfig>::default();
    backend.emit(builder.operations)
}

/// A utility function to convert a `ShardProof` into a `ShardProofVariable`. Should be replaced by
/// more refined witness generation.
pub fn const_shard_proof(
    builder: &mut Builder<OuterConfig>,
    proof: &ShardProof<OuterSC>,
) -> ShardProofVariable<OuterConfig, BabyBearPoseidon2Outer> {
    let opening_proof = const_two_adic_pcs_proof(builder, proof.opening_proof.clone());
    let opened_values = proof
        .opened_values
        .chips
        .iter()
        .map(|chip| {
            let ChipOpenedValues {
                preprocessed,
                main,
                permutation,
                quotient,
                cumulative_sum,
                log_degree,
            } = chip;
            let AirOpenedValues { local: prepr_local, next: prepr_next } = preprocessed;
            let AirOpenedValues { local: main_local, next: main_next } = main;
            let AirOpenedValues { local: perm_local, next: perm_next } = permutation;

            let quotient =
                quotient.iter().map(|q| q.iter().map(|x| builder.constant(*x)).collect()).collect();
            let cumulative_sum = builder.constant(*cumulative_sum);

            let preprocessed = AirOpenedValues {
                local: prepr_local.iter().map(|x| builder.constant(*x)).collect(),
                next: prepr_next.iter().map(|x| builder.constant(*x)).collect(),
            };

            let main = AirOpenedValues {
                local: main_local.iter().map(|x| builder.constant(*x)).collect(),
                next: main_next.iter().map(|x| builder.constant(*x)).collect(),
            };

            let permutation = AirOpenedValues {
                local: perm_local.iter().map(|x| builder.constant(*x)).collect(),
                next: perm_next.iter().map(|x| builder.constant(*x)).collect(),
            };

            ChipOpenedValues {
                preprocessed,
                main,
                permutation,
                quotient,
                cumulative_sum,
                log_degree: *log_degree,
            }
        })
        .collect();
    let opened_values = ShardOpenedValues { chips: opened_values };
    let ShardCommitment { main_commit, permutation_commit, quotient_commit } = proof.commitment;
    let main_commit: [Bn254Fr; 1] = main_commit.into();
    let permutation_commit: [Bn254Fr; 1] = permutation_commit.into();
    let quotient_commit: [Bn254Fr; 1] = quotient_commit.into();

    let main_commit = core::array::from_fn(|i| builder.eval(main_commit[i]));
    let permutation_commit = core::array::from_fn(|i| builder.eval(permutation_commit[i]));
    let quotient_commit = core::array::from_fn(|i| builder.eval(quotient_commit[i]));

    let commitment = ShardCommitment { main_commit, permutation_commit, quotient_commit };
    ShardProofVariable {
        commitment,
        public_values: proof.public_values.iter().map(|x| builder.constant(*x)).collect(),
        opened_values,
        opening_proof,
        chip_ordering: proof.chip_ordering.clone(),
    }
}

type C = OuterConfig;
type SC = BabyBearPoseidon2Outer;
type N = <C as Config>::N;

// Copy-paste from InnerCircuit implementation, changing generic parameters.
fn const_fri_proof(
    builder: &mut Builder<C>,
    fri_proof: OuterFriProof,
) -> FriProofVariable<OuterConfig, SC> {
    // Set the commit phase commits.
    let commit_phase_commits = fri_proof
        .commit_phase_commits
        .iter()
        .map(|commit| {
            let commit: [N; DIGEST_SIZE] = (*commit).into();
            commit.map(|x| builder.eval(x))
        })
        .collect::<Vec<_>>();

    // Set the query proofs.
    let query_proofs = fri_proof
        .query_proofs
        .iter()
        .map(|query_proof| {
            let commit_phase_openings = query_proof
                .commit_phase_openings
                .iter()
                .map(|commit_phase_opening| {
                    let sibling_value =
                        builder.eval(SymbolicExt::from_f(commit_phase_opening.sibling_value));
                    let opening_proof = commit_phase_opening
                        .opening_proof
                        .iter()
                        .map(|sibling| sibling.map(|x| builder.eval(x)))
                        .collect::<Vec<_>>();
                    FriCommitPhaseProofStepVariable { sibling_value, opening_proof }
                })
                .collect::<Vec<_>>();
            FriQueryProofVariable { commit_phase_openings }
        })
        .collect::<Vec<_>>();

    // Initialize the FRI proof variable.
    FriProofVariable {
        commit_phase_commits,
        query_proofs,
        final_poly: builder.eval(SymbolicExt::from_f(fri_proof.final_poly)),
        pow_witness: builder.eval(fri_proof.pow_witness),
    }
}

pub fn const_two_adic_pcs_proof(
    builder: &mut Builder<OuterConfig>,
    proof: TwoAdicFriPcsProof<OuterVal, OuterChallenge, OuterValMmcs, OuterChallengeMmcs>,
) -> TwoAdicPcsProofVariable<OuterConfig, SC> {
    let fri_proof = const_fri_proof(builder, proof.fri_proof);
    let query_openings = proof
        .query_openings
        .iter()
        .map(|query_opening| {
            query_opening
                .iter()
                .map(|opening| BatchOpeningVariable {
                    opened_values: opening
                        .opened_values
                        .iter()
                        .map(|opened_value| {
                            opened_value
                                .iter()
                                .map(|value| vec![builder.eval::<Felt<_>, _>(*value)])
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>(),
                    opening_proof: opening
                        .opening_proof
                        .iter()
                        .map(|opening_proof| opening_proof.map(|x| builder.eval(x)))
                        .collect::<Vec<_>>(),
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    TwoAdicPcsProofVariable { fri_proof, query_openings }
}
#[cfg(test)]
pub mod tests {

    use std::{borrow::Borrow, iter::once, sync::Arc};

    use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
    use p3_challenger::{CanObserve, FieldChallenger};
    use p3_commit::{Pcs, TwoAdicMultiplicativeCoset};
    use p3_field::{extension::BinomialExtensionField, AbstractField};
    use p3_matrix::dense::RowMajorMatrix;
    use rand::{rngs::StdRng, SeedableRng};
    use sp1_core_machine::utils::{log2_strict_usize, run_test_machine, setup_logger};
    use sp1_recursion_compiler::{
        config::OuterConfig,
        constraints::ConstraintCompiler,
        ir::{Builder, Config, Ext, SymbolicExt},
    };
    use sp1_recursion_core_v2::{
        air::RecursionPublicValues,
        instruction as instr,
        machine::RecursionAir,
        stark::config::{
            outer_fri_config, outer_perm, BabyBearPoseidon2Outer, OuterChallenge, OuterChallenger,
            OuterCompress, OuterDft, OuterHash, OuterPcs, OuterVal, OuterValMmcs,
        },
        BaseAluOpcode, MemAccessKind, RecursionProgram, Runtime,
    };
    use sp1_recursion_gnark_ffi::{Groth16Bn254Prover, PlonkBn254Prover};
    use sp1_stark::{BabyBearPoseidon2Inner, StarkMachine};

    use crate::{
        challenger::CanObserveVariable,
        fri::verify_two_adic_pcs,
        hash::BN254_DIGEST_SIZE,
        utils::{babybear_bytes_to_bn254, babybears_to_bn254, words_to_bytes},
        witness::{OuterWitness, Witnessable},
        Digest, TwoAdicPcsMatsVariable, TwoAdicPcsRoundVariable,
    };

    use super::{build_wrap_circuit_v2, const_two_adic_pcs_proof};

    fn test_machine<F, const DEGREE: usize>(machine_maker: F)
    where
        F: Fn() -> StarkMachine<BabyBearPoseidon2Outer, RecursionAir<BabyBear, DEGREE, 0>>,
    {
        setup_logger();
        let n = 10;
        // Fibonacci(n)
        let instructions = once(instr::mem(MemAccessKind::Write, 1, 0, 0))
            .chain(once(instr::mem(MemAccessKind::Write, 2, 1, 1)))
            .chain((2..=n).map(|i| instr::base_alu(BaseAluOpcode::AddF, 2, i, i - 2, i - 1)))
            .chain(once(instr::mem(MemAccessKind::Read, 1, n - 1, 34)))
            .chain(once(instr::mem(MemAccessKind::Read, 2, n, 55)))
            .collect::<Vec<_>>();

        let machine = machine_maker();
        let program = RecursionProgram { instructions, ..Default::default() };
        let mut runtime =
            Runtime::<BabyBear, BinomialExtensionField<BabyBear, 4>, DiffusionMatrixBabyBear>::new(
                Arc::new(program.clone()),
                BabyBearPoseidon2Inner::new().perm,
            );
        runtime.run().unwrap();

        let (pk, vk) = machine.setup(&program);
        let result = run_test_machine(vec![runtime.record], machine, pk, vk.clone()).unwrap();

        let machine = machine_maker();
        let constraints =
            build_wrap_circuit_v2::<BabyBear, DEGREE>(&vk, result.shard_proofs[0].clone(), machine);

        let pv: &RecursionPublicValues<_> =
            result.shard_proofs[0].public_values.as_slice().borrow();
        let vkey_hash = babybears_to_bn254(&pv.sp1_vk_digest);
        let committed_values_digest_bytes: [BabyBear; 32] =
            words_to_bytes(&pv.committed_value_digest).try_into().unwrap();
        let committed_values_digest = babybear_bytes_to_bn254(&committed_values_digest_bytes);

        // Build the witness.
        let mut witness = OuterWitness::default();
        result.shard_proofs[0].write(&mut witness);
        witness.write_commited_values_digest(committed_values_digest);
        witness.write_vkey_hash(vkey_hash);

        PlonkBn254Prover::test::<OuterConfig>(constraints.clone(), witness.clone());
        Groth16Bn254Prover::test::<OuterConfig>(constraints, witness);
    }

    pub fn machine_with_all_chips<const DEGREE: usize>(
        log_erbl_rows: usize,
        log_p2_rows: usize,
        log_frifold_rows: usize,
    ) -> StarkMachine<BabyBearPoseidon2Outer, RecursionAir<BabyBear, DEGREE, 0>> {
        let config = SC::new_with_log_blowup(log2_strict_usize(DEGREE - 1));
        RecursionAir::<BabyBear, DEGREE, 0>::machine_with_padding(
            config,
            log_frifold_rows,
            log_p2_rows,
            log_erbl_rows,
        )
    }

    #[test]
    fn test_build_wrap() {
        let machine_maker = || machine_with_all_chips::<17>(3, 3, 3);
        test_machine(machine_maker);
    }
    type C = OuterConfig;
    type SC = BabyBearPoseidon2Outer;

    #[allow(clippy::type_complexity)]
    pub fn const_two_adic_pcs_rounds(
        builder: &mut Builder<OuterConfig>,
        commit: [<C as Config>::N; BN254_DIGEST_SIZE],
        os: Vec<(TwoAdicMultiplicativeCoset<OuterVal>, Vec<(OuterChallenge, Vec<OuterChallenge>)>)>,
    ) -> (Digest<OuterConfig, SC>, Vec<TwoAdicPcsRoundVariable<OuterConfig, SC>>) {
        let commit: Digest<OuterConfig, SC> = commit.map(|x| builder.eval(x));

        let mut domains_points_and_opens = Vec::new();
        for (domain, poly) in os.into_iter() {
            let points: Vec<Ext<OuterVal, OuterChallenge>> =
                poly.iter().map(|(p, _)| builder.eval(SymbolicExt::from_f(*p))).collect::<Vec<_>>();
            let values: Vec<Vec<Ext<OuterVal, OuterChallenge>>> = poly
                .iter()
                .map(|(_, v)| {
                    v.clone()
                        .iter()
                        .map(|t| builder.eval(SymbolicExt::from_f(*t)))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let domain_points_and_values = TwoAdicPcsMatsVariable { domain, points, values };
            domains_points_and_opens.push(domain_points_and_values);
        }

        (commit, vec![TwoAdicPcsRoundVariable { batch_commit: commit, domains_points_and_opens }])
    }

    #[test]
    fn test_verify_two_adic_pcs_outer() {
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
        let log_degrees = &[19, 19];
        let perm = outer_perm();
        let mut fri_config = outer_fri_config();

        // Lower blowup factor for testing.
        fri_config.log_blowup = 2;
        let hash = OuterHash::new(perm.clone()).unwrap();
        let compress = OuterCompress::new(perm.clone());
        let val_mmcs = OuterValMmcs::new(hash, compress);
        let dft = OuterDft {};
        let pcs: OuterPcs =
            OuterPcs::new(log_degrees.iter().copied().max().unwrap(), dft, val_mmcs, fri_config);

        // Generate proof.
        let domains_and_polys = log_degrees
            .iter()
            .map(|&d| {
                (
                    <OuterPcs as Pcs<OuterChallenge, OuterChallenger>>::natural_domain_for_degree(
                        &pcs,
                        1 << d,
                    ),
                    RowMajorMatrix::<OuterVal>::rand(&mut rng, 1 << d, 100),
                )
            })
            .collect::<Vec<_>>();
        let (commit, data) = <OuterPcs as Pcs<OuterChallenge, OuterChallenger>>::commit(
            &pcs,
            domains_and_polys.clone(),
        );
        let mut challenger = OuterChallenger::new(perm.clone()).unwrap();
        challenger.observe(commit);
        let zeta = challenger.sample_ext_element::<OuterChallenge>();
        let points = domains_and_polys.iter().map(|_| vec![zeta]).collect::<Vec<_>>();
        let (opening, proof) = pcs.open(vec![(&data, points)], &mut challenger);

        // Verify proof.
        let mut challenger = OuterChallenger::new(perm.clone()).unwrap();
        challenger.observe(commit);
        let x1 = challenger.sample_ext_element::<OuterChallenge>();
        let os = domains_and_polys
            .iter()
            .zip(&opening[0])
            .map(|((domain, _), mat_openings)| (*domain, vec![(zeta, mat_openings[0].clone())]))
            .collect::<Vec<_>>();
        pcs.verify(vec![(commit, os.clone())], &proof, &mut challenger).unwrap();

        // Define circuit.
        let mut builder = Builder::<OuterConfig>::default();
        let mut config = outer_fri_config();

        // Lower blowup factor for testing.
        config.log_blowup = 2;
        let proof = const_two_adic_pcs_proof(&mut builder, proof);
        let (commit, rounds) = const_two_adic_pcs_rounds(&mut builder, commit.into(), os);
        let mut challenger = crate::challenger::MultiField32ChallengerVariable::new(&mut builder);
        challenger.observe_slice(&mut builder, commit);
        let x2 = challenger.sample_ext(&mut builder);
        let x1: Ext<_, _> = builder.constant(x1);
        builder.assert_ext_eq(x1, x2);
        verify_two_adic_pcs::<_, BabyBearPoseidon2Outer>(
            &mut builder,
            &config,
            &proof,
            &mut challenger,
            rounds,
        );
        let mut backend = ConstraintCompiler::<OuterConfig>::default();
        let constraints = backend.emit(builder.operations);
        let witness = OuterWitness::default();
        PlonkBn254Prover::test::<OuterConfig>(constraints, witness);
    }
}
