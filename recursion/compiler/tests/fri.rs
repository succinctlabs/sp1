#![allow(clippy::needless_range_loop)]

use p3_challenger::CanSampleBits;
use p3_challenger::DuplexChallenger;
use p3_field::AbstractField;
use p3_field::PrimeField32;
use rand::rngs::OsRng;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::utils::poseidon2_instance::RC_16_30;
use sp1_core::utils::BabyBearPoseidon2;
use sp1_recursion_compiler::asm::AsmConfig;
use sp1_recursion_compiler::asm::VmBuilder;
use sp1_recursion_compiler::ir::Array;
use sp1_recursion_compiler::ir::Ext;
use sp1_recursion_compiler::ir::SymbolicExt;
use sp1_recursion_compiler::ir::Usize;
use sp1_recursion_compiler::ir::Var;
use sp1_recursion_compiler::verifier::challenger::DuplexChallengerVariable;
use sp1_recursion_compiler::verifier::fri;
use sp1_recursion_compiler::verifier::fri::types::Commitment;
use sp1_recursion_compiler::verifier::fri::types::FriCommitPhaseProofStepVariable;
use sp1_recursion_compiler::verifier::fri::types::FriConfigVariable;
use sp1_recursion_compiler::verifier::fri::types::FriProofVariable;
use sp1_recursion_compiler::verifier::fri::types::FriQueryProofVariable;
use sp1_recursion_compiler::verifier::fri::types::DIGEST_SIZE;
use sp1_recursion_core::runtime::Runtime;

use itertools::Itertools;
use p3_baby_bear::{BabyBear, DiffusionMatrixBabybear};
use p3_challenger::FieldChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::{Radix2Dit, TwoAdicSubgroupDft};
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::{prover, verifier, FriConfig};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::util::reverse_matrix_index_bits;
use p3_matrix::{Matrix, MatrixRows};
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::Poseidon2;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_util::log2_strict_usize;
use sp1_recursion_core::runtime::POSEIDON2_WIDTH;

pub type Val = BabyBear;
pub type Challenge = BinomialExtensionField<Val, 4>;
pub type Perm = Poseidon2<Val, DiffusionMatrixBabybear, 16, 7>;
pub type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
pub type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
pub type ValMmcs =
    FieldMerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 8>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Challenger = DuplexChallenger<Val, Perm, 16>;
type MyFriConfig = FriConfig<ChallengeMmcs>;

fn get_ldt_for_testing() -> (Perm, MyFriConfig) {
    let perm = Perm::new(8, 22, RC_16_30.to_vec(), DiffusionMatrixBabybear);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress));
    let fri_config = FriConfig {
        log_blowup: 1,
        num_queries: 10,
        proof_of_work_bits: 8,
        mmcs,
    };
    (perm, fri_config)
}

#[test]
fn test_fri_verify_shape_and_sample_challenges() {
    let rng = &mut OsRng;
    let (perm, fc) = get_ldt_for_testing();
    let dft = Radix2Dit::default();

    let shift = Val::generator();

    let ldes: Vec<RowMajorMatrix<Val>> = (3..10)
        .map(|deg_bits| {
            let evals = RowMajorMatrix::<Val>::rand_nonzero(rng, 1 << deg_bits, 16);
            let mut lde = dft.coset_lde_batch(evals, 1, shift);
            reverse_matrix_index_bits(&mut lde);
            lde
        })
        .collect();

    let (proof, reduced_openings, _) = {
        // Prover world
        let mut chal = Challenger::new(perm.clone());
        let alpha: Challenge = chal.sample_ext_element();

        let input: [_; 32] = core::array::from_fn(|log_height| {
            let matrices_with_log_height: Vec<&RowMajorMatrix<Val>> = ldes
                .iter()
                .filter(|m| log2_strict_usize(m.height()) == log_height)
                .collect();
            if matrices_with_log_height.is_empty() {
                None
            } else {
                let reduced: Vec<Challenge> = (0..(1 << log_height))
                    .map(|r| {
                        alpha
                            .powers()
                            .zip(matrices_with_log_height.iter().flat_map(|m| m.row(r)))
                            .map(|(alpha_pow, v)| alpha_pow * v)
                            .sum()
                    })
                    .collect();
                Some(reduced)
            }
        });

        let (proof, idxs) = prover::prove(&fc, &input, &mut chal);

        let log_max_height = input.iter().rposition(Option::is_some).unwrap();
        let reduced_openings: Vec<[Challenge; 32]> = idxs
            .into_iter()
            .map(|idx| {
                input
                    .iter()
                    .enumerate()
                    .map(|(log_height, v)| {
                        if let Some(v) = v {
                            v[idx >> (log_max_height - log_height)]
                        } else {
                            Challenge::zero()
                        }
                    })
                    .collect_vec()
                    .try_into()
                    .unwrap()
            })
            .collect();

        (proof, reduced_openings, chal.sample_bits(8))
    };

    let mut v_challenger = Challenger::new(perm);
    let _alpha: Challenge = v_challenger.sample_ext_element();
    assert_eq!(proof.query_proofs.len(), fc.num_queries);
    let fri_challenges =
        verifier::verify_shape_and_sample_challenges(&fc, &proof, &mut v_challenger)
            .expect("failed verify shape and sample");
    verifier::verify_challenges(&fc, &proof, &fri_challenges, &reduced_openings).unwrap();

    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    type C = AsmConfig<F, EF>;

    let config = SC::default();
    let mut builder = VmBuilder::<F, EF>::default();

    let configvar = FriConfigVariable::<AsmConfig<F, EF>> {
        log_blowup: builder.eval(F::from_canonical_usize(fc.log_blowup)),
        num_queries: builder.eval(F::from_canonical_usize(fc.num_queries)),
        proof_of_work_bits: builder.eval(F::from_canonical_usize(fc.proof_of_work_bits)),
    };
    let mut proofvar = FriProofVariable::<AsmConfig<F, EF>> {
        commit_phase_commits: builder.dyn_array(proof.commit_phase_commits.len()),
        query_proofs: builder.dyn_array(proof.query_proofs.len()),
        final_poly: builder.eval(SymbolicExt::Const(proof.final_poly)),
        pow_witness: builder.eval(proof.pow_witness),
    };
    println!("fc.proof_of_work_bits={:?}", fc.proof_of_work_bits);
    println!(
        "proof.commit_phase_commits.len()={:?}",
        proof.commit_phase_commits.len()
    );
    println!("config.log_blowup={:?}", fc.log_blowup);
    println!("proof.pow_witness={:?}", proof.pow_witness);

    // set commit phase commits
    for i in 0..proof.commit_phase_commits.len() {
        let mut commitment: Commitment<C> = builder.dyn_array(DIGEST_SIZE);
        let h: [F; DIGEST_SIZE] = proof.commit_phase_commits[i].into();
        for j in 0..DIGEST_SIZE {
            builder.set(&mut commitment, j, h[j]);
        }
        builder.set(&mut proofvar.commit_phase_commits, i, commitment);
    }

    // set query proofs
    for i in 0..proof.query_proofs.len() {
        // create commit phase openings
        let mut commit_phase_openings: Array<
            AsmConfig<F, EF>,
            FriCommitPhaseProofStepVariable<AsmConfig<F, EF>>,
        > = builder.dyn_array(proof.query_proofs[i].commit_phase_openings.len());

        for j in 0..proof.query_proofs[i].commit_phase_openings.len() {
            let mut commit_phase_opening = FriCommitPhaseProofStepVariable {
                sibling_value: builder.eval(SymbolicExt::Const(
                    proof.query_proofs[i].commit_phase_openings[j].sibling_value,
                )),
                opening_proof: builder.dyn_array(
                    proof.query_proofs[i].commit_phase_openings[j]
                        .opening_proof
                        .len(),
                ),
            };
            for k in 0..proof.query_proofs[i].commit_phase_openings[j]
                .opening_proof
                .len()
            {
                let mut arr = builder.dyn_array(DIGEST_SIZE);
                let proof = proof.query_proofs[i].commit_phase_openings[j].opening_proof[k];
                if i == 0 && j == 0 && k == 0 {
                    println!("proof={:?}", proof);
                }

                for l in 0..DIGEST_SIZE {
                    builder.set(&mut arr, l, proof[l]);
                }
                builder.set(&mut commit_phase_opening.opening_proof, k, arr);
            }

            builder.set(&mut commit_phase_openings, j, commit_phase_opening);
        }

        let query_proof = FriQueryProofVariable {
            commit_phase_openings,
        };
        builder.set(&mut proofvar.query_proofs, i, query_proof);
    }

    // set reduced openings
    let mut reduced_openings_var = builder.dyn_array(reduced_openings.len());
    for i in 0..reduced_openings.len() {
        let mut reduced_opening = builder.dyn_array(32);
        for j in 0..32 {
            let challenge: Ext<F, EF> = builder.eval(SymbolicExt::Const(reduced_openings[i][j]));
            builder.set(&mut reduced_opening, j, challenge);
        }
        builder.set(&mut reduced_openings_var, i, reduced_opening);
    }

    let width: Var<_> = builder.eval(F::from_canonical_usize(POSEIDON2_WIDTH));
    let mut challenger = DuplexChallengerVariable::<AsmConfig<F, EF>> {
        sponge_state: builder.array(Usize::Var(width)),
        nb_inputs: builder.eval(F::zero()),
        input_buffer: builder.array(Usize::Var(width)),
        nb_outputs: builder.eval(F::zero()),
        output_buffer: builder.array(Usize::Var(width)),
    };
    challenger.sample_ext(&mut builder);
    let challenges = fri::verify_shape_and_sample_challenges(
        &mut builder,
        &configvar,
        &proofvar,
        &mut challenger,
    );
    fri::verify_challenges(
        &mut builder,
        &configvar,
        &proofvar,
        &challenges,
        &reduced_openings_var,
    );

    for i in 0..fri_challenges.query_indices.len() {
        println!(
            "fri_challenges.query_indices[{}] = {}",
            i, fri_challenges.query_indices[i]
        );
        let gt: Var<_> = builder.eval(F::from_canonical_usize(fri_challenges.query_indices[i]));
        let index = builder.get(&challenges.query_indices, i);
        builder.print_v(index);
        builder.assert_var_eq(index, gt);
    }

    let program = builder.compile();

    let mut runtime = Runtime::<F, EF, _>::new(&program, config.perm.clone());
    runtime.run();
    println!(
        "The program executed successfully, number of cycles: {}",
        runtime.clk.as_canonical_u32() / 4
    );
}
