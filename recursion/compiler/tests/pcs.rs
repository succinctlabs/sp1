#![allow(clippy::needless_range_loop)]
#![allow(clippy::type_complexity)]

use p3_baby_bear::{BabyBear, DiffusionMatrixBabybear};
use p3_challenger::CanObserve;
use p3_challenger::DuplexChallenger;
use p3_challenger::FieldChallenger;
use p3_commit::ExtensionMmcs;
use p3_commit::Pcs;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::AbstractField;
use p3_field::Field;
use p3_field::PrimeField32;
use p3_fri::FriConfig;
use p3_fri::FriProof;
use p3_fri::TwoAdicFriPcs;
use p3_fri::TwoAdicFriPcsProof;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::Poseidon2;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::rngs::OsRng;
use sp1_core::utils::poseidon2_instance::RC_16_30;
use sp1_recursion_compiler::asm::AsmConfig;
use sp1_recursion_compiler::ir::Array;
use sp1_recursion_compiler::ir::Builder;
use sp1_recursion_compiler::ir::Ext;
use sp1_recursion_compiler::ir::Felt;
use sp1_recursion_compiler::ir::SymbolicExt;
use sp1_recursion_compiler::ir::SymbolicFelt;
use sp1_recursion_compiler::verifier::challenger::DuplexChallengerVariable;
use sp1_recursion_compiler::verifier::fri;
use sp1_recursion_compiler::verifier::fri::pcs::TwoAdicPcsMatsVariable;
use sp1_recursion_compiler::verifier::fri::pcs::TwoAdicPcsRoundVariable;
use sp1_recursion_compiler::verifier::fri::types::Commitment;
use sp1_recursion_compiler::verifier::fri::types::FriCommitPhaseProofStepVariable;
use sp1_recursion_compiler::verifier::fri::types::FriConfigVariable;
use sp1_recursion_compiler::verifier::fri::types::FriProofVariable;
use sp1_recursion_compiler::verifier::fri::types::FriQueryProofVariable;
use sp1_recursion_compiler::verifier::fri::types::DIGEST_SIZE;
use sp1_recursion_compiler::verifier::fri::BatchOpeningVariable;
use sp1_recursion_compiler::verifier::fri::TwoAdicPcsProofVariable;
use sp1_recursion_core::runtime::Runtime;

pub type Val = BabyBear;
pub type Challenge = BinomialExtensionField<Val, 4>;
pub type Perm = Poseidon2<Val, DiffusionMatrixBabybear, 16, 7>;
pub type Hash = PaddingFreeSponge<Perm, 16, 8, 8>;
pub type Compress = TruncatedPermutation<Perm, 2, 8, 16>;
pub type ValMmcs =
    FieldMerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, Hash, Compress, 8>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Challenger = DuplexChallenger<Val, Perm, 16>;
pub type Dft = Radix2DitParallel;
pub type CustomPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
pub type CustomFriProof = FriProof<Challenge, ChallengeMmcs, Val>;
pub type CustomPcsProof = TwoAdicFriPcsProof<Val, Dft, ValMmcs, ChallengeMmcs>;
pub type RecursionConfig = AsmConfig<Val, Challenge>;
pub type RecursionBuilder = Builder<RecursionConfig>;

pub fn const_fri_config(
    builder: &mut RecursionBuilder,
    config: FriConfig<ChallengeMmcs>,
) -> FriConfigVariable<RecursionConfig> {
    FriConfigVariable {
        log_blowup: builder.eval(Val::from_canonical_usize(config.log_blowup)),
        num_queries: builder.eval(Val::from_canonical_usize(config.num_queries)),
        proof_of_work_bits: builder.eval(Val::from_canonical_usize(config.proof_of_work_bits)),
    }
}

pub fn const_fri_proof(
    builder: &mut RecursionBuilder,
    fri_proof: CustomFriProof,
) -> FriProofVariable<RecursionConfig> {
    // Initialize the FRI proof variable.
    let mut fri_proof_var = FriProofVariable {
        commit_phase_commits: builder.dyn_array(fri_proof.commit_phase_commits.len()),
        query_proofs: builder.dyn_array(fri_proof.query_proofs.len()),
        final_poly: builder.eval(SymbolicExt::Const(fri_proof.final_poly)),
        pow_witness: builder.eval(fri_proof.pow_witness),
    };

    // Set the commit phase commits.
    for i in 0..fri_proof.commit_phase_commits.len() {
        let mut commitment: Commitment<_> = builder.dyn_array(DIGEST_SIZE);
        let h: [Val; DIGEST_SIZE] = fri_proof.commit_phase_commits[i].into();
        for j in 0..DIGEST_SIZE {
            builder.set(&mut commitment, j, h[j]);
        }
        builder.set(&mut fri_proof_var.commit_phase_commits, i, commitment);
    }

    // Set the query proofs.
    for (i, query_proof) in fri_proof.query_proofs.iter().enumerate() {
        let mut commit_phase_openings_var: Array<_, FriCommitPhaseProofStepVariable<_>> =
            builder.dyn_array(query_proof.commit_phase_openings.len());

        for (j, commit_phase_opening) in query_proof.commit_phase_openings.iter().enumerate() {
            let mut commit_phase_opening_var = FriCommitPhaseProofStepVariable {
                sibling_value: builder.eval(SymbolicExt::Const(commit_phase_opening.sibling_value)),
                opening_proof: builder.dyn_array(commit_phase_opening.opening_proof.len()),
            };
            for (k, proof) in commit_phase_opening.opening_proof.iter().enumerate() {
                let mut proof_var = builder.dyn_array(DIGEST_SIZE);
                for l in 0..DIGEST_SIZE {
                    builder.set(&mut proof_var, l, proof[l]);
                }
                builder.set(&mut commit_phase_opening_var.opening_proof, k, proof_var);
            }
            builder.set(&mut commit_phase_openings_var, j, commit_phase_opening_var);
        }
        let query_proof = FriQueryProofVariable {
            commit_phase_openings: commit_phase_openings_var,
        };
        builder.set(&mut fri_proof_var.query_proofs, i, query_proof);
    }

    fri_proof_var
}

pub fn const_two_adic_pcs_proof(
    builder: &mut RecursionBuilder,
    proof: TwoAdicFriPcsProof<Val, Challenge, ValMmcs, ChallengeMmcs>,
) -> TwoAdicPcsProofVariable<RecursionConfig> {
    let fri_proof_var = const_fri_proof(builder, proof.fri_proof);
    let mut proof_var = TwoAdicPcsProofVariable {
        fri_proof: fri_proof_var,
        query_openings: builder.dyn_array(proof.query_openings.len()),
    };

    for (i, openings) in proof.query_openings.iter().enumerate() {
        let mut openings_var: Array<_, BatchOpeningVariable<_>> = builder.dyn_array(openings.len());
        for (j, opening) in openings.iter().enumerate() {
            let mut opened_values_var = builder.dyn_array(opening.opened_values.len());
            for (k, opened_value) in opening.opened_values.iter().enumerate() {
                let mut opened_value_var: Array<_, Ext<_, _>> =
                    builder.dyn_array(opened_value.len());
                for (l, ext) in opened_value.iter().enumerate() {
                    let el: Ext<_, _> =
                        builder.eval(SymbolicExt::Base(SymbolicFelt::Const(*ext).into()));
                    builder.set(&mut opened_value_var, l, el);
                }
                builder.set(&mut opened_values_var, k, opened_value_var);
            }

            let mut opening_proof_var = builder.dyn_array(opening.opening_proof.len());
            for (k, sibling) in opening.opening_proof.iter().enumerate() {
                let mut sibling_var = builder.dyn_array(DIGEST_SIZE);
                for l in 0..DIGEST_SIZE {
                    let el: Felt<_> = builder.eval(sibling[l]);
                    builder.set(&mut sibling_var, l, el);
                }
                builder.set(&mut opening_proof_var, k, sibling_var);
            }
            let batch_opening_var = BatchOpeningVariable {
                opened_values: opened_values_var,
                opening_proof: opening_proof_var,
            };
            builder.set(&mut openings_var, j, batch_opening_var);
        }

        builder.set(&mut proof_var.query_openings, i, openings_var);
    }

    proof_var
}

fn const_two_adic_pcs_rounds(
    builder: &mut RecursionBuilder,
    commit: [Val; DIGEST_SIZE],
    os: Vec<(
        TwoAdicMultiplicativeCoset<Val>,
        Vec<(Challenge, Vec<Challenge>)>,
    )>,
) -> (
    Array<RecursionConfig, Felt<Val>>,
    Array<RecursionConfig, TwoAdicPcsRoundVariable<RecursionConfig>>,
) {
    let mut commit_var: Array<_, Felt<_>> = builder.dyn_array(DIGEST_SIZE);
    for i in 0..DIGEST_SIZE {
        let el: Felt<_> = builder.eval(commit[i]);
        builder.set(&mut commit_var, i, el);
    }

    let mut mats: Array<_, TwoAdicPcsMatsVariable<_>> = builder.dyn_array(os.len());
    for (m, (domain, poly)) in os.into_iter().enumerate() {
        let domain = builder.const_domain(&domain);
        let points = poly.iter().map(|(p, _)| *p).collect::<Vec<_>>();
        let values = poly.iter().map(|(_, v)| v.clone()).collect::<Vec<_>>();
        let mut pointsvar: Array<_, Ext<_, _>> = builder.dyn_array(points.len());
        for i in 0..points.len() {
            let el: Ext<_, _> = builder.eval(SymbolicExt::Const(points[i]));
            builder.set(&mut pointsvar, i, el);
        }
        let mut valuesvar: Array<_, Array<_, Ext<_, _>>> = builder.dyn_array(values.len());
        for i in 0..values.len() {
            let mut tmp = builder.dyn_array(values[i].len());
            for j in 0..values[i].len() {
                let el: Ext<_, _> = builder.eval(SymbolicExt::Const(values[i][j]));
                builder.set(&mut tmp, j, el);
            }
            builder.set(&mut valuesvar, i, tmp);
        }
        let mat = TwoAdicPcsMatsVariable {
            domain,
            points: pointsvar,
            values: valuesvar,
        };
        builder.set(&mut mats, m, mat);
    }

    let mut rounds_var: Array<_, TwoAdicPcsRoundVariable<_>> = builder.dyn_array(1);
    let round_var = TwoAdicPcsRoundVariable {
        batch_commit: commit_var.clone(),
        mats,
    };
    builder.set(&mut rounds_var, 0, round_var);

    (commit_var, rounds_var)
}

fn default_fri_config() -> FriConfig<ChallengeMmcs> {
    let perm = Perm::new(8, 22, RC_16_30.to_vec(), DiffusionMatrixBabybear);
    let hash = Hash::new(perm.clone());
    let compress = Compress::new(perm.clone());
    let challenge_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress));
    FriConfig {
        log_blowup: 1,
        num_queries: 100,
        proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    }
}

#[test]
fn test_pcs_verify() {
    let mut rng = &mut OsRng;
    let log_degrees = &[16];
    let perm = Perm::new(8, 22, RC_16_30.to_vec(), DiffusionMatrixBabybear);
    let fri_config = default_fri_config();
    let hash = Hash::new(perm.clone());
    let compress = Compress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let dft = Dft {};
    let pcs: CustomPcs = CustomPcs::new(
        log_degrees.iter().copied().max().unwrap(),
        dft,
        val_mmcs,
        fri_config,
    );

    // Generate proof.
    let domains_and_polys = log_degrees
        .iter()
        .map(|&d| {
            (
                <CustomPcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(&pcs, 1 << d),
                RowMajorMatrix::<Val>::rand(&mut rng, 1 << d, 10),
            )
        })
        .collect::<Vec<_>>();
    let (commit, data) =
        <CustomPcs as Pcs<Challenge, Challenger>>::commit(&pcs, domains_and_polys.clone());
    let mut challenger = Challenger::new(perm.clone());
    challenger.observe(commit);
    let zeta = challenger.sample_ext_element::<Challenge>();
    let points = domains_and_polys
        .iter()
        .map(|_| vec![zeta])
        .collect::<Vec<_>>();
    let (opening, proof) = pcs.open(vec![(&data, points)], &mut challenger);

    // Verify proof.
    let mut challenger = Challenger::new(perm.clone());
    challenger.observe(commit);
    challenger.sample_ext_element::<Challenge>();
    let os: Vec<(
        TwoAdicMultiplicativeCoset<Val>,
        Vec<(Challenge, Vec<Challenge>)>,
    )> = domains_and_polys
        .iter()
        .zip(&opening[0])
        .map(|((domain, _), mat_openings)| (*domain, vec![(zeta, mat_openings[0].clone())]))
        .collect();
    pcs.verify(vec![(commit, os.clone())], &proof, &mut challenger)
        .unwrap();

    let mut builder = RecursionBuilder::default();
    let config = const_fri_config(&mut builder, default_fri_config());
    let proof = const_two_adic_pcs_proof(&mut builder, proof);
    let (commit, rounds) = const_two_adic_pcs_rounds(&mut builder, commit.into(), os);
    let mut challenger = DuplexChallengerVariable::new(&mut builder);
    challenger.observe_commitment(&mut builder, commit);
    challenger.sample_ext(&mut builder);
    fri::verify_two_adic_pcs(&mut builder, &config, rounds, proof, &mut challenger);

    let program = builder.compile();
    let mut runtime = Runtime::<Val, Challenge, _>::new(&program, perm.clone());
    runtime.run();
    println!(
        "The program executed successfully, number of cycles: {}",
        runtime.clk.as_canonical_u32() / 4
    );
}
