#![allow(clippy::needless_range_loop)]
#![allow(clippy::type_complexity)]

use p3_challenger::CanObserve;
use p3_challenger::FieldChallenger;
use p3_commit::Pcs;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::AbstractField;
use p3_fri::FriConfig;
use p3_fri::TwoAdicFriPcsProof;
use p3_matrix::dense::RowMajorMatrix;
use rand::rngs::OsRng;
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
use sp1_recursion_core::stark::config::inner_fri_config;
use sp1_recursion_core::stark::config::inner_perm;
use sp1_recursion_core::stark::config::InnerChallenge;
use sp1_recursion_core::stark::config::InnerChallengeMmcs;
use sp1_recursion_core::stark::config::InnerChallenger;
use sp1_recursion_core::stark::config::InnerCompress;
use sp1_recursion_core::stark::config::InnerDft;
use sp1_recursion_core::stark::config::InnerFriProof;
use sp1_recursion_core::stark::config::InnerHash;
use sp1_recursion_core::stark::config::InnerPcs;
use sp1_recursion_core::stark::config::InnerVal;
use sp1_recursion_core::stark::config::InnerValMmcs;

pub type RecursionConfig = AsmConfig<InnerVal, InnerChallenge>;
pub type RecursionBuilder = Builder<RecursionConfig>;

pub fn const_fri_config(
    builder: &mut RecursionBuilder,
    config: FriConfig<InnerChallengeMmcs>,
) -> FriConfigVariable<RecursionConfig> {
    FriConfigVariable {
        log_blowup: builder.eval(InnerVal::from_canonical_usize(config.log_blowup)),
        num_queries: builder.eval(InnerVal::from_canonical_usize(config.num_queries)),
        proof_of_work_bits: builder.eval(InnerVal::from_canonical_usize(config.proof_of_work_bits)),
    }
}

pub fn const_fri_proof(
    builder: &mut RecursionBuilder,
    fri_proof: InnerFriProof,
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
        let h: [InnerVal; DIGEST_SIZE] = fri_proof.commit_phase_commits[i].into();
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
    proof: TwoAdicFriPcsProof<InnerVal, InnerChallenge, InnerValMmcs, InnerChallengeMmcs>,
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
    commit: [InnerVal; DIGEST_SIZE],
    os: Vec<(
        TwoAdicMultiplicativeCoset<InnerVal>,
        Vec<(InnerChallenge, Vec<InnerChallenge>)>,
    )>,
) -> (
    Array<RecursionConfig, Felt<InnerVal>>,
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

#[test]
fn test_pcs_verify() {
    let mut rng = &mut OsRng;
    let log_degrees = &[16, 9, 7, 4, 2];
    let perm = inner_perm();
    let fri_config = inner_fri_config();
    let hash = InnerHash::new(perm.clone());
    let compress = InnerCompress::new(perm.clone());
    let val_mmcs = InnerValMmcs::new(hash, compress);
    let dft = InnerDft {};
    let pcs = InnerPcs::new(
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
                <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::natural_domain_for_degree(
                    &pcs,
                    1 << d,
                ),
                RowMajorMatrix::<InnerVal>::rand(&mut rng, 1 << d, 10),
            )
        })
        .collect::<Vec<_>>();
    let (commit, data) =
        <InnerPcs as Pcs<InnerChallenge, InnerChallenger>>::commit(&pcs, domains_and_polys.clone());
    let mut challenger = InnerChallenger::new(perm.clone());
    challenger.observe(commit);
    let zeta = challenger.sample_ext_element::<InnerChallenge>();
    let points = domains_and_polys
        .iter()
        .map(|_| vec![zeta])
        .collect::<Vec<_>>();
    let (opening, proof) = pcs.open(vec![(&data, points)], &mut challenger);

    // Verify proof.
    let mut challenger = InnerChallenger::new(perm.clone());
    challenger.observe(commit);
    challenger.sample_ext_element::<InnerChallenge>();
    let os: Vec<(
        TwoAdicMultiplicativeCoset<InnerVal>,
        Vec<(InnerChallenge, Vec<InnerChallenge>)>,
    )> = domains_and_polys
        .iter()
        .zip(&opening[0])
        .map(|((domain, _), mat_openings)| (*domain, vec![(zeta, mat_openings[0].clone())]))
        .collect();
    pcs.verify(vec![(commit, os.clone())], &proof, &mut challenger)
        .unwrap();

    let mut builder = RecursionBuilder::default();
    let config = const_fri_config(&mut builder, inner_fri_config());
    let proof = const_two_adic_pcs_proof(&mut builder, proof);
    let (commit, rounds) = const_two_adic_pcs_rounds(&mut builder, commit.into(), os);
    let mut challenger = DuplexChallengerVariable::new(&mut builder);
    challenger.observe_commitment(&mut builder, commit);
    challenger.sample_ext(&mut builder);
    fri::verify_two_adic_pcs(&mut builder, &config, rounds, proof, &mut challenger);

    let program = builder.compile();
    let mut runtime = Runtime::<InnerVal, InnerChallenge, _>::new(&program, perm.clone());
    runtime.run();
    println!(
        "The program executed successfully, number of cycles: {}, number of poseidons: {}",
        runtime.timestamp, runtime.nb_poseidons,
    );
}
