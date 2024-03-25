use p3_challenger::CanObserve;
use p3_challenger::CanSampleBits;
use p3_challenger::DuplexChallenger;
use p3_commit::Pcs;
use p3_commit::PolynomialSpace;
use p3_dft::Radix2DitParallel;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_fri::TwoAdicFriPcs;
use rand::rngs::OsRng;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::utils::poseidon2_instance::RC_16_30;
use sp1_core::utils::BabyBearPoseidon2;
use sp1_recursion_compiler::asm::AsmConfig;
use sp1_recursion_compiler::asm::VmBuilder;
use sp1_recursion_compiler::ir::Array;
use sp1_recursion_compiler::ir::Ext;
use sp1_recursion_compiler::ir::Felt;
use sp1_recursion_compiler::ir::SymbolicExt;
use sp1_recursion_compiler::ir::SymbolicFelt;
use sp1_recursion_compiler::ir::Usize;
use sp1_recursion_compiler::ir::Var;
use sp1_recursion_compiler::verifier::challenger::DuplexChallengerVariable;
use sp1_recursion_compiler::verifier::fri;
use sp1_recursion_compiler::verifier::fri::pcs::TwoAdicPcsMats;
use sp1_recursion_compiler::verifier::fri::pcs::TwoAdicPcsRound;
use sp1_recursion_compiler::verifier::fri::types::Commitment;
use sp1_recursion_compiler::verifier::fri::types::FriCommitPhaseProofStepVariable;
use sp1_recursion_compiler::verifier::fri::types::FriConfigVariable;
use sp1_recursion_compiler::verifier::fri::types::FriProofVariable;
use sp1_recursion_compiler::verifier::fri::types::FriQueryProofVariable;
use sp1_recursion_compiler::verifier::fri::types::DIGEST_SIZE;
use sp1_recursion_compiler::verifier::fri::BatchOpening;
use sp1_recursion_compiler::verifier::fri::TwoAdicPcsProof;
use sp1_recursion_compiler::verifier::TwoAdicMultiplicativeCoset;
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
pub type Dft = Radix2DitParallel;
type MyPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

#[test]
fn test_pcs_verify() {
    let log_degrees = &[3];
    let perm = Perm::new(8, 22, RC_16_30.to_vec(), DiffusionMatrixBabybear);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let challenge_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress));
    let fri_config = FriConfig {
        log_blowup: 1,
        num_queries: 10,
        proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let dft = Dft {};
    let max_log_n = log_degrees.iter().copied().max().unwrap();
    let pcs: MyPcs = MyPcs::new(max_log_n, dft, val_mmcs, fri_config);
    let mut challenger = Challenger::new(perm.clone());
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let challenge_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress));
    let fri_config = FriConfig {
        log_blowup: 1,
        num_queries: 10,
        proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };

    let mut rng = &mut OsRng;
    let domains_and_polys = log_degrees
        .iter()
        .map(|&d| {
            (
                <MyPcs as Pcs<Challenge, Challenger>>::natural_domain_for_degree(&pcs, 1 << d),
                RowMajorMatrix::<Val>::rand(&mut rng, 1 << d, 10),
            )
        })
        .collect::<Vec<_>>();

    let (commit, data) =
        <MyPcs as Pcs<Challenge, Challenger>>::commit(&pcs, domains_and_polys.clone());

    challenger.observe(commit);

    let zeta = challenger.sample_ext_element::<Challenge>();

    let points = domains_and_polys
        .iter()
        .map(|_| vec![zeta])
        .collect::<Vec<_>>();

    let (opening, proof) = pcs.open(vec![(&data, points)], &mut challenger);

    // verify the proof.
    println!("RRRRRRR");
    let mut challenger = Challenger::new(perm);
    challenger.observe(commit);
    challenger.sample_ext_element::<Challenge>();

    let os = domains_and_polys
        .iter()
        .zip(&opening[0])
        .map(|((domain, _), mat_openings)| (*domain, vec![(zeta, mat_openings[0].clone())]))
        .collect();
    pcs.verify(vec![(commit, os)], &proof, &mut challenger)
        .unwrap();

    type SC = BabyBearPoseidon2;
    type F = <SC as StarkGenericConfig>::Val;
    type EF = <SC as StarkGenericConfig>::Challenge;
    type C = AsmConfig<F, EF>;

    let mut builder = VmBuilder::<F, EF>::default();
    let commit: [F; DIGEST_SIZE] = commit.into();
    let mut commitvar: Array<C, Felt<F>> = builder.dyn_array(DIGEST_SIZE);
    for i in 0..DIGEST_SIZE {
        let el: Felt<F> = builder.eval(commit[i]);
        builder.set(&mut commitvar, i, el);
    }

    let os: Vec<_> = domains_and_polys
        .iter()
        .zip(&opening[0])
        .map(|((domain, _), mat_openings)| (*domain, vec![(zeta, mat_openings[0].clone())]))
        .collect();
    let mut mats: Array<C, TwoAdicPcsMats<C>> = builder.dyn_array(os.len());
    for (m, (domain, poly)) in os.into_iter().enumerate() {
        let domain = builder.const_domain(&domain);
        let points = poly.iter().map(|(p, _)| *p).collect::<Vec<_>>();
        let values = poly.iter().map(|(_, v)| v.clone()).collect::<Vec<_>>();
        let mut pointsvar: Array<C, Ext<F, EF>> = builder.dyn_array(points.len());
        for i in 0..points.len() {
            let el: Ext<F, EF> = builder.eval(SymbolicExt::Const(points[i]));
            builder.set(&mut pointsvar, i, el);
        }
        let mut valuesvar: Array<C, Array<C, Ext<F, EF>>> = builder.dyn_array(values.len());
        for i in 0..values.len() {
            let mut tmp = builder.dyn_array(values[i].len());
            for j in 0..values[i].len() {
                let el: Ext<F, EF> = builder.eval(SymbolicExt::Const(values[i][j]));
                builder.set(&mut tmp, j, el);
            }
            builder.set(&mut valuesvar, i, tmp);
        }
        let mat = TwoAdicPcsMats::<C> {
            domain,
            points: pointsvar,
            values: valuesvar,
        };
        builder.set(&mut mats, m, mat);
    }

    let mut rounds: Array<C, TwoAdicPcsRound<C>> = builder.dyn_array(1);
    let round = TwoAdicPcsRound::<C> {
        batch_commit: commitvar.clone(),
        mats,
    };
    builder.set(&mut rounds, 0, round);

    let configvar = FriConfigVariable::<AsmConfig<F, EF>> {
        log_blowup: builder.eval(F::from_canonical_usize(fri_config.log_blowup)),
        num_queries: builder.eval(F::from_canonical_usize(fri_config.num_queries)),
        proof_of_work_bits: builder.eval(F::from_canonical_usize(fri_config.proof_of_work_bits)),
    };
    let mut fri_proofvar = FriProofVariable::<AsmConfig<F, EF>> {
        commit_phase_commits: builder.dyn_array(proof.fri_proof.commit_phase_commits.len()),
        query_proofs: builder.dyn_array(proof.fri_proof.query_proofs.len()),
        final_poly: builder.eval(SymbolicExt::Const(proof.fri_proof.final_poly)),
        pow_witness: builder.eval(proof.fri_proof.pow_witness),
    };
    for i in 0..proof.fri_proof.commit_phase_commits.len() {
        let mut commitment: Commitment<C> = builder.dyn_array(DIGEST_SIZE);
        let h: [F; DIGEST_SIZE] = proof.fri_proof.commit_phase_commits[i].into();
        #[allow(clippy::needless_range_loop)]
        for j in 0..DIGEST_SIZE {
            builder.set(&mut commitment, j, h[j]);
        }
        builder.set(&mut fri_proofvar.commit_phase_commits, i, commitment);
    }

    // set query proofs
    for i in 0..proof.fri_proof.query_proofs.len() {
        // create commit phase openings
        let mut commit_phase_openings: Array<
            AsmConfig<F, EF>,
            FriCommitPhaseProofStepVariable<AsmConfig<F, EF>>,
        > = builder.dyn_array(proof.fri_proof.query_proofs[i].commit_phase_openings.len());

        for j in 0..proof.fri_proof.query_proofs[i].commit_phase_openings.len() {
            let mut commit_phase_opening = FriCommitPhaseProofStepVariable {
                sibling_value: builder.eval(SymbolicExt::Const(
                    proof.fri_proof.query_proofs[i].commit_phase_openings[j].sibling_value,
                )),
                opening_proof: builder.dyn_array(
                    proof.fri_proof.query_proofs[i].commit_phase_openings[j]
                        .opening_proof
                        .len(),
                ),
            };
            for k in 0..proof.fri_proof.query_proofs[i].commit_phase_openings[j]
                .opening_proof
                .len()
            {
                let mut arr = builder.dyn_array(DIGEST_SIZE);
                let proof =
                    proof.fri_proof.query_proofs[i].commit_phase_openings[j].opening_proof[k];

                #[allow(clippy::needless_range_loop)]
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
        builder.set(&mut fri_proofvar.query_proofs, i, query_proof);
    }

    let mut proofvar = TwoAdicPcsProof::<C> {
        fri_proof: fri_proofvar,
        query_openings: builder.dyn_array(proof.query_openings.len()), // TODO: fix this
    };
    for i in 0..proof.query_openings.len() {
        let openings = &proof.query_openings[i];
        let mut openingsvar: Array<C, BatchOpening<C>> = builder.dyn_array(openings.len());
        for j in 0..openings.len() {
            let opening = &openings[j];
            let mut opened_valuesvar = builder.dyn_array(opening.opened_values.len());
            for k in 0..opening.opened_values.len() {
                let opened_value = &opening.opened_values[k];
                let mut opened_valuevar: Array<C, Ext<F, EF>> =
                    builder.dyn_array(opened_value.len());
                for l in 0..opened_value.len() {
                    let opened_value = &opened_value[l];
                    let el: Ext<F, EF> = builder.eval(SymbolicExt::Base(
                        SymbolicFelt::Const(opened_value.clone()).into(),
                    ));
                    builder.set(&mut opened_valuevar, l, el);
                }
                builder.set(&mut opened_valuesvar, k, opened_valuevar);
            }
            let mut opening_proofvar = builder.dyn_array(opening.opening_proof.len());
            for k in 0..opening.opening_proof.len() {
                let sibling = &opening.opening_proof[k];
                let mut sibling_var = builder.dyn_array(DIGEST_SIZE);
                for l in 0..DIGEST_SIZE {
                    let el: Felt<_> = builder.eval(sibling[l].clone());
                    builder.set(&mut sibling_var, l, el);
                }
                builder.set(&mut opening_proofvar, k, sibling_var);
            }
            let batch_opening_var = BatchOpening::<C> {
                opened_values: opened_valuesvar,
                opening_proof: opening_proofvar,
            };
            builder.set(&mut openingsvar, j, batch_opening_var);
        }
        builder.set(&mut proofvar.query_openings, i, openingsvar);
    }

    let width: Var<_> = builder.eval(F::from_canonical_usize(POSEIDON2_WIDTH));
    let mut challengervar = DuplexChallengerVariable::<AsmConfig<F, EF>> {
        sponge_state: builder.array(Usize::Var(width)),
        nb_inputs: builder.eval(F::zero()),
        input_buffer: builder.array(Usize::Var(width)),
        nb_outputs: builder.eval(F::zero()),
        output_buffer: builder.array(Usize::Var(width)),
    };
    challengervar.observe_commitment(&mut builder, commitvar);
    challengervar.sample_ext(&mut builder);
    fri::verify_two_adic_pcs(
        &mut builder,
        &configvar,
        rounds,
        proofvar,
        &mut challengervar,
    );

    let program = builder.compile();

    let perm = Perm::new(8, 22, RC_16_30.to_vec(), DiffusionMatrixBabybear);
    let mut runtime = Runtime::<F, EF, _>::new(&program, perm.clone());
    runtime.run();
    println!(
        "The program executed successfully, number of cycles: {}",
        runtime.clk.as_canonical_u32() / 4
    );
}
